/* Private full-file bytes for ordinary read admission. No private section is
 * exported. The existing broker hashes the exact bytes sent to INSTREAM. */
#include "driver.h"
#include <bcrypt.h>

BOOLEAN AxReserveReadBytes(ULONG64 bytes) {
    LONG64 old;
    if (bytes > AX_READ_BUDGET) return FALSE;
    do {
        old = InterlockedCompareExchange64(&Ax.read_bytes, 0, 0);
        if (old < 0 || (ULONG64)old > AX_READ_BUDGET - bytes) return FALSE;
    } while (InterlockedCompareExchange64(&Ax.read_bytes, old + (LONG64)bytes, old) != old);
    return TRUE;
}
void AxReleaseReadBytes(ULONG64 bytes) {
    LONG64 old;
    do {
        old = InterlockedCompareExchange64(&Ax.read_bytes, 0, 0);
        NT_ASSERT(old >= 0 && (ULONG64)old >= bytes);
    } while (InterlockedCompareExchange64(&Ax.read_bytes, old - (LONG64)bytes, old) != old);
}
static BOOLEAN AxSnapshotCurrent(PFLT_CALLBACK_DATA data, AX_SCAN_CONTEXT *scan) {
    return AxRemaining(scan) && !FltIsIoCanceled(data) && !Ax.poisoned &&
        !scan->stream->writers && (!scan->section || !scan->section->conflicted) &&
        InterlockedCompareExchange64(&scan->stream->generation, 0, 0) == scan->generation &&
        !(scan->file->SectionObjectPointer && MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer));
}
NTSTATUS AxMakeSnapshot(PFLT_CALLBACK_DATA data, AX_SCAN_CONTEXT *scan) {
    NTSTATUS status;
    AX_METADATA after;
    SIZE_T view_bytes = 0;
    ULONG64 offset = 0, bytes = scan->notification.bytes;
    UCHAR empty = 0;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL && scan->snapshot_mode);
    if (bytes > AX_MAX_FILE || !ExAcquireRundownProtection(&Ax.rundown)) return STATUS_INSUFFICIENT_RESOURCES;
    scan->snapshot_rundown = TRUE;
    status = AxOpenScanSection(scan);
    if (!NT_SUCCESS(status)) return status;
    if (!AxSnapshotCurrent(data, scan)) return STATUS_FILE_LOCK_CONFLICT;
    if (bytes) {
        if (!AxReserveReadBytes(bytes)) return STATUS_INSUFFICIENT_RESOURCES;
        scan->snapshot_charge = bytes;
        scan->snapshot = ExAllocatePool2(POOL_FLAG_PAGED, (SIZE_T)bytes, AX_TAG);
        if (!scan->snapshot) return STATUS_INSUFFICIENT_RESOURCES;
        view_bytes = (SIZE_T)bytes;
        status = MmMapViewInSystemSpace(scan->section_object, &scan->source_view, &view_bytes);
        if (!NT_SUCCESS(status)) return status;
        if (!scan->source_view || view_bytes < bytes) status = STATUS_FILE_LOCK_CONFLICT;
        else {
            __try {
                while (offset < bytes) {
                    SIZE_T count = (SIZE_T)((bytes - offset) > 65536 ? 65536 : bytes - offset);
                    if (!AxSnapshotCurrent(data, scan)) { status = STATUS_FILE_LOCK_CONFLICT; break; }
                    RtlCopyMemory((PUCHAR)scan->snapshot + (SIZE_T)offset,
                        (PUCHAR)scan->source_view + (SIZE_T)offset, count);
                    offset += count;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); }
        }
        if (scan->source_view) {
            NTSTATUS unmapped = MmUnmapViewInSystemSpace(scan->source_view);
            if (!NT_SUCCESS(unmapped)) {
                /* An unconfirmed live view must keep its section, snapshot,
                 * slot, charge and independent rundown reference. Poison stops
                 * new admission; final release cannot pretend cleanup worked.
                 * Host recovery is required for this exceptional API failure. */
                InterlockedExchange(&Ax.poisoned, 1);
                InterlockedIncrement(&Ax.retained_views);
                return unmapped;
            }
            scan->source_view = NULL;
        }
        if (!NT_SUCCESS(status) || offset != bytes) return NT_SUCCESS(status) ? STATUS_FILE_LOCK_CONFLICT : status;
    }
    if (!AxSnapshotCurrent(data, scan)) return STATUS_FILE_LOCK_CONFLICT;
    status = AxMetadata(scan->instance, scan->file, &after);
    if (!NT_SUCCESS(status) || !AxSameMetadata(&scan->metadata, &after)) return STATUS_FILE_LOCK_CONFLICT;
    /* Windows 10+ CNG pseudo-handles are supported in kernel mode below
     * DISPATCH. BCryptHash owns its internal hash lifetime, including errors. */
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0,
        bytes ? scan->snapshot : &empty, (ULONG)bytes,
        scan->snapshot_sha256, sizeof(scan->snapshot_sha256));
    if (!NT_SUCCESS(status)) return status;
    if (!AxSnapshotCurrent(data, scan)) return STATUS_FILE_LOCK_CONFLICT;
    scan->snapshot_ready = TRUE;
    return STATUS_SUCCESS;
}
BOOLEAN AxReleaseSnapshot(AX_SCAN_CONTEXT *scan) {
    if (scan->source_view) {
        NT_ASSERT(Ax.poisoned && Ax.retained_views && scan->snapshot_rundown);
        return FALSE;
    }
    if (scan->snapshot) { ExFreePoolWithTag(scan->snapshot, AX_TAG); scan->snapshot = NULL; }
    if (scan->snapshot_charge) { AxReleaseReadBytes(scan->snapshot_charge); scan->snapshot_charge = 0; }
    return TRUE;
}
