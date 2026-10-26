/* Request-owned file-backed mappings. Private read snapshots are never exported. */
#include "driver.h"

static AX_SCAN_CONTEXT *AxFindScan(uint64_t id) {
    PLIST_ENTRY entry;
    AX_SCAN_CONTEXT *found = NULL;
    AxLock(&Ax.lock);
    for (entry = Ax.scans.Flink; entry != &Ax.scans; entry = entry->Flink) {
        AX_SCAN_CONTEXT *scan = CONTAINING_RECORD(entry, AX_SCAN_CONTEXT, entry);
        if (scan->notification.request_id == id) {
            InterlockedIncrement(&scan->references);
            found = scan;
            break;
        }
    }
    AxUnlock(&Ax.lock);
    return found;
}
NTSTATUS AxOpenScanSection(AX_SCAN_CONTEXT *scan) {
    OBJECT_ATTRIBUTES attributes;
    AX_METADATA current;
    LARGE_INTEGER size;
    NTSTATUS status;
    if (scan->section || scan->section_handle || scan->section_object ||
        scan->stream->writers || (scan->file->SectionObjectPointer &&
        MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer)))
        return STATUS_FILE_LOCK_CONFLICT;
    size.QuadPart = 0;
    if (scan->notification.bytes) {
        status = FltAllocateContext(Ax.filter, FLT_SECTION_CONTEXT, sizeof(AX_SECTION),
            NonPagedPoolNx, (PFLT_CONTEXT *)&scan->section);
        if (!NT_SUCCESS(status)) return status;
        RtlZeroMemory(scan->section, sizeof(*scan->section));
        InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        status = FltCreateSectionForDataScan(scan->instance, scan->file,
            (PFLT_CONTEXT)scan->section, SECTION_MAP_READ | SECTION_QUERY,
            &attributes, NULL, PAGE_READONLY, SEC_COMMIT, 0,
            &scan->section_handle, &scan->section_object, &size);
        if (!NT_SUCCESS(status)) {
            FltReleaseContext((PFLT_CONTEXT)scan->section);
            scan->section = NULL;
            return status;
        }
    }
    scan->generation = InterlockedCompareExchange64(&scan->stream->generation, 0, 0);
    status = AxMetadata(scan->instance, scan->file, &current);
    if (!NT_SUCCESS(status) || !AxSameMetadata(&scan->metadata, &current) ||
        size.QuadPart != (LONGLONG)scan->notification.bytes || scan->stream->writers ||
        (scan->section && scan->section->conflicted)) return STATUS_FILE_LOCK_CONFLICT;
    return AxRemaining(scan) ? STATUS_SUCCESS : STATUS_IO_TIMEOUT;
}
NTSTATUS AxMapScan(uint64_t id, AX_MAPPING *mapping) {
    AX_METADATA current;
    HANDLE user_handle = NULL;
    NTSTATUS status = STATUS_NOT_FOUND;
    AX_SCAN_CONTEXT *scan = AxFindScan(id);
    if (!scan) return status;
    AxLock(&scan->lock);
    if (!AxRemaining(scan) || scan->cancelled || scan->mapped || scan->stream->writers ||
        (scan->file->SectionObjectPointer && MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer))) {
        status = STATUS_FILE_LOCK_CONFLICT;
        goto done;
    }
    if (scan->snapshot_mode) {
        /* Reuse only this request's already copied file section. Never reset its
         * generation or substitute another request's section after snapshotting. */
        if (!scan->snapshot_ready || scan->source_view ||
            (scan->notification.bytes && (!scan->section || !scan->section_object)) ||
            (scan->section && scan->section->conflicted) ||
            InterlockedCompareExchange64(&scan->stream->generation, 0, 0) != scan->generation) {
            status = STATUS_FILE_LOCK_CONFLICT;
            goto done;
        }
        status = AxMetadata(scan->instance, scan->file, &current);
        if (!NT_SUCCESS(status) || !AxSameMetadata(&scan->metadata, &current)) {
            status = STATUS_FILE_LOCK_CONFLICT;
            goto done;
        }
    } else {
        status = AxOpenScanSection(scan);
        if (!NT_SUCCESS(status)) goto done;
    }
    /* The unchanged ABI exposes only a read-only FILE-backed section handle. */
    status = scan->section_object ?
        ObOpenObjectByPointer(scan->section_object, 0, NULL, SECTION_MAP_READ, NULL, KernelMode, &user_handle) : STATUS_SUCCESS;
    if (NT_SUCCESS(status) && !AxRemaining(scan)) {
        if (user_handle) ZwClose(user_handle);
        user_handle = NULL;
        status = STATUS_IO_TIMEOUT;
    }
    if (NT_SUCCESS(status)) {
        RtlZeroMemory(mapping, sizeof(*mapping));
        mapping->version = AX_VERSION;
        mapping->request_id = id;
        mapping->section_handle = (uint64_t)(ULONG_PTR)user_handle;
        mapping->bytes = scan->notification.bytes;
        scan->mapped = TRUE;
    }
done:
    AxUnlock(&scan->lock);
    AxReleaseScan(scan);
    return status;
}
