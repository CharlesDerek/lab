#include "driver.h"

/* Push locks keep PASSIVE_LEVEL while protecting section creation and teardown. */
void AxLock(EX_PUSH_LOCK *lock) { KeEnterCriticalRegion(); ExAcquirePushLockExclusive(lock); }
void AxUnlock(EX_PUSH_LOCK *lock) { ExReleasePushLockExclusive(lock); KeLeaveCriticalRegion(); }

static BOOLEAN AxSystemProcess(void) {
    PACCESS_TOKEN token = PsReferencePrimaryToken(PsGetCurrentProcess());
    PTOKEN_USER user = NULL;
    NTSTATUS status = SeQueryInformationToken(token, TokenUser, (PVOID *)&user);
    BOOLEAN system = NT_SUCCESS(status) && RtlEqualSid(user->User.Sid, SeExports->SeLocalSystemSid);
    if (user) ExFreePool(user);
    PsDereferencePrimaryToken(token);
    return system;
}
NTSTATUS AxConnect(PFLT_PORT port, PVOID cookie, PVOID context, ULONG bytes, PVOID *connection) {
    UNREFERENCED_PARAMETER(cookie); UNREFERENCED_PARAMETER(context);
    *connection = NULL;
    if (bytes != 0 || !AxSystemProcess()) return STATUS_ACCESS_DENIED;
    AxLock(&Ax.lock);
    /* Closing the port clears Ax.client before disconnect has released the
     * referenced process. Do not let a reconnect replace that reference. */
    if (Ax.client || Ax.client_process || Ax.configuring || Ax.pending) {
        AxUnlock(&Ax.lock); return STATUS_DEVICE_BUSY;
    }
    Ax.client_process = PsGetCurrentProcess();
    ObReferenceObject(Ax.client_process);
    Ax.client = port;
    *connection = Ax.client_process;
    AxUnlock(&Ax.lock);
    return STATUS_SUCCESS;
}
void AxDisconnect(PVOID connection) {
    PEPROCESS process;
    FltCloseClientPort(Ax.filter, &Ax.client);
    AxLock(&Ax.lock);
    process = Ax.client_process;
    NT_ASSERT(process == connection);
    if (process == connection) Ax.client_process = NULL;
    else process = NULL;
    AxUnlock(&Ax.lock);
    if (process) ObDereferenceObject(process);
    /* Keep the policy armed: connection loss never turns protected opens clean. */
}
NTSTATUS AxSectionConflict(PFLT_INSTANCE instance, PFLT_CONTEXT context, PFLT_CALLBACK_DATA data) {
    UNREFERENCED_PARAMETER(instance); UNREFERENCED_PARAMETER(data);
    InterlockedExchange(&((AX_SECTION *)context)->conflicted, 1);
    return STATUS_SUCCESS;
}
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
static NTSTATUS AxMap(uint64_t id, AX_MAPPING *mapping) {
    OBJECT_ATTRIBUTES attributes;
    AX_METADATA current;
    LARGE_INTEGER size;
    HANDLE user_handle = NULL;
    NTSTATUS status = STATUS_NOT_FOUND;
    AX_SCAN_CONTEXT *scan = AxFindScan(id);
    if (!scan) return status;
    AxLock(&scan->lock);
    if (!AxRemaining(scan) || scan->cancelled || scan->mapped || scan->section || scan->stream->writers ||
        (scan->file->SectionObjectPointer && MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer))) {
        status = STATUS_FILE_LOCK_CONFLICT;
        goto done;
    }
    if (scan->notification.bytes == 0) {
        size.QuadPart = 0;
        goto verify;
    }
    status = FltAllocateContext(Ax.filter, FLT_SECTION_CONTEXT, sizeof(AX_SECTION), NonPagedPoolNx, (PFLT_CONTEXT *)&scan->section);
    if (!NT_SUCCESS(status)) goto done;
    RtlZeroMemory(scan->section, sizeof(*scan->section));
    InitializeObjectAttributes(&attributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = FltCreateSectionForDataScan(scan->instance, scan->file, (PFLT_CONTEXT)scan->section,
        SECTION_MAP_READ | SECTION_QUERY, &attributes, NULL, PAGE_READONLY, SEC_COMMIT, 0,
        &scan->section_handle, &scan->section_object, &size);
    if (!NT_SUCCESS(status)) {
        FltReleaseContext((PFLT_CONTEXT)scan->section);
        scan->section = NULL;
        goto done;
    }
verify:
    scan->generation = InterlockedCompareExchange64(&scan->stream->generation, 0, 0);
    status = AxMetadata(scan->instance, scan->file, &current);
    if (!NT_SUCCESS(status) || !AxSameMetadata(&scan->metadata, &current) ||
        size.QuadPart != (LONGLONG)scan->notification.bytes || scan->stream->writers ||
        (scan->section && scan->section->conflicted)) {
        status = STATUS_FILE_LOCK_CONFLICT;
        goto done;
    }
    /* A read-only user handle in the connected process, never a kernel pointer. */
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
NTSTATUS AxMessage(PVOID connection, PVOID input, ULONG input_bytes, PVOID output, ULONG output_bytes, PULONG returned) {
    AX_HEADER header;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    PVOID request = NULL;
    AX_MAPPING mapping;
    AX_STATUS state;
    PVOID result = NULL;
    ULONG result_bytes = 0;
    BOOLEAN same_process;
    *returned = 0;
    AxLock(&Ax.lock);
    same_process = Ax.client && Ax.client_process == connection && connection == PsGetCurrentProcess();
    AxUnlock(&Ax.lock);
    if (!same_process) return STATUS_ACCESS_DENIED;
    if (!input || input_bytes < sizeof(header) || input_bytes > sizeof(AX_CONFIG)) return status;
    request = ExAllocatePool2(POOL_FLAG_NON_PAGED, input_bytes, AX_TAG);
    if (!request) return STATUS_INSUFFICIENT_RESOURCES;
    __try { RtlCopyMemory(request, input, input_bytes); }
    __except (EXCEPTION_EXECUTE_HANDLER) { status = GetExceptionCode(); goto done; }
    RtlCopyMemory(&header, request, sizeof(header));
    if (!AxHeaderValid(&header, input_bytes)) goto done;
    switch (header.operation) {
    case AX_CONFIGURE:
        if (input_bytes != sizeof(AX_CONFIG) || output_bytes != 0 || !AxConfigValid(request)) break;
        status = AxConfigure(request);
        break;
    case AX_DISARM:
        if (input_bytes != sizeof(header) || output_bytes != 0) break;
        status = AxDisarm();
        break;
    case AX_MAP_SCAN:
        if (input_bytes != sizeof(AX_MAP_REQUEST) || output_bytes < sizeof(mapping) || !output) break;
        status = AxMap(((AX_MAP_REQUEST *)request)->request_id, &mapping);
        if (NT_SUCCESS(status)) { result = &mapping; result_bytes = sizeof(mapping); }
        break;
    case AX_GET_STATUS:
        if (input_bytes != sizeof(header) || output_bytes < sizeof(state) || !output) break;
        RtlZeroMemory(&state, sizeof(state));
        AxLock(&Ax.lock);
        state.version = AX_VERSION; state.armed = Ax.armed; state.connected = Ax.client != NULL; state.pending = Ax.pending;
        RtlCopyMemory(state.policy_sha256, Ax.config.policy_sha256, sizeof(state.policy_sha256));
        AxUnlock(&Ax.lock);
        state.allowed = InterlockedCompareExchange64(&Ax.allowed, 0, 0);
        state.malware = InterlockedCompareExchange64(&Ax.malware, 0, 0);
        state.errors = InterlockedCompareExchange64(&Ax.errors, 0, 0);
        state.evidence_dropped = InterlockedCompareExchange64(&Ax.evidence_dropped, 0, 0);
        RtlCopyMemory(state.instance, &Ax.instance, sizeof(state.instance));
        result = &state; result_bytes = sizeof(state); status = STATUS_SUCCESS;
        break;
    default: break;
    }
    if (result) {
        __try { RtlCopyMemory(output, result, result_bytes); *returned = result_bytes; }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            if (header.operation == AX_MAP_SCAN) ZwClose((HANDLE)(ULONG_PTR)mapping.section_handle);
            status = GetExceptionCode();
        }
    }
done:
    ExFreePoolWithTag(request, AX_TAG);
    return status;
}
