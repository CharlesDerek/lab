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
        status = AxMapScan(((AX_MAP_REQUEST *)request)->request_id, &mapping);
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
