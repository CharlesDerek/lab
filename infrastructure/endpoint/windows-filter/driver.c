/* Native file-open enforcement. This driver is never installed by a repo build.
 * Runtime validation, assigned altitude and Microsoft signing are release gates. */
#include "driver.h"
AX_GLOBALS Ax;

BOOLEAN AxIsClient(void) {
    BOOLEAN match;
    AxLock(&Ax.lock);
    match = Ax.client && Ax.client_process == PsGetCurrentProcess();
    AxUnlock(&Ax.lock);
    return match;
}
static FLT_PREOP_CALLBACK_STATUS AxPreMutation(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *completion) {
    AX_STREAM *stream = NULL;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(data);
    *completion = NULL;
    if (!Ax.armed || !objects->FileObject || (objects->FileObject->Flags & FO_STREAM_FILE)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    status = AxGetStream(objects, &stream);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_INSUFFICIENT_RESOURCES) InterlockedExchange(&Ax.poisoned, 1);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    InterlockedIncrement(&stream->writers);
    InterlockedIncrement64(&stream->generation);
    *completion = stream;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}
static FLT_POSTOP_CALLBACK_STATUS AxPostMutation(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID completion, FLT_POST_OPERATION_FLAGS flags) {
    AX_STREAM *stream = completion;
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(objects); UNREFERENCED_PARAMETER(flags);
    InterlockedIncrement64(&stream->generation);
    InterlockedDecrement(&stream->writers);
    FltReleaseContext((PFLT_CONTEXT)stream);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
static FLT_PREOP_CALLBACK_STATUS AxSectionCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *completion) {
    AX_STREAM *stream = NULL;
    *completion = NULL;
    if (Ax.armed && data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType == SyncTypeCreateSection &&
        NT_SUCCESS(AxGetStream(objects, &stream))) {
        InterlockedIncrement64(&stream->generation);
        FltReleaseContext((PFLT_CONTEXT)stream);
    }
    /* This callback only invalidates concurrent scans. It does not pretend the
     * section-synchronization API supports an arbitrary malware-denial status. */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}
static NTSTATUS AxInstanceSetup(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_SETUP_FLAGS flags, DEVICE_TYPE type, FLT_FILESYSTEM_TYPE filesystem) {
    UNREFERENCED_PARAMETER(flags);
    if (type != FILE_DEVICE_DISK_FILE_SYSTEM || filesystem != FLT_FSTYPE_NTFS) return STATUS_FLT_DO_NOT_ATTACH;
    return NT_SUCCESS(FltRegisterForDataScan(objects->Instance)) ? STATUS_SUCCESS : STATUS_FLT_DO_NOT_ATTACH;
}
static NTSTATUS AxQueryTeardown(PCFLT_RELATED_OBJECTS objects, FLT_INSTANCE_QUERY_TEARDOWN_FLAGS flags) {
    UNREFERENCED_PARAMETER(objects); UNREFERENCED_PARAMETER(flags);
    return Ax.armed ? STATUS_FLT_DO_NOT_DETACH : STATUS_SUCCESS;
}
static NTSTATUS AxUnload(FLT_FILTER_UNLOAD_FLAGS flags) {
    if (Ax.armed && !(flags & FLTFL_FILTER_UNLOAD_MANDATORY)) return STATUS_FLT_DO_NOT_DETACH;
    FltCloseCommunicationPort(Ax.server);
    FltCloseClientPort(Ax.filter, &Ax.client);
    ExWaitForRundownProtectionRelease(&Ax.rundown);
    FltUnregisterFilter(Ax.filter);
    AxClosePins(Ax.pins);
    Ax.pins = NULL;
    return STATUS_SUCCESS;
}
static const FLT_CONTEXT_REGISTRATION AxContexts[] = {
    { FLT_STREAM_CONTEXT, 0, NULL, sizeof(AX_STREAM), AX_TAG, NULL, NULL, NULL },
    { FLT_SECTION_CONTEXT, 0, NULL, sizeof(AX_SECTION), AX_TAG, NULL, NULL, NULL },
    { FLT_CONTEXT_END, 0, NULL, 0, 0, NULL, NULL, NULL }
};
static const FLT_OPERATION_REGISTRATION AxOperations[] = {
    { IRP_MJ_CREATE, 0, AxPreCreate, AxPostCreate, NULL },
    { IRP_MJ_WRITE, 0, AxPreMutation, AxPostMutation, NULL },
    { IRP_MJ_SET_INFORMATION, 0, AxPreMutation, AxPostMutation, NULL },
    { IRP_MJ_FILE_SYSTEM_CONTROL, 0, AxPreMutation, AxPostMutation, NULL },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, AxSectionCreate, NULL, NULL },
    { IRP_MJ_OPERATION_END, 0, NULL, NULL, NULL }
};
static const FLT_REGISTRATION AxRegistration = {
    .Size = sizeof(FLT_REGISTRATION),
    .Version = FLT_REGISTRATION_VERSION,
    .ContextRegistration = AxContexts,
    .OperationRegistration = AxOperations,
    .FilterUnloadCallback = AxUnload,
    .InstanceSetupCallback = AxInstanceSetup,
    .InstanceQueryTeardownCallback = AxQueryTeardown,
    .SectionNotificationCallback = AxSectionConflict
};
DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING registry) {
    NTSTATUS status;
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    PSECURITY_DESCRIPTOR security = NULL;
    UNREFERENCED_PARAMETER(registry);
    RtlInitUnicodeString(&name, AX_PORT_NAME);
    RtlZeroMemory(&Ax, sizeof(Ax));
    /* Counters belong to this load, including across client reconnects. A local
     * UUID is sufficient because durable accounting is scoped to one endpoint. */
    status = ExUuidCreate(&Ax.instance);
    if (status != STATUS_SUCCESS && status != RPC_NT_UUID_LOCAL_ONLY)
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    ExInitializePushLock(&Ax.lock);
    ExInitializeRundownProtection(&Ax.rundown);
    InitializeListHead(&Ax.scans);
    status = FltRegisterFilter(driver, &AxRegistration, &Ax.filter);
    if (!NT_SUCCESS(status)) return status;
    status = FltBuildDefaultSecurityDescriptor(&security, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) goto failed;
    InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, security);
    status = FltCreateCommunicationPort(Ax.filter, &Ax.server, &attributes, NULL, AxConnect, AxDisconnect, AxMessage, 1);
    FltFreeSecurityDescriptor(security);
    if (!NT_SUCCESS(status)) goto failed;
    status = FltStartFiltering(Ax.filter);
    if (NT_SUCCESS(status)) return status;
    FltCloseCommunicationPort(Ax.server);
failed:
    FltUnregisterFilter(Ax.filter);
    return status;
}
