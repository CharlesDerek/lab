/* Native file-open enforcement. This driver is never installed by a repo build.
 * Runtime validation, assigned altitude and Microsoft signing are release gates. */
#include "driver.h"
AX_GLOBALS Ax;

NTSTATUS AxMetadata(PFLT_INSTANCE instance, PFILE_OBJECT file, AX_METADATA *metadata) {
    NTSTATUS status;
    RtlZeroMemory(metadata, sizeof(*metadata));
    status = FltQueryInformationFile(instance, file, &metadata->id, sizeof(metadata->id), FileIdInformation, NULL);
    if (!NT_SUCCESS(status)) return status;
    status = FltQueryInformationFile(instance, file, &metadata->basic, sizeof(metadata->basic), FileBasicInformation, NULL);
    if (!NT_SUCCESS(status)) return status;
    return FltQueryInformationFile(instance, file, &metadata->standard, sizeof(metadata->standard), FileStandardInformation, NULL);
}
BOOLEAN AxSameMetadata(const AX_METADATA *a, const AX_METADATA *b) {
    return RtlCompareMemory(&a->id, &b->id, sizeof(a->id)) == sizeof(a->id) &&
        a->standard.EndOfFile.QuadPart == b->standard.EndOfFile.QuadPart &&
        !b->standard.DeletePending && !b->standard.Directory &&
        !(b->basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
        a->basic.LastWriteTime.QuadPart == b->basic.LastWriteTime.QuadPart &&
        a->basic.ChangeTime.QuadPart == b->basic.ChangeTime.QuadPart;
}
NTSTATUS AxGetStream(PCFLT_RELATED_OBJECTS objects, AX_STREAM **stream) {
    AX_STREAM *created = NULL, *existing = NULL;
    NTSTATUS status = FltGetStreamContext(objects->Instance, objects->FileObject, (PFLT_CONTEXT *)stream);
    if (status != STATUS_NOT_FOUND) return status;
    status = FltAllocateContext(Ax.filter, FLT_STREAM_CONTEXT, sizeof(*created), NonPagedPoolNx, (PFLT_CONTEXT *)&created);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(created, sizeof(*created));
    status = FltSetStreamContext(objects->Instance, objects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        (PFLT_CONTEXT)created, (PFLT_CONTEXT *)&existing);
    if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
        FltReleaseContext((PFLT_CONTEXT)created);
        *stream = existing;
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) FltReleaseContext((PFLT_CONTEXT)created);
    else *stream = created;
    return status;
}
/* Scope and capacity admission share the policy lock with disarm/configure.
 * A scan must never observe one policy's roots and another policy's digest. */
static NTSTATUS AxAdmit(PUNICODE_STRING name, ULONG *timeout, BOOLEAN *admitted) {
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;
    *admitted = FALSE;
    AxLock(&Ax.lock);
    *timeout = Ax.config.timeout_ms;
    if (Ax.armed) for (i = 0; i < Ax.config.root_count; ++i) {
        AX_ROOT *root = &Ax.config.roots[i];
        UNICODE_STRING prefix;
        prefix.Buffer = (PWCHAR)root->path;
        prefix.Length = (USHORT)(root->characters * sizeof(WCHAR));
        prefix.MaximumLength = prefix.Length;
        if (name->Length > prefix.Length && name->Buffer[root->characters] == L'\\' &&
            RtlPrefixUnicodeString(&prefix, name, TRUE)) {
            if (Ax.pending >= (LONG)AX_PENDING) status = STATUS_INSUFFICIENT_RESOURCES;
            else { InterlockedIncrement(&Ax.pending); *admitted = TRUE; }
            break;
        }
    }
    AxUnlock(&Ax.lock);
    return status;
}
static BOOLEAN AxIsClient(void) {
    BOOLEAN match;
    AxLock(&Ax.lock);
    match = Ax.client && Ax.client_process == PsGetCurrentProcess();
    AxUnlock(&Ax.lock);
    return match;
}
static void AxDeny(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects) {
    FltCancelFileOpen(objects->Instance, objects->FileObject);
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
}
static void AxApplied(AX_SCAN_CONTEXT *scan, AX_REPLY *reply, NTSTATUS status) {
    AX_APPLIED_NOTIFICATION *message = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*message), AX_TAG);
    LARGE_INTEGER deadline;
    NTSTATUS delivered;
    if (!message) { InterlockedIncrement64(&Ax.evidence_dropped); return; }
    RtlCopyMemory(&message->file, &scan->notification, sizeof(message->file));
    message->file.operation = AX_APPLIED;
    RtlCopyMemory(&message->decision, reply, sizeof(*reply));
    message->status = status;
    deadline.QuadPart = -100000; /* Evidence delivery cannot add an unbounded wait. */
    delivered = FltSendMessage(Ax.filter, &Ax.client, message, sizeof(*message), NULL, NULL, &deadline);
    if (delivered != STATUS_SUCCESS) InterlockedIncrement64(&Ax.evidence_dropped);
    ExFreePoolWithTag(message, AX_TAG);
}
static NTSTATUS AxScan(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PUNICODE_STRING name, ULONG timeout) {
    AX_SCAN_CONTEXT *scan;
    AX_STREAM *stream = NULL;
    AX_METADATA after;
    AX_REPLY reply;
    LARGE_INTEGER deadline;
    ULONG bytes = sizeof(reply);
    NTSTATUS status;
    BOOLEAN clean = FALSE;
    /* AxAdmit owns one pending slot; the final context reference releases it. */
    scan = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*scan), AX_TAG);
    if (!scan) { InterlockedDecrement(&Ax.pending); return STATUS_INSUFFICIENT_RESOURCES; }
    status = AxGetStream(objects, &stream);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(scan, AX_TAG); InterlockedDecrement(&Ax.pending); return status; }
    scan->references = 1;
    scan->stream = stream;
    scan->instance = objects->Instance;
    scan->file = objects->FileObject;
    ExInitializePushLock(&scan->lock);
    FltObjectReference(scan->instance);
    ObReferenceObject(scan->file);
    status = AxMetadata(scan->instance, scan->file, &scan->metadata);
    if (!NT_SUCCESS(status)) goto done;
    if (scan->metadata.standard.Directory || scan->metadata.standard.DeletePending ||
        scan->metadata.standard.EndOfFile.QuadPart < 0 ||
        scan->metadata.standard.EndOfFile.QuadPart > (LONGLONG)AX_MAX_FILE ||
        (scan->metadata.basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        objects->Transaction || Ax.poisoned) { status = STATUS_NOT_SUPPORTED; goto done; }
    scan->notification.version = AX_VERSION;
    scan->notification.operation = AX_SCAN;
    scan->notification.request_id = (uint64_t)InterlockedIncrement64(&Ax.next_id);
    scan->notification.bytes = scan->metadata.standard.EndOfFile.QuadPart;
    scan->notification.volume = scan->metadata.id.VolumeSerialNumber;
    scan->notification.actor_pid = FltGetRequestorProcessId(data);
    if (FltGetRequestorProcess(data)) scan->notification.actor_created = PsGetProcessCreateTimeQuadPart(FltGetRequestorProcess(data));
    RtlCopyMemory(scan->notification.file_id, scan->metadata.id.FileId.Identifier, 16);
    scan->notification.path_characters = name->Length / sizeof(WCHAR);
    RtlCopyMemory(scan->notification.path, name->Buffer, name->Length);
    AxLock(&Ax.lock);
    RtlCopyMemory(scan->notification.policy_sha256, Ax.config.policy_sha256, sizeof(scan->notification.policy_sha256));
    InsertTailList(&Ax.scans, &scan->entry);
    scan->listed = TRUE;
    AxUnlock(&Ax.lock);
    RtlZeroMemory(&reply, sizeof(reply));
    /* Absolute deadline bounds both delivery and reply waits. STATUS_TIMEOUT is
     * an NT_SUCCESS status, so only exact STATUS_SUCCESS can authorize a file. */
    KeQuerySystemTimePrecise(&deadline);
    deadline.QuadPart += (LONGLONG)timeout * 10000;
    status = FltSendMessage(Ax.filter, &Ax.client, &scan->notification,
        sizeof(scan->notification), &reply, &bytes, &deadline);
    AxLock(&scan->lock);
    if (status == STATUS_SUCCESS && bytes == sizeof(reply) && AxReplyValid(&reply, scan->notification.request_id) &&
        scan->mapped && (!scan->section || !scan->section->conflicted) && !scan->stream->writers && !Ax.poisoned &&
        InterlockedCompareExchange64(&scan->stream->generation, 0, 0) == scan->generation &&
        !(scan->file->SectionObjectPointer && MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer)) &&
        NT_SUCCESS(AxMetadata(scan->instance, scan->file, &after)) && AxSameMetadata(&scan->metadata, &after)) {
        clean = reply.verdict == AX_CLEAN;
        if (reply.verdict == AX_MALWARE) InterlockedIncrement64(&Ax.malware);
    } else {
        RtlZeroMemory(&reply, sizeof(reply));
        reply.version = AX_VERSION; reply.verdict = AX_ERROR; reply.request_id = scan->notification.request_id;
    }
    scan->cancelled = TRUE;
    AxUnlock(&scan->lock);
    /* Cancellation may issue filesystem cleanup. Release our scan section
     * first so that cleanup cannot wait on synchronization owned by this call. */
    AxCloseScanSection(scan);
    status = clean ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    if (clean) InterlockedIncrement64(&Ax.allowed);
    else {
        if (reply.verdict == AX_ERROR) InterlockedIncrement64(&Ax.errors);
        AxDeny(data, objects);
    }
    AxApplied(scan, &reply, status);
done:
    AxLock(&Ax.lock);
    if (scan->listed) { RemoveEntryList(&scan->entry); scan->listed = FALSE; }
    AxUnlock(&Ax.lock);
    AxLock(&scan->lock);
    scan->cancelled = TRUE;
    AxUnlock(&scan->lock);
    AxReleaseScan(scan);
    return status;
}
static FLT_PREOP_CALLBACK_STATUS AxPreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *completion) {
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(objects);
    *completion = NULL;
    return Ax.armed && !AxIsClient() ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SUCCESS_NO_CALLBACK;
}
static FLT_POSTOP_CALLBACK_STATUS AxPostCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID completion, FLT_POST_OPERATION_FLAGS flags) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS status;
    BOOLEAN directory = FALSE;
    BOOLEAN admitted = FALSE;
    ULONG timeout = 0;
    UNREFERENCED_PARAMETER(completion);
    if ((flags & FLTFL_POST_OPERATION_DRAINING) || !NT_SUCCESS(data->IoStatus.Status) ||
        data->IoStatus.Status == STATUS_REPARSE || !Ax.armed || AxIsClient()) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!ExAcquireRundownProtection(&Ax.rundown)) { AxDeny(data, objects); return FLT_POSTOP_FINISHED_PROCESSING; }
    status = FltIsDirectory(objects->FileObject, objects->Instance, &directory);
    if (NT_SUCCESS(status) && directory) goto done;
    if (!NT_SUCCESS(status)) goto deny;
    status = FltGetFileNameInformation(data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &name);
    if (!NT_SUCCESS(status)) goto deny;
    /* Delete/attribute-only handles cannot consume file contents. This also
     * permits controlled response to move evidence out of the protected scope. */
    if (!objects->FileObject->ReadAccess &&
        !(data->Iopb->Parameters.Create.SecurityContext->DesiredAccess &
          (FILE_READ_DATA | FILE_EXECUTE | MAXIMUM_ALLOWED | GENERIC_READ | GENERIC_EXECUTE | GENERIC_ALL))) goto done;
    status = AxAdmit(&name->Name, &timeout, &admitted);
    if (!NT_SUCCESS(status)) goto deny;
    if (!admitted) goto done;
    if (name->Name.Length == 0 || name->Name.Length >= AX_PATH_CHARS * sizeof(WCHAR)) goto deny;
    admitted = FALSE; /* Transfer capacity ownership to AxScan. */
    status = AxScan(data, objects, &name->Name, timeout);
    if (status == STATUS_SUCCESS) goto done;
deny:
    if (NT_SUCCESS(data->IoStatus.Status)) {
        InterlockedIncrement64(&Ax.errors);
        InterlockedIncrement64(&Ax.evidence_dropped);
        AxDeny(data, objects);
    }
done:
    if (admitted) InterlockedDecrement(&Ax.pending);
    if (name) FltReleaseFileNameInformation(name);
    ExReleaseRundownProtection(&Ax.rundown);
    return FLT_POSTOP_FINISHED_PROCESSING;
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
