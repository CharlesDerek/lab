/* Operation-neutral scan preparation. The adapter owns the applied decision;
 * no file-open cancellation or allowed/malware/error accounting occurs here. */
#include "driver.h"

static ULONG64 AxNow(void) {
    ULONG64 qpc;
    return KeQueryInterruptTimePrecise(&qpc);
}
ULONG64 AxRemaining(const AX_SCAN_CONTEXT *scan) {
    ULONG64 now = AxNow();
    return now >= scan->admitted_at && now < scan->deadline ? scan->deadline - now : 0;
}
NTSTATUS AxAdmit(PUNICODE_STRING name, AX_ADMISSION *admission, BOOLEAN *admitted) {
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;
    *admitted = FALSE;
    AxLock(&Ax.lock);
    if (Ax.armed) for (i = 0; i < Ax.config.root_count; ++i) {
        AX_ROOT *root = &Ax.config.roots[i];
        UNICODE_STRING prefix;
        prefix.Buffer = (PWCHAR)root->path;
        prefix.Length = (USHORT)(root->characters * sizeof(WCHAR));
        prefix.MaximumLength = prefix.Length;
        if (name->Length > prefix.Length && name->Buffer[root->characters] == L'\\' &&
            RtlPrefixUnicodeString(&prefix, name, TRUE)) {
            ULONG64 budget = (ULONG64)Ax.config.timeout_ms * 10000;
            ULONG64 now = AxNow();
            if (Ax.poisoned) status = STATUS_FILE_LOCK_CONFLICT;
            else if (!budget || now > MAXULONGLONG - budget) status = STATUS_IO_TIMEOUT;
            else if (Ax.pending >= (LONG)AX_PENDING) status = STATUS_INSUFFICIENT_RESOURCES;
            else {
                admission->admitted_at = now;
                admission->deadline = now + budget;
                RtlCopyMemory(admission->policy_sha256, Ax.config.policy_sha256, sizeof(admission->policy_sha256));
                InterlockedIncrement(&Ax.pending);
                *admitted = TRUE;
            }
            break;
        }
    }
    AxUnlock(&Ax.lock);
    return status;
}
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
/* Called after cancellation excludes new mappings, or by the last reference. */
void AxCloseScanSection(AX_SCAN_CONTEXT *scan) {
    if (scan->section_handle) { ZwClose(scan->section_handle); scan->section_handle = NULL; }
    if (scan->section_object) { ObDereferenceObject(scan->section_object); scan->section_object = NULL; }
    if (scan->section) {
        NTSTATUS status = FltCloseSectionForDataScan((PFLT_CONTEXT)scan->section);
        /* Conflict callbacks can run during closure. Read the owned context
         * after the close returns, before releasing its final local reference. */
        if (status != STATUS_SUCCESS || scan->section->conflicted) scan->conflicted = TRUE;
        FltReleaseContext((PFLT_CONTEXT)scan->section);
        scan->section = NULL;
    }
}
void AxReleaseScan(AX_SCAN_CONTEXT *scan) {
    BOOLEAN snapshot_rundown;
    if (InterlockedDecrement(&scan->references)) return;
    if (!AxReleaseSnapshot(scan)) {
        /* Preserve one exceptional retained-view owner; never admit its slot
         * or free section callback storage while unmapping is unconfirmed. */
        InterlockedIncrement(&scan->references);
        return;
    }
    AxCloseScanSection(scan);
    FltReleaseContext((PFLT_CONTEXT)scan->stream);
    ObDereferenceObject(scan->file);
    FltObjectDereference(scan->instance);
    snapshot_rundown = scan->snapshot_rundown;
    ExFreePoolWithTag(scan, AX_TAG);
    InterlockedDecrement(&Ax.pending);
    if (snapshot_rundown) ExReleaseRundownProtection(&Ax.rundown);
}

static BOOLEAN AxRequestCancelled(PFLT_CALLBACK_DATA data) {
    return FLT_IS_IRP_OPERATION(data) && FltIsIoCanceled(data);
}
static void AxErrorReply(AX_REPLY *reply, uint64_t id) {
    RtlZeroMemory(reply, sizeof(*reply));
    reply->version = AX_VERSION;
    reply->verdict = AX_ERROR;
    reply->request_id = id;
}
static NTSTATUS AxPrepare(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects,
    PUNICODE_STRING name, const AX_ADMISSION *admission, BOOLEAN snapshot,
    ULONG64 actor_pid, ULONG64 actor_created, AX_SCAN_RESULT *result) {
    AX_SCAN_CONTEXT *scan;
    AX_STREAM *stream = NULL;
    AX_METADATA after;
    LARGE_INTEGER wall_deadline;
    ULONG bytes = sizeof(result->reply);
    ULONG64 remaining;
    NTSTATUS status;
    RtlZeroMemory(result, sizeof(*result));
    /* Admission owns exactly one slot; even setup failure consumes/releases it. */
    scan = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*scan), AX_TAG);
    if (!scan) { InterlockedDecrement(&Ax.pending); return STATUS_INSUFFICIENT_RESOURCES; }
    status = AxGetStream(objects, &stream);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(scan, AX_TAG); InterlockedDecrement(&Ax.pending); return status; }
    status = FltObjectReference(objects->Instance);
    if (!NT_SUCCESS(status)) {
        FltReleaseContext((PFLT_CONTEXT)stream);
        ExFreePoolWithTag(scan, AX_TAG);
        InterlockedDecrement(&Ax.pending);
        return status;
    }
    scan->references = 1;
    scan->stream = stream;
    scan->instance = objects->Instance;
    scan->file = objects->FileObject;
    scan->admitted_at = admission->admitted_at;
    scan->deadline = admission->deadline;
    scan->snapshot_mode = snapshot;
    ExInitializePushLock(&scan->lock);
    ObReferenceObject(scan->file);
    result->scan = scan;
    if (!AxRemaining(scan) || AxRequestCancelled(data)) return STATUS_IO_TIMEOUT;
    status = AxMetadata(scan->instance, scan->file, &scan->metadata);
    if (!NT_SUCCESS(status)) return status;
    if (scan->metadata.standard.Directory || scan->metadata.standard.DeletePending ||
        scan->metadata.standard.EndOfFile.QuadPart < 0 ||
        scan->metadata.standard.EndOfFile.QuadPart > (LONGLONG)AX_MAX_FILE ||
        (scan->metadata.basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) ||
        objects->Transaction || Ax.poisoned) return STATUS_NOT_SUPPORTED;
    if (!AxRemaining(scan) || AxRequestCancelled(data)) return STATUS_IO_TIMEOUT;
    scan->notification.version = AX_VERSION;
    scan->notification.operation = AX_SCAN;
    scan->notification.request_id = (uint64_t)InterlockedIncrement64(&Ax.next_id);
    scan->notification.bytes = scan->metadata.standard.EndOfFile.QuadPart;
    scan->notification.volume = scan->metadata.id.VolumeSerialNumber;
    scan->notification.actor_pid = actor_pid;
    scan->notification.actor_created = actor_created;
    RtlCopyMemory(scan->notification.file_id, scan->metadata.id.FileId.Identifier, 16);
    scan->notification.path_characters = name->Length / sizeof(WCHAR);
    RtlCopyMemory(scan->notification.path, name->Buffer, name->Length);
    RtlCopyMemory(scan->notification.policy_sha256, admission->policy_sha256, sizeof(scan->notification.policy_sha256));
    if (snapshot) {
        status = AxMakeSnapshot(data, scan);
        if (!NT_SUCCESS(status)) return status;
    }
    AxLock(&Ax.lock);
    InsertTailList(&Ax.scans, &scan->entry);
    scan->listed = TRUE;
    AxUnlock(&Ax.lock);
    /* Preserve a single absolute message deadline for delivery plus reply.
     * Wall-clock changes may alter this finite wait; they cannot extend the
     * independent monotonic authorization budget. Kernel FS calls may stall. */
    KeQuerySystemTimePrecise(&wall_deadline);
    remaining = AxRemaining(scan);
    if (!remaining || wall_deadline.QuadPart <= 0 ||
        remaining > (ULONG64)MAXLONGLONG - (ULONG64)wall_deadline.QuadPart) status = STATUS_IO_TIMEOUT;
    else {
        wall_deadline.QuadPart += (LONGLONG)remaining;
        status = FltSendMessage(Ax.filter, &Ax.client, &scan->notification,
            sizeof(scan->notification), &result->reply, &bytes, &wall_deadline);
    }
    AxLock(&scan->lock);
    result->valid = status == STATUS_SUCCESS && bytes == sizeof(result->reply) &&
        AxReplyValid(&result->reply, scan->notification.request_id) && !scan->cancelled &&
        (!snapshot || (scan->snapshot_ready && RtlCompareMemory(result->reply.sha256,
            scan->snapshot_sha256, sizeof(scan->snapshot_sha256)) == sizeof(scan->snapshot_sha256))) &&
        scan->mapped && (!scan->section || !scan->section->conflicted) && !scan->stream->writers && !Ax.poisoned &&
        InterlockedCompareExchange64(&scan->stream->generation, 0, 0) == scan->generation &&
        !(scan->file->SectionObjectPointer && MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer)) &&
        NT_SUCCESS(AxMetadata(scan->instance, scan->file, &after)) && AxSameMetadata(&scan->metadata, &after);
    /* cancelled means closed to further AX_MAP requests, not an IRP cancel
     * state machine. Preserve any prior seal as an invalid preparation. */
    scan->cancelled = TRUE;
    AxUnlock(&scan->lock);
    AxCloseScanSection(scan);
    return STATUS_SUCCESS;
}
NTSTATUS AxPrepareScan(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects,
    PUNICODE_STRING name, const AX_ADMISSION *admission, AX_SCAN_RESULT *result) {
    PEPROCESS actor = FltGetRequestorProcess(data);
    return AxPrepare(data, objects, name, admission, FALSE,
        FltGetRequestorProcessId(data), actor ? PsGetProcessCreateTimeQuadPart(actor) : 0, result);
}
NTSTATUS AxPrepareReadScan(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects,
    PUNICODE_STRING name, const AX_ADMISSION *admission, ULONG64 actor_pid,
    ULONG64 actor_created, AX_SCAN_RESULT *result) {
    return AxPrepare(data, objects, name, admission, TRUE, actor_pid, actor_created, result);
}
void AxFinalizeScan(PFLT_CALLBACK_DATA data, AX_SCAN_RESULT *result) {
    AX_SCAN_CONTEXT *scan = result->scan;
    /* Last check before the adapter applies the decision. Closure/conflict,
     * revalidation and observed cancellation must all precede this cutoff. */
    if (!result->valid || scan->conflicted || scan->stream->writers || Ax.poisoned ||
        InterlockedCompareExchange64(&scan->stream->generation, 0, 0) != scan->generation ||
        (scan->file->SectionObjectPointer && MmDoesFileHaveUserWritableReferences(scan->file->SectionObjectPointer)) ||
        AxRequestCancelled(data) || !AxRemaining(scan)) {
        AxErrorReply(&result->reply, scan->notification.request_id);
    }
}
void AxFinishScan(AX_SCAN_RESULT *result) {
    AX_SCAN_CONTEXT *scan = result->scan;
    if (!scan) return;
    AxLock(&Ax.lock);
    if (scan->listed) { RemoveEntryList(&scan->entry); scan->listed = FALSE; }
    AxUnlock(&Ax.lock);
    AxLock(&scan->lock);
    scan->cancelled = TRUE;
    AxUnlock(&scan->lock);
    AxReleaseScan(scan);
    result->scan = NULL;
}
void AxApplied(AX_SCAN_CONTEXT *scan, AX_REPLY *reply, NTSTATUS status) {
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
