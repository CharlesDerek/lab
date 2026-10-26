/* Ordinary nonpaging IRP reads only. Lower I/O targets a private shadow;
 * nothing reaches the original destination before a whole-file byte decision.
 * Paging, new MDL reads and mapped views are not covered by this adapter. */
#include "driver.h"

typedef struct AX_READ_CONTEXT {
    PFLT_INSTANCE instance;
    PFLT_VOLUME volume;
    PFILE_OBJECT file;
    AX_ADMISSION admission;
    BOOLEAN admitted;
    ULONG64 actor_pid, actor_created;
    LARGE_INTEGER offset;
    ULONG length, key;
    PVOID original_buffer, shadow;
    PMDL original_mdl, unpublished_mdl;
    ULONG64 shadow_charge;
    PFLT_DEFERRED_IO_WORKITEM work;
    UNICODE_STRING name;
    WCHAR path[AX_PATH_CHARS];
} AX_READ_CONTEXT;

static BOOLEAN AxReadCurrent(PFLT_CALLBACK_DATA data, AX_READ_CONTEXT *read) {
    ULONG64 qpc, now = KeQueryInterruptTimePrecise(&qpc);
    return now >= read->admission.admitted_at && now < read->admission.deadline &&
        !FltIsIoCanceled(data) && !Ax.poisoned;
}
/* Every field here is nonpaged, or a documented <=DISPATCH cleanup reference.
 * No scan/section/name-information ownership reaches the post queue-fail path. */
static void AxFreeRead(AX_READ_CONTEXT *read) {
    if (read->unpublished_mdl) IoFreeMdl(read->unpublished_mdl);
    if (read->shadow) FltFreePoolAlignedWithTag(read->instance, read->shadow, AX_TAG);
    if (read->shadow_charge) AxReleaseReadBytes(read->shadow_charge);
    if (read->work) FltFreeDeferredIoWorkItem(read->work);
    if (read->admitted) InterlockedDecrement(&Ax.pending);
    if (read->file) ObDereferenceObject(read->file);
    if (read->volume) FltObjectDereference(read->volume);
    if (read->instance) FltObjectDereference(read->instance);
    ExFreePoolWithTag(read, AX_TAG);
    ExReleaseRundownProtection(&Ax.rundown);
}
static void AxDenyRead(PFLT_CALLBACK_DATA data) {
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
}
static void AxReadSetupError(PFLT_CALLBACK_DATA data) {
    AxDenyRead(data);
    InterlockedIncrement64(&Ax.errors);
    InterlockedIncrement64(&Ax.evidence_dropped);
}
static BOOLEAN AxOriginalRead(PFLT_CALLBACK_DATA data, const AX_READ_CONTEXT *read) {
    return data->Iopb->Parameters.Read.ReadBuffer == read->original_buffer &&
        data->Iopb->Parameters.Read.MdlAddress == read->original_mdl &&
        data->Iopb->Parameters.Read.Length == read->length &&
        data->Iopb->Parameters.Read.Key == read->key &&
        data->Iopb->Parameters.Read.ByteOffset.QuadPart == read->offset.QuadPart;
}
static NTSTATUS AxShadowRead(PFLT_CALLBACK_DATA data, AX_READ_CONTEXT *read) {
    FLT_VOLUME_PROPERTIES properties;
    ULONG used, sector;
    ULONG64 bytes = read->length;
    NTSTATUS status;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!AxOriginalRead(data, read) || !AxReadCurrent(data, read)) return STATUS_IO_TIMEOUT;
    if ((data->Iopb->IrpFlags & IRP_NOCACHE) || (read->file->Flags & FO_NO_INTERMEDIATE_BUFFERING)) {
        RtlZeroMemory(&properties, sizeof(properties));
        status = FltGetVolumeProperties(read->volume, &properties, sizeof(properties), &used);
        if ((status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW) || used < sizeof(properties)) return STATUS_NOT_SUPPORTED;
        sector = properties.SectorSize;
        if (!sector || (sector & (sector - 1)) || sector > AX_MAX_FILE) return STATUS_NOT_SUPPORTED;
        bytes = (bytes + sector - 1) & ~((ULONG64)sector - 1);
    }
    if (!bytes || bytes > AX_MAX_FILE || !AxReserveReadBytes(bytes)) return STATUS_INSUFFICIENT_RESOURCES;
    read->shadow_charge = bytes;
    read->shadow = FltAllocatePoolAlignedWithTag(read->instance, NonPagedPoolNx, (SIZE_T)bytes, AX_TAG);
    if (!read->shadow) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(read->shadow, (SIZE_T)bytes);
    read->unpublished_mdl = IoAllocateMdl(read->shadow, (ULONG)bytes, FALSE, FALSE, NULL);
    if (!read->unpublished_mdl) return STATUS_INSUFFICIENT_RESOURCES;
    MmBuildMdlForNonPagedPool(read->unpublished_mdl);
    read->work = FltAllocateDeferredIoWorkItem();
    if (!read->work) return STATUS_INSUFFICIENT_RESOURCES;
    if (!AxReadCurrent(data, read)) return STATUS_IO_TIMEOUT;
    data->Iopb->Parameters.Read.ReadBuffer = read->shadow;
    data->Iopb->Parameters.Read.MdlAddress = read->unpublished_mdl;
    FltSetCallbackDataDirty(data);
    /* FltMgr owns the committed swapped MDL. Own post receives the incoming
     * ORIGINAL buffer/MDL, even when that original MDL was NULL. */
    read->unpublished_mdl = NULL;
    return STATUS_SUCCESS;
}
static VOID AxPreReadWorker(PFLT_DEFERRED_IO_WORKITEM work, PFLT_CALLBACK_DATA data, PVOID context) {
    AX_READ_CONTEXT *read = context;
    NTSTATUS status = AxShadowRead(data, read);
    if (!NT_SUCCESS(status)) {
        AxReadSetupError(data);
        AxFreeRead(read);
        FltCompletePendedPreOperation(data, FLT_PREOP_COMPLETE, NULL);
    } else FltCompletePendedPreOperation(data, FLT_PREOP_SUCCESS_WITH_CALLBACK, read);
    /* Completion may already have destroyed read; touch only this work item. */
    FltFreeDeferredIoWorkItem(work);
}
FLT_PREOP_CALLBACK_STATUS AxPreRead(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *completion) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    AX_READ_CONTEXT *read = NULL;
    PFLT_DEFERRED_IO_WORKITEM work;
    AX_ADMISSION admission = {0};
    PEPROCESS actor;
    NTSTATUS status;
    BOOLEAN admitted = FALSE;
    *completion = NULL;
    /* MDL completion retires a previous operation, not a new content read.
     * Never leak prior I/O resources by treating this cleanup as new admission. */
    if ((data->Iopb->MinorFunction & IRP_MN_COMPLETE) || !Ax.armed ||
        !objects->FileObject || (objects->FileObject->Flags & (FO_STREAM_FILE | FO_VOLUME_OPEN)) ||
        !data->Iopb->Parameters.Read.Length) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (KeGetCurrentIrql() > APC_LEVEL) { AxReadSetupError(data); return FLT_PREOP_COMPLETE; }
    if (AxIsClient()) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (FLT_IS_FASTIO_OPERATION(data)) return FLT_PREOP_DISALLOW_FASTIO;
    if (IoGetTopLevelIrp()) { AxReadSetupError(data); return FLT_PREOP_COMPLETE; }
    if (!FLT_IS_IRP_OPERATION(data) || !ExAcquireRundownProtection(&Ax.rundown)) {
        AxReadSetupError(data); return FLT_PREOP_COMPLETE;
    }
    /* Cached names remain available in an unsafe FS-query context. A cache
     * miss still refuses; this flag does not authorize an unsafe FS query. */
    status = FltGetFileNameInformation(data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP, &name);
    if (!NT_SUCCESS(status)) goto deny;
    status = AxAdmit(&name->Name, &admission, &admitted);
    if (!NT_SUCCESS(status)) goto deny;
    if (!admitted) {
        FltReleaseFileNameInformation(name);
        ExReleaseRundownProtection(&Ax.rundown);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (data->Iopb->MinorFunction || objects->Transaction ||
        data->Iopb->Parameters.Read.ByteOffset.QuadPart < 0 ||
        data->Iopb->Parameters.Read.Length > AX_MAX_FILE || !name->Name.Length ||
        name->Name.Length >= AX_PATH_CHARS * sizeof(WCHAR)) goto deny;
    actor = FltGetRequestorProcess(data);
    if (!actor || !FltGetRequestorProcessId(data)) goto deny;
    read = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*read), AX_TAG);
    if (!read) goto deny;
    read->admission = admission;
    read->admitted = TRUE;
    admitted = FALSE;
    status = FltObjectReference(objects->Instance);
    if (!NT_SUCCESS(status)) goto deny;
    read->instance = objects->Instance;
    status = FltObjectReference(objects->Volume);
    if (!NT_SUCCESS(status)) goto deny;
    read->volume = objects->Volume;
    read->file = objects->FileObject;
    ObReferenceObject(read->file);
    read->actor_pid = FltGetRequestorProcessId(data);
    read->actor_created = PsGetProcessCreateTimeQuadPart(actor);
    read->offset = data->Iopb->Parameters.Read.ByteOffset;
    read->length = data->Iopb->Parameters.Read.Length;
    read->key = data->Iopb->Parameters.Read.Key;
    read->original_buffer = data->Iopb->Parameters.Read.ReadBuffer;
    read->original_mdl = data->Iopb->Parameters.Read.MdlAddress;
    read->name.Buffer = read->path;
    read->name.Length = read->name.MaximumLength = name->Name.Length;
    RtlCopyMemory(read->path, name->Name.Buffer, name->Name.Length);
    FltReleaseFileNameInformation(name);
    name = NULL;
    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        status = AxShadowRead(data, read);
        if (!NT_SUCCESS(status)) goto deny;
        *completion = read;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    work = FltAllocateDeferredIoWorkItem();
    if (!work) goto deny;
    status = FltQueueDeferredIoWorkItem(work, data, AxPreReadWorker, DelayedWorkQueue, read);
    if (NT_SUCCESS(status)) return FLT_PREOP_PENDING;
    FltFreeDeferredIoWorkItem(work);
deny:
    AxReadSetupError(data);
    if (name) FltReleaseFileNameInformation(name);
    if (read) AxFreeRead(read);
    else {
        if (admitted) InterlockedDecrement(&Ax.pending);
        ExReleaseRundownProtection(&Ax.rundown);
    }
    return FLT_PREOP_COMPLETE;
}
static PVOID AxReadDestination(PFLT_CALLBACK_DATA data, AX_READ_CONTEXT *read) {
    PMDL mdl = data->Iopb->Parameters.Read.MdlAddress;
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (!AxOriginalRead(data, read)) return NULL;
    if (!mdl && FLT_IS_SYSTEM_BUFFER(data)) return read->original_buffer;
    if (!mdl) {
        if (!NT_SUCCESS(FltLockUserBuffer(data))) return NULL;
        mdl = data->Iopb->Parameters.Read.MdlAddress;
    }
    if (!mdl || MmGetMdlByteCount(mdl) < read->length) return NULL;
    return MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
}
static VOID AxPostReadWorker(PFLT_DEFERRED_IO_WORKITEM work, PFLT_CALLBACK_DATA data, PVOID context) {
    AX_READ_CONTEXT *read = context;
    AX_SCAN_RESULT result = {0};
    FLT_RELATED_OBJECTS objects = {
        .Size = sizeof(FLT_RELATED_OBJECTS), .Filter = Ax.filter,
        .Instance = read->instance, .FileObject = read->file, .Volume = read->volume
    };
    PVOID destination;
    ULONG64 returned = data->IoStatus.Information, offset = (ULONG64)read->offset.QuadPart;
    NTSTATUS status;
    if (!AxReadCurrent(data, read) || !(destination = AxReadDestination(data, read))) goto denied;
    read->admitted = FALSE; /* Core consumes exactly this pending reservation. */
    status = AxPrepareReadScan(data, &objects, &read->name, &read->admission,
        read->actor_pid, read->actor_created, &result);
    if (status != STATUS_SUCCESS) goto denied;
    if (!result.scan->snapshot_ready || offset > result.scan->notification.bytes ||
        returned > result.scan->notification.bytes - offset ||
        RtlCompareMemory(read->shadow, (PUCHAR)result.scan->snapshot + (SIZE_T)offset,
            (SIZE_T)returned) != returned) result.valid = FALSE;
    /* The single authorization point follows hash/range, section-close and
     * metadata checks. A cancellation after this point cannot revoke a CPU
     * copy already begun. No deadline for OS completion itself is claimed. */
    AxFinalizeScan(data, &result);
    if (result.reply.verdict == AX_CLEAN) {
        __try { RtlCopyMemory(destination, read->shadow, (SIZE_T)returned); }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            result.valid = FALSE;
            AxFinalizeScan(data, &result);
        }
    }
    if (result.reply.verdict == AX_CLEAN) InterlockedIncrement64(&Ax.allowed);
    else {
        AxDenyRead(data);
        if (result.reply.verdict == AX_MALWARE) InterlockedIncrement64(&Ax.malware);
        else InterlockedIncrement64(&Ax.errors);
    }
    AxApplied(result.scan, &result.reply, result.reply.verdict == AX_CLEAN ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
    goto done;
denied:
    AxReadSetupError(data);
done:
    AxFinishScan(&result);
    AxFreeRead(read);
    FltCompletePendedPostOperation(data);
    FltFreeDeferredIoWorkItem(work);
}
FLT_POSTOP_CALLBACK_STATUS AxPostRead(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID completion, FLT_POST_OPERATION_FLAGS flags) {
    AX_READ_CONTEXT *read = completion;
    PFLT_DEFERRED_IO_WORKITEM work;
    NTSTATUS status;
    UNREFERENCED_PARAMETER(objects);
    if (flags & FLTFL_POST_OPERATION_DRAINING) {
        /* Swapped operations are not normally drained. This is a copied data
         * block: only retire our resources, never queue/copy/pend it. */
        InterlockedIncrement64(&Ax.errors);
        InterlockedIncrement64(&Ax.evidence_dropped);
        AxFreeRead(read);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(data->IoStatus.Status) || !data->IoStatus.Information) {
        data->IoStatus.Information = 0;
        AxFreeRead(read);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!AxOriginalRead(data, read) || data->IoStatus.Information > read->length ||
        data->IoStatus.Information > read->shadow_charge) goto deny;
    work = read->work;
    read->work = NULL;
    status = FltQueueDeferredIoWorkItem(work, data, AxPostReadWorker, DelayedWorkQueue, read);
    if (NT_SUCCESS(status)) return FLT_POSTOP_MORE_PROCESSING_REQUIRED;
    FltFreeDeferredIoWorkItem(work);
deny:
    AxReadSetupError(data);
    AxFreeRead(read);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
