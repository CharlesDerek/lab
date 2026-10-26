/* Post-create adapter. Only this file cancels newly opened file objects. */
#include "driver.h"
static void AxDenyCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects) {
    FltCancelFileOpen(objects->Instance, objects->FileObject);
    data->IoStatus.Status = STATUS_ACCESS_DENIED;
    data->IoStatus.Information = 0;
}
FLT_PREOP_CALLBACK_STATUS AxPreCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID *completion) {
    UNREFERENCED_PARAMETER(data); UNREFERENCED_PARAMETER(objects);
    *completion = NULL;
    return Ax.armed && !AxIsClient() ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SUCCESS_NO_CALLBACK;
}
FLT_POSTOP_CALLBACK_STATUS AxPostCreate(PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID completion, FLT_POST_OPERATION_FLAGS flags) {
    PFLT_FILE_NAME_INFORMATION name = NULL;
    NTSTATUS status;
    BOOLEAN directory = FALSE;
    BOOLEAN admitted = FALSE;
    AX_ADMISSION admission = {0};
    AX_SCAN_RESULT result = {0};
    UNREFERENCED_PARAMETER(completion);
    if ((flags & FLTFL_POST_OPERATION_DRAINING) || !NT_SUCCESS(data->IoStatus.Status) ||
        data->IoStatus.Status == STATUS_REPARSE || !Ax.armed || AxIsClient()) return FLT_POSTOP_FINISHED_PROCESSING;
    if (!ExAcquireRundownProtection(&Ax.rundown)) { AxDenyCreate(data, objects); return FLT_POSTOP_FINISHED_PROCESSING; }
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
    status = AxAdmit(&name->Name, &admission, &admitted);
    if (!NT_SUCCESS(status)) goto deny;
    if (!admitted) goto done;
    if (name->Name.Length == 0 || name->Name.Length >= AX_PATH_CHARS * sizeof(WCHAR)) goto deny;
    admitted = FALSE; /* Preparation consumes this single capacity reservation. */
    status = AxPrepareScan(data, objects, &name->Name, &admission, &result);
    if (status != STATUS_SUCCESS) goto deny;
    /* This is the create authorization point. All scanning, metadata checks and
     * section closure precede the final monotonic/cancellation/conflict check.
     * Receipt delivery follows the applied decision, not a provisional reply. */
    AxFinalizeScan(data, &result);
    if (result.reply.verdict == AX_CLEAN) InterlockedIncrement64(&Ax.allowed);
    else {
        if (result.reply.verdict == AX_MALWARE) InterlockedIncrement64(&Ax.malware);
        else InterlockedIncrement64(&Ax.errors);
        AxDenyCreate(data, objects);
    }
    AxApplied(result.scan, &result.reply, result.reply.verdict == AX_CLEAN ? STATUS_SUCCESS : STATUS_ACCESS_DENIED);
    goto done;
deny:
    if (NT_SUCCESS(data->IoStatus.Status)) {
        InterlockedIncrement64(&Ax.errors);
        InterlockedIncrement64(&Ax.evidence_dropped);
        AxDenyCreate(data, objects);
    }
done:
    AxFinishScan(&result);
    if (admitted) InterlockedDecrement(&Ax.pending);
    if (name) FltReleaseFileNameInformation(name);
    ExReleaseRundownProtection(&Ax.rundown);
    return FLT_POSTOP_FINISHED_PROCESSING;
}
