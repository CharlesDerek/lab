/* Real unload policy; retained snapshot ownership must outlive callbacks. */
#include "driver.h"
NTSTATUS AxUnload(FLT_FILTER_UNLOAD_FLAGS flags) {
    /* Mandatory unload ignores a failure status. It must reach the rundown
     * wait below, which cannot complete while an unconfirmed view is retained.
     * This exceptional condition requires host recovery, not false teardown. */
    if (Ax.retained_views && !(flags & FLTFL_FILTER_UNLOAD_MANDATORY)) return STATUS_FLT_DO_NOT_DETACH;
    if (Ax.armed && !(flags & FLTFL_FILTER_UNLOAD_MANDATORY)) return STATUS_FLT_DO_NOT_DETACH;
    FltCloseCommunicationPort(Ax.server);
    FltCloseClientPort(Ax.filter, &Ax.client);
    ExWaitForRundownProtectionRelease(&Ax.rundown);
    FltUnregisterFilter(Ax.filter);
    AxClosePins(Ax.pins);
    Ax.pins = NULL;
    return STATUS_SUCCESS;
}
