#include "driver.h"
#define AX_ANCESTORS 128u
typedef struct AX_PINS {
    ULONG count;
    HANDLE handles[AX_ROOTS * AX_ANCESTORS];
} AX_PINS;

void AxClosePins(AX_PINS *pins) {
    if (!pins) return;
    while (pins->count) ZwClose(pins->handles[--pins->count]);
    ExFreePoolWithTag(pins, AX_TAG);
}
static NTSTATUS AxPinDirectory(AX_PINS *pins, HANDLE parent, PUNICODE_STRING name, HANDLE *directory) {
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK io;
    FILE_BASIC_INFORMATION basic;
    FILE_STANDARD_INFORMATION standard;
    NTSTATUS status;
    HANDLE handle = NULL;
    if (pins->count == RTL_NUMBER_OF(pins->handles)) return STATUS_INSUFFICIENT_RESOURCES;
    InitializeObjectAttributes(&attributes, name, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE | OBJ_DONT_REPARSE, parent, NULL);
    status = ZwCreateFile(&handle, SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
        &attributes, &io, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(status)) return status;
    status = ZwQueryInformationFile(handle, &io, &basic, sizeof(basic), FileBasicInformation);
    if (NT_SUCCESS(status)) status = ZwQueryInformationFile(handle, &io, &standard, sizeof(standard), FileStandardInformation);
    if (!NT_SUCCESS(status) || (basic.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) || !standard.Directory || standard.DeletePending) {
        ZwClose(handle);
        return NT_SUCCESS(status) ? STATUS_REPARSE_POINT_ENCOUNTERED : status;
    }
    pins->handles[pins->count++] = handle;
    *directory = handle;
    return STATUS_SUCCESS;
}
static NTSTATUS AxPinRoot(AX_PINS *pins, const AX_ROOT *root) {
    UNICODE_STRING prefix, name;
    PFLT_VOLUME volume = NULL;
    PFLT_INSTANCE instance = NULL;
    HANDLE parent = NULL;
    ULONG separator, start, depth = 0;
    WCHAR *volume_root;
    NTSTATUS status;
    RtlInitUnicodeString(&prefix, L"\\Device\\");
    name.Buffer = (PWCHAR)root->path;
    name.Length = (USHORT)(root->characters * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    if (!RtlPrefixUnicodeString(&prefix, &name, TRUE)) return STATUS_INVALID_PARAMETER;
    for (separator = prefix.Length / sizeof(WCHAR); separator < root->characters && root->path[separator] != L'\\'; ++separator) {}
    if (separator == prefix.Length / sizeof(WCHAR)) return STATUS_INVALID_PARAMETER;
    name.Length = (USHORT)(separator * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    status = FltGetVolumeFromName(Ax.filter, &name, &volume);
    if (!NT_SUCCESS(status)) return status;
    /* Every root must be on a volume to which this exact driver instance has
     * attached successfully; an unsupported filesystem cannot be armed. */
    status = FltGetVolumeInstanceFromName(Ax.filter, volume, NULL, &instance);
    FltObjectDereference(volume);
    if (!NT_SUCCESS(status)) return status;
    FltObjectDereference(instance);
    volume_root = ExAllocatePool2(POOL_FLAG_NON_PAGED, (separator + 2) * sizeof(WCHAR), AX_TAG);
    if (!volume_root) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(volume_root, root->path, separator * sizeof(WCHAR));
    volume_root[separator] = L'\\';
    name.Buffer = volume_root;
    name.Length = (USHORT)((separator + 1) * sizeof(WCHAR));
    name.MaximumLength = (USHORT)((separator + 2) * sizeof(WCHAR));
    status = AxPinDirectory(pins, NULL, &name, &parent);
    ExFreePoolWithTag(volume_root, AX_TAG);
    if (!NT_SUCCESS(status)) return status;
    ++depth;
    start = separator + 1;
    while (start < root->characters) {
        ULONG end = start;
        if (++depth > AX_ANCESTORS) return STATUS_INVALID_PARAMETER;
        while (end < root->characters && root->path[end] != L'\\') ++end;
        name.Buffer = (PWCHAR)&root->path[start];
        name.Length = (USHORT)((end - start) * sizeof(WCHAR));
        name.MaximumLength = name.Length;
        status = AxPinDirectory(pins, parent, &name, &parent);
        if (!NT_SUCCESS(status)) return status;
        start = end + 1;
    }
    return STATUS_SUCCESS;
}
NTSTATUS AxConfigure(const AX_CONFIG *config) {
    AX_PINS *pins;
    ULONG i;
    NTSTATUS status = STATUS_SUCCESS;
    AxLock(&Ax.lock);
    if (Ax.armed) {
        status = !Ax.configuring && RtlCompareMemory(&Ax.config, config, sizeof(*config)) == sizeof(*config)
            ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
        AxUnlock(&Ax.lock);
        return status;
    }
    if (Ax.pending || Ax.configuring) { AxUnlock(&Ax.lock); return STATUS_DEVICE_BUSY; }
    Ax.configuring = 1;
    AxUnlock(&Ax.lock);
    /* Filesystem calls cannot hold the global lock: their callbacks inspect the
     * client identity. Build all pinned ancestry before publishing the policy. */
    pins = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*pins), AX_TAG);
    if (!pins) status = STATUS_INSUFFICIENT_RESOURCES;
    else for (i = 0; i < config->root_count; ++i) {
        status = AxPinRoot(pins, &config->roots[i]);
        if (!NT_SUCCESS(status)) break;
    }
    AxLock(&Ax.lock);
    if (NT_SUCCESS(status) && (!Ax.client || Ax.client_process != PsGetCurrentProcess())) status = STATUS_PORT_DISCONNECTED;
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(&Ax.config, config, sizeof(*config));
        Ax.pins = pins;
        pins = NULL;
        InterlockedExchange(&Ax.armed, 1);
    }
    Ax.configuring = 0;
    AxUnlock(&Ax.lock);
    AxClosePins(pins);
    return status;
}
NTSTATUS AxDisarm(void) {
    AX_PINS *pins;
    AxLock(&Ax.lock);
    if (Ax.pending || Ax.configuring) { AxUnlock(&Ax.lock); return STATUS_DEVICE_BUSY; }
    InterlockedExchange(&Ax.armed, 0);
    pins = Ax.pins;
    Ax.pins = NULL;
    AxUnlock(&Ax.lock);
    AxClosePins(pins);
    return STATUS_SUCCESS;
}
