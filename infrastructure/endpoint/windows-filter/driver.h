#ifndef ATHERNEX_FILTER_DRIVER_H
#define ATHERNEX_FILTER_DRIVER_H
#include <fltKernel.h>
#include "wire.h"
#define AX_TAG 'SxtA'

typedef struct AX_STREAM {
    volatile LONG64 generation;
    volatile LONG writers;
} AX_STREAM;
typedef struct AX_SECTION {
    volatile LONG conflicted;
} AX_SECTION;
typedef struct AX_METADATA {
    FILE_ID_INFORMATION id;
    FILE_BASIC_INFORMATION basic;
    FILE_STANDARD_INFORMATION standard;
} AX_METADATA;
typedef struct AX_SCAN_CONTEXT {
    LIST_ENTRY entry;
    volatile LONG references;
    EX_PUSH_LOCK lock;
    BOOLEAN cancelled, listed, mapped;
    PFLT_INSTANCE instance;
    PFILE_OBJECT file;
    AX_STREAM *stream;
    AX_SECTION *section;
    HANDLE section_handle;
    PVOID section_object;
    LONG64 generation;
    AX_METADATA metadata;
    AX_NOTIFICATION notification;
} AX_SCAN_CONTEXT;
typedef struct AX_GLOBALS {
    PFLT_FILTER filter;
    PFLT_PORT server, client;
    PEPROCESS client_process;
    EX_PUSH_LOCK lock;
    EX_RUNDOWN_REF rundown;
    LIST_ENTRY scans;
    AX_CONFIG config;
    UUID instance;
    volatile LONG armed, pending, poisoned, configuring;
    struct AX_PINS *pins;
    volatile LONG64 next_id, allowed, malware, errors, evidence_dropped;
} AX_GLOBALS;
extern AX_GLOBALS Ax;
void AxLock(EX_PUSH_LOCK *lock);
void AxUnlock(EX_PUSH_LOCK *lock);
NTSTATUS AxMetadata(PFLT_INSTANCE instance, PFILE_OBJECT file, AX_METADATA *metadata);
BOOLEAN AxSameMetadata(const AX_METADATA *a, const AX_METADATA *b);
void AxReleaseScan(AX_SCAN_CONTEXT *scan);
void AxCloseScanSection(AX_SCAN_CONTEXT *scan);
NTSTATUS AxGetStream(PCFLT_RELATED_OBJECTS objects, AX_STREAM **stream);
NTSTATUS AxConnect(PFLT_PORT port, PVOID cookie, PVOID context, ULONG bytes, PVOID *connection);
void AxDisconnect(PVOID connection);
NTSTATUS AxMessage(PVOID connection, PVOID input, ULONG input_bytes, PVOID output, ULONG output_bytes, PULONG returned);
NTSTATUS AxSectionConflict(PFLT_INSTANCE instance, PFLT_CONTEXT context, PFLT_CALLBACK_DATA data);
NTSTATUS AxConfigure(const AX_CONFIG *config);
NTSTATUS AxDisarm(void);
void AxClosePins(struct AX_PINS *pins);
#endif
