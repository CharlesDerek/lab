/* Test-only OS declarations. Never in the WDK build include path. */
#ifndef ATHERNEX_TEST_FLT_KERNEL_H
#define ATHERNEX_TEST_FLT_KERNEL_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
typedef uint8_t BOOLEAN, UCHAR;
typedef uint16_t WCHAR, USHORT;
typedef uint32_t ULONG;
typedef uint64_t ULONG64;
typedef size_t SIZE_T;
typedef uintptr_t ULONG_PTR;
typedef void VOID;
typedef UCHAR *PUCHAR;
typedef int32_t LONG, NTSTATUS;
typedef int64_t LONG64, LONGLONG;
typedef void *PVOID, *HANDLE, *PFLT_INSTANCE, *PFLT_FILTER, *PFLT_PORT, *PEPROCESS, *PFLT_CONTEXT;
typedef void *PFLT_VOLUME;
typedef struct { PVOID buffer; ULONG bytes; unsigned owner; } MDL, *PMDL;
typedef struct TEST_WORK *PFLT_DEFERRED_IO_WORKITEM;
typedef WCHAR *PWCHAR;
typedef ULONG *PULONG;
typedef struct { LONGLONG QuadPart; } LARGE_INTEGER;
typedef struct { USHORT Length, MaximumLength; PWCHAR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct LIST_ENTRY { struct LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef int EX_PUSH_LOCK, EX_RUNDOWN_REF;
typedef struct { UCHAR bytes[16]; } UUID;
typedef struct { ULONG64 VolumeSerialNumber; struct { UCHAR Identifier[16]; } FileId; } FILE_ID_INFORMATION;
typedef struct { LARGE_INTEGER LastWriteTime, ChangeTime; ULONG FileAttributes; } FILE_BASIC_INFORMATION;
typedef struct { LARGE_INTEGER EndOfFile; BOOLEAN DeletePending, Directory; } FILE_STANDARD_INFORMATION;
typedef struct { BOOLEAN ReadAccess; PVOID SectionObjectPointer; ULONG Flags; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { ULONG DesiredAccess; } IO_SECURITY_CONTEXT;
typedef struct { UCHAR MinorFunction; ULONG IrpFlags; struct { struct { IO_SECURITY_CONTEXT *SecurityContext; } Create; struct { ULONG Length, Key; LARGE_INTEGER ByteOffset; PVOID ReadBuffer; PMDL MdlAddress; } Read; } Parameters; } FLT_IO_PARAMETER_BLOCK;
typedef struct { struct { NTSTATUS Status; ULONG64 Information; } IoStatus; FLT_IO_PARAMETER_BLOCK *Iopb; BOOLEAN irp, cancelled, fastio, system_buffer; } FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;
typedef struct { USHORT Size; PFLT_FILTER Filter; PFLT_VOLUME Volume; PFLT_INSTANCE Instance; PFILE_OBJECT FileObject; PVOID Transaction; } FLT_RELATED_OBJECTS;
typedef const FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;
typedef struct { UNICODE_STRING Name; } FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;
typedef int FLT_PREOP_CALLBACK_STATUS, FLT_POSTOP_CALLBACK_STATUS, FLT_POST_OPERATION_FLAGS;
typedef ULONG FLT_FILTER_UNLOAD_FLAGS;
#define FLTFL_FILTER_UNLOAD_MANDATORY 1
#define STATUS_FLT_DO_NOT_DETACH ((NTSTATUS)0xc01c0010)
typedef struct { ULONG SectorSize; } FLT_VOLUME_PROPERTIES;
typedef struct { ULONG flags; } OBJECT_ATTRIBUTES;
typedef void (*PFLT_DEFERRED_IO_WORKITEM_ROUTINE)(PFLT_DEFERRED_IO_WORKITEM, PFLT_CALLBACK_DATA, PVOID);
#define TRUE 1
#define FALSE 0
#define MAXULONGLONG UINT64_MAX
#define MAXLONGLONG INT64_MAX
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_TIMEOUT ((NTSTATUS)0x102)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_NOT_FOUND ((NTSTATUS)0xc0000225)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_FILE_LOCK_CONFLICT ((NTSTATUS)0xc0000054)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)
#define STATUS_END_OF_FILE ((NTSTATUS)0xc0000011)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_REPARSE ((NTSTATUS)0x104)
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED ((NTSTATUS)0xc01c0002)
#define NT_SUCCESS(s) ((s)>=0)
#define FLT_PREOP_SUCCESS_WITH_CALLBACK 1
#define FLT_PREOP_SUCCESS_NO_CALLBACK 2
#define FLT_PREOP_COMPLETE 4
#define FLT_PREOP_PENDING 5
#define FLT_PREOP_DISALLOW_FASTIO 6
#define FLT_POSTOP_FINISHED_PROCESSING 3
#define FLT_POSTOP_MORE_PROCESSING_REQUIRED 7
#define FLTFL_POST_OPERATION_DRAINING 1
#define FLT_FILE_NAME_NORMALIZED 1
#define FLT_FILE_NAME_QUERY_DEFAULT 2
#define FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP 4
#define FLT_STREAM_CONTEXT 1
#define FLT_SECTION_CONTEXT 2
#define FLT_SET_CONTEXT_KEEP_IF_EXISTS 1
#define NonPagedPoolNx 1
#define POOL_FLAG_NON_PAGED 1
#define POOL_FLAG_PAGED 2
#define FO_STREAM_FILE 0x1
#define FO_VOLUME_OPEN 0x2
#define FO_NO_INTERMEDIATE_BUFFERING 0x4
#define IRP_NOCACHE 0x1
#define IRP_MN_MDL 2
#define IRP_MN_COMPLETE 4
#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define DelayedWorkQueue 0
#define NormalPagePriority 0
#define MdlMappingNoExecute 1
#define OBJ_KERNEL_HANDLE 1
#define SECTION_MAP_READ 4
#define SECTION_QUERY 1
#define PAGE_READONLY 2
#define SEC_COMMIT 0x8000000
#define KernelMode 0
#define EXCEPTION_EXECUTE_HANDLER 1
extern unsigned test_seh_exception;
#define __try if (!test_seh_exception)
#define __except(x) else
#define GetExceptionCode() STATUS_ACCESS_DENIED
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define FILE_READ_DATA 1
#define FILE_EXECUTE 0x20
#define MAXIMUM_ALLOWED 0x2000000
#define GENERIC_READ 0x80000000u
#define GENERIC_EXECUTE 0x20000000u
#define GENERIC_ALL 0x10000000u
#define FileIdInformation 1
#define FileBasicInformation 2
#define FileStandardInformation 3
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define RtlCopyMemory(d,s,n) memcpy((d),(s),(n))
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define FLT_IS_IRP_OPERATION(d) ((d)->irp)
#define FLT_IS_FASTIO_OPERATION(d) ((d)->fastio)
#define FLT_IS_SYSTEM_BUFFER(d) ((d)->system_buffer)
#define CONTAINING_RECORD(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define NT_ASSERT(x) assert(x)
static inline size_t RtlCompareMemory(const void *a,const void *b,size_t n) { return memcmp(a,b,n)==0?n:0; }
static inline int RtlPrefixUnicodeString(PUNICODE_STRING a,PUNICODE_STRING b,BOOLEAN fold) { (void)fold;return a->Length<=b->Length&&memcmp(a->Buffer,b->Buffer,a->Length)==0; }
static inline void InsertTailList(PLIST_ENTRY h,PLIST_ENTRY e) { e->Blink=h->Blink;e->Flink=h;h->Blink->Flink=e;h->Blink=e; }
static inline void RemoveEntryList(PLIST_ENTRY e) { e->Blink->Flink=e->Flink;e->Flink->Blink=e->Blink; }
static inline LONG InterlockedIncrement(volatile LONG *p) { return ++*p; }
static inline LONG InterlockedDecrement(volatile LONG *p) { return --*p; }
static inline LONG InterlockedExchange(volatile LONG *p,LONG n) { LONG old=*p;*p=n;return old; }
static inline LONG64 InterlockedIncrement64(volatile LONG64 *p) { return ++*p; }
static inline LONG64 InterlockedCompareExchange64(volatile LONG64 *p,LONG64 n,LONG64 old) { LONG64 v=*p;if(v==old)*p=n;return v; }
static inline void ExInitializePushLock(EX_PUSH_LOCK *p) { *p=0; }
static inline void InitializeObjectAttributes(OBJECT_ATTRIBUTES *a,PVOID n,ULONG f,HANDLE r,PVOID s) { (void)n;(void)r;(void)s;a->flags=f; }
static inline ULONG MmGetMdlByteCount(PMDL mdl) { return mdl->bytes; }
ULONG64 KeQueryInterruptTimePrecise(ULONG64 *qpc);
void KeQuerySystemTimePrecise(LARGE_INTEGER *value);
PVOID ExAllocatePool2(ULONG flags,size_t size,ULONG tag);
void ExFreePoolWithTag(PVOID p,ULONG tag);
NTSTATUS FltGetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,PFLT_CONTEXT *c);
NTSTATUS FltAllocateContext(PFLT_FILTER f,ULONG type,size_t size,ULONG pool,PFLT_CONTEXT *c);
NTSTATUS FltSetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,ULONG flags,PFLT_CONTEXT c,PFLT_CONTEXT *old);
void FltReleaseContext(PFLT_CONTEXT c);
NTSTATUS FltObjectReference(PVOID p);
void FltObjectDereference(PVOID p);
void ObReferenceObject(PVOID p);
void ObDereferenceObject(PVOID p);
void ZwClose(HANDLE h);
NTSTATUS FltCloseSectionForDataScan(PFLT_CONTEXT c);
NTSTATUS FltQueryInformationFile(PFLT_INSTANCE i,PFILE_OBJECT f,PVOID out,ULONG size,ULONG type,PVOID used);
ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA d);
PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA d);
ULONG64 PsGetProcessCreateTimeQuadPart(PEPROCESS p);
BOOLEAN MmDoesFileHaveUserWritableReferences(PVOID p);
BOOLEAN FltIsIoCanceled(PFLT_CALLBACK_DATA d);
NTSTATUS FltSendMessage(PFLT_FILTER f,PFLT_PORT *p,PVOID input,ULONG length,PVOID reply,PULONG reply_length,LARGE_INTEGER *deadline);
void FltCancelFileOpen(PFLT_INSTANCE i,PFILE_OBJECT f);
BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF *r);
void ExReleaseRundownProtection(EX_RUNDOWN_REF *r);
NTSTATUS FltIsDirectory(PFILE_OBJECT f,PFLT_INSTANCE i,BOOLEAN *directory);
NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA d,ULONG flags,PFLT_FILE_NAME_INFORMATION *name);
void FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION name);
ULONG KeGetCurrentIrql(void);
PVOID IoGetTopLevelIrp(void);
NTSTATUS FltGetVolumeProperties(PFLT_VOLUME volume,FLT_VOLUME_PROPERTIES *p,ULONG size,PULONG used);
PVOID FltAllocatePoolAlignedWithTag(PFLT_INSTANCE instance,ULONG pool,SIZE_T size,ULONG tag);
void FltFreePoolAlignedWithTag(PFLT_INSTANCE instance,PVOID buffer,ULONG tag);
PMDL IoAllocateMdl(PVOID buffer,ULONG bytes,BOOLEAN secondary,BOOLEAN quota,PVOID irp);
void IoFreeMdl(PMDL mdl);
void MmBuildMdlForNonPagedPool(PMDL mdl);
PFLT_DEFERRED_IO_WORKITEM FltAllocateDeferredIoWorkItem(void);
void FltFreeDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM work);
NTSTATUS FltQueueDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM work,PFLT_CALLBACK_DATA data,PFLT_DEFERRED_IO_WORKITEM_ROUTINE routine,ULONG queue,PVOID context);
void FltCompletePendedPreOperation(PFLT_CALLBACK_DATA data,FLT_PREOP_CALLBACK_STATUS status,PVOID context);
void FltCompletePendedPostOperation(PFLT_CALLBACK_DATA data);
void FltSetCallbackDataDirty(PFLT_CALLBACK_DATA data);
NTSTATUS FltLockUserBuffer(PFLT_CALLBACK_DATA data);
PVOID MmGetSystemAddressForMdlSafe(PMDL mdl,ULONG flags);
NTSTATUS MmMapViewInSystemSpace(PVOID section,PVOID *view,SIZE_T *bytes);
NTSTATUS MmUnmapViewInSystemSpace(PVOID view);
NTSTATUS FltCreateSectionForDataScan(PFLT_INSTANCE instance,PFILE_OBJECT file,PFLT_CONTEXT section,ULONG access,OBJECT_ATTRIBUTES *attrs,LARGE_INTEGER *size,ULONG protect,ULONG attributes,ULONG flags,HANDLE *handle,PVOID *object,LARGE_INTEGER *file_size);
NTSTATUS ObOpenObjectByPointer(PVOID object,ULONG attrs,PVOID state,ULONG access,PVOID type,ULONG mode,HANDLE *handle);
void FltCloseCommunicationPort(PFLT_PORT port);
void FltCloseClientPort(PFLT_FILTER filter,PFLT_PORT *port);
void ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF *rundown);
void FltUnregisterFilter(PFLT_FILTER filter);
#endif
