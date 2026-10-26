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
typedef int32_t LONG, NTSTATUS;
typedef int64_t LONG64, LONGLONG;
typedef void *PVOID, *HANDLE, *PFLT_INSTANCE, *PFLT_FILTER, *PFLT_PORT, *PEPROCESS, *PFLT_CONTEXT;
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
typedef struct { BOOLEAN ReadAccess; PVOID SectionObjectPointer; } FILE_OBJECT, *PFILE_OBJECT;
typedef struct { ULONG DesiredAccess; } IO_SECURITY_CONTEXT;
typedef struct { struct { struct { IO_SECURITY_CONTEXT *SecurityContext; } Create; } Parameters; } FLT_IO_PARAMETER_BLOCK;
typedef struct { struct { NTSTATUS Status; ULONG64 Information; } IoStatus; FLT_IO_PARAMETER_BLOCK *Iopb; BOOLEAN irp, cancelled; } FLT_CALLBACK_DATA, *PFLT_CALLBACK_DATA;
typedef struct { PFLT_INSTANCE Instance; PFILE_OBJECT FileObject; PVOID Transaction; } FLT_RELATED_OBJECTS;
typedef const FLT_RELATED_OBJECTS *PCFLT_RELATED_OBJECTS;
typedef struct { UNICODE_STRING Name; } FLT_FILE_NAME_INFORMATION, *PFLT_FILE_NAME_INFORMATION;
typedef int FLT_PREOP_CALLBACK_STATUS, FLT_POSTOP_CALLBACK_STATUS, FLT_POST_OPERATION_FLAGS;
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
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_REPARSE ((NTSTATUS)0x104)
#define STATUS_FLT_CONTEXT_ALREADY_DEFINED ((NTSTATUS)0xc01c0002)
#define NT_SUCCESS(s) ((s)>=0)
#define FLT_PREOP_SUCCESS_WITH_CALLBACK 1
#define FLT_PREOP_SUCCESS_NO_CALLBACK 2
#define FLT_POSTOP_FINISHED_PROCESSING 3
#define FLTFL_POST_OPERATION_DRAINING 1
#define FLT_FILE_NAME_NORMALIZED 1
#define FLT_FILE_NAME_QUERY_DEFAULT 2
#define FLT_STREAM_CONTEXT 1
#define FLT_SET_CONTEXT_KEEP_IF_EXISTS 1
#define NonPagedPoolNx 1
#define POOL_FLAG_NON_PAGED 1
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
#define CONTAINING_RECORD(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define NT_ASSERT(x) assert(x)
static inline size_t RtlCompareMemory(const void *a,const void *b,size_t n) { return memcmp(a,b,n)==0?n:0; }
static inline int RtlPrefixUnicodeString(PUNICODE_STRING a,PUNICODE_STRING b,BOOLEAN fold) { (void)fold;return a->Length<=b->Length&&memcmp(a->Buffer,b->Buffer,a->Length)==0; }
static inline void InsertTailList(PLIST_ENTRY h,PLIST_ENTRY e) { e->Blink=h->Blink;e->Flink=h;h->Blink->Flink=e;h->Blink=e; }
static inline void RemoveEntryList(PLIST_ENTRY e) { e->Blink->Flink=e->Flink;e->Flink->Blink=e->Blink; }
static inline LONG InterlockedIncrement(volatile LONG *p) { return ++*p; }
static inline LONG InterlockedDecrement(volatile LONG *p) { return --*p; }
static inline LONG64 InterlockedIncrement64(volatile LONG64 *p) { return ++*p; }
static inline LONG64 InterlockedCompareExchange64(volatile LONG64 *p,LONG64 n,LONG64 old) { LONG64 v=*p;if(v==old)*p=n;return v; }
static inline void ExInitializePushLock(EX_PUSH_LOCK *p) { *p=0; }
ULONG64 KeQueryInterruptTimePrecise(ULONG64 *qpc);
void KeQuerySystemTimePrecise(LARGE_INTEGER *value);
PVOID ExAllocatePool2(ULONG flags,size_t size,ULONG tag);
void ExFreePoolWithTag(PVOID p,ULONG tag);
NTSTATUS FltGetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,PFLT_CONTEXT *c);
NTSTATUS FltAllocateContext(PFLT_FILTER f,ULONG type,size_t size,ULONG pool,PFLT_CONTEXT *c);
NTSTATUS FltSetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,ULONG flags,PFLT_CONTEXT c,PFLT_CONTEXT *old);
void FltReleaseContext(PFLT_CONTEXT c);
void FltObjectReference(PVOID p);
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
#endif
