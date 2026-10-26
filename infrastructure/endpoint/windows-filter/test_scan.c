/* Actual production scan/create logic, with deterministic OS effects only.
 * This is not a loaded-driver, kernel scheduling or memory-confinement proof. */
#ifdef NDEBUG
#error "Windows scan decision controls require assertions"
#endif
#include "driver.h"
#include <stdio.h>
#include <stdlib.h>
#include "scan.c"
#include "create.c"

AX_GLOBALS Ax;
static AX_STREAM stream;
static FILE_OBJECT file;
static IO_SECURITY_CONTEXT security;
static FLT_IO_PARAMETER_BLOCK iopb;
static FLT_CALLBACK_DATA data;
static FLT_RELATED_OBJECTS objects;
static FLT_FILE_NAME_INFORMATION name;
static WCHAR path[] = {'\\','v','\\','r','\\','f'};
static ULONG64 now, wall, deadline, setup_delay, send_delay, initial_metadata_delay, metadata_delay, close_delay;
static LONGLONG file_bytes;
static unsigned allocations, frees, fail_allocation, queries, sends, applied, cancelled, closes;
static unsigned stream_refs, instance_refs, file_refs, section_refs, handle_refs, section_object_refs;
static unsigned io_cancel_queries, rundown, metadata_fail;
static BOOLEAN mapped, conflict_close, fail_close, extra_ref, bad_metadata, writable, cancel_send, cancel_close, seal_send;
static BOOLEAN change_generation, mutate_close, malformed, short_reply, no_rundown;
static NTSTATUS send_status, stream_status;
static ULONG verdict;
static AX_SCAN_CONTEXT *held;
static AX_APPLIED_NOTIFICATION receipt;
static LARGE_INTEGER sent_deadline;

ULONG64 KeQueryInterruptTimePrecise(ULONG64 *qpc) { assert(qpc);*qpc=now;return now; }
void KeQuerySystemTimePrecise(LARGE_INTEGER *v) { v->QuadPart=(LONGLONG)wall; }
PVOID ExAllocatePool2(ULONG flags,size_t size,ULONG tag) { (void)flags;(void)tag;++allocations;if(allocations==fail_allocation)return NULL;return calloc(1,size); }
void ExFreePoolWithTag(PVOID p,ULONG tag) { (void)tag;++frees;free(p); }
void AxLock(EX_PUSH_LOCK *lock) { assert(*lock==0);*lock=1; }
void AxUnlock(EX_PUSH_LOCK *lock) { assert(*lock==1);*lock=0; }
BOOLEAN AxIsClient(void) { return FALSE; }
NTSTATUS FltGetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,PFLT_CONTEXT *out) { (void)i;(void)f;now+=setup_delay;if(stream_status!=STATUS_SUCCESS)return stream_status;*out=&stream;++stream_refs;return STATUS_SUCCESS; }
NTSTATUS FltAllocateContext(PFLT_FILTER f,ULONG t,size_t size,ULONG p,PFLT_CONTEXT *out) { (void)f;(void)t;(void)size;(void)p;(void)out;assert(!"unexpected stream allocation");return STATUS_NOT_SUPPORTED; }
NTSTATUS FltSetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,ULONG flags,PFLT_CONTEXT c,PFLT_CONTEXT *old) { (void)i;(void)f;(void)flags;(void)c;(void)old;assert(!"unexpected stream attach");return STATUS_NOT_SUPPORTED; }
void FltReleaseContext(PFLT_CONTEXT c) { if(c==&stream){assert(stream_refs);--stream_refs;}else{assert(section_refs);--section_refs;free(c);} }
void FltObjectReference(PVOID p) { (void)p;++instance_refs; }
void FltObjectDereference(PVOID p) { (void)p;assert(instance_refs);--instance_refs; }
void ObReferenceObject(PVOID p) { assert(p==&file);++file_refs; }
void ObDereferenceObject(PVOID p) { if(p==&file){assert(file_refs);--file_refs;}else{assert(section_object_refs);--section_object_refs;} }
void ZwClose(HANDLE h) { assert(h==(HANDLE)(uintptr_t)1);assert(handle_refs);--handle_refs; }
NTSTATUS FltCloseSectionForDataScan(PFLT_CONTEXT c) { AX_SECTION *s=c;++closes;now+=close_delay;if(conflict_close)s->conflicted=1;if(cancel_close)data.cancelled=TRUE;if(mutate_close)++stream.generation;return fail_close?STATUS_NOT_FOUND:STATUS_SUCCESS; }
NTSTATUS FltQueryInformationFile(PFLT_INSTANCE i,PFILE_OBJECT f,PVOID out,ULONG bytes,ULONG type,PVOID used) {
    (void)i;(void)f;(void)used;++queries;
    if(queries==metadata_fail)return STATUS_NOT_SUPPORTED;
    memset(out,0,bytes);
    if(type==FileIdInformation){FILE_ID_INFORMATION *v=out;v->VolumeSerialNumber=9;v->FileId.Identifier[0]=7;}
    if(type==FileBasicInformation){FILE_BASIC_INFORMATION *v=out;v->LastWriteTime.QuadPart=1;v->ChangeTime.QuadPart=(bad_metadata&&queries>3)?2:1;}
    if(type==FileStandardInformation){FILE_STANDARD_INFORMATION *v=out;v->EndOfFile.QuadPart=file_bytes;now+=queries>3?metadata_delay:initial_metadata_delay;}
    return STATUS_SUCCESS;
}
ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA d) { assert(d==&data);return 42; }
PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA d) { assert(d==&data);return (PVOID)(uintptr_t)3; }
ULONG64 PsGetProcessCreateTimeQuadPart(PEPROCESS p) { assert(p==(PVOID)(uintptr_t)3);return 17; }
BOOLEAN MmDoesFileHaveUserWritableReferences(PVOID p) { (void)p;return writable; }
BOOLEAN FltIsIoCanceled(PFLT_CALLBACK_DATA d) { assert(d->irp);++io_cancel_queries;return d->cancelled; }
NTSTATUS FltSendMessage(PFLT_FILTER f,PFLT_PORT *p,PVOID input,ULONG length,PVOID reply,PULONG reply_length,LARGE_INTEGER *until) {
    (void)f;(void)p;
    if(length==sizeof(AX_APPLIED_NOTIFICATION)) {
        AX_APPLIED_NOTIFICATION *v=input;assert(!reply&&!reply_length);++applied;receipt=*v;
        assert(Ax.pending==1);assert(!handle_refs&&!section_object_refs&&!section_refs);
        assert(v->status==(v->decision.verdict==AX_CLEAN?STATUS_SUCCESS:STATUS_ACCESS_DENIED));
        if(v->decision.verdict==AX_CLEAN){assert(Ax.allowed==1&&!cancelled&&!Ax.errors&&!Ax.malware);assert(now<deadline);}
        else{assert(cancelled==1&&data.IoStatus.Status==STATUS_ACCESS_DENIED);assert(v->decision.verdict==AX_MALWARE?Ax.malware==1&&Ax.errors==0:Ax.errors==1&&Ax.malware==0);}
        return STATUS_SUCCESS;
    }
    assert(length==sizeof(AX_NOTIFICATION));++sends;sent_deadline=*until;
    AX_NOTIFICATION *n=input;AX_SCAN_CONTEXT *s=CONTAINING_RECORD(Ax.scans.Flink,AX_SCAN_CONTEXT,entry);
    assert(n==&s->notification&&Ax.pending==1&&s->listed);
    assert(n->actor_pid==42&&n->actor_created==17&&n->policy_sha256[0]==5);
    s->mapped=mapped;s->generation=stream.generation;
    if(mapped&&n->bytes){s->section=calloc(1,sizeof(*s->section));++section_refs;s->section_handle=(HANDLE)(uintptr_t)1;++handle_refs;s->section_object=(PVOID)(uintptr_t)2;++section_object_refs;}
    if(extra_ref){InterlockedIncrement(&s->references);held=s;}
    AX_REPLY *v=reply;memset(v,0,sizeof(*v));v->version=AX_VERSION;v->verdict=verdict;v->request_id=n->request_id;v->sha256[0]=1;
    if(verdict==AX_MALWARE)memcpy(v->detection,"Fixture.Signature",sizeof("Fixture.Signature"));
    if(malformed)++v->request_id;
    if(short_reply)--*reply_length;
    if(seal_send)s->cancelled=TRUE;
    if(change_generation)++stream.generation;
    if(cancel_send)data.cancelled=TRUE;
    now+=send_delay;
    return send_status;
}
void FltCancelFileOpen(PFLT_INSTANCE i,PFILE_OBJECT f) { (void)i;assert(f==&file);assert(!handle_refs&&!section_refs&&!section_object_refs);++cancelled; }
BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF *r) { (void)r;if(no_rundown)return FALSE;++rundown;return TRUE; }
void ExReleaseRundownProtection(EX_RUNDOWN_REF *r) { (void)r;assert(rundown);--rundown; }
NTSTATUS FltIsDirectory(PFILE_OBJECT f,PFLT_INSTANCE i,BOOLEAN *d) { (void)f;(void)i;*d=FALSE;return STATUS_SUCCESS; }
NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA d,ULONG flags,PFLT_FILE_NAME_INFORMATION *out) { (void)d;(void)flags;*out=&name;return STATUS_SUCCESS; }
void FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION n) { assert(n==&name); }
static void quiet(void) { assert(!Ax.pending&&!stream_refs&&!instance_refs&&!file_refs&&!section_refs&&!handle_refs&&!section_object_refs&&!rundown);assert(Ax.scans.Flink==&Ax.scans&&Ax.scans.Blink==&Ax.scans); }
static void reset(void) {
    quiet();memset(&Ax,0,sizeof(Ax));memset(&stream,0,sizeof(stream));memset(&receipt,0,sizeof(receipt));
    Ax.scans.Flink=Ax.scans.Blink=&Ax.scans;Ax.armed=1;Ax.config.root_count=1;Ax.config.timeout_ms=100;Ax.config.policy_sha256[0]=5;
    Ax.config.roots[0].characters=4;memcpy(Ax.config.roots[0].path,path,8);
    now=1000;deadline=1001000;wall=1000000000;
    setup_delay=send_delay=initial_metadata_delay=metadata_delay=close_delay=0;file_bytes=8;
    allocations=frees=fail_allocation=queries=sends=applied=cancelled=closes=io_cancel_queries=metadata_fail=0;
    conflict_close=fail_close=extra_ref=bad_metadata=writable=cancel_send=cancel_close=seal_send=FALSE;
    change_generation=mutate_close=malformed=short_reply=no_rundown=FALSE;
    mapped=TRUE;send_status=stream_status=STATUS_SUCCESS;verdict=AX_CLEAN;held=NULL;
    file.ReadAccess=TRUE;file.SectionObjectPointer=&file;security.DesiredAccess=FILE_READ_DATA;iopb.Parameters.Create.SecurityContext=&security;
    memset(&data,0,sizeof(data));data.Iopb=&iopb;data.irp=TRUE;data.IoStatus.Status=STATUS_SUCCESS;
    objects.Instance=&objects;objects.FileObject=&file;objects.Transaction=NULL;
    name.Name.Buffer=path;name.Name.Length=name.Name.MaximumLength=sizeof(path);
}
static void create(void) { assert(AxPostCreate(&data,&objects,NULL,0)==FLT_POSTOP_FINISHED_PROCESSING);if(!extra_ref)quiet(); }
static void refused(BOOLEAN notified) { assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&cancelled==1&&!Ax.allowed&&!Ax.malware&&Ax.errors==1);assert(applied==(unsigned)notified);if(notified)assert(receipt.decision.verdict==AX_ERROR);else assert(Ax.evidence_dropped==1); }
int main(void) {
    Ax.scans.Flink=Ax.scans.Blink=&Ax.scans;
    reset();PVOID completion=(PVOID)(uintptr_t)1;assert(AxPreCreate(&data,&objects,&completion)==FLT_PREOP_SUCCESS_WITH_CALLBACK&&!completion);create();assert(Ax.allowed==1&&applied==1&&!Ax.errors&&sent_deadline.QuadPart==(LONGLONG)(wall+1000000));
    reset();data.IoStatus.Status=0x105;create();assert(Ax.allowed==1&&data.IoStatus.Status==0x105&&receipt.status==STATUS_SUCCESS);
    reset();verdict=AX_MALWARE;create();assert(Ax.malware==1&&!Ax.errors&&cancelled==1&&applied==1);
    reset();file_bytes=0;create();assert(Ax.allowed==1&&applied==1&&!closes);
    reset();data.cancelled=TRUE;create();refused(FALSE);assert(!sends&&!queries);
    reset();initial_metadata_delay=1000000;create();refused(FALSE);assert(!sends&&queries==3);
    reset();setup_delay=1000000;create();refused(FALSE);assert(!sends);
    reset();setup_delay=400000;create();assert(Ax.allowed==1&&sent_deadline.QuadPart==(LONGLONG)(wall+600000));
    reset();send_delay=1000000;create();refused(TRUE);
    reset();verdict=AX_MALWARE;send_delay=1000000;create();refused(TRUE);
    reset();metadata_delay=1000000;create();refused(TRUE);
    reset();close_delay=1000000;create();refused(TRUE);
    reset();conflict_close=TRUE;create();refused(TRUE);
    reset();fail_close=TRUE;create();refused(TRUE);
    reset();mutate_close=TRUE;create();refused(TRUE);
    reset();cancel_close=TRUE;create();refused(TRUE);
    reset();cancel_send=TRUE;create();refused(TRUE);
    reset();data.irp=FALSE;create();assert(!io_cancel_queries&&Ax.allowed==1);
    reset();seal_send=TRUE;create();refused(TRUE);
    reset();malformed=TRUE;create();refused(TRUE);
    reset();short_reply=TRUE;create();refused(TRUE);
    reset();send_status=STATUS_TIMEOUT;create();refused(TRUE);
    reset();mapped=FALSE;create();refused(TRUE);
    reset();bad_metadata=TRUE;create();refused(TRUE);
    reset();change_generation=TRUE;create();refused(TRUE);
    reset();writable=TRUE;create();refused(TRUE);
    reset();metadata_fail=1;create();refused(FALSE);
    reset();metadata_fail=4;create();refused(TRUE);
    reset();fail_allocation=1;create();refused(FALSE);assert(!stream_refs&&frees==0);
    reset();stream_status=STATUS_NOT_SUPPORTED;create();refused(FALSE);assert(frees==1);
    reset();fail_allocation=2;create();assert(Ax.allowed==1&&!applied&&Ax.evidence_dropped==1);
    reset();extra_ref=TRUE;create();assert(Ax.pending==1&&held&&held->cancelled&&!held->listed&&held->references==1);AxReleaseScan(held);extra_ref=FALSE;quiet();
    reset();wall=0;create();refused(TRUE);assert(!sends);
    reset();wall=INT64_MAX;create();refused(TRUE);assert(!sends);
    reset();no_rundown=TRUE;create();assert(cancelled==1&&!allocations&&!applied);
    reset();file.ReadAccess=FALSE;security.DesiredAccess=0;create();assert(!cancelled&&!allocations&&!sends);
    reset();AX_ADMISSION admission;BOOLEAN admitted;Ax.pending=AX_PENDING;assert(AxAdmit(&name.Name,&admission,&admitted)==STATUS_INSUFFICIENT_RESOURCES&&!admitted&&Ax.pending==AX_PENDING);Ax.pending=0;
    reset();now=UINT64_MAX-999;assert(AxAdmit(&name.Name,&admission,&admitted)==STATUS_IO_TIMEOUT&&!admitted&&!Ax.pending);
    reset();assert(AxAdmit(&name.Name,&admission,&admitted)==STATUS_SUCCESS&&admitted);AX_SCAN_RESULT result;assert(AxPrepareScan(&data,&objects,&name.Name,&admission,&result)==STATUS_SUCCESS);now=deadline;AxFinalizeScan(&data,&result);assert(result.reply.verdict==AX_ERROR&&!Ax.allowed&&!applied);AxFinishScan(&result);quiet();
    reset();assert(AxAdmit(&name.Name,&admission,&admitted)==STATUS_SUCCESS);assert(AxPrepareScan(&data,&objects,&name.Name,&admission,&result)==STATUS_SUCCESS);now=999;AxFinalizeScan(&data,&result);assert(result.reply.verdict==AX_ERROR);AxFinishScan(&result);quiet();
    puts("Windows scan/create production decision controls: passed (mocked kernel effects; no native runtime claim)");
    return 0;
}
