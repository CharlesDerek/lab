/* Actual scan/mapping/snapshot/read sources with controlled platform effects.
 * No loaded-driver, actual MDL/IRQL scheduling or filesystem proof is claimed. */
#ifdef NDEBUG
#error "Windows read controls require assertions"
#endif
#include "driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <setjmp.h>
static jmp_buf exception_target, rundown_block_target;
static void copy_memory(void *, const void *, size_t);
#undef __try
#undef __except
#undef RtlCopyMemory
#define __try if (setjmp(exception_target) == 0)
#define __except(x) else
#define RtlCopyMemory(d,s,n) copy_memory((d),(s),(n))
#include "scan.c"
#include "mapping.c"
#include "snapshot.c"
#include "read.c"
#include "lifecycle.c"

struct TEST_WORK { unsigned id; };
AX_GLOBALS Ax;
unsigned test_seh_exception;
static AX_STREAM stream;
static FILE_OBJECT file;
static FLT_CALLBACK_DATA data;
static FLT_IO_PARAMETER_BLOCK incoming, pre_iopb, post_iopb;
static FLT_RELATED_OBJECTS objects;
static FLT_FILE_NAME_INFORMATION name;
static WCHAR path[] = {'\\','v','\\','r','\\','f'};
static UCHAR source[65545], expected[65545], output[32];
static const UCHAR digest8[32] = {0x9a,0xc2,0x19,0x7d,0x92,0x58,0x25,0x7b,0x1a,0xe8,0x46,0x3e,0x42,0x14,0xe4,0xcd,0x0a,0x57,0x8b,0xc1,0x51,0x7f,0x24,0x15,0x92,0x8b,0x91,0xbe,0x42,0x83,0xfc,0x48};
static const UCHAR digest_changed[32] = {0x76,0x67,0x80,0x70,0x16,0xbc,0x47,0xfe,0xce,0x27,0x12,0x27,0x2f,0x89,0xe6,0x04,0x2d,0x32,0xd1,0x35,0xaf,0x26,0xc5,0x53,0xeb,0xcd,0x9e,0x49,0xf8,0xeb,0xc3,0x3c};
static const UCHAR digest_large[32] = {0x09,0x5b,0x2d,0x0a,0xc5,0x4a,0x33,0x04,0xbe,0x3a,0xb4,0xfc,0xc5,0x14,0x8c,0xe7,0xc6,0xa5,0x20,0xa0,0xc5,0x65,0x43,0x6e,0x9a,0xc0,0x71,0x72,0x1f,0xc1,0x8d,0x2a};
static MDL original_mdl, locked_mdl;
static PMDL swapped_mdl;
static PFLT_DEFERRED_IO_WORKITEM queued_work;
static PFLT_DEFERRED_IO_WORKITEM_ROUTINE queued_routine;
static PVOID queued_context, pre_context;
static ULONG irql, sector, source_bytes, verdict;
static ULONG64 now, deadline, lower_bytes, shadow_allocated;
static ULONG64 setup_delay, source_delay, hash_delay, send_delay, close_delay, open_delay, lower_delay;
static unsigned allocations, frees, fail_allocation, aligned, mdls, workitems, work_seq;
static unsigned instances, volumes, files, stream_refs, sections, section_objects, kernel_handles, user_handles;
static unsigned rundown, views, reference_calls, fail_reference, unload_step, sends, applied, copied, complete_pre, complete_post, names, hashes, locks, map_calls, dirty;
static BOOLEAN top_level, client, immediate, pre_reentrant, no_name, no_lock, no_destination;
static BOOLEAN fail_shadow, fail_mdl, fail_work, fail_queue, fail_section, fail_map, fail_unmap, small_view;
static BOOLEAN crypto_fail, bad_hash, shadow_mismatch, source_fault, copy_fault, mutate_send, conflict_close, fail_close;
static BOOLEAN cancel_source, cancel_send, cancel_close, held_map_ref, no_map, second_map, map_after_seal, mapping_timeout;
static BOOLEAN changed_metadata, writable, decline_rundown, drain, changed_original, mutate_bytes;
static FLT_PREOP_CALLBACK_STATUS pre_result;
static AX_SCAN_CONTEXT *held, *retained;
static AX_APPLIED_NOTIFICATION receipt;
static void lower_and_post(PVOID context);

static void copy_memory(void *destination,const void *from,size_t n) {
    if (source_fault && (uintptr_t)from >= (uintptr_t)source && (uintptr_t)from < (uintptr_t)(source+sizeof(source))) longjmp(exception_target,1);
    if (destination==output) {
        ++copied;
        if(copy_fault) { if(n)memcpy(destination,from,1);longjmp(exception_target,1); }
    }
    memcpy(destination,from,n);
}
ULONG64 KeQueryInterruptTimePrecise(ULONG64 *qpc) { assert(qpc);*qpc=now;return now; }
void KeQuerySystemTimePrecise(LARGE_INTEGER *v) { v->QuadPart=1000000000; }
ULONG KeGetCurrentIrql(void) { return irql; }
PVOID IoGetTopLevelIrp(void) { return top_level?&data:NULL; }
PVOID ExAllocatePool2(ULONG flags,size_t bytes,ULONG tag) { (void)flags;(void)tag;++allocations;if(allocations==fail_allocation)return NULL;PVOID p=calloc(1,bytes);if(bytes==sizeof(AX_SCAN_CONTEXT))retained=p;return p; }
void ExFreePoolWithTag(PVOID p,ULONG tag) { (void)tag;assert(p);if(p==retained)retained=NULL;++frees;free(p); }
void AxLock(EX_PUSH_LOCK *lock) { assert(irql<=APC_LEVEL&&!*lock);*lock=1; }
void AxUnlock(EX_PUSH_LOCK *lock) { assert(*lock);*lock=0; }
BOOLEAN AxIsClient(void) { assert(irql<=APC_LEVEL);return client; }
NTSTATUS FltGetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,PFLT_CONTEXT *out) { assert(i==objects.Instance&&f==&file);*out=&stream;++stream_refs;return STATUS_SUCCESS; }
NTSTATUS FltAllocateContext(PFLT_FILTER f,ULONG type,size_t bytes,ULONG pool,PFLT_CONTEXT *out) { (void)f;(void)pool;assert(type==FLT_SECTION_CONTEXT&&bytes==sizeof(AX_SECTION));if(fail_section)return STATUS_FLT_CONTEXT_ALREADY_DEFINED;*out=calloc(1,bytes);++sections;return STATUS_SUCCESS; }
NTSTATUS FltSetStreamContext(PFLT_INSTANCE i,PFILE_OBJECT f,ULONG flags,PFLT_CONTEXT c,PFLT_CONTEXT *old) { (void)i;(void)f;(void)flags;(void)c;(void)old;assert(!"unexpected attach");return STATUS_NOT_SUPPORTED; }
void FltReleaseContext(PFLT_CONTEXT c) { if(c==&stream){assert(stream_refs);--stream_refs;}else{assert(sections);--sections;free(c);} }
NTSTATUS FltObjectReference(PVOID p) { if(++reference_calls==fail_reference)return STATUS_NOT_FOUND;if(p==objects.Instance)++instances;else{assert(p==objects.Volume);++volumes;}return STATUS_SUCCESS; }
void FltObjectDereference(PVOID p) { if(p==objects.Instance){assert(instances);--instances;}else{assert(p==objects.Volume&&volumes);--volumes;} }
void ObReferenceObject(PVOID p) { assert(p==&file);++files; }
void ObDereferenceObject(PVOID p) { if(p==&file){assert(files);--files;}else{assert(p==source&&section_objects);--section_objects;} }
void ZwClose(HANDLE h) { if(h==(HANDLE)(uintptr_t)1){assert(kernel_handles);--kernel_handles;}else{assert(h==(HANDLE)(uintptr_t)2&&user_handles);--user_handles;} }
NTSTATUS FltCloseSectionForDataScan(PFLT_CONTEXT c) { assert(irql==PASSIVE_LEVEL);if(conflict_close)((AX_SECTION*)c)->conflicted=1;if(cancel_close)data.cancelled=TRUE;now+=close_delay;return fail_close?STATUS_NOT_FOUND:STATUS_SUCCESS; }
NTSTATUS FltQueryInformationFile(PFLT_INSTANCE i,PFILE_OBJECT f,PVOID out,ULONG bytes,ULONG type,PVOID used) {
    (void)used;assert(irql==PASSIVE_LEVEL&&i==objects.Instance&&f==&file);memset(out,0,bytes);
    if(type==FileIdInformation){FILE_ID_INFORMATION *v=out;v->VolumeSerialNumber=9;v->FileId.Identifier[0]=7;}
    if(type==FileBasicInformation){FILE_BASIC_INFORMATION *v=out;v->LastWriteTime.QuadPart=1;v->ChangeTime.QuadPart=(changed_metadata&&sends)?2:1;}
    if(type==FileStandardInformation)((FILE_STANDARD_INFORMATION*)out)->EndOfFile.QuadPart=source_bytes;
    return STATUS_SUCCESS;
}
ULONG FltGetRequestorProcessId(PFLT_CALLBACK_DATA d) { assert(d==&data);return 42; }
PEPROCESS FltGetRequestorProcess(PFLT_CALLBACK_DATA d) { assert(d==&data);return (PVOID)(uintptr_t)3; }
ULONG64 PsGetProcessCreateTimeQuadPart(PEPROCESS p) { assert(p==(PVOID)(uintptr_t)3);return 17; }
BOOLEAN MmDoesFileHaveUserWritableReferences(PVOID p) { (void)p;return writable; }
BOOLEAN FltIsIoCanceled(PFLT_CALLBACK_DATA d) { assert(d==&data&&d->irp);return d->cancelled; }
BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF *r) { (void)r;if(decline_rundown)return FALSE;++rundown;return TRUE; }
void ExReleaseRundownProtection(EX_RUNDOWN_REF *r) { (void)r;assert(rundown);--rundown; }
void FltCloseCommunicationPort(PFLT_PORT p) { (void)p;assert(unload_step==0);unload_step=1; }
void FltCloseClientPort(PFLT_FILTER f,PFLT_PORT *p) { (void)f;assert(unload_step==1);unload_step=2;*p=NULL; }
void ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF *r) { (void)r;assert(unload_step==2);unload_step=3;if(rundown)longjmp(rundown_block_target,1); }
void FltUnregisterFilter(PFLT_FILTER f) { (void)f;assert(unload_step==3&&!rundown);unload_step=4; }
void AxClosePins(struct AX_PINS *p) { assert(unload_step==4&&p==Ax.pins);unload_step=5; }
NTSTATUS FltGetFileNameInformation(PFLT_CALLBACK_DATA d,ULONG flags,PFLT_FILE_NAME_INFORMATION *out) { assert(d==&data&&irql<=APC_LEVEL&&!top_level);assert(flags==(FLT_FILE_NAME_NORMALIZED|FLT_FILE_NAME_QUERY_ALWAYS_ALLOW_CACHE_LOOKUP));++names;if(no_name)return STATUS_NOT_FOUND;*out=&name;return STATUS_SUCCESS; }
void FltReleaseFileNameInformation(PFLT_FILE_NAME_INFORMATION n) { assert(n==&name); }
NTSTATUS FltGetVolumeProperties(PFLT_VOLUME v,FLT_VOLUME_PROPERTIES *p,ULONG size,PULONG used) { assert(v==objects.Volume&&size==sizeof(*p));p->SectorSize=sector;*used=size;return STATUS_BUFFER_OVERFLOW; }
PVOID FltAllocatePoolAlignedWithTag(PFLT_INSTANCE i,ULONG pool,SIZE_T size,ULONG tag) { (void)pool;(void)tag;assert(i==objects.Instance);shadow_allocated=size;now+=setup_delay;if(fail_shadow)return NULL;++aligned;return calloc(1,size); }
void FltFreePoolAlignedWithTag(PFLT_INSTANCE i,PVOID buffer,ULONG tag) { (void)tag;assert(i==objects.Instance&&aligned);--aligned;free(buffer); }
PMDL IoAllocateMdl(PVOID buffer,ULONG bytes,BOOLEAN secondary,BOOLEAN quota,PVOID irp) { assert(!secondary&&!quota&&!irp);if(fail_mdl)return NULL;PMDL m=malloc(sizeof(*m));*m=(MDL){buffer,bytes,1};++mdls;return m; }
void IoFreeMdl(PMDL m) { assert(m->owner==1&&mdls);--mdls;free(m); }
void MmBuildMdlForNonPagedPool(PMDL m) { assert(m->owner==1); }
PFLT_DEFERRED_IO_WORKITEM FltAllocateDeferredIoWorkItem(void) { if(fail_work)return NULL;PFLT_DEFERRED_IO_WORKITEM w=malloc(sizeof(*w));w->id=++work_seq;++workitems;return w; }
void FltFreeDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM w) { assert(w&&workitems);--workitems;free(w); }
NTSTATUS FltQueueDeferredIoWorkItem(PFLT_DEFERRED_IO_WORKITEM w,PFLT_CALLBACK_DATA d,PFLT_DEFERRED_IO_WORKITEM_ROUTINE routine,ULONG queue,PVOID context) {
    assert(w&&d==&data&&queue==DelayedWorkQueue&&!queued_work);
    if(fail_queue)return STATUS_NOT_SUPPORTED;
    if(immediate){ULONG saved=irql;irql=PASSIVE_LEVEL;routine(w,d,context);irql=saved;}
    else{queued_work=w;queued_routine=routine;queued_context=context;}
    return STATUS_SUCCESS;
}
void FltCompletePendedPreOperation(PFLT_CALLBACK_DATA d,FLT_PREOP_CALLBACK_STATUS status,PVOID context) {
    assert(d==&data&&irql==PASSIVE_LEVEL&&workitems);++complete_pre;pre_result=status;pre_context=context;
    if(pre_reentrant&&status==FLT_PREOP_SUCCESS_WITH_CALLBACK)lower_and_post(context);
}
void FltCompletePendedPostOperation(PFLT_CALLBACK_DATA d) { assert(d==&data&&irql==PASSIVE_LEVEL&&workitems);++complete_post; }
void FltSetCallbackDataDirty(PFLT_CALLBACK_DATA d) { assert(d==&data);++dirty; }
NTSTATUS FltLockUserBuffer(PFLT_CALLBACK_DATA d) { assert(d==&data&&irql==PASSIVE_LEVEL&&!d->Iopb->Parameters.Read.MdlAddress&&d->Iopb->Parameters.Read.ReadBuffer==output);++locks;if(no_lock)return STATUS_ACCESS_DENIED;locked_mdl=(MDL){output,(ULONG)sizeof(output),3};d->Iopb->Parameters.Read.MdlAddress=&locked_mdl;return STATUS_SUCCESS; }
PVOID MmGetSystemAddressForMdlSafe(PMDL m,ULONG flags) { assert(irql==PASSIVE_LEVEL&&(flags&MdlMappingNoExecute)&&m->owner!=1);return no_destination?NULL:m->buffer; }
NTSTATUS FltCreateSectionForDataScan(PFLT_INSTANCE i,PFILE_OBJECT f,PFLT_CONTEXT c,ULONG access,OBJECT_ATTRIBUTES *attrs,LARGE_INTEGER *size,ULONG protection,ULONG attributes,ULONG flags,HANDLE *h,PVOID *o,LARGE_INTEGER *file_size) {
    assert(irql==PASSIVE_LEVEL&&i==objects.Instance&&f==&file&&c&&access==(SECTION_MAP_READ|SECTION_QUERY)&&attrs->flags==OBJ_KERNEL_HANDLE&&!size&&protection==PAGE_READONLY&&attributes==SEC_COMMIT&&!flags);
    *h=(HANDLE)(uintptr_t)1;*o=source;file_size->QuadPart=source_bytes;++kernel_handles;++section_objects;++stream.generation;return STATUS_SUCCESS;
}
NTSTATUS ObOpenObjectByPointer(PVOID object,ULONG attrs,PVOID state,ULONG access,PVOID type,ULONG mode,HANDLE *h) {
    assert(object==source&&!attrs&&!state&&access==SECTION_MAP_READ&&!type&&mode==KernelMode);*h=(HANDLE)(uintptr_t)2;++user_handles;now+=open_delay;return STATUS_SUCCESS;
}
NTSTATUS MmMapViewInSystemSpace(PVOID section,PVOID *view,SIZE_T *bytes) {
    assert(irql==PASSIVE_LEVEL&&section==source&&*bytes==source_bytes&&!*view);++map_calls;
    if(fail_map)return STATUS_NOT_SUPPORTED;
    *view=source;*bytes=small_view?source_bytes-1:source_bytes;++views;now+=source_delay;if(cancel_source)data.cancelled=TRUE;return STATUS_SUCCESS;
}
NTSTATUS MmUnmapViewInSystemSpace(PVOID view) { assert(irql==PASSIVE_LEVEL&&view==source&&views);if(fail_unmap)return STATUS_NOT_SUPPORTED;--views;return STATUS_SUCCESS; }
NTSTATUS BCryptHash(PVOID a,PUCHAR secret,ULONG secrets,PUCHAR in,ULONG bytes,PUCHAR out,ULONG outbytes) {
    assert(irql==PASSIVE_LEVEL&&a==BCRYPT_SHA256_ALG_HANDLE&&!secret&&!secrets&&outbytes==32);++hashes;
    assert(bytes==source_bytes&&memcmp(in,expected,bytes)==0);now+=hash_delay;
    if(crypto_fail)return STATUS_NOT_SUPPORTED;
    memcpy(out,bytes==8?digest8:digest_large,32);return STATUS_SUCCESS;
}
NTSTATUS FltSendMessage(PFLT_FILTER filter,PFLT_PORT *port,PVOID input,ULONG bytes,PVOID reply,PULONG reply_bytes,LARGE_INTEGER *until) {
    (void)filter;(void)port;assert(irql==PASSIVE_LEVEL);
    if(bytes==sizeof(AX_APPLIED_NOTIFICATION)) {
        receipt=*(AX_APPLIED_NOTIFICATION*)input;++applied;assert(!reply&&!reply_bytes&&until->QuadPart<0&&!sections&&!kernel_handles&&!section_objects&&!views);
        assert(receipt.status==(receipt.decision.verdict==AX_CLEAN?STATUS_SUCCESS:STATUS_ACCESS_DENIED));
        assert(receipt.file.actor_pid==42&&receipt.file.actor_created==17&&receipt.file.bytes==source_bytes);
        if(receipt.decision.verdict==AX_CLEAN)assert(Ax.allowed==1&&copied==1&&data.IoStatus.Information==lower_bytes);
        else assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&!data.IoStatus.Information&&!Ax.allowed);
        return STATUS_SUCCESS;
    }
    assert(bytes==sizeof(AX_NOTIFICATION)&&*reply_bytes==sizeof(AX_REPLY));++sends;
    AX_NOTIFICATION *n=input;AX_SCAN_CONTEXT *s=CONTAINING_RECORD(Ax.scans.Flink,AX_SCAN_CONTEXT,entry);
    assert(n==&s->notification&&s->snapshot_mode&&s->snapshot_ready&&!s->source_view&&s->snapshot);
    assert(n->actor_pid==42&&n->actor_created==17&&n->policy_sha256[0]==5);
    AX_MAPPING m;memset(&m,0xa5,sizeof(m));
    if(!no_map) {
        if(mapping_timeout)open_delay=deadline-now;
        NTSTATUS status=AxMapScan(n->request_id,&m);
        if(mapping_timeout)assert(status==STATUS_IO_TIMEOUT&&m.version==0xa5a5a5a5&&!user_handles);
        else if(changed_metadata)assert(status==STATUS_FILE_LOCK_CONFLICT&&m.version==0xa5a5a5a5&&!user_handles);
        else {assert(status==STATUS_SUCCESS&&m.bytes==source_bytes&&m.section_handle==2);ZwClose((HANDLE)(uintptr_t)m.section_handle);}
        if(second_map)assert(AxMapScan(n->request_id,&m)==STATUS_FILE_LOCK_CONFLICT);
    }
    if(held_map_ref){InterlockedIncrement(&s->references);held=s;}
    if(map_after_seal){s->cancelled=TRUE;assert(AxMapScan(n->request_id,&m)==STATUS_FILE_LOCK_CONFLICT);}
    AX_REPLY *r=reply;memset(r,0,sizeof(*r));r->version=AX_VERSION;r->request_id=n->request_id;r->verdict=verdict;memcpy(r->sha256,source_bytes==8?digest8:digest_large,32);
    if(mutate_bytes){source[7]='X';memcpy(r->sha256,digest_changed,32);}
    if(bad_hash)r->sha256[0]^=1;
    if(verdict==AX_MALWARE)memcpy(r->detection,"Fixture.Signature",sizeof("Fixture.Signature"));
    if(mutate_send)++stream.generation;
    if(cancel_send)data.cancelled=TRUE;
    now+=send_delay;return STATUS_SUCCESS;
}
static void run_queued(void) {
    assert(queued_work);PFLT_DEFERRED_IO_WORKITEM w=queued_work;PFLT_DEFERRED_IO_WORKITEM_ROUTINE routine=queued_routine;PVOID context=queued_context;
    queued_work=NULL;queued_routine=NULL;queued_context=NULL;ULONG saved=irql;irql=PASSIVE_LEVEL;routine(w,&data,context);irql=saved;
}
static void fm_free_shadow_mdl(void) { assert(swapped_mdl&&swapped_mdl->owner==1&&mdls);/* Filter Manager, not production adapter, owns this release. */--mdls;free(swapped_mdl);swapped_mdl=NULL; }
static void lower_and_post(PVOID context) {
    assert(data.Iopb==&pre_iopb&&data.Iopb->Parameters.Read.ReadBuffer!=output);
    swapped_mdl=data.Iopb->Parameters.Read.MdlAddress;assert(swapped_mdl&&swapped_mdl->owner==1);
    if(lower_bytes<=incoming.Parameters.Read.Length&&lower_bytes<=source_bytes-(ULONG64)incoming.Parameters.Read.ByteOffset.QuadPart)memcpy(data.Iopb->Parameters.Read.ReadBuffer,source+(size_t)incoming.Parameters.Read.ByteOffset.QuadPart,(size_t)lower_bytes);
    if(shadow_mismatch)((UCHAR*)data.Iopb->Parameters.Read.ReadBuffer)[0]^=1;
    post_iopb=incoming;data.Iopb=&post_iopb;data.IoStatus.Information=lower_bytes;now+=lower_delay;
    if(changed_original)post_iopb.Parameters.Read.ReadBuffer=output+1;
    ULONG saved=irql;irql=DISPATCH_LEVEL;FLT_POSTOP_CALLBACK_STATUS post=AxPostRead(&data,&objects,context,drain?FLTFL_POST_OPERATION_DRAINING:0);irql=saved;
    if(post==FLT_POSTOP_MORE_PROCESSING_REQUIRED){if(queued_work)run_queued();assert(complete_post==1);}else assert(post==FLT_POSTOP_FINISHED_PROCESSING&&!complete_post);
    fm_free_shadow_mdl();
}
static void quiet(void) {
    assert(!Ax.pending&&!Ax.read_bytes&&!Ax.retained_views&&!rundown&&!aligned&&!mdls&&!workitems&&!instances&&!volumes&&!files&&!stream_refs&&!sections&&!section_objects&&!kernel_handles&&!user_handles&&!views&&!queued_work);
    assert(Ax.scans.Flink==&Ax.scans&&Ax.scans.Blink==&Ax.scans);
}
static void reset(void) {
    quiet();memset(&Ax,0,sizeof(Ax));memset(&stream,0,sizeof(stream));memset(&file,0,sizeof(file));memset(&data,0,sizeof(data));memset(&receipt,0,sizeof(receipt));
    Ax.scans.Flink=Ax.scans.Blink=&Ax.scans;Ax.armed=1;Ax.config.root_count=1;Ax.config.timeout_ms=100;Ax.config.policy_sha256[0]=5;Ax.config.roots[0].characters=4;memcpy(Ax.config.roots[0].path,path,8);
    source_bytes=8;memcpy(source,"ABCDEFGH",8);memcpy(expected,source,8);memset(output,0xa5,sizeof(output));
    now=1000;deadline=1001000;irql=PASSIVE_LEVEL;sector=512;lower_bytes=3;verdict=AX_CLEAN;
    setup_delay=source_delay=hash_delay=send_delay=close_delay=open_delay=lower_delay=0;
    reference_calls=fail_reference=unload_step=0;
    allocations=frees=fail_allocation=work_seq=shadow_allocated=sends=applied=copied=complete_pre=complete_post=names=hashes=locks=map_calls=dirty=0;
    top_level=client=immediate=pre_reentrant=no_name=no_lock=no_destination=FALSE;
    fail_shadow=fail_mdl=fail_work=fail_queue=fail_section=fail_map=fail_unmap=small_view=FALSE;
    crypto_fail=bad_hash=shadow_mismatch=source_fault=copy_fault=mutate_send=conflict_close=fail_close=FALSE;
    cancel_source=cancel_send=cancel_close=held_map_ref=no_map=second_map=map_after_seal=mapping_timeout=FALSE;
    changed_metadata=writable=decline_rundown=drain=changed_original=mutate_bytes=FALSE;held=retained=NULL;pre_context=NULL;pre_result=0;
    memset(&incoming,0,sizeof(incoming));incoming.Parameters.Read.Length=3;incoming.Parameters.Read.Key=7;incoming.Parameters.Read.ByteOffset.QuadPart=2;incoming.Parameters.Read.ReadBuffer=output;
    original_mdl=(MDL){output,(ULONG)sizeof(output),2};locked_mdl=(MDL){0};pre_iopb=incoming;data.Iopb=&pre_iopb;data.irp=TRUE;data.IoStatus.Status=STATUS_SUCCESS;
    file.SectionObjectPointer=&file;file.ReadAccess=TRUE;objects.Instance=&objects;objects.Volume=&name;objects.FileObject=&file;objects.Transaction=NULL;name.Name.Buffer=path;name.Name.Length=name.Name.MaximumLength=sizeof(path);
}
static FLT_PREOP_CALLBACK_STATUS begin(void) { pre_iopb=incoming;data.Iopb=&pre_iopb;PVOID context=NULL;FLT_PREOP_CALLBACK_STATUS result=AxPreRead(&data,&objects,&context);if(result==FLT_PREOP_PENDING){if(queued_work)run_queued();assert(complete_pre==1);if(!pre_reentrant&&pre_result==FLT_PREOP_SUCCESS_WITH_CALLBACK)lower_and_post(pre_context);}else if(result==FLT_PREOP_SUCCESS_WITH_CALLBACK)lower_and_post(context);return result; }
static void clean(void) { assert(data.IoStatus.Status==STATUS_SUCCESS&&data.IoStatus.Information==lower_bytes&&Ax.allowed==1&&!Ax.errors&&!Ax.malware&&applied==1&&copied==1);assert(memcmp(output,expected+2,(size_t)lower_bytes)==0);for(size_t i=(size_t)lower_bytes;i<sizeof(output);++i)assert(output[i]==0xa5);quiet(); }
static void denied(BOOLEAN notified) { assert(data.IoStatus.Status==STATUS_ACCESS_DENIED&&!data.IoStatus.Information&&!Ax.allowed&&Ax.errors==1&&!Ax.malware);assert(applied==(unsigned)notified);if(notified)assert(receipt.decision.verdict==AX_ERROR);else assert(Ax.evidence_dropped==1);if(!copy_fault)for(size_t i=0;i<sizeof(output);++i)assert(output[i]==0xa5); }
int main(void) {
    Ax.scans.Flink=Ax.scans.Blink=&Ax.scans;
    reset();begin();clean();assert(locks==1&&post_iopb.Parameters.Read.MdlAddress==&locked_mdl&&hashes==1&&map_calls==1);
    reset();incoming.Parameters.Read.MdlAddress=&original_mdl;begin();clean();assert(!locks);
    reset();data.system_buffer=TRUE;begin();clean();assert(!locks);
    reset();irql=APC_LEVEL;begin();clean();assert(complete_pre==1);
    reset();irql=APC_LEVEL;immediate=TRUE;pre_reentrant=TRUE;begin();clean();assert(complete_pre==1&&complete_post==1);
    reset();data.IoStatus.Status=0x105;begin();assert(data.IoStatus.Status==0x105&&receipt.status==STATUS_SUCCESS);quiet();
    reset();incoming.Parameters.Read.Length=6;begin();clean(); /* short read */
    reset();incoming.IrpFlags=IRP_NOCACHE;begin();clean();assert(shadow_allocated==512);
    reset();source_bytes=sizeof(source);for(size_t i=0;i<sizeof(source);++i)source[i]=expected[i]=(UCHAR)(i%251);begin();clean();assert(hashes==1&&receipt.file.bytes==65545);
    reset();verdict=AX_MALWARE;begin();assert(!Ax.allowed&&Ax.malware==1&&!Ax.errors&&!copied&&applied==1&&data.IoStatus.Status==STATUS_ACCESS_DENIED);quiet();
    reset();second_map=TRUE;begin();clean();
    reset();lower_bytes=0;data.IoStatus.Status=STATUS_END_OF_FILE;begin();assert(data.IoStatus.Status==STATUS_END_OF_FILE&&!data.IoStatus.Information&&!sends&&!copied);quiet();
    reset();lower_bytes=0;begin();assert(data.IoStatus.Status==STATUS_SUCCESS&&!sends&&!copied);quiet();
    reset();data.IoStatus.Status=STATUS_NOT_FOUND;begin();assert(data.IoStatus.Status==STATUS_NOT_FOUND&&!data.IoStatus.Information&&!sends&&!copied);quiet();
    reset();lower_bytes=4;begin();denied(FALSE);quiet();
    reset();incoming.Parameters.Read.ByteOffset.QuadPart=7;begin();denied(TRUE);quiet(); /* count exceeds snapshot EOF */
    reset();bad_hash=TRUE;begin();denied(TRUE);quiet();
    reset();mutate_bytes=TRUE;begin();denied(TRUE);quiet(); /* mutation outside returned range, independent hash catches it */
    reset();changed_original=TRUE;begin();denied(FALSE);quiet();
    reset();drain=TRUE;begin();assert(!copied&&!sends&&!complete_post&&Ax.errors==1&&Ax.evidence_dropped==1);quiet();
    reset();shadow_mismatch=TRUE;begin();denied(TRUE);quiet();
    reset();source_fault=TRUE;begin();denied(FALSE);quiet();assert(!hashes&&!sends);
    reset();copy_fault=TRUE;begin();denied(TRUE);assert(output[0]=='C'&&output[1]==0xa5);quiet();
    reset();crypto_fail=TRUE;begin();denied(FALSE);quiet();
    reset();fail_map=TRUE;begin();denied(FALSE);quiet();assert(!views&&!Ax.poisoned);
    reset();small_view=TRUE;begin();denied(FALSE);quiet();
    reset();fail_section=TRUE;begin();denied(FALSE);quiet();
    reset();mutate_send=TRUE;begin();denied(TRUE);quiet();
    reset();conflict_close=TRUE;begin();denied(TRUE);quiet();
    reset();fail_close=TRUE;begin();denied(TRUE);quiet();
    reset();changed_metadata=TRUE;begin();denied(TRUE);quiet();
    reset();writable=TRUE;begin();denied(FALSE);quiet();
    reset();cancel_source=TRUE;begin();denied(FALSE);quiet();
    reset();cancel_send=TRUE;begin();denied(TRUE);quiet();
    reset();cancel_close=TRUE;begin();denied(TRUE);quiet();
    reset();lower_delay=1000000;begin();denied(FALSE);quiet();assert(!sends);
    reset();setup_delay=1000000;begin();denied(FALSE);quiet();assert(!sends);
    reset();source_delay=1000000;begin();denied(FALSE);quiet();
    reset();hash_delay=1000000;begin();denied(FALSE);quiet();
    reset();send_delay=1000000;begin();denied(TRUE);quiet();
    reset();close_delay=1000000;begin();denied(TRUE);quiet();
    reset();mapping_timeout=TRUE;begin();denied(TRUE);quiet();assert(!user_handles);
    reset();no_map=TRUE;begin();denied(TRUE);quiet();
    reset();map_after_seal=TRUE;begin();denied(TRUE);quiet();
    reset();no_lock=TRUE;begin();denied(FALSE);quiet();
    reset();no_destination=TRUE;begin();denied(FALSE);quiet();
    reset();incoming.Parameters.Read.MdlAddress=&original_mdl;original_mdl.bytes=2;begin();denied(FALSE);quiet();
    reset();fail_reference=1;begin();denied(FALSE);quiet();
    reset();fail_reference=2;begin();denied(FALSE);quiet();
    reset();fail_reference=3;begin();denied(FALSE);quiet();
    reset();fail_allocation=1;begin();denied(FALSE);quiet();
    reset();fail_allocation=2;begin();denied(FALSE);quiet();
    reset();fail_allocation=3;begin();denied(FALSE);quiet();
    reset();fail_shadow=TRUE;begin();denied(FALSE);quiet();
    reset();fail_mdl=TRUE;begin();denied(FALSE);quiet();
    reset();fail_work=TRUE;begin();denied(FALSE);quiet();
    reset();fail_queue=TRUE;begin();denied(FALSE);quiet(); /* post queue failure, no scan */
    reset();irql=APC_LEVEL;fail_queue=TRUE;begin();denied(FALSE);quiet(); /* pre queue failure */
    reset();top_level=TRUE;begin();denied(FALSE);quiet();assert(!names);
    reset();no_name=TRUE;begin();denied(FALSE);quiet();
    reset();decline_rundown=TRUE;begin();denied(FALSE);quiet();
    reset();incoming.MinorFunction=IRP_MN_MDL;begin();denied(FALSE);quiet();
    reset();incoming.MinorFunction=IRP_MN_MDL|IRP_MN_COMPLETE;assert(begin()==FLT_PREOP_SUCCESS_NO_CALLBACK&&!names&&!sends);quiet();
    reset();incoming.Parameters.Read.ByteOffset.QuadPart=-2;begin();denied(FALSE);quiet();
    reset();incoming.Parameters.Read.Length=AX_MAX_FILE+1;begin();denied(FALSE);quiet();
    reset();incoming.Parameters.Read.Length=AX_MAX_FILE;fail_shadow=TRUE;begin();denied(FALSE);assert(shadow_allocated==AX_MAX_FILE);quiet();
    reset();Ax.pending=AX_PENDING;begin();denied(FALSE);assert(Ax.pending==AX_PENDING);Ax.pending=0;quiet();
    reset();assert(AxReserveReadBytes(AX_READ_BUDGET));assert(!AxReserveReadBytes(1));AxReleaseReadBytes(AX_READ_BUDGET);quiet();
    reset();Ax.read_bytes=AX_READ_BUDGET-2;begin();denied(FALSE);assert(Ax.read_bytes==AX_READ_BUDGET-2);Ax.read_bytes=0;quiet();
    reset();data.fastio=TRUE;data.irp=FALSE;assert(begin()==FLT_PREOP_DISALLOW_FASTIO&&!copied&&!names);quiet();
    reset();client=TRUE;assert(begin()==FLT_PREOP_SUCCESS_NO_CALLBACK&&!names);quiet();
    reset();Ax.config.roots[0].path[1]='x';assert(begin()==FLT_PREOP_SUCCESS_NO_CALLBACK&&!sends);quiet();
    reset();held_map_ref=TRUE;begin();assert(held&&Ax.pending==1&&Ax.read_bytes==source_bytes&&rundown==1&&!aligned&&applied==1);irql=PASSIVE_LEVEL;AxReleaseScan(held);held=NULL;quiet();
    /* Permanent unmap failure retains one real owner/slot/charge/rundown. The
     * harness subsequently simulates external host recovery solely to release
     * mock allocations; production has no retry-to-success/authorization path. */
    reset();fail_unmap=TRUE;begin();denied(FALSE);assert(Ax.poisoned&&Ax.retained_views==1&&Ax.pending==1&&Ax.read_bytes==source_bytes&&rundown==1&&views==1&&!aligned&&!workitems);
    /* Recover the retained pointer through the platform's allocation observer. */
    assert(retained&&retained->references==1&&retained->source_view==source);
    assert(AxUnload(0)==STATUS_FLT_DO_NOT_DETACH&&unload_step==0);
    if(setjmp(rundown_block_target)==0){(void)AxUnload(FLTFL_FILTER_UNLOAD_MANDATORY);assert(!"mandatory unload returned through retained rundown");}
    assert(unload_step==3&&rundown==1&&views==1&&Ax.pending==1&&Ax.read_bytes==source_bytes);
    AX_ADMISSION admission;BOOLEAN admitted;assert(AxAdmit(&name.Name,&admission,&admitted)==STATUS_FILE_LOCK_CONFLICT&&!admitted&&Ax.pending==1);
    fail_unmap=FALSE;assert(MmUnmapViewInSystemSpace(retained->source_view)==STATUS_SUCCESS);retained->source_view=NULL;Ax.retained_views=0;AxReleaseScan(retained);retained=NULL;quiet();
    reset();assert(AxUnload(0)==STATUS_FLT_DO_NOT_DETACH&&unload_step==0);
    Ax.armed=0;Ax.pins=(struct AX_PINS*)(uintptr_t)7;assert(AxUnload(0)==STATUS_SUCCESS&&unload_step==5&&!Ax.pins);quiet();
    puts("Windows ordinary-read production controls: passed (mocked kernel effects; no native runtime claim)");
    return 0;
}
