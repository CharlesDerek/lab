#import "bridge.h"
#import "NetworkIPC.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const NSUInteger AXControlLimit=4096, AXFrameLimit=1048576;
static atomic_bool AXConnecting=false;

@interface AXNetworkAttempt : NSObject
@property(nonatomic,strong) NSLock *lock;
@property(nonatomic,strong) dispatch_semaphore_t signal;
@property(nonatomic) BOOL finished;
@property(nonatomic) BOOL success;
@property(nonatomic,strong) NSData *control;
@property(nonatomic,strong) NSData *batch;
- (void)finish:(NSData *)control batch:(NSData *)batch;
- (BOOL)wait;
@end
@implementation AXNetworkAttempt
- (instancetype)init { if((self=[super init])){_lock=[NSLock new];_signal=dispatch_semaphore_create(0);}return self; }
- (void)finish:(NSData *)control batch:(NSData *)batch {
    BOOL valid=[control isKindOfClass:[NSData class]] && [batch isKindOfClass:[NSData class]]
        && control.length<=AXControlLimit && batch.length<=AXFrameLimit-control.length;
    [_lock lock];
    if(!_finished){_finished=YES;_success=valid;if(valid){_control=[control copy];_batch=[batch copy];}dispatch_semaphore_signal(_signal);}
    [_lock unlock];
}
- (BOOL)wait {
    long rc=dispatch_semaphore_wait(_signal,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC));
    [_lock lock];BOOL ok=rc==0&&_finished&&_success;
    if(!ok){_finished=YES;_success=NO;_control=nil;_batch=nil;}
    [_lock unlock];return ok;
}
@end

@interface AXNetworkOwner : NSObject
@property(nonatomic,strong) NSLock *lock;
@property(nonatomic,strong) NSXPCConnection *connection;
@property(nonatomic,strong) NSData *nonce;
@property(nonatomic) BOOL failed;
- (void)invalidate;
@end
@implementation AXNetworkOwner
- (instancetype)init {if((self=[super init])){_lock=[NSLock new];}return self;}
- (void)invalidate {[_lock lock];_failed=YES;NSXPCConnection *c=_connection;_connection=nil;[_lock unlock];[c invalidate];}
@end

BOOL AXNetworkHex(NSString *s,NSUInteger length){
    if(![s isKindOfClass:[NSString class]]||s.length!=length)return NO;
    for(NSUInteger i=0;i<length;i++){unichar c=[s characterAtIndex:i];if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return NO;}
    return YES;
}
NSData *AXNetworkUnhex(NSString *s){
    if(!AXNetworkHex(s,s.length)||(s.length&1)||s.length>64)return nil;
    uint8_t data[32];for(NSUInteger i=0;i<s.length;i+=2){unichar a=[s characterAtIndex:i],b=[s characterAtIndex:i+1];
        data[i/2]=(uint8_t)(((a<='9'?a-'0':a-'a'+10)<<4)|(b<='9'?b-'0':b-'a'+10));}
    return [NSData dataWithBytes:data length:s.length/2];
}
static BOOL AXIdentifier(NSString *s){
    if(![s isKindOfClass:[NSString class]]||s.length==0||s.length>255||[s rangeOfString:@"."].location==NSNotFound)return NO;
    for(NSString *part in [s componentsSeparatedByString:@"."]){if(part.length==0||part.length>63)return NO;
        for(NSUInteger i=0;i<part.length;i++){unichar c=[part characterAtIndex:i];
            if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'))return NO;}}
    return YES;
}
NSString *AXNetworkRequirement(NSString *team,NSString *identifier,NSArray<NSString *> *hashes){
    if(![team isKindOfClass:[NSString class]]||team.length!=10||!AXIdentifier(identifier))return nil;
    for(NSUInteger i=0;i<team.length;i++){unichar c=[team characterAtIndex:i];if(!((c>='A'&&c<='Z')||(c>='0'&&c<='9')))return nil;}
    NSMutableString *r=[NSMutableString stringWithFormat:@"anchor apple generic and certificate leaf[subject.OU] = \"%@\" and identifier \"%@\"",team,identifier];
    if(hashes){if(![hashes isKindOfClass:[NSArray class]]||hashes.count==0||hashes.count>4)return nil;
        NSMutableArray *terms=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
        for(NSString *h in hashes){if(!AXNetworkHex(h,40)||[seen containsObject:h])return nil;[seen addObject:h];
            [terms addObject:[NSString stringWithFormat:@"cdhash H\"%@\"",h]];}
        [r appendFormat:@" and (%@)",[terms componentsJoinedByString:@" or "]];}
    return r;
}
BOOL AXNetworkCompileRequirement(NSString *text,SecRequirementRef *out){
    if(!text||text.length>2048)return NO;*out=NULL;
    OSStatus s=SecRequirementCreateWithString((__bridge CFStringRef)text,kSecCSDefaultFlags,out);
    if(s!=errSecSuccess||!*out){if(*out){CFRelease(*out);*out=NULL;}return NO;}return YES;
}
static NSXPCInterface *AXInterface(void){
    NSXPCInterface *i=[NSXPCInterface interfaceWithProtocol:@protocol(AXNetworkProvider)];
    NSSet *data=[NSSet setWithObject:[NSData class]];
    SEL methods[]={@selector(hello:nonce:policy:reply:),@selector(pull:request:nonce:reply:),
        @selector(ack:request:nonce:batch:digest:reply:),@selector(detach:request:nonce:reply:)};
    for(NSUInteger n=0;n<4;n++){[i setClasses:data forSelector:methods[n] argumentIndex:0 ofReply:YES];
        [i setClasses:data forSelector:methods[n] argumentIndex:1 ofReply:YES];}
    [i setClasses:data forSelector:methods[0] argumentIndex:1 ofReply:NO];
    [i setClasses:data forSelector:methods[0] argumentIndex:2 ofReply:NO];
    for(NSUInteger n=1;n<4;n++)[i setClasses:data forSelector:methods[n] argumentIndex:2 ofReply:NO];
    [i setClasses:data forSelector:methods[2] argumentIndex:4 ofReply:NO];return i;
}
static BOOL AXCopyReply(AXNetworkAttempt *attempt,AXNetworkReply *out){
    if(!out)return NO;memset(out,0,sizeof(*out));
    NSData *c=attempt.control,*b=attempt.batch;
    if(!c||!b||c.length>AXControlLimit||b.length>AXFrameLimit-c.length)return NO;
    if(c.length){out->control=malloc(c.length);if(!out->control)return NO;memcpy(out->control,c.bytes,c.length);out->control_len=c.length;}
    if(b.length){out->batch=malloc(b.length);if(!out->batch){ax_network_reply_free(out);return NO;}memcpy(out->batch,b.bytes,b.length);out->batch_len=b.length;}
    return YES;
}
void ax_network_reply_free(AXNetworkReply *out){if(out){free(out->control);free(out->batch);memset(out,0,sizeof(*out));}}

void *ax_network_connect(const uint8_t *bytes,size_t length,AXNetworkReply *out){
    @autoreleasepool {
        if(!out||!bytes||length>8192||geteuid()!=0)return NULL;memset(out,0,sizeof(*out));
        if(@available(macOS 13.0,*)){}else{return NULL;}
        bool expected=false;if(!atomic_compare_exchange_strong(&AXConnecting,&expected,true))return NULL;
        NSData *input=[NSData dataWithBytes:bytes length:length];
        AXNetworkOwner *owner=[AXNetworkOwner new];AXNetworkAttempt *attempt=[AXNetworkAttempt new];
        // Security validation may itself block in the OS. One global startup
        // lease bounds our retained work; the caller's wait still expires. A
        // late worker cannot publish a connection after owner invalidation.
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
            @autoreleasepool {@try {
                NSDictionary *message=[NSJSONSerialization JSONObjectWithData:input options:0 error:NULL];
                if(![message isKindOfClass:[NSDictionary class]])@throw [NSException exceptionWithName:@"refused" reason:nil userInfo:nil];
                NSDictionary *config=message[@"config"];NSString *nonce=message[@"nonce"];
                if(![config isKindOfClass:[NSDictionary class]]||!AXNetworkHex(nonce,64)
                    ||!AXIdentifier(config[@"mach_service_name"])||!AXIdentifier(config[@"app_group"])
                    ||![config[@"mach_service_name"] hasPrefix:[config[@"app_group"] stringByAppendingString:@"."]]
                    ||!AXNetworkHex(config[@"source_policy_sha256"],64)||!AXNetworkCurrentAgent(config))
                    @throw [NSException exceptionWithName:@"refused" reason:nil userInfo:nil];
                NSString *requirement=AXNetworkRequirement(config[@"team_id"],config[@"provider_identifier"],config[@"provider_cdhashes"]);
                SecRequirementRef compiled=NULL;if(!AXNetworkCompileRequirement(requirement,&compiled))@throw [NSException exceptionWithName:@"refused" reason:nil userInfo:nil];
                CFRelease(compiled);
                NSXPCConnection *c=[[NSXPCConnection alloc] initWithMachServiceName:config[@"mach_service_name"] options:0];
                c.remoteObjectInterface=AXInterface();
                if(@available(macOS 13.0,*)){[c setCodeSigningRequirement:requirement];}else{@throw [NSException exceptionWithName:@"refused" reason:nil userInfo:nil];}
                __weak AXNetworkOwner *weak=owner;
                c.invalidationHandler=^{dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
                    AXNetworkOwner *o=weak;[o.lock lock];o.failed=YES;[o.lock unlock];});};
                c.interruptionHandler=^{[weak invalidate];};
                [owner.lock lock];BOOL cancelled=owner.failed;
                // Serialize publication/resume with timeout retirement. The
                // invalidation handler defers its own lock acquisition.
                @try {if(!cancelled){owner.connection=c;owner.nonce=AXNetworkUnhex(nonce);[c resume];}}
                @finally {[owner.lock unlock];}
                if(cancelled){[c invalidate];@throw [NSException exceptionWithName:@"refused" reason:nil userInfo:nil];}
                id<AXNetworkProvider> proxy=[c remoteObjectProxyWithErrorHandler:^(__unused NSError *e){[attempt finish:nil batch:nil];[weak invalidate];}];
                [proxy hello:1 nonce:owner.nonce policy:AXNetworkUnhex(config[@"source_policy_sha256"])
                    reply:^(NSData *control,NSData *batch){[attempt finish:control batch:batch];}];
            } @catch(__unused NSException *e){[owner invalidate];[attempt finish:nil batch:nil];}}
            atomic_store(&AXConnecting,false);
        });
        if(![attempt wait]||!AXCopyReply(attempt,out)){[owner invalidate];return NULL;}
        [owner.lock lock];BOOL failed=owner.failed;[owner.lock unlock];if(failed){ax_network_reply_free(out);return NULL;}
        return (__bridge_retained void *)owner;
    }
}
int ax_network_exchange(void *handle,uint32_t op,uint64_t epoch,uint64_t request,uint64_t batch,
    const uint8_t *digest,size_t digest_len,AXNetworkReply *out){
    @autoreleasepool {@try {
        if(!handle||!out||op<1||op>3||!epoch||!request||digest_len>64)return 1;
        memset(out,0,sizeof(*out));AXNetworkOwner *owner=(__bridge AXNetworkOwner *)handle;
        [owner.lock lock];NSXPCConnection *c=owner.connection;BOOL failed=owner.failed;[owner.lock unlock];if(!c||failed)return 1;
        AXNetworkAttempt *attempt=[AXNetworkAttempt new];
        id<AXNetworkProvider> proxy=[c remoteObjectProxyWithErrorHandler:^(__unused NSError *e){[attempt finish:nil batch:nil];}];
        void (^reply)(NSData *,NSData *)=^(NSData *control,NSData *body){[attempt finish:control batch:body];};
        if(op==1)[proxy pull:epoch request:request nonce:owner.nonce reply:reply];
        else if(op==3)[proxy detach:epoch request:request nonce:owner.nonce reply:reply];
        else {NSString *hex=digest?[[NSString alloc] initWithBytes:digest length:digest_len encoding:NSASCIIStringEncoding]:nil;
            if(!batch||!AXNetworkHex(hex,64)){[owner invalidate];return 1;}
            [proxy ack:epoch request:request nonce:owner.nonce batch:batch digest:AXNetworkUnhex(hex) reply:reply];}
        if(![attempt wait]||!AXCopyReply(attempt,out)){[owner invalidate];return 1;}return 0;
    } @catch(__unused NSException *e){if(handle)[(__bridge AXNetworkOwner *)handle invalidate];return 1;}}
}
void ax_network_invalidate(void *handle){@autoreleasepool{if(handle)[(__bridge AXNetworkOwner *)handle invalidate];}}
void ax_network_release(void *handle){@autoreleasepool{if(handle){AXNetworkOwner *owner=CFBridgingRelease(handle);[owner invalidate];}}}
