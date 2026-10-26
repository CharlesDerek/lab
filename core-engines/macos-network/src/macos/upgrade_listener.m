#import "upgrade.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const NSUInteger AXUpgradeLimit=32768;
static NSXPCInterface *AXUpgradeInterface(void){
    NSXPCInterface *i=[NSXPCInterface interfaceWithProtocol:@protocol(AXNetworkUpgrade)];
    NSSet *data=[NSSet setWithObject:[NSData class]];
    [i setClasses:data forSelector:@selector(request:reply:) argumentIndex:0 ofReply:NO];
    [i setClasses:data forSelector:@selector(request:reply:) argumentIndex:0 ofReply:YES];return i;
}
@interface AXUpgradeOwner : NSObject <NSXPCListenerDelegate,AXNetworkUpgrade>
@property(nonatomic,strong) NSCondition *condition;
@property(nonatomic,strong) dispatch_semaphore_t signal;
@property(nonatomic,strong) dispatch_source_t timer;
@property(nonatomic,strong) NSXPCListener *listener;
@property(nonatomic,strong) NSXPCConnection *connection;
@property(nonatomic,copy) NSString *requirement;
@property(nonatomic) uint32_t uid;
@property(nonatomic) BOOL accepted;
@property(nonatomic) BOOL closed;
@property(nonatomic) BOOL disconnected;
@property(nonatomic) BOOL disconnectDelivered;
@property(nonatomic) uint64_t nextToken;
@property(nonatomic) uint64_t token;
@property(nonatomic,strong) NSData *body;
@property(nonatomic,copy) void (^replyBlock)(NSData *);
- (void)retire;
- (void)retireToken:(uint64_t)token;
- (BOOL)complete:(uint64_t)token body:(NSData *)body;
- (void)receive:(NSData *)body sender:(NSXPCConnection *)sender reply:(void (^)(NSData *))reply;
@end
@implementation AXUpgradeOwner
- (instancetype)init {if((self=[super init])){_condition=[NSCondition new];_signal=dispatch_semaphore_create(0);}return self;}
- (void)retire { [self retireToken:0]; }
- (void)retireToken:(uint64_t)token {
    [_condition lock];
    if(token&&(_token!=token||!_replyBlock)){[_condition unlock];return;}
    _disconnected=YES;_body=nil;_replyBlock=nil;_token=0;
    if(_timer){dispatch_source_cancel(_timer);_timer=nil;}
    NSXPCConnection *c=_connection;_connection=nil;dispatch_semaphore_signal(_signal);[_condition unlock];[c invalidate];
}
- (BOOL)listener:(NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)c {
    if(@available(macOS 13.0,*)){
    [_condition lock];BOOL ok=NO;
    @try {
        if(listener==_listener&&!_closed&&!_accepted&&c.effectiveUserIdentifier==_uid){
            // Never reopen this incarnation after owner loss. A fresh broker
            // must obtain its own journal decision, not reattach by PID.
            _accepted=YES;_connection=c;
            [c setCodeSigningRequirement:_requirement];c.exportedInterface=AXUpgradeInterface();c.exportedObject=self;
            __weak AXUpgradeOwner *weak=self;
            c.invalidationHandler=^{dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{[weak retire];});};
            c.interruptionHandler=^{dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{[weak retire];});};
            [c resume];ok=YES;
        }
    } @catch(__unused NSException *e){_disconnected=YES;_connection=nil;}
    [_condition unlock];if(!ok)[c invalidate];return ok;
    }else{return NO;}
}
- (void)request:(NSData *)body reply:(void (^)(NSData *))reply {
    [self receive:body sender:NSXPCConnection.currentConnection reply:reply];
}
- (void)receive:(NSData *)body sender:(NSXPCConnection *)sender reply:(void (^)(NSData *))reply {
    [_condition lock];BOOL valid=!_closed&&!_disconnected&&_accepted&&sender==_connection
        &&!_replyBlock&&[body isKindOfClass:[NSData class]]&&body.length>0&&body.length<=AXUpgradeLimit&&_nextToken<UINT64_MAX;
    uint64_t token=0;
    if(valid){token=++_nextToken;_token=token;_body=[body copy];_replyBlock=[reply copy];
        _timer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_global_queue(QOS_CLASS_UTILITY,0));
        __weak AXUpgradeOwner *weak=self;
        dispatch_source_set_timer(_timer,dispatch_time(DISPATCH_TIME_NOW,5*NSEC_PER_SEC),DISPATCH_TIME_FOREVER,0);
        dispatch_source_set_event_handler(_timer,^{[weak retireToken:token];});
        dispatch_resume(_timer);dispatch_semaphore_signal(_signal);}
    [_condition unlock];
    if(!valid){[self retire];return;}
    // At most one retained request. Timeout retires the entire owner; a late
    // durable reply cannot silently create another permit or reconnect.
}
- (BOOL)complete:(uint64_t)token body:(NSData *)body {
    [_condition lock];BOOL ok=!_closed&&!_disconnected&&_token==token&&_replyBlock&&body.length>0&&body.length<=AXUpgradeLimit;
    void (^reply)(NSData *)=ok?_replyBlock:nil;
    if(ok){_replyBlock=nil;_token=0;_body=nil;if(_timer){dispatch_source_cancel(_timer);_timer=nil;}}[_condition unlock];
    // The journal was persisted by Rust before this call. Losing this reply is
    // still uncertain to the GUI; it never retries a Claim.
    if(reply)reply(body);return ok;
}
@end

void *ax_upgrade_start(const uint8_t *bytes,size_t length){
    @autoreleasepool {@try {
        if(!bytes||length==0||length>AXUpgradeLimit||geteuid()!=0)return NULL;
        if(@available(macOS 13.0,*)){}else{return NULL;}
        NSDictionary *config=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:length] options:0 error:NULL];
        if(![config isKindOfClass:[NSDictionary class]]||!AXNetworkCurrentAgent(config[@"identity"]))return NULL;
        NSDictionary *identity=config[@"identity"];NSString *service=[identity[@"app_group"] stringByAppendingString:@".network-upgrade"];
        NSString *requirement=AXNetworkRequirement(identity[@"team_id"],identity[@"container_identifier"],config[@"container_cdhashes"]);
        SecRequirementRef compiled=NULL;if(service.length>=128||!AXNetworkCompileRequirement(requirement,&compiled))return NULL;CFRelease(compiled);
        AXUpgradeOwner *owner=[AXUpgradeOwner new];owner.uid=[config[@"operator_uid"] unsignedIntValue];owner.requirement=requirement;
        owner.listener=[[NSXPCListener alloc] initWithMachServiceName:service];owner.listener.delegate=owner;
        if(@available(macOS 13.0,*)){[owner.listener setConnectionCodeSigningRequirement:requirement];}
        [owner.listener resume];return (__bridge_retained void *)owner;
    } @catch(__unused NSException *e){return NULL;}}
}
int ax_upgrade_poll(void *handle,uint32_t timeout_ms,AXUpgradeIncoming *out){
    @autoreleasepool {@try {
        if(!handle||!out||timeout_ms>5000)return 1;memset(out,0,sizeof(*out));AXUpgradeOwner *o=(__bridge AXUpgradeOwner *)handle;
        [o.condition lock];BOOL ready=o.body||o.disconnected||o.closed;[o.condition unlock];
        if(ready)dispatch_semaphore_wait(o.signal,DISPATCH_TIME_NOW);
        else if(timeout_ms)dispatch_semaphore_wait(o.signal,dispatch_time(DISPATCH_TIME_NOW,(int64_t)timeout_ms*NSEC_PER_MSEC));
        [o.condition lock];@try {
            if(o.closed)return 1;
            out->peer_euid=o.uid;out->connection_generation=o.accepted?1:0;
            if(o.disconnected&&!o.disconnectDelivered){o.disconnectDelivered=YES;out->kind=2;return 0;}
            if(o.body){out->data=malloc(o.body.length);if(!out->data)return 1;
                memcpy(out->data,o.body.bytes,o.body.length);out->length=o.body.length;out->kind=1;out->request_token=o.token;o.body=nil;}
            return 0;
        } @finally {[o.condition unlock];}
    } @catch(__unused NSException *e){return 1;}}
}
int ax_upgrade_reply(void *handle,uint64_t token,const uint8_t *bytes,size_t length){
    @autoreleasepool {@try {if(!handle||!token||!bytes||!length||length>AXUpgradeLimit)return 1;
        return [(__bridge AXUpgradeOwner *)handle complete:token body:[NSData dataWithBytes:bytes length:length]]?0:1;
    } @catch(__unused NSException *e){return 1;}}
}
void ax_upgrade_incoming_free(AXUpgradeIncoming *out){if(out){free(out->data);memset(out,0,sizeof(*out));}}
void ax_upgrade_close(void *handle){@autoreleasepool {if(handle){AXUpgradeOwner *o=CFBridgingRelease(handle);
    [o.condition lock];o.closed=YES;dispatch_semaphore_signal(o.signal);[o.condition unlock];[o.listener invalidate];[o retire];}}}
