// Include the production owner to exercise request retirement and single-use
// replies without pretending a synthetic connection has authenticated a peer.
#import "../../../../core-engines/macos-network/src/macos/upgrade_listener.m"
#include <stdio.h>
static BOOL checks(void){
    AXUpgradeOwner *o=[AXUpgradeOwner new];o.accepted=YES;o.uid=501;
    NSXPCConnection *c=[[NSXPCConnection alloc] initWithMachServiceName:@"com.example.unused" options:0];o.connection=c;
    NSData *request=[@"{\"type\":\"plan\"}" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *reply=[@"{\"type\":\"refused\"}" dataUsingEncoding:NSUTF8StringEncoding];
    __block NSUInteger calls=0;
    [o receive:request sender:c reply:^(NSData *body){if([body isEqual:reply])calls++;}];
    AXUpgradeIncoming input={0};if(ax_upgrade_poll((__bridge void *)o,0,&input)||input.kind!=1||input.request_token!=1||input.length!=request.length)return NO;
    if(memcmp(input.data,request.bytes,request.length))return NO;ax_upgrade_incoming_free(&input);
    if(![o complete:1 body:reply]||calls!=1||[o complete:1 body:reply])return NO;
    [o receive:request sender:c reply:^(__unused NSData *body){calls++;}];
    [o retireToken:1];if(o.disconnected||o.token!=2||!o.replyBlock)return NO;
    [o retire];if([o complete:2 body:reply]||calls!=1)return NO;
    if(ax_upgrade_poll((__bridge void *)o,0,&input)||input.kind!=2||input.request_token||input.length)return NO;
    ax_upgrade_incoming_free(&input);
    if(ax_upgrade_poll((__bridge void *)o,0,&input)||input.kind)return NO;
    [o receive:request sender:c reply:^(__unused NSData *body){calls++;}];if(o.token||o.replyBlock||calls!=1)return NO;
    AXUpgradeOwner *busy=[AXUpgradeOwner new];busy.accepted=YES;busy.connection=c;
    [busy receive:request sender:c reply:^(__unused NSData *body){calls++;}];
    [busy receive:request sender:c reply:^(__unused NSData *body){calls++;}];
    if(!busy.disconnected||busy.replyBlock||[busy complete:1 body:reply]||calls!=1)return NO;
    AXUpgradeOwner *foreign=[AXUpgradeOwner new];foreign.accepted=YES;foreign.connection=c;
    [foreign receive:request sender:nil reply:^(__unused NSData *body){calls++;}];
    if(!foreign.disconnected||foreign.token||calls!=1)return NO;
    AXUpgradeOwner *large=[AXUpgradeOwner new];large.accepted=YES;large.connection=c;
    [large receive:[NSMutableData dataWithLength:32769] sender:c reply:^(__unused NSData *body){calls++;}];
    if(!large.disconnected||large.token||calls!=1)return NO;
    return YES;
}
int main(void){@autoreleasepool{@try{if(checks()){puts("Network upgrade bridge controls passed; mocked ownership only");return 0;}}
    @catch(__unused NSException *e){}fputs("Network upgrade bridge controls failed\n",stderr);return 1;}}
