#import "bridge.h"
#include <stdio.h>
#include <string.h>

static BOOL checks(void){
    NSString *good=AXNetworkRequirement(@"TESTTEAM00",@"com.example.agent",@[@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]);
    SecRequirementRef r=NULL;if(!AXNetworkCompileRequirement(good,&r)||!r)return NO;CFRelease(r);
    if(AXNetworkRequirement(@"TESTTEAM00",@"com.example.agent\" or true",nil))return NO;
    if(AXNetworkRequirement(@"TESTTEAM00",@"com..agent",nil))return NO;
    if(AXNetworkRequirement(@"TESTTEAM00",@"com.example.agent",@[@"short"]))return NO;
    if(AXNetworkRequirement(@"TESTTEAM00",@"com.example.agent",@[@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",@"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]))return NO;
    if(AXNetworkCompileRequirement(@"not a requirement",&r))return NO;
    if(![AXNetworkUnhex(@"0011aa") isEqual:[NSData dataWithBytes:(uint8_t[]){0,17,170} length:3]])return NO;
    AXNetworkReply out={0};if(ax_network_exchange(NULL,1,1,1,0,NULL,0,&out)==0)return NO;
    ax_network_reply_free(&out);if(out.control||out.batch||out.control_len||out.batch_len)return NO;
    return YES;
}
int main(void){@autoreleasepool{@try{if(checks()){puts("Network bridge controls passed; no live peer authentication proof");return 0;}}
    @catch(__unused NSException *e){}fputs("Network bridge controls failed\n",stderr);return 1;}}
