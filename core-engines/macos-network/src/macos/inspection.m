#import "bridge.h"
#import "NetworkIPC.h"
#import <Security/SecTask.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static BOOL AXHasGroup(NSDictionary *entitlements,NSString *group){
    if(![entitlements isKindOfClass:[NSDictionary class]])return NO;
    NSArray *groups=entitlements[@"com.apple.security.application-groups"];
    if(![groups isKindOfClass:[NSArray class]]||groups.count>16)return NO;
    for(id value in groups)if(![value isKindOfClass:[NSString class]]||[value length]>255)return NO;
    return [groups containsObject:group];
}
static NSDictionary *AXSigningInfo(SecStaticCodeRef code){
    CFDictionaryRef raw=NULL;
    if(SecCodeCopySigningInformation(code,kSecCSSigningInformation,&raw)!=errSecSuccess||!raw){if(raw)CFRelease(raw);return nil;}
    return CFBridgingRelease(raw);
}
BOOL AXNetworkCurrentAgent(NSDictionary *identity){
    if(geteuid()!=0)return NO;
    NSString *r=AXNetworkRequirement(identity[@"team_id"],identity[@"agent_identifier"],nil);
    SecRequirementRef requirement=NULL;if(!AXNetworkCompileRequirement(r,&requirement))return NO;
    SecCodeRef current=NULL;OSStatus s=SecCodeCopySelf(kSecCSDefaultFlags,&current);
    BOOL valid=s==errSecSuccess&&current&&SecCodeCheckValidity(current,kSecCSDefaultFlags,requirement)==errSecSuccess;
    CFRelease(requirement);if(current)CFRelease(current);if(!valid)return NO;
    // Read the running process's own entitlement, not a PID lookup or a later
    // replacement executable's plist. The task never leaves this call.
    SecTaskRef task=SecTaskCreateFromSelf(kCFAllocatorDefault);if(!task)return NO;
    CFTypeRef raw=SecTaskCopyValueForEntitlement(task,CFSTR("com.apple.security.application-groups"),NULL);
    CFRelease(task);id groups=raw?CFBridgingRelease(raw):nil;
    return AXHasGroup(groups?@{@"com.apple.security.application-groups":groups}:@{},identity[@"app_group"]);
}
NSDictionary *AXVerifyBundle(NSURL *url,NSString *team,NSString *identifier){
    NSString *text=AXNetworkRequirement(team,identifier,nil);SecRequirementRef requirement=NULL;
    if(!AXNetworkCompileRequirement(text,&requirement))return nil;
    SecStaticCodeRef code=NULL;OSStatus s=SecStaticCodeCreateWithPath((__bridge CFURLRef)url,kSecCSDefaultFlags,&code);
    BOOL good=s==errSecSuccess&&code&&SecStaticCodeCheckValidity(code,
        kSecCSCheckAllArchitectures|kSecCSCheckNestedCode|kSecCSStrictValidate,requirement)==errSecSuccess;
    CFRelease(requirement);NSDictionary *info=good?AXSigningInfo(code):nil;if(code)CFRelease(code);
    if(![info[(__bridge NSString *)kSecCodeInfoIdentifier] isEqual:identifier]
        ||![info[(__bridge NSString *)kSecCodeInfoTeamIdentifier] isEqual:team])return nil;
    return info;
}
BOOL AXBundleInfo(NSDictionary *info,NSDictionary *identity,BOOL provider){
    NSDictionary *plist=info[(__bridge NSString *)kSecCodeInfoPList];
    NSDictionary *entitlements=info[(__bridge NSString *)kSecCodeInfoEntitlementsDict];
    if(![plist isKindOfClass:[NSDictionary class]]||!AXHasGroup(entitlements,identity[@"app_group"])
        ||entitlements[@"com.apple.security.app-sandbox"]!=(__bridge id)kCFBooleanTrue)return NO;
    NSArray *kinds=entitlements[@"com.apple.developer.networking.networkextension"];
    if(![kinds isKindOfClass:[NSArray class]]||kinds.count!=1||![kinds[0] isEqual:@"content-filter-provider-systemextension"])return NO;
    NSString *identifier=identity[provider?@"provider_identifier":@"container_identifier"];
    if(![plist[@"CFBundleIdentifier"] isEqual:identifier]
        ||![plist[@"CFBundleExecutable"] isEqual:provider?@"AthernexNetworkProvider":@"AthernexNetwork"]
        ||![plist[@"LSMinimumSystemVersion"] isEqual:@"13.0"]
        ||![plist[@"AXNetworkIdentity"] isEqual:identity]
        ||![plist[@"AXNetworkPolicy"] isEqual:@AX_NETWORK_POLICY])return NO;
    if(provider){
        NSDictionary *ne=plist[@"NetworkExtension"];if(![ne isKindOfClass:[NSDictionary class]]||ne.count!=2
            ||![ne[@"NEMachServiceName"] isEqual:identity[@"mach_service_name"]])return NO;
        NSDictionary *classes=ne[@"NEProviderClasses"];
        if(![classes isKindOfClass:[NSDictionary class]]||classes.count!=1
            ||![classes[@"com.apple.networkextension.filter-data"] isEqual:@"AthernexNetworkProvider.NetworkProvider"])return NO;
    }else if(entitlements[@"com.apple.developer.system-extension.install"]!=(__bridge id)kCFBooleanTrue)return NO;
    return YES;
}
static NSData *AXInspect(NSData *input){
    NSDictionary *message=[NSJSONSerialization JSONObjectWithData:input options:0 error:NULL];
    if(![message isKindOfClass:[NSDictionary class]])return nil;
    NSDictionary *identity=message[@"identity"];NSString *path=message[@"path"];
    if(![identity isKindOfClass:[NSDictionary class]]||![path isKindOfClass:[NSString class]]||path.length>4096
        ||![path isAbsolutePath]||![path.lastPathComponent isEqual:@"AthernexNetwork.app"]
        ||![path isEqual:path.stringByStandardizingPath]||![path isEqual:path.stringByResolvingSymlinksInPath]
        ||!AXNetworkCurrentAgent(identity))return nil;
    NSString *providerID=identity[@"provider_identifier"];
    if(!AXNetworkRequirement(identity[@"team_id"],providerID,nil))return nil;
    NSString *nested=[path stringByAppendingPathComponent:[NSString stringWithFormat:@"Contents/Library/SystemExtensions/%@.systemextension",providerID]];
    NSURL *container=[NSURL fileURLWithPath:path isDirectory:YES],*provider=[NSURL fileURLWithPath:nested isDirectory:YES];
    NSDictionary *c=AXVerifyBundle(container,identity[@"team_id"],identity[@"container_identifier"]);
    NSDictionary *p=AXVerifyBundle(provider,identity[@"team_id"],providerID);
    if(!c||!p||!AXBundleInfo(c,identity,NO)||!AXBundleInfo(p,identity,YES))return nil;
    // The API enumerates digest algorithms for the host-selected architecture.
    // Validation above checked all slices; this is not an all-architecture list.
    NSArray *hashes=p[(__bridge NSString *)kSecCodeInfoCdHashes];
    if(![hashes isKindOfClass:[NSArray class]]||hashes.count==0||hashes.count>4)return nil;
    NSMutableArray *encoded=[NSMutableArray array];
    for(NSData *h in hashes){if(![h isKindOfClass:[NSData class]]||h.length!=20)return nil;
        const uint8_t *b=h.bytes;NSMutableString *s=[NSMutableString stringWithCapacity:40];
        for(NSUInteger n=0;n<20;n++)[s appendFormat:@"%02x",b[n]];
        if(![encoded containsObject:s])[encoded addObject:s];}
    [encoded sortUsingSelector:@selector(compare:)];
    NSData *reply=[NSJSONSerialization dataWithJSONObject:@{@"identity":identity,@"provider_cdhashes":encoded} options:NSJSONWritingSortedKeys error:NULL];
    return reply.length<=4096?reply:nil;
}
int ax_network_inspect(const uint8_t *bytes,size_t length,AXNetworkReply *out){
    @autoreleasepool {@try {
        if(!out||!bytes||length>8192||geteuid()!=0)return 1;memset(out,0,sizeof(*out));
        if(@available(macOS 13.0,*)){}else{return 1;}
        // Inspection is a maintenance operation, not the callback or bounded
        // XPC exchange. Security may wait on native services. The Rust caller
        // separately requires the bounded system Gatekeeper assessment command.
        NSData *reply=AXInspect([NSData dataWithBytes:bytes length:length]);if(!reply)return 1;
        out->control=malloc(reply.length);if(!out->control)return 1;
        memcpy(out->control,reply.bytes,reply.length);out->control_len=reply.length;return 0;
    } @catch(__unused NSException *e){return 1;}}
}
