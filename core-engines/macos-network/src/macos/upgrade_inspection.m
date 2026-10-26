#import "upgrade.h"
#import "NetworkIPC.h"
#import <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

// Traverse from a held root descriptor. Every component must be root-owned,
// not a symlink and not replaceable by a less privileged user.
static int AXProtectedDirectory(NSString *path){
    if(![path isKindOfClass:[NSString class]]||![path isAbsolutePath]||path.length>4096
        ||[path rangeOfCharacterFromSet:[NSCharacterSet characterSetWithRange:NSMakeRange(0,1)]].location!=NSNotFound
        ||![path isEqual:path.stringByStandardizingPath])return -1;
    int fd=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)return -1;
    NSString *prefix=@"";
    for(NSString *part in path.pathComponents){
        if([part isEqual:@"/"])continue;
        prefix=[prefix stringByAppendingPathComponent:part];
        int next=openat(fd,part.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(fd);fd=next;struct stat s;
        if(fd<0||fstat(fd,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=0||(s.st_mode&07002)){if(fd>=0)close(fd);return -1;}
        if(s.st_mode&020){
            struct group record,*result=NULL;char buffer[16384];
            if(![prefix isEqual:@"Applications"]||getgrnam_r("admin",&record,buffer,sizeof(buffer),&result)||!result||s.st_gid!=result->gr_gid){close(fd);return -1;}
        }
    }return fd;
}
BOOL AXUpgradeOrdinaryActionsAllowed(void){
    int fd=AXProtectedDirectory(@"/Library/Application Support/AthernexNetwork");if(fd<0)return NO;
    // A marker is denial-only. Its contents cannot grant authority, so every
    // present object (including malformed, symlink or unreadable) refuses.
    int marker=openat(fd,"upgrade-state.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    int error=errno;if(marker>=0)close(marker);close(fd);return marker<0&&error==ENOENT;
}
static NSString *AXFileDigest(NSString *path){
    int parent=AXProtectedDirectory(path.stringByDeletingLastPathComponent);if(parent<0)return nil;
    int fd=openat(parent,path.lastPathComponent.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);close(parent);
    struct stat before,after;if(fd<0)return nil;
    if(fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_uid!=0||(before.st_mode&022)||before.st_nlink!=1
        ||before.st_size<0||before.st_size>64*1024*1024){close(fd);return nil;}
    CC_SHA256_CTX ctx;CC_SHA256_Init(&ctx);uint8_t buffer[16384];off_t total=0;BOOL ok=YES;
    for(;;){ssize_t n=read(fd,buffer,sizeof(buffer));if(n<0&&errno==EINTR)continue;if(n<0){ok=NO;break;}if(n==0)break;
        if(n>before.st_size-total){ok=NO;break;}total+=n;CC_SHA256_Update(&ctx,buffer,(CC_LONG)n);}
    if(fstat(fd,&after)||total!=before.st_size||after.st_dev!=before.st_dev||after.st_ino!=before.st_ino
        ||after.st_size!=before.st_size||after.st_mtimespec.tv_sec!=before.st_mtimespec.tv_sec
        ||after.st_mtimespec.tv_nsec!=before.st_mtimespec.tv_nsec||after.st_ctimespec.tv_sec!=before.st_ctimespec.tv_sec
        ||after.st_ctimespec.tv_nsec!=before.st_ctimespec.tv_nsec)ok=NO;
    close(fd);if(!ok)return nil;uint8_t digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256_Final(digest,&ctx);
    NSMutableString *text=[NSMutableString stringWithCapacity:64];for(NSUInteger n=0;n<sizeof(digest);n++)[text appendFormat:@"%02x",digest[n]];return text;
}
static NSArray *AXCodeHashes(NSDictionary *info){
    NSArray *raw=info[(__bridge NSString *)kSecCodeInfoCdHashes];if(![raw isKindOfClass:[NSArray class]]||raw.count==0||raw.count>4)return nil;
    NSMutableArray *hashes=[NSMutableArray array];for(NSData *d in raw){if(![d isKindOfClass:[NSData class]]||d.length!=20)return nil;
        const uint8_t *p=d.bytes;NSMutableString *s=[NSMutableString stringWithCapacity:40];for(NSUInteger n=0;n<20;n++)[s appendFormat:@"%02x",p[n]];
        if([hashes containsObject:s])return nil;[hashes addObject:s];}[hashes sortUsingSelector:@selector(compare:)];return hashes;
}
static NSDictionary *AXPin(NSString *path,NSDictionary *info){
    NSString *executable=AXFileDigest([path stringByAppendingPathComponent:@"Contents/MacOS/AthernexNetworkProvider"]);
    NSString *plist=AXFileDigest([path stringByAppendingPathComponent:@"Contents/Info.plist"]);
    NSArray *hashes=AXCodeHashes(info);NSDictionary *p=info[(__bridge NSString *)kSecCodeInfoPList];
    if(!executable||!plist||!hashes||![p[@"CFBundleVersion"] isKindOfClass:[NSString class]]||![p[@"CFBundleShortVersionString"] isKindOfClass:[NSString class]])return nil;
    return @{@"executable_sha256":executable,@"info_plist_sha256":plist,@"cdhashes":hashes,
        @"bundle_version":p[@"CFBundleVersion"],@"short_version":p[@"CFBundleShortVersionString"]};
}
BOOL AXUpgradeCurrentContainer(NSDictionary *identity,NSArray<NSString *> *hashes){
    NSString *text=AXNetworkRequirement(identity[@"team_id"],identity[@"container_identifier"],hashes);SecRequirementRef requirement=NULL;
    if(!AXNetworkCompileRequirement(text,&requirement))return NO;
    SecCodeRef current=NULL;BOOL ok=SecCodeCopySelf(kSecCSDefaultFlags,&current)==errSecSuccess&&current
        &&SecCodeCheckValidity(current,kSecCSDefaultFlags,requirement)==errSecSuccess;
    CFRelease(requirement);if(current)CFRelease(current);return ok;
}
BOOL AXUpgradeVerifyProperty(NSDictionary *property,NSDictionary *identity,NSDictionary *pin,BOOL installed){
    @try {
        NSString *path=property[@"url"],*identifier=identity[@"provider_identifier"];
        if(![path isKindOfClass:[NSString class]]||path.length>4096||![path isEqual:path.stringByStandardizingPath]
            ||![path isEqual:path.stringByResolvingSymlinksInPath]||![property[@"bundle_identifier"] isEqual:identifier]
            ||![property[@"bundle_version"] isEqual:pin[@"bundle_version"]]||![property[@"bundle_short_version"] isEqual:pin[@"short_version"]])return NO;
        NSString *leaf=[identifier stringByAppendingString:@".systemextension"];
        NSString *candidate=[@"/Applications/AthernexNetwork.app/Contents/Library/SystemExtensions" stringByAppendingPathComponent:leaf];
        if(installed){if(![path hasPrefix:@"/Library/SystemExtensions/"]||![path.lastPathComponent isEqual:leaf])return NO;}
        else if(![path isEqual:candidate])return NO;
        int directory=AXProtectedDirectory(path);if(directory<0)return NO;close(directory);
        NSDictionary *info=AXVerifyBundle([NSURL fileURLWithPath:path isDirectory:YES],identity[@"team_id"],identifier);
        if(!info||!AXBundleInfo(info,identity,YES)||![AXPin(path,info) isEqual:pin])return NO;
        // Recheck the exact host code requirement as well as all-architecture
        // whole-bundle validity. Versions and URL selectors alone never suffice.
        NSString *text=AXNetworkRequirement(identity[@"team_id"],identifier,pin[@"cdhashes"]);SecRequirementRef r=NULL;
        if(!AXNetworkCompileRequirement(text,&r))return NO;SecStaticCodeRef code=NULL;
        BOOL ok=SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path],kSecCSDefaultFlags,&code)==errSecSuccess
            &&code&&SecStaticCodeCheckValidity(code,kSecCSCheckNestedCode|kSecCSStrictValidate,r)==errSecSuccess;
        CFRelease(r);if(code)CFRelease(code);return ok;
    } @catch(__unused NSException *e){return NO;}
}
int ax_upgrade_inspect(const uint8_t *bytes,size_t length,AXNetworkReply *out){
    @autoreleasepool {@try {
        if(!bytes||!out||!length||length>32768||geteuid()!=0)return 1;memset(out,0,sizeof(*out));
        NSDictionary *m=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:length] options:0 error:NULL];
        NSDictionary *identity=m[@"identity"];NSString *path=m[@"path"];
        if(!AXNetworkCurrentAgent(identity)||![path isKindOfClass:[NSString class]]||![path.lastPathComponent isEqual:@"AthernexNetwork.app"])return 1;
        int directory=AXProtectedDirectory(path);if(directory<0)return 1;close(directory);
        NSString *nested=[path stringByAppendingPathComponent:[NSString stringWithFormat:@"Contents/Library/SystemExtensions/%@.systemextension",identity[@"provider_identifier"]]];
        NSDictionary *c=AXVerifyBundle([NSURL fileURLWithPath:path],identity[@"team_id"],identity[@"container_identifier"]);
        NSDictionary *p=AXVerifyBundle([NSURL fileURLWithPath:nested],identity[@"team_id"],identity[@"provider_identifier"]);
        if(!c||!p||!AXBundleInfo(c,identity,NO)||!AXBundleInfo(p,identity,YES))return 1;
        NSArray *hashes=AXCodeHashes(c);NSDictionary *pin=AXPin(nested,p);if(!hashes||!pin)return 1;
        NSData *data=[NSJSONSerialization dataWithJSONObject:@{@"container_cdhashes":hashes,@"provider":pin} options:NSJSONWritingSortedKeys error:NULL];
        if(!data||data.length>32768)return 1;out->control=malloc(data.length);if(!out->control)return 1;
        memcpy(out->control,data.bytes,data.length);out->control_len=data.length;return 0;
    } @catch(__unused NSException *e){return 1;}}
}
int ax_upgrade_inspect_property(const uint8_t *bytes,size_t length){
    @autoreleasepool {@try {if(!bytes||!length||length>32768||geteuid()!=0)return 1;
        NSDictionary *m=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes length:length] options:0 error:NULL];
        return AXNetworkCurrentAgent(m[@"identity"])&&AXUpgradeVerifyProperty(m[@"property"],m[@"identity"],m[@"pin"],YES)?0:1;
    } @catch(__unused NSException *e){return 1;}}
}
