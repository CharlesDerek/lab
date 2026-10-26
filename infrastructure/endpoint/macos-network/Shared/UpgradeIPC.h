#import <Foundation/Foundation.h>

// A separate lifecycle channel: bounded JSON bytes only, never flow originals.
// Peer identity comes from the authenticated connection, not the JSON body.
NS_ASSUME_NONNULL_BEGIN
@protocol AXNetworkUpgrade
- (void)request:(NSData *)body reply:(void (^)(NSData *))reply;
@end
NS_ASSUME_NONNULL_END
