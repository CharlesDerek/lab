#import <Foundation/Foundation.h>

#define AX_NETWORK_POLICY "faf8a5d37afe9cdc39b09b3562832b0db72b9c0b03281dd1ce701fc889f1dc64"
NS_ASSUME_NONNULL_BEGIN

// Only primitive scalars and bounded NSData cross this interface. It never
// carries NEFilterFlow, NWEndpoint, NSError or arbitrary object dictionaries.
@protocol AXNetworkProvider
- (void)hello:(uint32_t)version nonce:(NSData *)nonce policy:(NSData *)policy
    reply:(void (^)(NSData *, NSData *))reply;
- (void)pull:(uint64_t)epoch request:(uint64_t)request nonce:(NSData *)nonce
    reply:(void (^)(NSData *, NSData *))reply;
- (void)ack:(uint64_t)epoch request:(uint64_t)request nonce:(NSData *)nonce
    batch:(uint64_t)batch digest:(NSData *)digest reply:(void (^)(NSData *, NSData *))reply;
- (void)detach:(uint64_t)epoch request:(uint64_t)request nonce:(NSData *)nonce
    reply:(void (^)(NSData *, NSData *))reply;
@end
NS_ASSUME_NONNULL_END
