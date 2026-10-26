#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t *control;
    size_t control_len;
    uint8_t *batch;
    size_t batch_len;
} AXNetworkReply;

void *ax_network_connect(const uint8_t *, size_t, AXNetworkReply *);
int ax_network_exchange(void *, uint32_t, uint64_t, uint64_t, uint64_t,
                        const uint8_t *, size_t, AXNetworkReply *);
void ax_network_invalidate(void *);
void ax_network_release(void *);
void ax_network_reply_free(AXNetworkReply *);
int ax_network_inspect(const uint8_t *, size_t, AXNetworkReply *);
BOOL AXNetworkCurrentAgent(NSDictionary *);
NSString *AXNetworkRequirement(NSString *, NSString *, NSArray<NSString *> *);
BOOL AXNetworkCompileRequirement(NSString *, SecRequirementRef *);
BOOL AXNetworkHex(NSString *, NSUInteger);
NSData *AXNetworkUnhex(NSString *);
