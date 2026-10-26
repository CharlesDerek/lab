#import "bridge.h"
#import "UpgradeIPC.h"

typedef struct {
    uint8_t *data;
    size_t length;
    uint64_t connection_generation;
    uint64_t request_token;
    uint32_t peer_euid;
    uint32_t kind; // 1=request, 2=disconnect; zero means no event
} AXUpgradeIncoming;
void *ax_upgrade_start(const uint8_t *, size_t);
int ax_upgrade_poll(void *, uint32_t, AXUpgradeIncoming *);
int ax_upgrade_reply(void *, uint64_t, const uint8_t *, size_t);
void ax_upgrade_incoming_free(AXUpgradeIncoming *);
void ax_upgrade_close(void *);
int ax_upgrade_inspect(const uint8_t *, size_t, AXNetworkReply *);
int ax_upgrade_inspect_property(const uint8_t *, size_t);

NSDictionary *AXVerifyBundle(NSURL *, NSString *, NSString *);
BOOL AXBundleInfo(NSDictionary *, NSDictionary *, BOOL);
BOOL AXUpgradeCurrentContainer(NSDictionary *, NSArray<NSString *> *);
BOOL AXUpgradeVerifyProperty(NSDictionary *, NSDictionary *, NSDictionary *, BOOL);
BOOL AXUpgradeOrdinaryActionsAllowed(void);
