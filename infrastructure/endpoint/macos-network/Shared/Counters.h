#include <stdbool.h>
#include <stdint.h>
typedef struct AXNetworkCounters AXNetworkCounters;
AXNetworkCounters *AXCountersCreate(void);
void AXCountersDestroy(AXNetworkCounters *);
bool AXCountersIncrement(AXNetworkCounters *, unsigned field);
uint64_t AXCountersRead(AXNetworkCounters *, unsigned field);
bool AXCountersOverflowed(AXNetworkCounters *);
