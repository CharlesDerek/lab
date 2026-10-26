#include "Counters.h"
#include <stdatomic.h>
#include <stdlib.h>
struct AXNetworkCounters { _Atomic uint64_t fields[6]; _Atomic bool overflowed; };
AXNetworkCounters *AXCountersCreate(void){
    AXNetworkCounters *p=malloc(sizeof(*p));if(!p)return NULL;
    for(unsigned n=0;n<6;n++)atomic_init(&p->fields[n],0);
    atomic_init(&p->overflowed,false);return p;
}
void AXCountersDestroy(AXNetworkCounters *p){free(p);}
bool AXCountersIncrement(AXNetworkCounters *p,unsigned field){
    if(!p||field>=6)return false;
    uint64_t old=atomic_load(&p->fields[field]);
    for(;;){if(old==UINT64_MAX){atomic_store(&p->overflowed,true);return false;}
        if(atomic_compare_exchange_weak(&p->fields[field],&old,old+1))return true;}
}
uint64_t AXCountersRead(AXNetworkCounters *p,unsigned field){return p&&field<6?atomic_load(&p->fields[field]):0;}
bool AXCountersOverflowed(AXNetworkCounters *p){return !p||atomic_load(&p->overflowed);}
