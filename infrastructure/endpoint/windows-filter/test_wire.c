/* Executes the actual kernel-side validators with sanitizers on a portable host. */
#include "wire.h"
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
_Static_assert(sizeof(AX_HEADER) == 16, "header ABI");
_Static_assert(sizeof(AX_ROOT) == 2052, "root ABI");
_Static_assert(sizeof(AX_CONFIG) == 32888, "policy ABI");
_Static_assert(sizeof(AX_NOTIFICATION) == 2152, "notification ABI");
_Static_assert(sizeof(AX_REPLY) == 304, "reply ABI");
_Static_assert(sizeof(AX_MAP_REQUEST) == 24, "map request ABI");
_Static_assert(sizeof(AX_MAPPING) == 32, "mapping ABI");
_Static_assert(sizeof(AX_STATUS) == 96, "status ABI");
_Static_assert(offsetof(AX_STATUS, instance) == 48, "driver instance offset");
_Static_assert(offsetof(AX_STATUS, policy_sha256) == 64, "status policy offset");
_Static_assert(sizeof(AX_APPLIED_NOTIFICATION) == 2464, "decision ABI");
_Static_assert(offsetof(AX_NOTIFICATION, policy_sha256) == 48, "policy offset");
_Static_assert(offsetof(AX_NOTIFICATION, path) == 104, "path offset");
int main(void) {
    AX_CONFIG config = {0};
    AX_REPLY reply = {0};
    AX_ROOT root;
    const char *name = "\\Device\\HarddiskVolume3\\protected";
    uint32_t i, seed = 0x12345678u;
    config.header.version = AX_VERSION;
    config.header.operation = AX_CONFIGURE;
    config.header.bytes = sizeof(config);
    config.root_count = 1; config.timeout_ms = 1000; config.policy_sha256[0] = 1;
    config.roots[0].characters = (uint32_t)strlen(name);
    for (i = 0; name[i]; ++i) config.roots[0].path[i] = (uint8_t)name[i];
    assert(AxConfigValid(&config));
    config.header.version = 1; assert(!AxConfigValid(&config)); config.header.version = AX_VERSION;
    config.header.reserved = 1; assert(!AxConfigValid(&config)); config.header.reserved = 0;
    config.root_count = UINT32_MAX; assert(!AxConfigValid(&config)); config.root_count = 1;
    config.timeout_ms = 5001; assert(!AxConfigValid(&config)); config.timeout_ms = 1000;
    config.roots[1].path[1023] = 1; assert(!AxConfigValid(&config)); config.roots[1].path[1023] = 0;
    root = config.roots[0]; root.characters = UINT32_MAX; assert(!AxRootValid(&root));
    root = config.roots[0]; root.path[10] = ':'; assert(!AxRootValid(&root));
    root = config.roots[0]; root.path[1023] = 'x'; assert(!AxRootValid(&root));
    reply.version = AX_VERSION; reply.verdict = AX_CLEAN; reply.request_id = 7; reply.sha256[0] = 1;
    assert(AxReplyValid(&reply, 7)); assert(!AxReplyValid(&reply, 8));
    reply.verdict = AX_MALWARE; assert(!AxReplyValid(&reply, 7));
    memcpy(reply.detection, "Fixture.Signature", sizeof("Fixture.Signature")); assert(AxReplyValid(&reply, 7));
    reply.detection[255] = 'x'; assert(!AxReplyValid(&reply, 7));
    /* Exercise arbitrary lengths, terminators, versions and flags under ASan/
     * UBSan; invalid arrays must be refused before their lengths are indexed. */
    for (i = 0; i < 20000; ++i) {
        unsigned char *bytes = (unsigned char *)&root;
        size_t n;
        for (n = 0; n < sizeof(root); ++n) { seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5; bytes[n] = (unsigned char)seed; }
        if ((i % 3) == 0) {
            root = config.roots[0];
            root.path[seed % AX_PATH_CHARS] = (uint16_t)(seed >> 16);
        } else if ((i % 3) == 1) {
            root.characters = seed % AX_PATH_CHARS;
            root.path[0] = '\\';
            for (n = 1; n < root.characters; ++n) root.path[n] = 'a';
            for (n = root.characters; n < AX_PATH_CHARS; ++n) root.path[n] = 0;
        }
        (void)AxRootValid(&root);
        memcpy(&reply, &root, sizeof(reply));
        (void)AxReplyValid(&reply, seed);
    }
    puts("Windows kernel wire validators and ABI: passed (20000 adversarial inputs)");
    return 0;
}
