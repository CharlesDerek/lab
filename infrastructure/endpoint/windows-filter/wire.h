/* Athernex native scanner wire contract. No pointers, size_t or native handles
 * cross this boundary. The client must be the connected LocalSystem process. */
#ifndef ATHERNEX_FILTER_WIRE_H
#define ATHERNEX_FILTER_WIRE_H
#include <stdint.h>

#define AX_VERSION 2u
#define AX_ROOTS 16u
#define AX_PATH_CHARS 1024u
#define AX_PENDING 64u
#define AX_MAX_FILE (128ull * 1024ull * 1024ull)
#define AX_PORT_NAME L"\\AthernexScanV2"
#define AX_CONFIGURE 1u
#define AX_MAP_SCAN 2u
#define AX_GET_STATUS 3u
#define AX_DISARM 4u
#define AX_SCAN 1u
#define AX_APPLIED 2u
#define AX_CLEAN 1u
#define AX_MALWARE 2u
#define AX_ERROR 3u

typedef struct AX_HEADER {
    uint32_t version, operation, bytes, reserved;
} AX_HEADER;
typedef struct AX_ROOT {
    uint32_t characters;
    uint16_t path[AX_PATH_CHARS];
} AX_ROOT;
typedef struct AX_CONFIG {
    AX_HEADER header;
    uint32_t root_count, timeout_ms;
    uint8_t policy_sha256[32];
    AX_ROOT roots[AX_ROOTS];
} AX_CONFIG;
typedef struct AX_NOTIFICATION {
    uint32_t version, operation;
    uint64_t request_id, bytes, volume, actor_pid, actor_created;
    uint8_t policy_sha256[32];
    uint8_t file_id[16];
    uint32_t path_characters, reserved;
    uint16_t path[AX_PATH_CHARS];
} AX_NOTIFICATION;
typedef struct AX_REPLY {
    uint32_t version, verdict;
    uint64_t request_id;
    uint8_t sha256[32];
    uint8_t detection[256];
} AX_REPLY;
typedef struct AX_MAP_REQUEST {
    AX_HEADER header;
    uint64_t request_id;
} AX_MAP_REQUEST;
typedef struct AX_MAPPING {
    uint32_t version, reserved;
    uint64_t request_id, section_handle, bytes;
} AX_MAPPING;
typedef struct AX_STATUS {
    uint32_t version, armed, connected, pending;
    uint64_t allowed, malware, errors, evidence_dropped;
    uint8_t instance[16];
    uint8_t policy_sha256[32];
} AX_STATUS;
typedef struct AX_APPLIED_NOTIFICATION {
    AX_NOTIFICATION file;
    AX_REPLY decision;
    int32_t status;
    uint32_t reserved;
} AX_APPLIED_NOTIFICATION;

/* Shared validation executes in the actual kernel/client protocol boundary. */
static inline int AxHeaderValid(const AX_HEADER *h, uint32_t bytes) {
    return h->version == AX_VERSION && h->bytes == bytes && h->reserved == 0;
}
static inline int AxReplyValid(const AX_REPLY *r, uint64_t id) {
    uint32_t i, has_hash = 0, ended = 0, length = 0;
    if (r->version != AX_VERSION || r->request_id != id ||
        (r->verdict != AX_CLEAN && r->verdict != AX_MALWARE && r->verdict != AX_ERROR)) return 0;
    for (i = 0; i < sizeof(r->sha256); ++i) has_hash |= r->sha256[i];
    for (i = 0; i < sizeof(r->detection); ++i) {
        if (r->detection[i] == 0) ended = 1;
        else if (ended || r->detection[i] < 0x20 || r->detection[i] > 0x7e) return 0;
        else ++length;
    }
    return ended && (r->verdict == AX_ERROR || has_hash) &&
        (r->verdict != AX_MALWARE || length != 0) &&
        (r->verdict != AX_CLEAN || length == 0);
}
static inline int AxRootValid(const AX_ROOT *root) {
    uint32_t i, start = 1;
    if (root->characters < 3 || root->characters >= AX_PATH_CHARS ||
        root->path[0] != '\\' || root->path[root->characters - 1] == '\\') return 0;
    for (i = 1; i <= root->characters; ++i) {
        uint16_t ch = root->path[i];
        if (i == root->characters || ch == '\\') {
            uint32_t n = i - start;
            if (n == 0 || (n == 1 && root->path[start] == '.') ||
                (n == 2 && root->path[start] == '.' && root->path[start + 1] == '.')) return 0;
            start = i + 1;
        } else if (ch < 0x20 || ch == '/' || ch == ':' || ch == '*' || ch == '?' ||
                   ch == '"' || ch == '<' || ch == '>' || ch == '|') return 0;
    }
    for (i = root->characters; i < AX_PATH_CHARS; ++i) if (root->path[i]) return 0;
    return 1;
}
static inline int AxConfigValid(const AX_CONFIG *c) {
    uint32_t i, j, digest = 0;
    if (!AxHeaderValid(&c->header, sizeof(*c)) || c->header.operation != AX_CONFIGURE ||
        c->root_count == 0 || c->root_count > AX_ROOTS ||
        c->timeout_ms < 100 || c->timeout_ms > 5000) return 0;
    for (i = 0; i < sizeof(c->policy_sha256); ++i) digest |= c->policy_sha256[i];
    if (!digest) return 0;
    for (i = 0; i < c->root_count; ++i) if (!AxRootValid(&c->roots[i])) return 0;
    for (; i < AX_ROOTS; ++i) {
        if (c->roots[i].characters) return 0;
        for (j = 0; j < AX_PATH_CHARS; ++j) if (c->roots[i].path[j]) return 0;
    }
    return 1;
}
#endif
