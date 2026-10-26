/* Platform declaration only; actual-source controls supply a checked CNG stub. */
#ifndef ATHERNEX_TEST_BCRYPT_H
#define ATHERNEX_TEST_BCRYPT_H
#define BCRYPT_SHA256_ALG_HANDLE ((PVOID)(uintptr_t)0x41)
NTSTATUS BCryptHash(PVOID algorithm,PUCHAR secret,ULONG secret_bytes,PUCHAR input,ULONG input_bytes,PUCHAR output,ULONG output_bytes);
#endif
