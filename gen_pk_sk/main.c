#include "c25519/edsign.h" // UERANSIM ext/compact25519/edsign.h 같은 경로
#include <stdint.h>
#include <stdio.h>

// 하드코딩된 gNB 시크릿키 (32B)
static const uint8_t GNB_SECRET[32] = {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22,
                                       0x22, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
                                       0x33, 0x33, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44};

// gNB 공개키(32B) – UE에 배포해서 검증에 사용
static const uint8_t GNB_PUB[32] = {0x64, 0xE7, 0x78, 0x2E, 0x29, 0xF2, 0x21, 0x99, 0x99, 0x66, 0x4E,
                                    0x16, 0x3F, 0xD6, 0xAD, 0xBB, 0x80, 0xCF, 0xBA, 0xE5, 0xAD, 0x86,
                                    0xA2, 0x85, 0xA3, 0x86, 0x40, 0x5A, 0x70, 0x20, 0x10, 0x61};

int main()
{
    // uint8_t pub[32];

    // // 비밀키 → 공개키 도출
    // edsign_sec_to_pub(pub, GNB_SECRET);

    // // 결과 출력
    // printf("gNB Secret Key (32B):\n");
    // for (int i = 0; i < 32; i++)
    //     printf("%02X", GNB_SECRET[i]);
    // printf("\n\n");

    // printf("gNB Public Key (32B):\n");
    // for (int i = 0; i < 32; i++)
    //     printf("%02X", pub[i]);
    // printf("\n");

    // return 0;

    // 위의 GNB_SECRET/GNB_PUB 사용
    uint8_t msg[] = "test";
    uint8_t sig[64];

    edsign_sign(sig, GNB_PUB, GNB_SECRET, msg, sizeof(msg) - 1);
    uint8_t ok = edsign_verify(sig, GNB_PUB, msg, sizeof(msg) - 1);

    printf("self-test: %s\n", ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}