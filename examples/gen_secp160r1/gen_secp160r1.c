/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "../../uECC.h"

#include <stdio.h>
#include <string.h>

void tocode(uint8_t *buff, size_t size){
    printf(" {\n    ");
    for (uint8_t i = 0; i < size;){
        printf("0x%02x", buff[i]);
        i++;
        if (i < size){
            printf(",");
        }
        if (i % 15 == 0) {
            printf("\n    ");
        }
    }
    printf("};\n");
}

uint8_t hash[48] = {
    0x86,0x25,0x5f,0xa2,0xc3,0x6e,0x4b,0x30,0x96,0x9e,0xae,0x17,0xdc,0x34,0xc7,
    0x72,0xcb,0xeb,0xdf,0xc5,0x8b,0x58,0x40,0x39,0x00,0xbe,0x87,0x61,0x4e,0xb1,
    0xa3,0x4b,0x87,0x80,0x26,0x3f,0x25,0x5e,0xb5,0xe6,0x5c,0xa9,0xbb,0xb8,0x64,
    0x1c,0xcc,0xfe};

int main() {
    int i, c;
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t sig[64] = {0};

    const struct uECC_Curve_t * curve = uECC_secp160r1();

    printf("Generate pair\n");
    if (!uECC_make_key(public, private, curve)) {
        printf("uECC_make_key() failed\n");
        return 1;
    }

    printf("uint8_t public[64] =");
    tocode(public, 64);
    //memcpy(hash, public, sizeof(hash));     // just hash

    printf("uint8_t hash[48] =");
    tocode(hash, 48);

    printf("uint8_t private[32] =");
    tocode(private, 32);

    if (!uECC_sign(private, hash, sizeof(hash), sig, curve)) {
        printf("uECC_sign() failed\n");
        return 1;
    }

    printf("uint8_t sig[64] =");
    tocode(sig, 64);

    if (!uECC_verify(public, hash, sizeof(hash), sig, curve)) {
        printf("uECC_verify() failed\n");
        return 1;
    }

    return 0;
}
