/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "../../uECC.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

uint8_t private[32] = {
    0x00,0xd3,0x31,0x40,0x94,0x9d,0xbe,0xe2,0x46,0xb0,0x25,0xd4,0xb4,0xdd,0x86,
    0x99,0xfa,0xfb,0xe3,0x72,0x4a,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00};

uint8_t public[64] = {
    0x86,0x04,0xd7,0x17,0xd0,0x45,0xeb,0x28,0xde,0x54,0xe1,0x2d,0x9c,0x57,0x7f,
    0x1e,0xc5,0x07,0x35,0x2e,0x39,0x2f,0xe0,0x3b,0xef,0x5a,0xaa,0x52,0x8e,0xa6,
    0xc2,0x07,0xbc,0x1b,0x63,0x46,0x66,0x45,0xb8,0x7c,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00};

int main() {
    uint8_t sha256sum[32] = {0};
    uint8_t sig[64] = {0};

    uint8_t hex_byte[2];

    const struct uECC_Curve_t * curve = uECC_secp160r1();

    FILE * file;
    file = fopen("firmware.bin.256sum", "rb");
    if (file == NULL){
        printf("Could not open file firmware.bin.256sum\n");
        return 1;
    }

    for (uint8_t i = 0; i < 32; i++){
        if (fread(hex_byte, sizeof(uint8_t), 2, file) < 2){
            printf("sha256 sum must be 64 hex chars!\n");
            return 1;
        }
        sha256sum[i] = strtol(hex_byte, NULL, 16);
    }
    fclose(file);

    for (int i = 0; i < 32; i++){
        printf("%02x", sha256sum[i]);
    }
    printf("  firmware.bin\n");

    if (!uECC_sign(private, sha256sum, sizeof(sha256sum), sig, curve)) {
        printf("uECC_sign() failed\n");
        return 1;
    }

    file = fopen("firmware.sig", "wb+");
    if (file == NULL){
        printf("Could not open file firmware.sig\n");
        return 1;
    }

    fwrite(sig, sizeof(uint8_t), sizeof(sig), file);
    fclose(file);

    for (int i = 0; i < 64; i++){
        printf("%02x", sig[i]);
    }
    printf("  firmware.sig\n");


    if (uECC_verify(public, sha256sum, sizeof(sha256sum), sig, curve)) {
    	printf("uECC_verify() success!\n");
    } else {
    	printf("uECC_verify() failed!\n");
    }

    printf("Done\n");

    return 0;
}
