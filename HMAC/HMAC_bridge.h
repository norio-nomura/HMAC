//
//  HMAC_bridge.h
//  HMAC
//
//  Created by 野村 憲男 on 1/27/15.
//  Copyright (c) 2015 Norio Nomura. All rights reserved.
//

#ifndef HMAC_HMAC_bridge_h
#define HMAC_HMAC_bridge_h

#define HMAC_bridge_MD5_DIGEST_LENGTH       16
#define HMAC_bridge_SHA1_DIGEST_LENGTH      20
#define HMAC_bridge_SHA256_DIGEST_LENGTH    32
#define HMAC_bridge_SHA384_DIGEST_LENGTH    48
#define HMAC_bridge_SHA512_DIGEST_LENGTH    64
#define HMAC_bridge_SHA224_DIGEST_LENGTH    28

typedef NS_ENUM(unsigned int, HMAC_bridge_Algorithm) {
    HMAC_bridge_AlgorithmSHA1,
    HMAC_bridge_AlgorithmMD5,
    HMAC_bridge_AlgorithmSHA256,
    HMAC_bridge_AlgorithmSHA384,
    HMAC_bridge_AlgorithmSHA512,
    HMAC_bridge_AlgorithmSHA224
};

#define CC_HMAC_CONTEXT_SIZE    96
typedef struct {
    uint32_t            ctx[CC_HMAC_CONTEXT_SIZE];
} HMAC_bridge_Context;

void HMAC_bridge_Init(
    HMAC_bridge_Context *ctx,
    HMAC_bridge_Algorithm algorithm,
    const void *key,
    size_t keyLength)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

void HMAC_bridge_Update(
    HMAC_bridge_Context *ctx,
    const void *data,
    size_t dataLength)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

void HMAC_bridge_Final(
    HMAC_bridge_Context *ctx,
    void *macOut)
    __OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0);

#endif
