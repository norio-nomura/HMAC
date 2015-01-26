//
//  HMAC_bridge.m
//  HMAC
//
//  Created by 野村 憲男 on 1/27/15.
//  Copyright (c) 2015 Norio Nomura. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import "HMAC_bridge.h"

void HMAC_bridge_Init(
    HMAC_bridge_Context *ctx,
    HMAC_bridge_Algorithm algorithm,
    const void *key,
    size_t keyLength)
__OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0)
{
    CCHmacInit((CCHmacContext*)ctx, algorithm, key, keyLength);
}

void HMAC_bridge_Update(
    HMAC_bridge_Context *ctx,
    const void *data,
    size_t dataLength)
__OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0)
{
    CCHmacUpdate((CCHmacContext*)ctx, data, dataLength);
}

void HMAC_bridge_Final(
    HMAC_bridge_Context *ctx,
    void *macOut)
__OSX_AVAILABLE_STARTING(__MAC_10_4, __IPHONE_2_0)
{
    CCHmacFinal((CCHmacContext*)ctx, macOut);
}
