//
//  Hmac.swift
//  Hmac
//
//  Created by 野村 憲男 on 1/23/15.
//  Copyright (c) 2015 Norio Nomura. All rights reserved.
//

import Foundation

// https://tools.ietf.org/html/rfc2202

public struct HMAC {
    public enum Algorithm: CUnsignedInt {
        case SHA1, MD5, SHA256, SHA384, SHA512, SHA224
    }

    typealias Context = UnsafeMutablePointer<HMAC_bridge_Context>
    class CTX {
        var context = Context.alloc(1)
        deinit { context.dealloc(1) }
    }
    
    let ctx = CTX()
    let algorithm: Algorithm
    
    public init(algorithm: Algorithm, key string: String) {
        assert(!string.isEmpty, "key: String must not be empty.")
        
        // Passing String to UnsafePointer<Void> prameter is treated as UTF8 string ([UInt8]).
        // But I can't find this behavior in Apple's document.
        // So I use following forece unwrap style
        
        let key = string.cStringUsingEncoding(NSUTF8StringEncoding)!
        let length = string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)
        self.init(algorithm: algorithm, key: key, keyLength: length)
    }
    
    public init(algorithm: Algorithm, key array: [UInt8]) {
        assert(array.count > 0, "key: Array.count must be greater than zero.")
        self.init(algorithm: algorithm, key: array, keyLength: array.count)
    }
    
    public init(algorithm: Algorithm, key data: NSData) {
        assert(data.length > 0, "key: Data.length must be greater than zero.")
        self.init(algorithm: algorithm, key: data.bytes, keyLength: data.length)
    }
    
    private init(algorithm: Algorithm, key: UnsafePointer<Void>, keyLength: Int) {
        self.algorithm = algorithm
        HMAC_bridge_Init(ctx.context, algorithm.bridgedValue, key, UInt(keyLength))
    }
    
    public func update(string: String) -> HMAC {
        return string.nulTerminatedUTF8.withUnsafeBufferPointer {
            return self.update($0.baseAddress, dataLength: string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding))
        }
    }
    
    public func update(array: [UInt8]) -> HMAC {
        return update(array, dataLength: array.count)
    }
    
    public func update(data: NSData) -> HMAC {
        return update(data.bytes, dataLength: data.length)
    }
    
    public func update(var i: UInt64) -> HMAC {
        return update(&i, dataLength: sizeof(UInt64))
    }
    
    public func update(data: UnsafePointer<Void>, dataLength: Int) -> HMAC {
        HMAC_bridge_Update(ctx.context, data, UInt(dataLength))
        return self
    }
    
    public func final() -> [UInt8] {
        var hmac = Array<UInt8>(count: algorithm.digestLength, repeatedValue:0)
        HMAC_bridge_Final(ctx.context, &hmac)
        return hmac
    }
}

extension HMAC.Algorithm {
    public init?(_ string: String?) {
        if let string = string {
            self.init(string)
        } else {
            return nil
        }
    }
    
    public init?(_ string: String) {
        switch string.uppercaseString {
        case "SHA1": self = .SHA1
        case "MD5": self = .MD5
        case "SHA256": self = .SHA256
        case "SHA384": self = .SHA384
        case "SHA512": self = .SHA512
        case "SHA224": self = .SHA224
        default: return nil
        }
    }
    
    public var stringValue: String {
        switch self {
        case .SHA1: return "SHA1"
        case .MD5: return "MD5"
        case .SHA256: return "SHA256"
        case .SHA384: return "SHA384"
        case .SHA512: return "SHA512"
        case .SHA224: return "SHA224"
        }
    }
    
    var digestLength: Int {
        switch self {
        case .SHA1: return Int(HMAC_bridge_SHA1_DIGEST_LENGTH)
        case .MD5: return Int(HMAC_bridge_MD5_DIGEST_LENGTH)
        case .SHA256: return Int(HMAC_bridge_SHA256_DIGEST_LENGTH)
        case .SHA384: return Int(HMAC_bridge_SHA384_DIGEST_LENGTH)
        case .SHA512: return Int(HMAC_bridge_SHA512_DIGEST_LENGTH)
        case .SHA224: return Int(HMAC_bridge_SHA224_DIGEST_LENGTH)
        }
    }
    
    var bridgedValue: HMAC_bridge_Algorithm {
        switch self {
        case .SHA1: return .SHA1
        case .MD5: return .MD5
        case .SHA256: return .SHA256
        case .SHA384: return .SHA384
        case .SHA512: return .SHA512
        case .SHA224: return .SHA224
        }
    }
}

extension HMAC.Algorithm: Printable {
    public var description: String {
        return stringValue
    }
}
