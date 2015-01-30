//
//  Hmac.swift
//  Hmac
//
//  Created by 野村 憲男 on 1/23/15.
//  Copyright (c) 2015 Norio Nomura. All rights reserved.
//

import Foundation

// https://tools.ietf.org/html/rfc2202

public class HMAC {
    public enum Algorithm: CUnsignedInt {
        case SHA1, MD5, SHA256, SHA384, SHA512, SHA224
    }

    typealias Context = UnsafeMutablePointer<HMAC_bridge_Context>
    
    var context = Context.alloc(1)
    let algorithm: Algorithm
    
    public convenience init(algorithm: Algorithm, key string: String) {
        assert(!string.isEmpty, "key: String must not be empty.")
        let key = string.cStringUsingEncoding(NSUTF8StringEncoding)
        let length = string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)
        self.init(algorithm: algorithm, key: key!, keyLength: length)
    }
    
    public convenience init(algorithm: Algorithm, key array: [UInt8]) {
        assert(array.count > 0, "key: Array.count must be greater than zero.")
        self.init(algorithm: algorithm, key: array, keyLength: array.count)
    }
    
    public convenience init(algorithm: Algorithm, key data: NSData) {
        assert(data.length > 0, "key: Data.length must be greater than zero.")
        self.init(algorithm: algorithm, key: data.bytes, keyLength: data.length)
    }
    
    private init(algorithm: Algorithm, key: UnsafePointer<Void>, keyLength: Int) {
        self.algorithm = algorithm
        HMAC_bridge_Init(context, algorithm.bridgedValue, key, UInt(keyLength))
    }
    
    public func update(string: String) -> HMAC {
        let data = string.cStringUsingEncoding(NSUTF8StringEncoding)
        let length = string.lengthOfBytesUsingEncoding(NSUTF8StringEncoding)
        return update(data!, dataLength: length)
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
        HMAC_bridge_Update(context, data, UInt(dataLength))
        return self
    }
    
    public func final() -> [UInt8] {
        var hmac = Array<UInt8>(count: algorithm.digestLength, repeatedValue:0)
        HMAC_bridge_Final(context, &hmac)
        return hmac
    }
    
    public func finalHexString() -> String {
        return self.dynamicType.hexStringFromArray(final())
    }
    
    deinit {
        context.dealloc(1)
    }
}

extension HMAC {
    private class func convertHexDigit(c: UnicodeScalar) -> UInt8 {
        switch c {
        case UnicodeScalar("0")...UnicodeScalar("9"): return UInt8(c.value - UnicodeScalar("0").value)
        case UnicodeScalar("a")...UnicodeScalar("f"): return UInt8(c.value - UnicodeScalar("a").value + 0xa)
        case UnicodeScalar("A")...UnicodeScalar("F"): return UInt8(c.value - UnicodeScalar("A").value + 0xa)
        default: fatalError("convertHexDigit: Invalid hex digit")
        }
    }
    
    public class func arrayFromHexString(var s: String) -> [UInt8]{
        if s.hasPrefix("0x") {
            s = suffix(s, countElements(s) - 2)
        }
        var g = s.unicodeScalars.generate()
        var a = [UInt8]()
        while let msn = g.next() {
            if let lsn = g.next() {
                a += [convertHexDigit(msn) << 4 | convertHexDigit(lsn)]
            } else {
                a += [convertHexDigit(msn) << 4]
                assert(false, "arrayFromHexString: String must contain even number of characters")
            }
        }
        return a
    }
    
    public class func hexStringFromArray(a: [UInt8], uppercase: Bool = false) -> String {
        return a.map{ String(format: uppercase ? "%02X" : "%02x", $0) }.reduce("", +)
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
