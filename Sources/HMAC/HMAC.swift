//
//  Hmac.swift
//  Hmac
//
//  Created by 野村 憲男 on 1/23/15.
//
//  Copyright (c) 2015 Norio Nomura
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

import Foundation
#if SWIFT_PACKAGE
import BridgeToHMAC
#endif

// https://tools.ietf.org/html/rfc2202

public struct HMAC {
    public enum Algorithm: CUnsignedInt {
        case sha1, md5, sha256, sha384, sha512, sha224
    }

    typealias Context = UnsafeMutablePointer<HMAC_bridge_Context>
    class CTX {
        var context = Context.allocate(capacity: 1)
        deinit { context.deallocate(capacity: 1) }
    }

    let ctx = CTX()
    let algorithm: Algorithm

    public init(algorithm: Algorithm, key string: String) {
        assert(!string.isEmpty, "key: String must not be empty.")

        // Passing String to UnsafePointer<Void> prameter is treated as UTF8 string ([UInt8]).
        // But I can't find this behavior in Apple's document.
        // So I use following forece unwrap style

        let key = string.cString(using: .utf8)!
        let length = string.lengthOfBytes(using: .utf8)
        self.init(algorithm: algorithm, key: key, keyLength: length)

        // Swift crashes with following code: rdar://problem/19753599
        /*
        self.algorithm = algorithm
        string.nulTerminatedUTF8.withUnsafeBufferPointer {
            HMAC_bridge_Init(self.ctx.context, algorithm.bridgedValue, $0.baseAddress, numericCast($0.count - 1))
        }
        */
    }

    public init(algorithm: Algorithm, key array: [UInt8]) {
        assert(array.count > 0, "key: Array.count must be greater than zero.")
        self.init(algorithm: algorithm, key: array, keyLength: array.count)
    }

    public init(algorithm: Algorithm, key data: Data) {
        assert(data.count > 0, "key: Data.length must be greater than zero.")
        self.init(algorithm: algorithm, key: (data as NSData).bytes, keyLength: data.count)
    }

    fileprivate init(algorithm: Algorithm, key: UnsafeRawPointer, keyLength: Int) {
        self.algorithm = algorithm
        HMAC_bridge_Init(ctx.context, algorithm.bridgedValue, key, numericCast(keyLength))
    }

    public func update(_ string: String) -> HMAC {
        return string.utf8CString.withUnsafeBufferPointer {
            return self.update($0.baseAddress!, dataLength: $0.count - 1)
        }
    }

    public func update(_ array: [UInt8]) -> HMAC {
        return update(array, dataLength: array.count)
    }

    public func update(_ data: Data) -> HMAC {
        return update((data as NSData).bytes, dataLength: data.count)
    }

    public func update(_ i: UInt64) -> HMAC {
        var i = i
        return update(&i, dataLength: MemoryLayout<UInt64>.size)
    }

    public func update(_ data: UnsafeRawPointer, dataLength: Int) -> HMAC {
        HMAC_bridge_Update(ctx.context, data, numericCast(dataLength))
        return self
    }

    public func final() -> [UInt8] {
        var hmac = Array<UInt8>(repeating: 0, count: algorithm.digestLength)
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
        switch string.uppercased() {
        case "SHA1": self = .sha1
        case "MD5": self = .md5
        case "SHA256": self = .sha256
        case "SHA384": self = .sha384
        case "SHA512": self = .sha512
        case "SHA224": self = .sha224
        default: return nil
        }
    }

    public var stringValue: String {
        switch self {
        case .sha1: return "SHA1"
        case .md5: return "MD5"
        case .sha256: return "SHA256"
        case .sha384: return "SHA384"
        case .sha512: return "SHA512"
        case .sha224: return "SHA224"
        }
    }

    var digestLength: Int {
        switch self {
        case .sha1: return Int(HMAC_bridge_SHA1_DIGEST_LENGTH)
        case .md5: return Int(HMAC_bridge_MD5_DIGEST_LENGTH)
        case .sha256: return Int(HMAC_bridge_SHA256_DIGEST_LENGTH)
        case .sha384: return Int(HMAC_bridge_SHA384_DIGEST_LENGTH)
        case .sha512: return Int(HMAC_bridge_SHA512_DIGEST_LENGTH)
        case .sha224: return Int(HMAC_bridge_SHA224_DIGEST_LENGTH)
        }
    }

    var bridgedValue: HMAC_bridge_Algorithm {
        switch self {
        case .sha1: return .SHA1
        case .md5: return .MD5
        case .sha256: return .SHA256
        case .sha384: return .SHA384
        case .sha512: return .SHA512
        case .sha224: return .SHA224
        }
    }
}

extension HMAC.Algorithm: CustomStringConvertible {
    public var description: String {
        return stringValue
    }
}

extension HMAC.Algorithm {
    @available(*, unavailable, renamed: "sha1")
    static var SHA1: HMAC.Algorithm {
        return .sha1
    }
    @available(*, unavailable, renamed: "md5")
    static var MD5: HMAC.Algorithm {
        return .md5
    }
    @available(*, unavailable, renamed: "sha256")
    static var SHA256: HMAC.Algorithm {
        return .sha256
    }
    @available(*, unavailable, renamed: "sha384")
    static var SHA384: HMAC.Algorithm {
        return .sha384
    }
    @available(*, unavailable, renamed: "sha512")
    static var SHA512: HMAC.Algorithm {
        return .sha512
    }
    @available(*, unavailable, renamed: "sha224")
    static var SHA224: HMAC.Algorithm {
        return .sha224
    }
}
