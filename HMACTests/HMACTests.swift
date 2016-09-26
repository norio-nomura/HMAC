//
//  HMACTests.swift
//  HMACTests
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
import XCTest
import HMAC
import Base32

class HMACTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    // MARK: https://tools.ietf.org/html/rfc2202
    
    func test_RFC2202_Hmac_MD5_TestCase1() {
        let key =  Array<UInt8>(repeating: 0x0b, count: 16)
        let data = "Hi There"
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "9294727a3638bb1c13f48ef8158bfc9d"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_MD5_TestCase2() {
        let key = "Jefe"
        let data = "what do ya want for nothing?"
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "750c783e6ab0b503eaa86e310a5db738"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_MD5_TestCase3() {
        let key = Array<UInt8>(repeating: 0xAA, count: 16)
        let data = Array<UInt8>(repeating: 0xDD, count: 50)
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "56be34521d144c88dbb8c733f0e8b3f6"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_MD5_TestCase4() {
        let key = base16Decode("0102030405060708090a0b0c0d0e0f10111213141516171819")!
        let data = Array<UInt8>(repeating: 0xcd, count: 50)
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "697eaf0aca3a3aea3a75164746ffaa79"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_MD5_TestCase5() {
        let key = base16Decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")!
        let data = "Test With Truncation"
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "56461ef2342edc00f9bab995690efd4c"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_MD5_TestCase6() {
        let key = Array<UInt8>(repeating: 0xaa, count: 80)
        let data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_MD5_TestCase7() {
        let key = Array<UInt8>(repeating: 0xaa, count: 80)
        let data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        let hmacMD5 = base16Encode(HMAC(algorithm: .md5, key: key).update(data).final(), uppercase: false)
        let expect = "6f630fad67cda0ee1fb1f562db3aa53e"
        XCTAssertEqual(hmacMD5, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase1() {
        let key =  Array<UInt8>(repeating: 0x0b, count: 20)
        let data = "Hi There"
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "b617318655057264e28bc0b6fb378c8ef146be00"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase2() {
        let key = "Jefe"
        let data = "what do ya want for nothing?"
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase3() {
        let key = Array<UInt8>(repeating: 0xAA, count: 20)
        let data = Array<UInt8>(repeating: 0xDD, count: 50)
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase4() {
        let key = base16Decode("0102030405060708090a0b0c0d0e0f10111213141516171819")!
        let data = Array<UInt8>(repeating: 0xcd, count: 50)
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase5() {
        let key = base16Decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c")!
        let data = "Test With Truncation"
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase6() {
        let key = Array<UInt8>(repeating: 0xaa, count: 80)
        let data = "Test Using Larger Than Block-Size Key - Hash Key First"
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    func test_RFC2202_Hmac_SHA1_TestCase7() {
        let key = Array<UInt8>(repeating: 0xaa, count: 80)
        let data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        let hmacSHA1 = base16Encode(HMAC(algorithm: .sha1, key: key).update(data).final(), uppercase: false)
        let expect = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        XCTAssertEqual(hmacSHA1, expect)
    }
    
    // MARK: http://www.ietf.org/rfc/rfc4231.txt
    
    func test_RFC4231_Hmac_TestCase1() {
        let key = Array<UInt8>(repeating: 0x0b, count: 20)
        let data = base16Decode("4869205468657265")!
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false),
            "896fb1128abbdf196832107cd49df33f" +
            "47b4b1169912ba4f53684b22")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false),
            "b0344c61d8db38535ca8afceaf0bf12b" +
            "881dc200c9833da726e9376c2e32cff7")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false),
            "afd03944d84895626b0825f4ab46907f" +
                "15f9dadbe4101ec682aa034c7cebc59c" +
            "faea9ea9076ede7f4af152e8b2fa9cb6")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false),
            "87aa7cdea5ef619d4ff0b4241a1d6cb0" +
                "2379f4e2ce4ec2787ad0b30545e17cde" +
                "daa833b7d6b8a702038b274eaea3f4e4" +
            "be9d914eeb61f1702e696c203a126854")
    }
    
    func test_RFC4231_Hmac_TestCase2() {
        let key = base16Decode("4a656665")!
        let data = base16Decode(
            "7768617420646f2079612077616e7420" +
            "666f72206e6f7468696e673f")!
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false),
            "a30e01098bc6dbbf45690f3a7e9e6d0f" +
            "8bbea2a39e6148008fd05e44")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false),
            "5bdcc146bf60754e6a042426089575c7" +
            "5a003f089d2739839dec58b964ec3843")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false),
            "af45d2e376484031617f78d2b58a6b1b" +
                "9c7ef464f5a01b47e42ec3736322445e" +
            "8e2240ca5e69e2c78b3239ecfab21649")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false),
            "164b7a7bfcf819e2e395fbe73b56e0a3" +
                "87bd64222e831fd610270cd7ea250554" +
                "9758bf75c05a994a6d034f65f8f0e6fd" +
            "caeab1a34d4a6b4b636e070a38bce737")
    }
    
    func test_RFC4231_Hmac_TestCase3() {
        let key = base16Decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaaaa")!
        let data = base16Decode(
            "dddddddddddddddddddddddddddddddd" +
                "dddddddddddddddddddddddddddddddd" +
                "dddddddddddddddddddddddddddddddd" +
            "dddd")!
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false),
            "7fb3cb3588c6c1f6ffa9694d7d6ad264" +
            "9365b0c1f65d69d1ec8333ea")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false),
            "773ea91e36800e46854db8ebd09181a7" +
            "2959098b3ef8c122d9635514ced565fe")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false),
            "88062608d3e6ad8a0aa2ace014c8a86f" +
                "0aa635d947ac9febe83ef4e55966144b" +
            "2a5ab39dc13814b94e3ab6e101a34f27")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false),
            "fa73b0089d56a284efb0f0756c890be9" +
                "b1b5dbdd8ee81a3655f83e33b2279d39" +
                "bf3e848279a722c806b485a47e67c807" +
            "b946a337bee8942674278859e13292fb")
    }
    
    func test_RFC4231_Hmac_TestCase4() {
        let key = base16Decode(
            "0102030405060708090a0b0c0d0e0f10" +
            "111213141516171819")!
        let data = base16Decode(
            "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
                "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" +
            "cdcd")!
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false),
            "6c11506874013cac6a2abc1bb382627c" +
            "ec6a90d86efc012de7afec5a")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false),
            "82558a389a443c0ea4cc819899f2083a" +
            "85f0faa3e578f8077a2e3ff46729665b")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false),
            "3e8a69b7783c25851933ab6290af6ca7" +
                "7a9981480850009cc5577c6e1f573b4e" +
            "6801dd23c4a7d679ccf8a386c674cffb")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false),
            "b0ba465637458c6990e5a8c5f61d4af7" +
                "e576d97ff94b872de76f8050361ee3db" +
                "a91ca5c11aa25eb4d679275cc5788063" +
            "a5f19741120c4f2de2adebeb10a298dd")
    }
    
    func test_RFC4231_Hmac_TestCase5() {
        let key = base16Decode(
            "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c" +
            "0c0c0c0c")!
        let data = base16Decode(
            "546573742057697468205472756e6361" +
            "74696f6e")!
        XCTAssertTrue(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false)
                .hasPrefix("0e2aea68a90c8d37c988bcdb9fca6fa8"))
        XCTAssertTrue(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false)
                .hasPrefix("a3b6167473100ee06e0c796c2955552b"))
        XCTAssertTrue(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false)
                .hasPrefix("3abf34c3503b2a23a46efc619baef897"))
        XCTAssertTrue(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false)
                .hasPrefix("415fad6271580a531d4179bc891d87a6"))
    }
    
    func test_RFC4231_Hmac_TestCase6() {
        let key = base16Decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa")!
        let data = base16Decode(
            "54657374205573696e67204c61726765" +
                "72205468616e20426c6f636b2d53697a" +
                "65204b6579202d2048617368204b6579" +
            "204669727374")!
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false),
            "95e9a0db962095adaebe9b2d6f0dbce2" +
            "d499f112f2d2b7273fa6870e")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false),
            "60e431591ee0b67f0d8a26aacbf5b77f" +
            "8e0bc6213728c5140546040f0ee37f54")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false),
            "4ece084485813e9088d2c63a041bc5b4" +
                "4f9ef1012a2b588f3cd11f05033ac4c6" +
            "0c2ef6ab4030fe8296248df163f44952")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false),
            "80b24263c7c1a3ebb71493c1dd7be8b4" +
                "9b46d1f41b4aeec1121b013783f8f352" +
                "6b56d037e05f2598bd0fd2215d6a1e52" +
            "95e64f73f63f0aec8b915a985d786598")
    }
    
    func test_RFC4231_Hmac_TestCase7() {
        let key = base16Decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa")!
        let data = base16Decode(
            "54686973206973206120746573742075" +
                "73696e672061206c6172676572207468" +
                "616e20626c6f636b2d73697a65206b65" +
                "7920616e642061206c61726765722074" +
                "68616e20626c6f636b2d73697a652064" +
                "6174612e20546865206b6579206e6565" +
                "647320746f2062652068617368656420" +
                "6265666f7265206265696e6720757365" +
                "642062792074686520484d414320616c" +
            "676f726974686d2e")!
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha224, key: key).update(data).final(), uppercase: false),
            "3a854166ac5d9f023f54d517d0b39dbd" +
            "946770db9c2b95c9f6f565d1")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha256, key: key).update(data).final(), uppercase: false),
            "9b09ffa71b942fcb27635fbcd5b0e944" +
            "bfdc63644f0713938a7f51535c3a35e2")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha384, key: key).update(data).final(), uppercase: false),
            "6617178e941f020d351e2f254e8fd32c" +
                "602420feb0b8fb9adccebb82461e99c5" +
            "a678cc31e799176d3860e6110c46523e")
        XCTAssertEqual(
            base16Encode(HMAC(algorithm: .sha512, key: key).update(data).final(), uppercase: false),
            "e37b6a775dc87dbaa4dfa9f96e5e3ffd" +
                "debd71f8867289865df5a32d20cdc944" +
                "b6022cac3c4982b10d5eeb55c3e4de15" +
            "134676fb6de0446065c97440fa8c6a58")
    }
    
    func test_RFC4231_Hmac_TestCase7_multipartUpdates() {
        let key = base16Decode(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "aaaaaa")!
        let dataStringArray = [
            "54686973206973206120746573742075",
            "73696e672061206c6172676572207468",
            "616e20626c6f636b2d73697a65206b65",
            "7920616e642061206c61726765722074",
            "68616e20626c6f636b2d73697a652064",
            "6174612e20546865206b6579206e6565",
            "647320746f2062652068617368656420",
            "6265666f7265206265696e6720757365",
            "642062792074686520484d414320616c",
            "676f726974686d2e"
            ]
        let expects: [(HMAC.Algorithm, String)] = [
            (.sha224, "3a854166ac5d9f023f54d517d0b39dbd" +
                "946770db9c2b95c9f6f565d1"),
            (.sha256, "9b09ffa71b942fcb27635fbcd5b0e944" +
                "bfdc63644f0713938a7f51535c3a35e2"),
            (.sha384, "6617178e941f020d351e2f254e8fd32c" +
                "602420feb0b8fb9adccebb82461e99c5" +
                "a678cc31e799176d3860e6110c46523e"),
            (.sha512, "e37b6a775dc87dbaa4dfa9f96e5e3ffd" +
                "debd71f8867289865df5a32d20cdc944" +
                "b6022cac3c4982b10d5eeb55c3e4de15" +
                "134676fb6de0446065c97440fa8c6a58")
        ]
        for (algorithm, expect) in expects {
            let hmac = HMAC(algorithm: algorithm, key: key)
            for dataString in dataStringArray {
                let data = dataString.base16DecodedData!
                hmac.update(data)
            }
            XCTAssertEqual(base16Encode(hmac.final(), uppercase: false), expect)
        }
    }
}
