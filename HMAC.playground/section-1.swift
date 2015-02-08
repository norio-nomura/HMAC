// You need building target "HMAC-Mac"

import Foundation
import HMAC
import Base32

// case 2 from https://tools.ietf.org/html/rfc2202

let key = "Jefe"
let data = "what do ya want for nothing?"
let hmacMD5 = base16Encode(HMAC(algorithm: .MD5, key: key).update(data).final()).lowercaseString
if hmacMD5 == "750c783e6ab0b503eaa86e310a5db738" {
    print("Good!")
}
