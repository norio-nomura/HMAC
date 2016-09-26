import PackageDescription

let package = Package(
    name: "HMAC",
    targets: [
      Target(name: "HMAC", dependencies: ["BridgeToHMAC"]),
      Target(name: "BridgeToHMAC")
    ],
    dependencies: [
      .Package(url: "https://github.com/norio-nomura/Base32", majorVersion: 0, minor: 5),
    ]
)
