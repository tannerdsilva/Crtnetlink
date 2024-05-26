// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "Crtnetlink",
    products: [
        .library(
            name: "Crtnetlink",
            targets: ["Crtnetlink"]),
    ],
    targets: [
        .target(
        	name: "Crtnetlink",
			publicHeadersPath:"."
		)
    ]
)
