// NativeExternalSigner is only present when Swift is generated from the built library with `vls`
// (`scripts/ci/uniffi_generate_from_library.sh`). The default Swift E2E job uses UDL-only bindings,
// so this file is compiled only when `RLN_UNIFFI_LIBRARY_VLS` is set (see swift_uniffi_external_signer_smoke.sh).

#if RLN_UNIFFI_LIBRARY_VLS
import Foundation
import XCTest
import RGBLightningNode

final class SwiftExternalSignerSmokeTests: XCTestCase {
    func testNativeExternalSignerInitUnlockNodeInfoAndAddress() throws {
        let env = ProcessInfo.processInfo.environment

        let bitcoindUser = try requireEnv("BITCOIND_RPC_USERNAME", in: env)
        let bitcoindPassword = try requireEnv("BITCOIND_RPC_PASSWORD", in: env)
        let bitcoindHost = try requireEnv("BITCOIND_RPC_HOST", in: env)
        let bitcoindPort = try UInt16(requireEnv("BITCOIND_RPC_PORT", in: env))
            .unwrap(or: "BITCOIND_RPC_PORT must be a valid UInt16")

        let indexerUrl = env["INDEXER_URL"] ?? "127.0.0.1:50001"
        let proxyEndpoint = env["PROXY_ENDPOINT"] ?? "rpc://127.0.0.1:3000/json-rpc"
        let seedHex = env["RLN_TEST_NATIVE_SIGNER_SEED_HEX"] ?? String(repeating: "11", count: 32)

        let storageDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-ext-signer-smoke-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: storageDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: storageDir) }

        let signer = try NativeExternalSigner(
            seedHex: seedHex,
            network: "regtest",
            permissivePolicy: true
        )

        let node = try SdkNode.create(
            request: SdkInitRequest(
                storageDirPath: storageDir.path,
                daemonListeningPort: randomPort(),
                ldkPeerListeningPort: randomPort(),
                network: "regtest",
                maxMediaUploadSizeMb: 5,
                enableVirtualChannelsV0: false,
                virtualPeerPubkeys: nil,
                lspBaseUrl: nil,
                lspBearerToken: nil
            )
        )
        defer { node.shutdown() }

        try node.initWithNativeExternalSigner(signer: signer)
        try node.unlockWithNativeExternalSigner(
            signer: signer,
            bitcoindRpcUsername: bitcoindUser,
            bitcoindRpcPassword: bitcoindPassword,
            bitcoindRpcHost: bitcoindHost,
            bitcoindRpcPort: bitcoindPort,
            indexerUrl: indexerUrl,
            proxyEndpoint: proxyEndpoint,
            announceAddresses: [],
            announceAlias: "swift_ext_smoke"
        )

        let info = try node.nodeInfo()
        XCTAssertEqual(info.numChannels, 0)
        let address = try node.address()
        XCTAssertFalse(address.address.isEmpty)
        XCTAssertTrue(address.address.hasPrefix("bcrt") || address.address.hasPrefix("tb1"))
    }

    private func requireEnv(_ name: String, in env: [String: String]) throws -> String {
        guard let value = env[name], !value.isEmpty else {
            throw XCTSkip("missing required environment variable: \(name)")
        }
        return value
    }

    private func randomPort() -> UInt16 {
        UInt16.random(in: 30000...45000)
    }
}

private extension Optional {
    func unwrap(or message: @autoclosure () -> String) throws -> Wrapped {
        guard let value = self else {
            throw XCTSkip(message())
        }
        return value
    }
}
#endif
