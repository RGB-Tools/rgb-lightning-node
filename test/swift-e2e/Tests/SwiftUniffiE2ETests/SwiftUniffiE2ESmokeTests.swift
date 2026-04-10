import Foundation
import XCTest
import RGBLightningNode

final class SwiftUniffiE2ESmokeTests: XCTestCase {
    func testInitUnlockNodeInfoAndAddress() throws {
        let env = ProcessInfo.processInfo.environment

        let bitcoindUser = try requireEnv("BITCOIND_RPC_USERNAME", in: env)
        let bitcoindPassword = try requireEnv("BITCOIND_RPC_PASSWORD", in: env)
        let bitcoindHost = try requireEnv("BITCOIND_RPC_HOST", in: env)
        let bitcoindPort = try UInt16(requireEnv("BITCOIND_RPC_PORT", in: env))
            .unwrap(or: "BITCOIND_RPC_PORT must be a valid UInt16")

        let storageDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("swift-uniffi-e2e-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: storageDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: storageDir) }

        let node = try SdkNode.create(
            request: SdkInitRequest(
                storageDirPath: storageDir.path,
                daemonListeningPort: randomPort(),
                ldkPeerListeningPort: randomPort(),
                network: "regtest",
                maxMediaUploadSizeMb: 5,
                enableVirtualChannelsV0: false,
                virtualPeerPubkeys: nil
            )
        )
        defer { node.shutdown() }

        let _ = try node.`init`(password: "swift-e2e-pass", mnemonic: nil)

        try node.unlock(
            request: SdkUnlockRequest(
                password: "swift-e2e-pass",
                bitcoindRpcUsername: bitcoindUser,
                bitcoindRpcPassword: bitcoindPassword,
                bitcoindRpcHost: bitcoindHost,
                bitcoindRpcPort: bitcoindPort,
                indexerUrl: env["INDEXER_URL"],
                proxyEndpoint: env["PROXY_ENDPOINT"],
                announceAddresses: [],
                announceAlias: nil
            )
        )

        let info = try node.nodeInfo()
        XCTAssertEqual(info.numChannels, 0)
        XCTAssertEqual(info.numUsableChannels, 0)
        XCTAssertGreaterThanOrEqual(info.channelCapacityMaxSat, info.channelCapacityMinSat)

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
