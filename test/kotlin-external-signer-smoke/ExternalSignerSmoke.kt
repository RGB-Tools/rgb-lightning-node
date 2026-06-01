import java.io.File
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.Paths
import org.utexo.rgblightningnode.NativeExternalSigner
import org.utexo.rgblightningnode.SdkInitRequest
import org.utexo.rgblightningnode.SdkNode

private const val PROXY_ENDPOINT_LOCAL = "rpc://127.0.0.1:3000/json-rpc"

private fun env(name: String, default: String): String = System.getenv(name) ?: default

private fun freePort(): UShort {
    ServerSocket(0).use { return it.localPort.toUShort() }
}

fun main() {
    val bitcoindUser = env("BITCOIND_RPC_USERNAME", "user")
    val bitcoindPassword = env("BITCOIND_RPC_PASSWORD", "password")
    val bitcoindHost = env("BITCOIND_RPC_HOST", "127.0.0.1")
    val bitcoindPort = env("BITCOIND_RPC_PORT", "18443").toUShort()
    val indexerUrl = env("INDEXER_URL", "127.0.0.1:50001")
    val proxyEndpoint = env("PROXY_ENDPOINT", PROXY_ENDPOINT_LOCAL)
    val seedHex = env("RLN_TEST_NATIVE_SIGNER_SEED_HEX", "11".repeat(32))

    val repoRoot = Paths.get("").toAbsolutePath().normalize()
    val storageRoot = repoRoot.resolve("target/uniffi/kotlin-external-signer-smoke/data")
    val storageDir = storageRoot.resolve("node")
    if (env("RESET_DATA", "1") == "1") {
        val dirFile = File(storageDir.toString())
        if (dirFile.exists()) {
            dirFile.deleteRecursively()
        }
    }
    Files.createDirectories(storageDir)

    val signer = NativeExternalSigner(seedHex, "regtest", true)
    val node =
        SdkNode.create(
            SdkInitRequest(
                storageDirPath = storageDir.toString(),
                daemonListeningPort = freePort(),
                ldkPeerListeningPort = freePort(),
                network = "regtest",
                maxMediaUploadSizeMb = 20u,
                enableVirtualChannelsV0 = false,
                virtualPeerPubkeys = null,
                lspBaseUrl = null,
                lspBearerToken = null,
            )
        )
    try {
        node.initWithNativeExternalSigner(signer)
        node.unlockWithNativeExternalSigner(
            signer,
            bitcoindUser,
            bitcoindPassword,
            bitcoindHost,
            bitcoindPort,
            indexerUrl,
            proxyEndpoint,
            emptyList(),
            "kotlin_ext_smoke",
        )
        val info = node.nodeInfo()
        require(info.numChannels == 0UL) { "expected zero channels in smoke test" }
        val address = node.address()
        require(address.address.isNotEmpty()) { "expected non-empty on-chain address" }
        println("Kotlin external-signer smoke OK (pubkey prefix=${"${info.pubkey}".take(12)}...)")
    } finally {
        node.shutdown()
        signer.close()
    }
}
