import org.utexo.rgblightningnode.AssetRecipients
import org.utexo.rgblightningnode.AssignmentKind
import org.utexo.rgblightningnode.ContractId
import org.utexo.rgblightningnode.HtlcStatus
import org.utexo.rgblightningnode.InvoiceStatus
import org.utexo.rgblightningnode.LnInvoiceRequest
import org.utexo.rgblightningnode.Payment
import org.utexo.rgblightningnode.PaymentHash
import org.utexo.rgblightningnode.PaymentType
import org.utexo.rgblightningnode.RgbRecipient
import org.utexo.rgblightningnode.RlnException
import org.utexo.rgblightningnode.SdkCloseChannelRequest
import org.utexo.rgblightningnode.SdkCreateUtxosRequest
import org.utexo.rgblightningnode.SdkInitRequest
import org.utexo.rgblightningnode.SdkIssueAssetNiaRequest
import org.utexo.rgblightningnode.SdkKeysendRequest
import org.utexo.rgblightningnode.SdkNode
import org.utexo.rgblightningnode.SdkOpenChannelRequest
import org.utexo.rgblightningnode.SdkRefreshTransfersRequest
import org.utexo.rgblightningnode.SdkRgbInvoiceRequest
import org.utexo.rgblightningnode.SdkSendPaymentRequest
import org.utexo.rgblightningnode.SdkUnlockRequest
import org.utexo.rgblightningnode.SendRgbRequest
import org.utexo.rgblightningnode.Txid
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.MessageDigest
import kotlin.io.path.exists
import kotlin.io.path.pathString

private val REPO_ROOT: Path = Paths.get("").toAbsolutePath().normalize()
private val E2E_ROOT: Path = REPO_ROOT.resolve("target/uniffi/kotlin-e2e")

private val NODE_A_DAEMON_PORT: UShort = env("NODE_A_DAEMON_PORT", "3411").toUShort()
private val NODE_B_DAEMON_PORT: UShort = env("NODE_B_DAEMON_PORT", "3412").toUShort()
private val NODE_C_DAEMON_PORT: UShort = env("NODE_C_DAEMON_PORT", "3413").toUShort()
private val NODE_A_PEER_PORT: UShort = env("NODE_A_PEER_PORT", "10111").toUShort()
private val NODE_B_PEER_PORT: UShort = env("NODE_B_PEER_PORT", "10112").toUShort()
private val NODE_C_PEER_PORT: UShort = env("NODE_C_PEER_PORT", "10113").toUShort()

private val NODE_A_PASSWORD: String = env("NODE_A_PASSWORD", "nodeApass")
private val NODE_B_PASSWORD: String = env("NODE_B_PASSWORD", "nodeBpass")
private val NODE_C_PASSWORD: String = env("NODE_C_PASSWORD", "nodeCpass")

private val OPEN_CHANNEL_CAPACITY_SAT: ULong = env("OPEN_CHANNEL_CAPACITY_SAT", "500000").toULong()
private val OPEN_CHANNEL_PUSH_MSAT: ULong = env("OPEN_CHANNEL_PUSH_MSAT", "0").toULong()
private val PAYMENT_MSAT: ULong = env("PAYMENT_MSAT", "3000000").toULong()
private val CREATE_UTXOS_NUM: UByte = env("CREATE_UTXOS_NUM", "10").toUByte()
private val CREATE_UTXOS_SIZE_SAT: UInt = env("CREATE_UTXOS_SIZE_SAT", "100000").toUInt()
private val CREATE_UTXOS_FEE_RATE: ULong = env("CREATE_UTXOS_FEE_RATE", "1").toULong()
private val ISSUE_ASSET_TICKER: String = env("ISSUE_ASSET_TICKER", "USDT")
private val ISSUE_ASSET_NAME: String = env("ISSUE_ASSET_NAME", "Tether")
private val ISSUE_ASSET_PRECISION: UByte = env("ISSUE_ASSET_PRECISION", "0").toUByte()
private val ISSUE_ASSET_SUPPLY: ULong = env("ISSUE_ASSET_SUPPLY", "1000").toULong()
private val OPEN_CHANNEL_ASSET_AMOUNT: ULong = env("OPEN_CHANNEL_ASSET_AMOUNT", "200").toULong()
private val PAYMENT_ASSET_AMOUNT: ULong = env("PAYMENT_ASSET_AMOUNT", "50").toULong()
private const val OPEN_CHANNEL_CONFIRM_BLOCKS: Int = 6
private val CHANNEL_FUNDING_TX_TIMEOUT_SEC: Long = env("CHANNEL_FUNDING_TX_TIMEOUT_SEC", "240").toLong()
private val CHANNEL_CONFIRM_TIMEOUT_SEC: Long = env("CHANNEL_CONFIRM_TIMEOUT_SEC", "200").toLong()
private val CHANNEL_READY_TIMEOUT_SEC: Long = env("CHANNEL_READY_TIMEOUT_SEC", "60").toLong()
private val CHANNEL_COUNT_TIMEOUT_SEC: Long = env("CHANNEL_COUNT_TIMEOUT_SEC", "60").toLong()
private val BALANCE_TIMEOUT_SEC: Long = env("BALANCE_TIMEOUT_SEC", "240").toLong()
private val PAYMENT_TIMEOUT_SEC: Long = env("PAYMENT_TIMEOUT_SEC", "160").toLong()
private val RESET_DATA: Boolean = env("RESET_DATA", "1") == "1"
private val SCENARIO: String = env("KOTLIN_E2E_SCENARIO", "payment")

private const val RGB_MIN_HTLC_MSAT: ULong = 3_000_000UL
private const val PROXY_ENDPOINT_LOCAL: String = "rpc://127.0.0.1:3000/json-rpc"

private fun env(name: String, default: String): String = System.getenv(name) ?: default

private fun scenarioStorage(scenario: String, nodeName: String): Path =
    E2E_ROOT.resolve("data/$scenario/$nodeName")

private fun runCommand(vararg args: String): String {
    val process = ProcessBuilder(*args)
        .directory(REPO_ROOT.toFile())
        .redirectErrorStream(true)
        .start()
    val output = process.inputStream.bufferedReader().readText()
    val exitCode = process.waitFor()
    check(exitCode == 0) {
        "command failed (${args.joinToString(" ")}):\n${output.trim()}"
    }
    return output.trim()
}

private fun runRegtest(vararg args: String): String = runCommand("./regtest.sh", *args)

private fun ensureDir(path: Path) {
    if (RESET_DATA && path.exists()) {
        path.toFile().deleteRecursively()
    }
    Files.createDirectories(path)
}

private fun makeNode(storageDir: Path, daemonPort: UShort, peerPort: UShort): SdkNode {
    return SdkNode.create(
            SdkInitRequest(
                storageDirPath = storageDir.pathString,
                daemonListeningPort = daemonPort,
                ldkPeerListeningPort = peerPort,
                network = "regtest",
                maxMediaUploadSizeMb = 20u,
                enableVirtualChannelsV0 = false,
                virtualPeerPubkeys = null,
                lspBaseUrl = null,
                lspBearerToken = null,
            )
        )
    }

private fun unlockRequest(password: String): SdkUnlockRequest {
    return SdkUnlockRequest(
        password = password,
        bitcoindRpcUsername = "user",
        bitcoindRpcPassword = "password",
        bitcoindRpcHost = "localhost",
        bitcoindRpcPort = 18443u,
        indexerUrl = "127.0.0.1:50001",
        proxyEndpoint = PROXY_ENDPOINT_LOCAL,
        announceAddresses = emptyList(),
        announceAlias = null,
    )
}

private fun initIfNeeded(node: SdkNode, password: String, name: String) {
    try {
        val mnemonic = node.init(password, null)
        println("$name: initialized")
        println("$name: mnemonic[0..20]=${mnemonic.take(20)}...")
    } catch (_: RlnException.Conflict) {
        println("$name: already initialized")
    }
}

private fun unlockIfNeeded(node: SdkNode, password: String, name: String) {
    var unlockState = "unlocked"
    try {
        node.unlock(unlockRequest(password))
    } catch (_: RlnException.Conflict) {
        unlockState = "already unlocked"
    }
    try {
        node.nodeInfo()
    } catch (_: RlnException.NotInitialized) {
        error("$name: unlock did not leave node usable (state=$unlockState)")
    }
    println("$name: $unlockState")
}

private fun createUtxos(node: SdkNode, name: String) {
    node.createutxos(
        SdkCreateUtxosRequest(
            upTo = false,
            num = CREATE_UTXOS_NUM,
            size = CREATE_UTXOS_SIZE_SAT,
            feeRate = CREATE_UTXOS_FEE_RATE,
            skipSync = false,
        )
    )
    println("$name: createutxos done")
}

private fun issueAssetNia(node: SdkNode, name: String): ContractId {
    val asset = node.issueassetnia(
        SdkIssueAssetNiaRequest(
            amounts = listOf(ISSUE_ASSET_SUPPLY),
            ticker = ISSUE_ASSET_TICKER,
            name = ISSUE_ASSET_NAME,
            precision = ISSUE_ASSET_PRECISION,
        )
    )
    println("$name: issued NIA asset_id=${asset.assetId}")
    return asset.assetId
}

private fun ensureFundedWithAmount(
    node: SdkNode,
    name: String,
    minSpendableSat: ULong,
    amountBtc: String,
) {
    val spendable = node.btcBalance(false).vanilla.spendable
    println("$name spendable sats: $spendable")
    if (spendable >= minSpendableSat) {
        return
    }

    val address = node.address().address
    println("Funding $name address $address with $amountBtc BTC on regtest")
    runRegtest("sendtoaddress", address, amountBtc)
    runRegtest("mine", "6")
    node.sync()

    val spendableAfter = node.btcBalance(false).vanilla.spendable
    println("$name spendable sats after funding: $spendableAfter")
    check(spendableAfter >= minSpendableSat) {
        "$name spendable balance still too low: $spendableAfter < $minSpendableSat"
    }
}

// Align with Python E2E: pass explicit UTXO size instead of null
// to ensure deterministic UTXO layout for channel funding.
private fun fundAndCreateUtxos(node: SdkNode, name: String) {
    ensureFundedWithAmount(node, name, 1u, "1")
    node.createutxos(
        SdkCreateUtxosRequest(
            upTo = false,
            num = CREATE_UTXOS_NUM,
            size = CREATE_UTXOS_SIZE_SAT,
            feeRate = 7u,
            skipSync = false,
        )
    )
    println("$name: createutxos done")
    runRegtest("mine", "1")
    node.sync()
}

private fun assetBalanceSpendable(node: SdkNode, assetId: ContractId): ULong =
    node.assetBalance(assetId).spendable

private fun assetBalanceOffchainOutbound(node: SdkNode, assetId: ContractId): ULong =
    node.assetBalance(assetId).offchainOutbound

private fun channelMatchesAsset(channelAssetId: ContractId?, expectedAssetId: ContractId?): Boolean {
    return if (expectedAssetId != null) {
        channelAssetId == expectedAssetId
    } else {
        channelAssetId == null
    }
}

private fun waitForChannelFundingTx(
    nodeA: SdkNode,
    nodeB: SdkNode,
    assetId: ContractId?,
    timeoutSec: Long,
): Txid {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var lastSummary = "no channels"
    while (System.currentTimeMillis() < deadline) {
        nodeA.sync()
        nodeB.sync()
        lastSummary = nodeA.listChannels().joinToString { channel ->
            "id=${channel.channelId},asset=${channel.assetId},funding=${channel.fundingTxid},usable=${channel.isUsable}"
        }.ifEmpty { "no channels" }
        val opening = nodeA.listChannels().firstOrNull {
            channelMatchesAsset(it.assetId, assetId) && it.fundingTxid != null
        }
        if (opening != null) {
            println("channel funding tx found: ${opening.fundingTxid}")
            return requireNotNull(opening.fundingTxid)
        }
        println("waiting for channel funding tx broadcast...")
        Thread.sleep(1000L)
    }
    error("No funding tx after ${timeoutSec}s for assetId=$assetId; last_channels=$lastSummary")
}

private fun mineUntilTxConfirmed(
    node: SdkNode,
    txid: Txid,
    timeoutSec: Long = CHANNEL_CONFIRM_TIMEOUT_SEC,
) {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    while (System.currentTimeMillis() < deadline) {
        node.sync()
        val tx = node.listTransactions(false).firstOrNull { it.txid == txid }
        if (tx != null && tx.confirmationTime != null) {
            println("funding tx confirmed in block: $txid")
            return
        }
        println("waiting for funding tx to be included in a block...")
        runRegtest("mine", "1")
        Thread.sleep(1000L)
    }
    error("funding tx was not confirmed before timeout: txid=$txid")
}

private fun confirmChannelFunding(
    node: SdkNode,
    assetId: ContractId?,
    fundingTxid: Txid,
) {
    if (assetId != null) {
        println("Mining blocks one by one until funding tx is confirmed...")
        mineUntilTxConfirmed(node, fundingTxid, CHANNEL_CONFIRM_TIMEOUT_SEC)
    }
    println("Mining $OPEN_CHANNEL_CONFIRM_BLOCKS blocks for channel confirmations...")
    runRegtest("mine", OPEN_CHANNEL_CONFIRM_BLOCKS.toString())
}

private fun waitForUsableChannel(
    nodeA: SdkNode,
    nodeB: SdkNode,
    assetId: ContractId?,
    timeoutSec: Long,
    mineEveryPolls: Int = 5,
) {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var polls = 0
    var lastSummary = "no channels"
    while (System.currentTimeMillis() < deadline) {
        polls += 1
        nodeA.sync()
        nodeB.sync()
        lastSummary = nodeA.listChannels().joinToString { channel ->
            "id=${channel.channelId},asset=${channel.assetId},ready=${channel.ready},usable=${channel.isUsable}"
        }.ifEmpty { "no channels" }
        val ready = nodeA.listChannels().any { it.isUsable && channelMatchesAsset(it.assetId, assetId) }
        if (ready) {
            return
        }
        if (mineEveryPolls > 0 && polls % mineEveryPolls == 0) {
            println("channel not usable yet, mining 1 block...")
            runRegtest("mine", "1")
        }
        println("waiting for usable channel...")
        Thread.sleep(2000L)
    }
    error("No usable channel after ${timeoutSec}s for assetId=$assetId; last_channels=$lastSummary")
}

private fun waitForUsableChannels(node: SdkNode, expected: Int, timeoutSec: Long) {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var lastUsable = -1
    while (System.currentTimeMillis() < deadline) {
        node.sync()
        val usable = node.listChannels().count { it.ready && it.isUsable }
        lastUsable = usable
        if (usable == expected) {
            return
        }
        Thread.sleep(1000L)
    }
    error("usable channel count did not become expected=$expected actual=$lastUsable after ${timeoutSec}s")
}

private fun waitForPeer(node: SdkNode, peerPubkey: Any, timeoutSec: Long) {
    val expected = peerPubkey.toString()
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    while (System.currentTimeMillis() < deadline) {
        if (node.listPeers().any { it.pubkey.toString() == expected }) {
            return
        }
        println("waiting for peer connection: $expected")
        Thread.sleep(1000L)
    }
    error("peer did not appear in listPeers() after ${timeoutSec}s: peer=$expected")
}

private fun waitForBalance(node: SdkNode, assetId: ContractId, expected: ULong, timeoutSec: Long) {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var lastBalance = 0uL
    while (System.currentTimeMillis() < deadline) {
        val balance = assetBalanceSpendable(node, assetId)
        lastBalance = balance
        if (balance == expected) {
            return
        }
        node.refreshtransfers(SdkRefreshTransfersRequest(skipSync = false))
        Thread.sleep(1000L)
    }
    error("spendable balance did not become expected=$expected actual=$lastBalance assetId=$assetId after ${timeoutSec}s")
}

private fun waitForLnBalance(node: SdkNode, assetId: ContractId, expected: ULong, timeoutSec: Long) {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var lastBalance = 0uL
    while (System.currentTimeMillis() < deadline) {
        val balance = assetBalanceOffchainOutbound(node, assetId)
        lastBalance = balance
        if (balance == expected) {
            return
        }
        Thread.sleep(1000L)
    }
    error("offchain_outbound balance did not become expected=$expected actual=$lastBalance assetId=$assetId after ${timeoutSec}s")
}

private fun waitForPaymentStatus(
    node: SdkNode,
    paymentHash: PaymentHash,
    paymentType: PaymentType,
    timeoutSec: Long,
): Payment {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var lastStatus: String = "not found"
    while (System.currentTimeMillis() < deadline) {
        val payment = node.listPayments().firstOrNull {
            it.paymentHash == paymentHash && it.paymentType == paymentType
        }
        if (payment != null) {
            lastStatus = payment.status.name
            if (payment.status == HtlcStatus.SUCCEEDED) {
                return payment
            }
        }
        Thread.sleep(1000L)
    }
    error(
        "timeout waiting for payment success: paymentHash=$paymentHash paymentType=$paymentType " +
            "last_status=$lastStatus after ${timeoutSec}s"
    )
}

private fun waitForPaymentPresentInList(
    node: SdkNode,
    paymentHash: PaymentHash,
    paymentType: PaymentType,
    timeoutSec: Long,
): Payment {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var lastCount = 0
    while (System.currentTimeMillis() < deadline) {
        val payments = node.listPayments()
        lastCount = payments.size
        val payment = payments.firstOrNull {
            it.paymentHash == paymentHash && it.paymentType == paymentType
        }
        if (payment != null) {
            return payment
        }
        Thread.sleep(1000L)
    }
    error(
        "payment not found in listPayments: paymentHash=$paymentHash paymentType=$paymentType " +
            "list_size=$lastCount after ${timeoutSec}s"
    )
}

private fun hexToBytes(value: String): ByteArray {
    require(value.length % 2 == 0) { "hex string must have even length" }
    return ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }
}

private fun sha256Hex(bytes: ByteArray): String =
    MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }

private fun checkPreimageMatchesHash(payment: Payment, expectedPaymentHash: PaymentHash) {
    val paymentPreimage = requireNotNull(payment.preimage) { "payment preimage is null" }
    val paymentPreimageHash = sha256Hex(hexToBytes(paymentPreimage))
    check(paymentPreimageHash == expectedPaymentHash) {
        "payment preimage hash mismatch: expected=$expectedPaymentHash actual=$paymentPreimageHash"
    }
}

private fun waitPaymentFinal(node: SdkNode, invoice: String, timeoutSec: Long = PAYMENT_TIMEOUT_SEC): InvoiceStatus {
    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
    var last = InvoiceStatus.PENDING
    while (System.currentTimeMillis() < deadline) {
        node.sync()
        val status = node.invoiceStatus(invoice)
        last = status
        if (status == InvoiceStatus.SUCCEEDED || status == InvoiceStatus.FAILED || status == InvoiceStatus.EXPIRED) {
            return status
        }
        Thread.sleep(1000L)
    }
    error("Invoice did not finalize after ${timeoutSec}s, last=$last")
}

private fun keysend(
    sender: SdkNode,
    destPubkey: String,
    amtMsat: ULong?,
    assetId: ContractId?,
    assetAmount: ULong?,
): PaymentHash {
    val response = sender.keysend(
        SdkKeysendRequest(
            destPubkey = destPubkey,
            amtMsat = amtMsat ?: PAYMENT_MSAT,
            assetId = assetId,
            assetAmount = assetAmount,
        )
    )
    check(response.status == HtlcStatus.PENDING || response.status == HtlcStatus.SUCCEEDED) {
        "unexpected keysend status: ${response.status}"
    }
    waitForPaymentStatus(
        sender,
        response.paymentHash,
        PaymentType.OUTBOUND,
        PAYMENT_TIMEOUT_SEC,
    )
    return response.paymentHash
}

private fun keysendWithLnBalance(
    sender: SdkNode,
    receiver: SdkNode,
    destPubkey: String,
    amtMsat: ULong?,
    assetId: ContractId,
    assetAmount: ULong,
    initialSenderBalance: ULong,
    initialReceiverBalance: ULong,
) {
    val paymentHash = keysend(sender, destPubkey, amtMsat, assetId, assetAmount)
    waitForLnBalance(sender, assetId, initialSenderBalance - assetAmount, BALANCE_TIMEOUT_SEC)
    waitForLnBalance(receiver, assetId, initialReceiverBalance + assetAmount, BALANCE_TIMEOUT_SEC)
    waitForPaymentStatus(
        receiver,
        paymentHash,
        PaymentType.INBOUND_AUTO_CLAIM,
        PAYMENT_TIMEOUT_SEC,
    )
}

private fun closeChannel(node: SdkNode, channelId: String, peerPubkey: String, force: Boolean = false) {
    node.closechannel(
        SdkCloseChannelRequest(
            channelId = channelId,
            peerPubkey = peerPubkey,
            force = force,
        )
    )

    val deadline = System.currentTimeMillis() + 30_000L
    var lastChannels = "no channels"
    while (System.currentTimeMillis() < deadline) {
        val channels = node.listChannels()
        lastChannels = channels.joinToString { it.channelId }.ifEmpty { "no channels" }
        if (channels.none { it.channelId == channelId }) {
            runRegtest("mine", if (force) "144" else "6")
            return
        }
        Thread.sleep(1000L)
    }
    error("channel did not close in time: channelId=$channelId remaining_channels=$lastChannels")
}

private fun refreshTransfers(node: SdkNode) {
    node.refreshtransfers(SdkRefreshTransfersRequest(skipSync = false))
}

private fun dumpNodeState(name: String, node: SdkNode) {
    println("--- $name state dump ---")
    try {
        val channels = node.listChannels()
        println(
            "$name channels: " + channels.joinToString { channel ->
                "id=${channel.channelId},asset=${channel.assetId},ready=${channel.ready},usable=${channel.isUsable}," +
                    "localSat=${channel.localBalanceSat},outMsat=${channel.outboundBalanceMsat},inMsat=${channel.inboundBalanceMsat}," +
                    "assetLocal=${channel.assetLocalAmount},assetRemote=${channel.assetRemoteAmount}," +
                    "minHtlc=${channel.nextOutboundHtlcMinimumMsat},maxHtlc=${channel.nextOutboundHtlcLimitMsat}"
            }.ifEmpty { "no channels" }
        )
    } catch (t: Throwable) {
        println("$name channels: <error ${t::class.simpleName}: ${t.message}>")
    }
    try {
        val payments = node.listPayments()
        println(
            "$name payments: " + payments.joinToString { payment ->
                "hash=${payment.paymentHash},status=${payment.status},amtMsat=${payment.amtMsat},assetId=${payment.assetId},assetAmount=${payment.assetAmount}"
            }.ifEmpty { "no payments" }
        )
    } catch (t: Throwable) {
        println("$name payments: <error ${t::class.simpleName}: ${t.message}>")
    }
}

private fun safeShutdown(node: SdkNode?) {
    try {
        node?.shutdown()
    } catch (_: Exception) {
    }
}

private fun paymentScenario() {
    val nodeAStorage = scenarioStorage("payment", "node_a")
    val nodeBStorage = scenarioStorage("payment", "node_b")
    println("Kotlin UniFFI N2N payment flow")
    println("node A storage: $nodeAStorage")
    println("node B storage: $nodeBStorage")

    ensureDir(nodeAStorage)
    ensureDir(nodeBStorage)

    var nodeA: SdkNode? = null
    var nodeB: SdkNode? = null
    try {
        nodeA = makeNode(nodeAStorage, NODE_A_DAEMON_PORT, NODE_A_PEER_PORT)
        nodeB = makeNode(nodeBStorage, NODE_B_DAEMON_PORT, NODE_B_PEER_PORT)

        initIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        initIfNeeded(nodeB, NODE_B_PASSWORD, "node B")
        unlockIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        unlockIfNeeded(nodeB, NODE_B_PASSWORD, "node B")

        ensureFundedWithAmount(nodeA, "node A", OPEN_CHANNEL_CAPACITY_SAT + 200_000u, "0.02")
        ensureFundedWithAmount(nodeB, "node B", 200_000u, "0.02")

        createUtxos(nodeA, "node A")
        createUtxos(nodeB, "node B")
        runRegtest("mine", "1")
        nodeA.sync()
        nodeB.sync()

        val assetId = issueAssetNia(nodeA, "node A")

        val infoA = nodeA.nodeInfo()
        val infoB = nodeB.nodeInfo()
        println("node A pubkey: ${infoA.pubkey}")
        println("node B pubkey: ${infoB.pubkey}")

        val peerUri = "${infoB.pubkey}@127.0.0.1:${NODE_B_PEER_PORT.toInt()}"
        try {
            nodeA.connectpeer(peerUri)
            println("connectpeer: ok")
        } catch (_: RlnException.Conflict) {
            println("connectpeer: already connected")
        }
        waitForPeer(nodeA, infoB.pubkey, 20L)

        val openResponse = nodeA.openchannel(
            SdkOpenChannelRequest(
                peerPubkeyAndOptAddr = peerUri,
                capacitySat = OPEN_CHANNEL_CAPACITY_SAT,
                pushMsat = OPEN_CHANNEL_PUSH_MSAT,
                `public` = false,
                withAnchors = true,
                feeBaseMsat = null,
                feeProportionalMillionths = null,
                temporaryChannelId = null,
                assetId = assetId,
                assetAmount = OPEN_CHANNEL_ASSET_AMOUNT,
                pushAssetAmount = null,
                virtualOpenMode = null,
            )
        )
        println("openchannel temporary_channel_id: ${openResponse.temporaryChannelId}")

        val fundingTxid = waitForChannelFundingTx(nodeA, nodeB, assetId, timeoutSec = CHANNEL_FUNDING_TX_TIMEOUT_SEC)
        confirmChannelFunding(nodeA, assetId, fundingTxid)
        waitForUsableChannel(nodeA, nodeB, assetId, CHANNEL_READY_TIMEOUT_SEC, 5)
        println("Channel is usable")

        println("node A channels: ${nodeA.listChannels().size}")
        println("node B channels: ${nodeB.listChannels().size}")

        require(PAYMENT_MSAT >= RGB_MIN_HTLC_MSAT) {
            "PAYMENT_MSAT=$PAYMENT_MSAT is too low for RGB invoices, must be >= $RGB_MIN_HTLC_MSAT"
        }

        val invoice = nodeB.lnInvoice(
            LnInvoiceRequest(
                amtMsat = PAYMENT_MSAT,
                expirySec = 3600u,
                assetId = assetId,
                assetAmount = PAYMENT_ASSET_AMOUNT,
                descriptionHash = null,
                paymentHash = null,
                minFinalCltvExpiryDelta = null,
            )
        ).invoice
        println("invoice: $invoice")

        val paymentResponse = nodeA.sendpayment(
            SdkSendPaymentRequest(
                invoice = invoice,
                amtMsat = null,
                assetId = null,
                assetAmount = null,
            )
        )
        println("sendpayment status: ${paymentResponse.status.name}")
        println("sendpayment payment_id: ${paymentResponse.paymentId}")

        val finalStatus = waitPaymentFinal(nodeB, invoice)
        println("invoice final status on node B: ${finalStatus.name}")
        check(finalStatus == InvoiceStatus.SUCCEEDED) {
            "Payment did not succeed (status=$finalStatus)"
        }

        val decoded = nodeA.decodeLnInvoice(invoice)
        val senderPayment = waitForPaymentStatus(
            nodeA,
            decoded.paymentHash,
            PaymentType.OUTBOUND,
            PAYMENT_TIMEOUT_SEC,
        )
        val receiverPayment = waitForPaymentStatus(
            nodeB,
            decoded.paymentHash,
            PaymentType.INBOUND_AUTO_CLAIM,
            PAYMENT_TIMEOUT_SEC,
        )
        checkPreimageMatchesHash(senderPayment, decoded.paymentHash)
        checkPreimageMatchesHash(receiverPayment, decoded.paymentHash)

        val listedSenderPayment = waitForPaymentPresentInList(
            nodeA,
            decoded.paymentHash,
            PaymentType.OUTBOUND,
            PAYMENT_TIMEOUT_SEC,
        )
        check(listedSenderPayment.paymentHash == decoded.paymentHash)
        checkPreimageMatchesHash(listedSenderPayment, decoded.paymentHash)

        val listedReceiverPayment = waitForPaymentPresentInList(
            nodeB,
            decoded.paymentHash,
            PaymentType.INBOUND_AUTO_CLAIM,
            PAYMENT_TIMEOUT_SEC,
        )
        check(listedReceiverPayment.paymentHash == decoded.paymentHash)
        checkPreimageMatchesHash(listedReceiverPayment, decoded.paymentHash)

        println("SUCCESS: Kotlin SDK-only node-to-node payment completed")
    } finally {
        safeShutdown(nodeA)
        safeShutdown(nodeB)
    }
}

private fun openchannelPushAssetAmountScenario() {
    val scenario = "openchannel_push_asset_amount"
    val nodeAStorage = scenarioStorage(scenario, "node_a")
    val nodeBStorage = scenarioStorage(scenario, "node_b")
    val nodeCStorage = scenarioStorage(scenario, "node_c")
    val daemonOffset = 40u
    val peerOffset = 40u
    val channelCapacity = 100_000uL
    println("Kotlin UniFFI openchannel_push_asset_amount flow")
    println("node A storage: $nodeAStorage")
    println("node B storage: $nodeBStorage")
    println("node C storage: $nodeCStorage")

    ensureDir(nodeAStorage)
    ensureDir(nodeBStorage)
    ensureDir(nodeCStorage)

    var nodeA: SdkNode? = null
    var nodeB: SdkNode? = null
    var nodeC: SdkNode? = null
    try {
        nodeA = makeNode(nodeAStorage, (NODE_A_DAEMON_PORT.toUInt() + daemonOffset).toUShort(), (NODE_A_PEER_PORT.toUInt() + peerOffset).toUShort())
        nodeB = makeNode(nodeBStorage, (NODE_B_DAEMON_PORT.toUInt() + daemonOffset).toUShort(), (NODE_B_PEER_PORT.toUInt() + peerOffset).toUShort())
        nodeC = makeNode(nodeCStorage, (NODE_C_DAEMON_PORT.toUInt() + daemonOffset).toUShort(), (NODE_C_PEER_PORT.toUInt() + peerOffset).toUShort())

        initIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        initIfNeeded(nodeB, NODE_B_PASSWORD, "node B")
        initIfNeeded(nodeC, NODE_C_PASSWORD, "node C")
        unlockIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        unlockIfNeeded(nodeB, NODE_B_PASSWORD, "node B")
        unlockIfNeeded(nodeC, NODE_C_PASSWORD, "node C")

        val nodeAPubkey = nodeA.nodeInfo().pubkey
        val nodeBPubkey = nodeB.nodeInfo().pubkey

        fundAndCreateUtxos(nodeA, "node A")
        fundAndCreateUtxos(nodeB, "node B")
        fundAndCreateUtxos(nodeC, "node C")

        val assetId = issueAssetNia(nodeA, "node A")
        val peerUri = "${nodeBPubkey}@127.0.0.1:${(NODE_B_PEER_PORT.toUInt() + peerOffset).toInt()}"
        nodeA.connectpeer(peerUri)
        waitForPeer(nodeA, nodeBPubkey, 20L)

        val partialPushChannel = nodeA.openchannel(
            SdkOpenChannelRequest(
                peerPubkeyAndOptAddr = peerUri,
                capacitySat = channelCapacity,
                pushMsat = 0u,
                `public` = true,
                withAnchors = true,
                feeBaseMsat = null,
                feeProportionalMillionths = null,
                temporaryChannelId = null,
                assetId = assetId,
                assetAmount = 600u,
                pushAssetAmount = 250u,
                virtualOpenMode = null,
            )
        )

        var fundingTxid = waitForChannelFundingTx(nodeA, nodeB, assetId, CHANNEL_FUNDING_TX_TIMEOUT_SEC)
        confirmChannelFunding(nodeA, assetId, fundingTxid)
        // Wait for channel usable on both sides before attempting keysend.
        waitForUsableChannel(nodeA, nodeB, assetId, CHANNEL_READY_TIMEOUT_SEC)
        waitForUsableChannel(nodeB, nodeA, assetId, CHANNEL_READY_TIMEOUT_SEC)

        val partialChannelId = nodeA.getChannelId(partialPushChannel.temporaryChannelId)
        val nodeAPartial = nodeA.listChannels().first { it.channelId == partialChannelId }
        val nodeBPartial = nodeB.listChannels().first { it.channelId == partialChannelId }
        check(nodeAPartial.assetLocalAmount == 350uL && nodeAPartial.assetRemoteAmount == 250uL)
        check(nodeBPartial.assetLocalAmount == 250uL && nodeBPartial.assetRemoteAmount == 350uL)

        keysendWithLnBalance(nodeA, nodeB, nodeBPubkey, null, assetId, 100u, 350u, 250u)
        dumpNodeState("node A after asset keysend", nodeA)
        dumpNodeState("node B after asset keysend", nodeB)
        println("attempting plain BTC keysend on partially pushed RGB channel")
        dumpNodeState("node A before BTC keysend", nodeA)
        dumpNodeState("node B before BTC keysend", nodeB)
        try {
            keysend(nodeA, nodeBPubkey, 10_000_000u, null, null)
        } catch (t: Throwable) {
            println("plain BTC keysend failed, dumping node state")
            dumpNodeState("node A after BTC keysend failure", nodeA)
            dumpNodeState("node B after BTC keysend failure", nodeB)
            throw t
        }
        keysendWithLnBalance(nodeB, nodeA, nodeAPubkey, null, assetId, 50u, 350u, 250u)

        val nodeAPartialAfter = nodeA.listChannels().first { it.channelId == partialChannelId }
        val nodeBPartialAfter = nodeB.listChannels().first { it.channelId == partialChannelId }
        check(nodeAPartialAfter.assetLocalAmount == 300uL && nodeAPartialAfter.assetRemoteAmount == 300uL)
        check(nodeBPartialAfter.assetLocalAmount == 300uL && nodeBPartialAfter.assetRemoteAmount == 300uL)

        closeChannel(nodeA, partialChannelId, nodeBPubkey)
        waitForBalance(nodeA, assetId, 700u, BALANCE_TIMEOUT_SEC)
        waitForBalance(nodeB, assetId, 300u, BALANCE_TIMEOUT_SEC)

        val fullPushChannel = nodeA.openchannel(
            SdkOpenChannelRequest(
                peerPubkeyAndOptAddr = peerUri,
                capacitySat = channelCapacity,
                pushMsat = 0u,
                `public` = true,
                withAnchors = true,
                feeBaseMsat = null,
                feeProportionalMillionths = null,
                temporaryChannelId = null,
                assetId = assetId,
                assetAmount = 600u,
                pushAssetAmount = 600u,
                virtualOpenMode = null,
            )
        )

        fundingTxid = waitForChannelFundingTx(nodeA, nodeB, assetId, CHANNEL_FUNDING_TX_TIMEOUT_SEC)
        confirmChannelFunding(nodeA, assetId, fundingTxid)
        waitForUsableChannel(nodeA, nodeB, assetId, CHANNEL_READY_TIMEOUT_SEC)

        // This scenario intentionally restarts node A and node B mid-run on the same storage dirs.
        nodeA.shutdown()
        nodeB.shutdown()
        nodeA = makeNode(nodeAStorage, (NODE_A_DAEMON_PORT.toUInt() + daemonOffset).toUShort(), (NODE_A_PEER_PORT.toUInt() + peerOffset).toUShort())
        nodeB = makeNode(nodeBStorage, (NODE_B_DAEMON_PORT.toUInt() + daemonOffset).toUShort(), (NODE_B_PEER_PORT.toUInt() + peerOffset).toUShort())
        nodeA.unlock(unlockRequest(NODE_A_PASSWORD))
        nodeB.unlock(unlockRequest(NODE_B_PASSWORD))

        waitForUsableChannels(nodeA, 1, CHANNEL_COUNT_TIMEOUT_SEC)
        waitForUsableChannels(nodeB, 1, CHANNEL_COUNT_TIMEOUT_SEC)

        check(assetBalanceSpendable(nodeA, assetId) == 100uL)
        check(assetBalanceSpendable(nodeB, assetId) == 300uL)

        val fullChannelId = nodeA.getChannelId(fullPushChannel.temporaryChannelId)
        val nodeAFull = nodeA.listChannels().first { it.channelId == fullChannelId }
        val nodeBFull = nodeB.listChannels().first { it.channelId == fullChannelId }
        check(nodeAFull.assetLocalAmount == 0uL && nodeAFull.assetRemoteAmount == 600uL)
        check(nodeBFull.assetLocalAmount == 600uL && nodeBFull.assetRemoteAmount == 0uL)

        keysend(nodeA, nodeBPubkey, 10_000_000u, null, null)
        keysendWithLnBalance(nodeB, nodeA, nodeAPubkey, null, assetId, 100u, 600u, 0u)

        val nodeAFullAfter = nodeA.listChannels().first { it.channelId == fullChannelId }
        val nodeBFullAfter = nodeB.listChannels().first { it.channelId == fullChannelId }
        check(nodeAFullAfter.assetLocalAmount == 100uL && nodeAFullAfter.assetRemoteAmount == 500uL)
        check(nodeBFullAfter.assetLocalAmount == 500uL && nodeBFullAfter.assetRemoteAmount == 100uL)

        closeChannel(nodeA, fullChannelId, nodeBPubkey)
        waitForBalance(nodeA, assetId, 200u, BALANCE_TIMEOUT_SEC)
        waitForBalance(nodeB, assetId, 800u, BALANCE_TIMEOUT_SEC)

        val recipientId = nodeC.rgbinvoice(
            SdkRgbInvoiceRequest(
                assetId = null,
                assignmentKind = null,
                assignmentAmount = null,
                durationSeconds = null,
                minConfirmations = 1u,
                witness = false,
            )
        ).recipientId

        nodeB.sendRgb(
            SendRgbRequest(
                donation = true,
                feeRate = CREATE_UTXOS_FEE_RATE,
                minConfirmations = 1u,
                recipientGroups = listOf(
                    AssetRecipients(
                        assetId = assetId,
                        recipients = listOf(
                            RgbRecipient(
                                recipientId = recipientId,
                                witnessData = null,
                                assignmentKind = AssignmentKind.FUNGIBLE,
                                assignmentAmount = 100u,
                                transportEndpoints = listOf(PROXY_ENDPOINT_LOCAL),
                            )
                        ),
                    )
                ),
            )
        )
        runRegtest("mine", "1")
        refreshTransfers(nodeC)
        refreshTransfers(nodeC)
        refreshTransfers(nodeB)
        refreshTransfers(nodeB)

        check(assetBalanceSpendable(nodeA, assetId) == 200uL)
        check(assetBalanceSpendable(nodeB, assetId) == 700uL)
        check(assetBalanceSpendable(nodeC, assetId) == 100uL)

        println("SUCCESS: Kotlin openchannel_push_asset_amount completed")
    } finally {
        safeShutdown(nodeA)
        safeShutdown(nodeB)
        safeShutdown(nodeC)
    }
}

private fun closeCoopVanillaScenario(name: String, portOffset: UInt, withAnchors: Boolean) {
    val nodeAStorage = scenarioStorage(name, "node_a")
    val nodeBStorage = scenarioStorage(name, "node_b")
    val nodeCStorage = scenarioStorage(name, "node_c")
    val minSpendableBalanceAfterSetup = 90_000_000uL

    println("Kotlin UniFFI $name flow")
    println("node A storage: $nodeAStorage")
    println("node B storage: $nodeBStorage")
    println("node C storage: $nodeCStorage")

    ensureDir(nodeAStorage)
    ensureDir(nodeBStorage)
    ensureDir(nodeCStorage)

    var nodeA: SdkNode? = null
    var nodeB: SdkNode? = null
    var nodeC: SdkNode? = null
    try {
        nodeA = makeNode(
            nodeAStorage,
            (NODE_A_DAEMON_PORT.toUInt() + portOffset).toUShort(),
            (NODE_A_PEER_PORT.toUInt() + portOffset).toUShort(),
        )
        nodeB = makeNode(
            nodeBStorage,
            (NODE_B_DAEMON_PORT.toUInt() + portOffset).toUShort(),
            (NODE_B_PEER_PORT.toUInt() + portOffset).toUShort(),
        )
        nodeC = makeNode(
            nodeCStorage,
            (NODE_C_DAEMON_PORT.toUInt() + portOffset).toUShort(),
            (NODE_C_PEER_PORT.toUInt() + portOffset).toUShort(),
        )

        initIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        initIfNeeded(nodeB, NODE_B_PASSWORD, "node B")
        initIfNeeded(nodeC, NODE_C_PASSWORD, "node C")
        unlockIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        unlockIfNeeded(nodeB, NODE_B_PASSWORD, "node B")
        unlockIfNeeded(nodeC, NODE_C_PASSWORD, "node C")

        check(nodeA.listUnspents(false).isEmpty()) { "node A should start with 0 unspents" }

        fundAndCreateUtxos(nodeA, "node A")
        fundAndCreateUtxos(nodeB, "node B")
        fundAndCreateUtxos(nodeC, "node C")

        check(nodeA.btcBalance(false).vanilla.spendable >= minSpendableBalanceAfterSetup)
        check(nodeB.btcBalance(false).vanilla.spendable >= minSpendableBalanceAfterSetup)
        check(nodeC.btcBalance(false).vanilla.spendable >= minSpendableBalanceAfterSetup)

        val nodeAPubkey = nodeA.nodeInfo().pubkey
        val nodeBPubkey = nodeB.nodeInfo().pubkey

        val peersBefore = nodeA.listPeers()
        check(peersBefore.none { it.pubkey == nodeBPubkey }) { "node B should not be in peers yet" }

        val peerUri = "${nodeBPubkey}@127.0.0.1:${(NODE_B_PEER_PORT.toUInt() + portOffset).toInt()}"
        nodeA.connectpeer(peerUri)
        waitForPeer(nodeA, nodeBPubkey, 20L)

        val openChannel = nodeA.openchannel(
            SdkOpenChannelRequest(
                peerPubkeyAndOptAddr = peerUri,
                capacitySat = 600_000u,
                pushMsat = 300_000_000u,
                `public` = true,
                withAnchors = withAnchors,
                feeBaseMsat = null,
                feeProportionalMillionths = null,
                temporaryChannelId = null,
                assetId = null,
                assetAmount = null,
                pushAssetAmount = null,
                virtualOpenMode = null,
            )
        )

        val fundingTxid = waitForChannelFundingTx(nodeA, nodeB, null, CHANNEL_FUNDING_TX_TIMEOUT_SEC)
        confirmChannelFunding(nodeA, null, fundingTxid)
        waitForUsableChannel(nodeA, nodeB, null, CHANNEL_READY_TIMEOUT_SEC, mineEveryPolls = 5)
        val channelId = nodeA.getChannelId(openChannel.temporaryChannelId)

        keysend(nodeA, nodeBPubkey, 10_000_000u, null, null)
        keysend(nodeB, nodeAPubkey, 10_000_000u, null, null)
        check(nodeA.listPayments().size == 2) { "node A should have 2 payments after vanilla keysend pair" }
        check(nodeB.listPayments().size == 2) { "node B should have 2 payments after vanilla keysend pair" }

        val invoice = nodeA.lnInvoice(
            LnInvoiceRequest(
                amtMsat = 50_000_000u,
                expirySec = 900u,
                assetId = null,
                assetAmount = null,
                descriptionHash = null,
                paymentHash = null,
                minFinalCltvExpiryDelta = null,
            )
        ).invoice
        val sendPayment = nodeB.sendpayment(
            SdkSendPaymentRequest(
                invoice = invoice,
                amtMsat = null,
                assetId = null,
                assetAmount = null,
            )
        )
        val paymentHash = requireNotNull(sendPayment.paymentHash) { "vanilla payment hash missing" }
        waitForPaymentStatus(
            nodeB,
            paymentHash,
            PaymentType.OUTBOUND,
            PAYMENT_TIMEOUT_SEC,
        )
        waitForPaymentPresentInList(
            nodeA,
            paymentHash,
            PaymentType.INBOUND_AUTO_CLAIM,
            PAYMENT_TIMEOUT_SEC,
        )
        check(nodeA.listPayments().size == 3) { "node A should have 3 payments after invoice payment" }
        check(nodeB.listPayments().size == 3) { "node B should have 3 payments after invoice payment" }

        closeChannel(nodeA, channelId, nodeBPubkey)
        waitForUsableChannels(nodeA, 0, CHANNEL_COUNT_TIMEOUT_SEC)
        waitForUsableChannels(nodeB, 0, CHANNEL_COUNT_TIMEOUT_SEC)

        println("SUCCESS: Kotlin $name completed")
    } finally {
        safeShutdown(nodeA)
        safeShutdown(nodeB)
        safeShutdown(nodeC)
    }
}

private fun expectOpenchannelWithoutAddrFails(
    opener: SdkNode,
    peerPubkeyOnly: String,
    assetId: ContractId,
) {
    try {
        opener.openchannel(
            SdkOpenChannelRequest(
                peerPubkeyAndOptAddr = peerPubkeyOnly,
                capacitySat = 100_000u,
                pushMsat = 3_500_000u,
                `public` = true,
                withAnchors = true,
                feeBaseMsat = null,
                feeProportionalMillionths = null,
                temporaryChannelId = null,
                assetId = assetId,
                assetAmount = 600u,
                pushAssetAmount = null,
                virtualOpenMode = null,
            )
        )
        error("openchannel without addr should fail when peer is not connected")
    } catch (e: RlnException.InvalidRequest) {
        // SDK/UniFFI preserves the public error category, not the HTTP-style detail string.
    }
}

private fun openchannelOptionalAddrScenario(
    name: String,
    portOffset: UInt,
    issueOnNodeA: Boolean,
) {
    val nodeAStorage = scenarioStorage(name, "node_a")
    val nodeBStorage = scenarioStorage(name, "node_b")

    println("Kotlin UniFFI $name flow")
    println("node A storage: $nodeAStorage")
    println("node B storage: $nodeBStorage")

    ensureDir(nodeAStorage)
    ensureDir(nodeBStorage)

    var nodeA: SdkNode? = null
    var nodeB: SdkNode? = null
    try {
        nodeA = makeNode(
            nodeAStorage,
            (NODE_A_DAEMON_PORT.toUInt() + portOffset).toUShort(),
            (NODE_A_PEER_PORT.toUInt() + portOffset).toUShort(),
        )
        nodeB = makeNode(
            nodeBStorage,
            (NODE_B_DAEMON_PORT.toUInt() + portOffset).toUShort(),
            (NODE_B_PEER_PORT.toUInt() + portOffset).toUShort(),
        )

        initIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        initIfNeeded(nodeB, NODE_B_PASSWORD, "node B")
        unlockIfNeeded(nodeA, NODE_A_PASSWORD, "node A")
        unlockIfNeeded(nodeB, NODE_B_PASSWORD, "node B")

        fundAndCreateUtxos(nodeA, "node A")
        fundAndCreateUtxos(nodeB, "node B")

        val nodeAPubkey = nodeA.nodeInfo().pubkey
        val nodeBPubkey = nodeB.nodeInfo().pubkey

        if (issueOnNodeA) {
            val assetId = issueAssetNia(nodeA, "node A")

            println("opening channel with no addr (peer not connected)")
            expectOpenchannelWithoutAddrFails(nodeA, nodeBPubkey, assetId)
            check(nodeA.listChannels().isEmpty())
            check(nodeB.listChannels().isEmpty())

            println("connecting peer")
            nodeA.connectpeer("${nodeBPubkey}@127.0.0.1:${(NODE_B_PEER_PORT.toUInt() + portOffset).toInt()}")
            waitForPeer(nodeA, nodeBPubkey, 20L)

            println("opening channel with no addr (peer connected)")
            nodeA.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = nodeBPubkey,
                    capacitySat = 100_000u,
                    pushMsat = 3_500_000u,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = assetId,
                    assetAmount = 600u,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            val fundingTxid = waitForChannelFundingTx(nodeA, nodeB, assetId, CHANNEL_FUNDING_TX_TIMEOUT_SEC)
            confirmChannelFunding(nodeA, assetId, fundingTxid)
            waitForUsableChannel(nodeA, nodeB, assetId, CHANNEL_READY_TIMEOUT_SEC, 5)
            check(assetBalanceSpendable(nodeA, assetId) == 400uL)
            check(nodeA.listChannels().size == 1)
            check(nodeB.listChannels().size == 1)
        } else {
            val assetId = issueAssetNia(nodeB, "node B")

            println("opening channel with no addr (peer not connected)")
            expectOpenchannelWithoutAddrFails(nodeB, nodeAPubkey, assetId)
            check(nodeA.listChannels().isEmpty())
            check(nodeB.listChannels().isEmpty())

            println("connecting peer")
            nodeA.connectpeer("${nodeBPubkey}@127.0.0.1:${(NODE_B_PEER_PORT.toUInt() + portOffset).toInt()}")
            waitForPeer(nodeA, nodeBPubkey, 20L)

            println("opening channel with no addr (peer connected)")
            nodeB.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = nodeAPubkey,
                    capacitySat = 100_000u,
                    pushMsat = 3_500_000u,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = assetId,
                    assetAmount = 600u,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            val fundingTxid = waitForChannelFundingTx(nodeB, nodeA, assetId, CHANNEL_FUNDING_TX_TIMEOUT_SEC)
            confirmChannelFunding(nodeB, assetId, fundingTxid)
            waitForUsableChannel(nodeB, nodeA, assetId, CHANNEL_READY_TIMEOUT_SEC, 5)
            check(assetBalanceSpendable(nodeB, assetId) == 400uL)
            check(nodeA.listChannels().size == 1)
            check(nodeB.listChannels().size == 1)
        }

        println("SUCCESS: Kotlin $name completed")
    } finally {
        safeShutdown(nodeA)
        safeShutdown(nodeB)
    }
}

fun main() {
    when (SCENARIO) {
        "payment" -> paymentScenario()
        "openchannel_push_asset_amount" -> openchannelPushAssetAmountScenario()
        "close_coop_vanilla_with_anchors" ->
            closeCoopVanillaScenario("close_coop_vanilla_with_anchors", 80u, true)
        "close_coop_vanilla_without_anchors" ->
            closeCoopVanillaScenario("close_coop_vanilla_without_anchors", 90u, false)
        "openchannel_optional_addr_forward" ->
            openchannelOptionalAddrScenario("openchannel_optional_addr_forward", 120u, true)
        "openchannel_optional_addr_reverse" ->
            openchannelOptionalAddrScenario("openchannel_optional_addr_reverse", 130u, false)
        else -> error("Unsupported KOTLIN_E2E_SCENARIO=$SCENARIO")
    }
}
