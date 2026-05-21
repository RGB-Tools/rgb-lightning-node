package org.rgblightningnode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.runner.RunWith
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
import org.utexo.rgblightningnode.SdkNode
import org.utexo.rgblightningnode.SdkOpenChannelRequest
import org.utexo.rgblightningnode.SdkRefreshTransfersRequest
import org.utexo.rgblightningnode.SdkRgbInvoiceRequest
import org.utexo.rgblightningnode.SdkSendPaymentRequest
import org.utexo.rgblightningnode.SdkUnlockRequest
import org.utexo.rgblightningnode.SendRgbRequest
import org.utexo.rgblightningnode.TransactionType
import org.utexo.rgblightningnode.Txid
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class PaymentTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val storageBase = context.filesDir.absolutePath

    private val bitcoindHost = "10.0.2.2"
    private val bitcoindPort = 18443
    private val bitcoindUser = "user"
    private val bitcoindPass = "password"
    private val proxyEndpoint = "rpc://10.0.2.2:3000/json-rpc"

    private val nodeADaemonPort: UShort = 3711u
    private val nodeBDaemonPort: UShort = 3712u
    private val nodeCDaemonPort: UShort = 3713u
    private val nodeAPeerPort: UShort = 13111u
    private val nodeBPeerPort: UShort = 13112u
    private val nodeCPeerPort: UShort = 13113u

    private val channelCapacitySat: ULong = 100_000u
    private val channelPushMsat: ULong = 3_500_000u
    private val paymentMsat: ULong = 3_000_000u
    private val utxosNum: UByte = 10u
    private val utxosFeeRate: ULong = 7u
    private val assetSupply: ULong = 1000u
    private val channelAssetAmount: ULong = 600u
    private val channelReadyTimeoutSec: Long = 120L

    // ── Bitcoin RPC ──────────────────────────────────────────────────────────

    private fun bitcoindRpc(method: String, vararg params: Any): JSONObject {
        val url = URL("http://$bitcoindHost:$bitcoindPort/")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        val creds = Base64.getEncoder().encodeToString("$bitcoindUser:$bitcoindPass".toByteArray())
        conn.setRequestProperty("Authorization", "Basic $creds")

        val body = JSONObject().apply {
            put("jsonrpc", "1.0")
            put("id", "android-e2e")
            put("method", method)
            put("params", JSONArray().apply { params.forEach { put(it) } })
        }.toString()
        conn.outputStream.use { it.write(body.toByteArray()) }

        val response = conn.inputStream.bufferedReader().readText()
        return JSONObject(response)
    }

    private fun mine(blocks: Int) {
        val addrResp = bitcoindRpc("getnewaddress")
        val addr = addrResp.getString("result")
        bitcoindRpc("generatetoaddress", blocks, addr)
        log("mined $blocks block(s)")
    }

    private fun sendToAddress(address: String, amountBtc: String) {
        bitcoindRpc("sendtoaddress", address, amountBtc.toDouble())
        log("sent $amountBtc BTC to $address")
    }

    // ── Node helpers ─────────────────────────────────────────────────────────

    private fun makeNode(name: String, daemonPort: UShort, peerPort: UShort): SdkNode {
        return SdkNode.create(
            SdkInitRequest(
                storageDirPath = "$storageBase/$name",
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

    private fun unlockRequest(password: String) = SdkUnlockRequest(
        password = password,
        bitcoindRpcUsername = bitcoindUser,
        bitcoindRpcPassword = bitcoindPass,
        bitcoindRpcHost = bitcoindHost,
        bitcoindRpcPort = bitcoindPort.toUShort(),
        indexerUrl = "$bitcoindHost:50001",
        proxyEndpoint = proxyEndpoint,
        announceAddresses = listOf(),
        announceAlias = null,
    )

    private fun initNode(node: SdkNode, password: String, name: String) {
        node.init(password, null)
        log("$name: initialized")
    }

    private fun unlockNode(node: SdkNode, password: String, name: String) {
        node.unlock(unlockRequest(password))
        log("$name: unlocked")
    }

    private fun ensureFunded(node: SdkNode, name: String, minSat: ULong, amountBtc: String) {
        val spendable = node.btcBalance(false).vanilla.spendable
        log("$name spendable: $spendable sat")
        if (spendable >= minSat) return
        val address = node.address().address
        sendToAddress(address, amountBtc)
        mine(6)
        node.sync()
        val after = node.btcBalance(false).vanilla.spendable
        log("$name spendable after fund: $after sat")
        assertTrue("$name still underfunded: $after < $minSat", after >= minSat)
    }

    private fun fundAndCreateUtxos(node: SdkNode, name: String) {
        ensureFunded(node, name, 1u, "1")
        node.createutxos(
            SdkCreateUtxosRequest(
                upTo = false,
                num = utxosNum,
                size = null,
                feeRate = utxosFeeRate,
                skipSync = false,
            )
        )
        log("$name: createutxos done")
        mine(1)
        node.sync()
    }

    private fun assetBalanceSpendable(node: SdkNode, assetId: ContractId): ULong =
        node.assetBalance(assetId).spendable

    private fun assetBalanceOffchainOutbound(node: SdkNode, assetId: ContractId): ULong =
        node.assetBalance(assetId).offchainOutbound

    private fun waitForLnBalance(node: SdkNode, assetId: ContractId, expected: ULong, timeoutSec: Long) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastBalance = 0uL
        while (System.currentTimeMillis() < deadline) {
            val balance = assetBalanceOffchainOutbound(node, assetId)
            lastBalance = balance
            if (balance == expected) {
                return
            }
            Thread.sleep(1_000L)
        }
        error("offchain_outbound balance did not become expected=$expected actual=$lastBalance after ${timeoutSec}s")
    }

    private fun waitForBalance(node: SdkNode, assetId: ContractId, expected: ULong, timeoutSec: Long) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastBalance = 0uL
        while (System.currentTimeMillis() < deadline) {
            val balance = assetBalanceSpendable(node, assetId)
            lastBalance = balance
            if (balance == expected) {
                return
            }
            node.refreshtransfers(SdkRefreshTransfersRequest(skipSync = false))
            Thread.sleep(1_000L)
        }
        error("spendable balance did not become expected=$expected actual=$lastBalance after ${timeoutSec}s")
    }

    private fun waitForChannelFundingTx(nodeA: SdkNode, nodeB: SdkNode, assetId: ContractId, timeoutSec: Long): Txid {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        while (System.currentTimeMillis() < deadline) {
            nodeA.sync(); nodeB.sync()
            val opening = nodeA.listChannels().firstOrNull { it.assetId == assetId && it.fundingTxid != null }
            if (opening != null) {
                log("channel funding tx found: ${opening.fundingTxid}")
                return requireNotNull(opening.fundingTxid)
            }
            log("waiting for channel funding tx...")
            Thread.sleep(1_000L)
        }
        error("no channel funding tx after ${timeoutSec}s")
    }

    private fun mineUntilTxConfirmed(node: SdkNode, txid: Txid, timeoutSec: Long = 180L) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        while (System.currentTimeMillis() < deadline) {
            node.sync()
            val tx = node.listTransactions(false).firstOrNull { it.txid == txid }
            if (tx != null && tx.confirmationTime != null) {
                log("funding tx confirmed in block: $txid")
                return
            }
            log("waiting for funding tx to be included in a block...")
            mine(1)
            Thread.sleep(1_000L)
        }
        error("funding tx was not confirmed before timeout: txid=$txid")
    }

    private fun waitForUsableChannel(nodeA: SdkNode, nodeB: SdkNode, assetId: ContractId, timeoutSec: Long) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var polls = 0
        while (System.currentTimeMillis() < deadline) {
            polls++
            nodeA.sync(); nodeB.sync()
            val usable = nodeA.listChannels().any { it.isUsable && it.assetId == assetId }
            if (usable) { log("channel is usable"); return }
            if (polls % 5 == 0) { log("mining 1 block..."); mine(1) }
            log("waiting for usable channel... (poll $polls)")
            Thread.sleep(2_000L)
        }
        error("channel not usable after ${timeoutSec}s")
    }

    private fun waitForStableChannelBalances(
        nodeA: SdkNode,
        nodeB: SdkNode,
        channelId: String,
        expectedNodeABalance: ULong,
        expectedNodeBBalance: ULong,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastNodeABalance: ULong? = null
        var lastNodeBBalance: ULong? = null
        while (System.currentTimeMillis() < deadline) {
            nodeA.sync()
            nodeB.sync()
            val channelA = nodeA.listChannels().firstOrNull { it.channelId == channelId }
            val channelB = nodeB.listChannels().firstOrNull { it.channelId == channelId }
            lastNodeABalance = channelA?.localBalanceSat
            lastNodeBBalance = channelB?.localBalanceSat
            if (lastNodeABalance == expectedNodeABalance && lastNodeBBalance == expectedNodeBBalance) {
                return
            }
            Thread.sleep(1_000L)
        }
        error(
            "channel balances did not stabilize after ${timeoutSec}s: " +
                "expectedA=$expectedNodeABalance actualA=$lastNodeABalance " +
                "expectedB=$expectedNodeBBalance actualB=$lastNodeBBalance"
        )
    }

    private fun waitPaymentFinal(node: SdkNode, invoice: String, timeoutSec: Long = 60L): InvoiceStatus {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var last = InvoiceStatus.PENDING
        while (System.currentTimeMillis() < deadline) {
            node.sync()
            val status = node.invoiceStatus(invoice)
            last = status
            if (status == InvoiceStatus.SUCCEEDED || status == InvoiceStatus.FAILED || status == InvoiceStatus.EXPIRED) {
                return status
            }
            Thread.sleep(1_000L)
        }
        error("invoice did not finalize after ${timeoutSec}s, last=$last")
    }

    private fun waitForPaymentStatus(
        node: SdkNode,
        paymentHash: PaymentHash,
        paymentType: PaymentType,
        timeoutSec: Long,
    ): Payment {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var last = "not found"
        while (System.currentTimeMillis() < deadline) {
            val payment = node.listPayments().firstOrNull {
                it.paymentHash == paymentHash && it.paymentType == paymentType
            }
            if (payment != null) {
                last = payment.status.name
                if (payment.status == HtlcStatus.SUCCEEDED) {
                    return payment
                }
            }
            Thread.sleep(1_000L)
        }
        error("payment did not succeed after ${timeoutSec}s, paymentType=$paymentType, last=$last")
    }

    private fun waitForPaymentPresentInList(
        node: SdkNode,
        paymentHash: PaymentHash,
        paymentType: PaymentType,
        timeoutSec: Long,
    ): Payment {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
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
            Thread.sleep(1_000L)
        }
        error(
            "payment not found in listPayments: paymentHash=$paymentHash paymentType=$paymentType " +
                "list_size=$lastCount after ${timeoutSec}s"
        )
    }

    private fun sendPaymentWithLnBalance(
        sender: SdkNode,
        receiver: SdkNode,
        invoice: String,
        assetId: ContractId,
        assetAmount: ULong,
        initialSenderBalance: ULong,
        initialReceiverBalance: ULong,
    ) {
        sender.sendpayment(
            SdkSendPaymentRequest(
                invoice = invoice,
                amtMsat = null,
                assetId = null,
                assetAmount = null,
            )
        )
        waitForLnBalance(sender, assetId, initialSenderBalance - assetAmount, 60L)
        waitForLnBalance(receiver, assetId, initialReceiverBalance + assetAmount, 60L)
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
                mine(if (force) 144 else 6)
                return
            }
            Thread.sleep(1_000L)
        }
        error("channel did not close in time: channelId=$channelId remainingChannels=$lastChannels")
    }

    private fun refreshTransfers(node: SdkNode) {
        node.refreshtransfers(SdkRefreshTransfersRequest(skipSync = false))
    }

    private fun rgbInvoice(node: SdkNode): String {
        return node.rgbinvoice(
            SdkRgbInvoiceRequest(
                assetId = null,
                assignmentKind = null,
                assignmentAmount = null,
                durationSeconds = null,
                minConfirmations = 1u,
                witness = false,
            )
        ).recipientId
    }

    private fun sendRgb(node: SdkNode, assetId: ContractId, recipientId: String, amount: ULong) {
        node.sendRgb(
            SendRgbRequest(
                donation = true,
                feeRate = utxosFeeRate,
                minConfirmations = 1u,
                recipientGroups = listOf(
                    AssetRecipients(
                        assetId = assetId,
                        recipients = listOf(
                            RgbRecipient(
                                recipientId = recipientId,
                                witnessData = null,
                                assignmentKind = AssignmentKind.FUNGIBLE,
                                assignmentAmount = amount,
                                transportEndpoints = listOf(proxyEndpoint),
                            )
                        ),
                    )
                ),
            )
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
        assertEquals(expectedPaymentHash, paymentPreimageHash)
    }

    private fun log(msg: String) {
        android.util.Log.i("PaymentTest", msg)
    }

    private fun safeShutdown(node: SdkNode?) {
        try {
            node?.shutdown()
        } catch (_: Exception) {
        }
    }

    // ── Test ─────────────────────────────────────────────────────────────────

    @Test
    fun payment() {
        File("$storageBase/payment/node_a").deleteRecursively()
        File("$storageBase/payment/node_b").deleteRecursively()
        File("$storageBase/payment/node_c").deleteRecursively()

        val nodeA = makeNode("payment/node_a", nodeADaemonPort, nodeAPeerPort)
        val nodeB = makeNode("payment/node_b", nodeBDaemonPort, nodeBPeerPort)
        val nodeC = makeNode("payment/node_c", nodeCDaemonPort, nodeCPeerPort)
        try {
            initNode(nodeA, "nodeApass", "node A")
            initNode(nodeB, "nodeBpass", "node B")
            initNode(nodeC, "nodeCpass", "node C")
            unlockNode(nodeA, "nodeApass", "node A")
            unlockNode(nodeB, "nodeBpass", "node B")
            unlockNode(nodeC, "nodeCpass", "node C")

            fundAndCreateUtxos(nodeA, "node A")
            fundAndCreateUtxos(nodeB, "node B")
            fundAndCreateUtxos(nodeC, "node C")

            val assetId = nodeA.issueassetnia(
                SdkIssueAssetNiaRequest(
                    amounts = listOf(assetSupply),
                    ticker = "USDT",
                    name = "Tether",
                    precision = 0u,
                )
            ).assetId
            log("issued asset: $assetId")

            val infoA = nodeA.nodeInfo(); val infoB = nodeB.nodeInfo()
            log("node A pubkey: ${infoA.pubkey}")
            log("node B pubkey: ${infoB.pubkey}")

            val peerUri = "${infoB.pubkey}@127.0.0.1:${nodeBPeerPort.toInt()}"
            try {
                nodeA.connectpeer(peerUri)
                log("connectpeer: ok")
            } catch (_: RlnException.Conflict) {
                log("connectpeer: already connected")
            }

            val openResponse = nodeA.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = peerUri,
                    capacitySat = channelCapacitySat,
                    pushMsat = channelPushMsat,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = assetId,
                    assetAmount = channelAssetAmount,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            log("openchannel sent")

            val fundingTxid = waitForChannelFundingTx(nodeA, nodeB, assetId, 240L)
            log("Mining blocks one by one until funding tx is confirmed..."); mineUntilTxConfirmed(nodeA, fundingTxid)
            mine(6)
            waitForUsableChannel(nodeA, nodeB, assetId, channelReadyTimeoutSec)
            assertEquals(400uL, assetBalanceSpendable(nodeA, assetId))

            val channels1Before = nodeA.listChannels()
            val channels2Before = nodeB.listChannels()
            assertEquals(1, channels1Before.size)
            assertEquals(1, channels2Before.size)
            val chan1Before = channels1Before.first()
            val chan2Before = channels2Before.first()
            val channelId = nodeA.getChannelId(openResponse.temporaryChannelId)
            assertEquals(channelId, chan1Before.channelId)

            val invoice1 = nodeB.lnInvoice(
                LnInvoiceRequest(
                    amtMsat = paymentMsat,
                    expirySec = 900u,
                    assetId = assetId,
                    assetAmount = 100u,
                    descriptionHash = null,
                    paymentHash = null,
                )
            ).invoice
            sendPaymentWithLnBalance(nodeA, nodeB, invoice1, assetId, 100u, 600u, 0u)

            val decoded1 = nodeA.decodeLnInvoice(invoice1)
            assertEquals(assetId, decoded1.assetId)
            assertEquals(100uL, decoded1.assetAmount)
            assertEquals(paymentMsat, decoded1.amtMsat)
            assertEquals(900uL, decoded1.expirySec)
            assertEquals(infoB.pubkey, decoded1.payeePubkey)
            assertEquals("Regtest", decoded1.network)
            assertEquals(InvoiceStatus.SUCCEEDED, nodeB.invoiceStatus(invoice1))

            val payment1Sender = waitForPaymentStatus(
                nodeA,
                decoded1.paymentHash,
                PaymentType.OUTBOUND,
                60L,
            )
            assertEquals(HtlcStatus.SUCCEEDED, payment1Sender.status)
            assertEquals(assetId, payment1Sender.assetId)
            assertEquals(100uL, payment1Sender.assetAmount)
            checkPreimageMatchesHash(payment1Sender, decoded1.paymentHash)

            val payment1Receiver = waitForPaymentStatus(
                nodeB,
                decoded1.paymentHash,
                PaymentType.INBOUND_AUTO_CLAIM,
                60L,
            )
            assertEquals(HtlcStatus.SUCCEEDED, payment1Receiver.status)
            assertEquals(assetId, payment1Receiver.assetId)
            assertEquals(100uL, payment1Receiver.assetAmount)
            checkPreimageMatchesHash(payment1Receiver, decoded1.paymentHash)

            val listedPayment1Sender = waitForPaymentPresentInList(
                nodeA,
                decoded1.paymentHash,
                PaymentType.OUTBOUND,
                60L,
            )
            assertEquals(decoded1.paymentHash, listedPayment1Sender.paymentHash)
            checkPreimageMatchesHash(listedPayment1Sender, decoded1.paymentHash)

            val listedPayment1Receiver = waitForPaymentPresentInList(
                nodeB,
                decoded1.paymentHash,
                PaymentType.INBOUND_AUTO_CLAIM,
                60L,
            )
            assertEquals(decoded1.paymentHash, listedPayment1Receiver.paymentHash)
            checkPreimageMatchesHash(listedPayment1Receiver, decoded1.paymentHash)

            val invoice2 = nodeA.lnInvoice(
                LnInvoiceRequest(
                    amtMsat = paymentMsat,
                    expirySec = 900u,
                    assetId = assetId,
                    assetAmount = 50u,
                    descriptionHash = null,
                    paymentHash = null,
                )
            ).invoice
            sendPaymentWithLnBalance(nodeB, nodeA, invoice2, assetId, 50u, 100u, 500u)

            val decoded2 = nodeA.decodeLnInvoice(invoice2)
            val payment2Receiver = waitForPaymentStatus(
                nodeA,
                decoded2.paymentHash,
                PaymentType.INBOUND_AUTO_CLAIM,
                60L,
            )
            assertEquals(assetId, payment2Receiver.assetId)
            assertEquals(50uL, payment2Receiver.assetAmount)
            assertEquals(HtlcStatus.SUCCEEDED, payment2Receiver.status)
            checkPreimageMatchesHash(payment2Receiver, decoded2.paymentHash)
            val payment2Sender = waitForPaymentStatus(
                nodeB,
                decoded2.paymentHash,
                PaymentType.OUTBOUND,
                60L,
            )
            assertEquals(assetId, payment2Sender.assetId)
            assertEquals(50uL, payment2Sender.assetAmount)
            assertEquals(HtlcStatus.SUCCEEDED, payment2Sender.status)
            checkPreimageMatchesHash(payment2Sender, decoded2.paymentHash)

            val invoice3 = nodeB.lnInvoice(
                LnInvoiceRequest(
                    amtMsat = paymentMsat,
                    expirySec = 900u,
                    assetId = assetId,
                    assetAmount = 50u,
                    descriptionHash = null,
                    paymentHash = null,
                )
            ).invoice
            nodeA.sendpayment(
                SdkSendPaymentRequest(
                    invoice = invoice3,
                    amtMsat = null,
                    assetId = null,
                    assetAmount = null,
                )
            )
            val decoded3 = nodeA.decodeLnInvoice(invoice3)
            val payment3Sender = waitForPaymentStatus(
                nodeA,
                decoded3.paymentHash,
                PaymentType.OUTBOUND,
                60L,
            )
            assertEquals(assetId, payment3Sender.assetId)
            assertEquals(50uL, payment3Sender.assetAmount)
            assertEquals(HtlcStatus.SUCCEEDED, payment3Sender.status)
            checkPreimageMatchesHash(payment3Sender, decoded3.paymentHash)
            val payment3Receiver = waitForPaymentStatus(
                nodeB,
                decoded3.paymentHash,
                PaymentType.INBOUND_AUTO_CLAIM,
                60L,
            )
            assertEquals(assetId, payment3Receiver.assetId)
            assertEquals(50uL, payment3Receiver.assetAmount)
            assertEquals(HtlcStatus.SUCCEEDED, payment3Receiver.status)
            checkPreimageMatchesHash(payment3Receiver, decoded3.paymentHash)

            val invoice4 = nodeA.lnInvoice(
                LnInvoiceRequest(
                    amtMsat = paymentMsat,
                    expirySec = 900u,
                    assetId = assetId,
                    assetAmount = 50u,
                    descriptionHash = null,
                    paymentHash = null,
                )
            ).invoice
            nodeB.sendpayment(
                SdkSendPaymentRequest(
                    invoice = invoice4,
                    amtMsat = null,
                    assetId = null,
                    assetAmount = null,
                )
            )
            val decoded4 = nodeA.decodeLnInvoice(invoice4)
            val payment4Receiver = waitForPaymentStatus(
                nodeA,
                decoded4.paymentHash,
                PaymentType.INBOUND_AUTO_CLAIM,
                60L,
            )
            assertEquals(assetId, payment4Receiver.assetId)
            assertEquals(50uL, payment4Receiver.assetAmount)
            assertEquals(HtlcStatus.SUCCEEDED, payment4Receiver.status)
            checkPreimageMatchesHash(payment4Receiver, decoded4.paymentHash)
            val payment4Sender = waitForPaymentStatus(
                nodeB,
                decoded4.paymentHash,
                PaymentType.OUTBOUND,
                60L,
            )
            assertEquals(assetId, payment4Sender.assetId)
            assertEquals(50uL, payment4Sender.assetAmount)
            assertEquals(HtlcStatus.SUCCEEDED, payment4Sender.status)
            checkPreimageMatchesHash(payment4Sender, decoded4.paymentHash)

            waitForStableChannelBalances(
                nodeA = nodeA,
                nodeB = nodeB,
                channelId = channelId,
                expectedNodeABalance = chan1Before.localBalanceSat,
                expectedNodeBBalance = chan2Before.localBalanceSat,
                timeoutSec = 10L,
            )
            val channels1 = nodeA.listChannels()
            val channels2 = nodeB.listChannels()
            assertEquals(1, channels1.size)
            assertEquals(1, channels2.size)
            val chan1 = channels1.first()
            val chan2 = channels2.first()
            assertEquals(chan1Before.localBalanceSat, chan1.localBalanceSat)
            assertEquals(chan2Before.localBalanceSat, chan2.localBalanceSat)

            closeChannel(nodeA, channelId, infoB.pubkey)
            waitForBalance(nodeA, assetId, 950uL, 180L)
            waitForBalance(nodeB, assetId, 50uL, 180L)

            val recipientId1 = rgbInvoice(nodeC)
            sendRgb(nodeA, assetId, recipientId1, 925u)
            mine(1)
            refreshTransfers(nodeC)
            refreshTransfers(nodeC)
            refreshTransfers(nodeA)

            val recipientId2 = rgbInvoice(nodeC)
            sendRgb(nodeB, assetId, recipientId2, 25u)
            mine(1)
            refreshTransfers(nodeC)
            refreshTransfers(nodeC)
            refreshTransfers(nodeB)

            assertEquals(25uL, assetBalanceSpendable(nodeA, assetId))
            assertEquals(25uL, assetBalanceSpendable(nodeB, assetId))
            assertEquals(950uL, assetBalanceSpendable(nodeC, assetId))

            val transactions = nodeA.listTransactions(false)
            val txUser = transactions.first { it.received == 100_000_000uL }
            val txUtxos = transactions.first { it.sent == 100_000_000uL }
            val txSend = transactions.first { it.sent == 128_000uL }
            assertEquals(TransactionType.INCOMING, txUser.transactionType)
            assertEquals(TransactionType.CREATE_UTXOS, txUtxos.transactionType)
            assertEquals(TransactionType.RGB_SEND, txSend.transactionType)
            assertNotNull(txUtxos.confirmationTime)

            val transfers = nodeA.listTransfers(assetId)
            val xfer1 = transfers.first { it.idx == 1 }
            assertEquals("Settled", xfer1.status)
            assertEquals("Issuance", xfer1.kind)
            assertEquals(listOf("Fungible(1000)"), xfer1.assignments)
            assertNull(xfer1.txid)
            assertNull(xfer1.recipientId)
            assertNull(xfer1.receiveUtxo)
            assertNull(xfer1.changeUtxo)
            assertNull(xfer1.expiration)
            assertTrue(xfer1.transportEndpoints.isEmpty())

            val xfer2 = transfers.first { it.idx == 2 }
            assertEquals("Settled", xfer2.status)
            assertEquals("Send", xfer2.kind)
            assertEquals("Fungible(600)", xfer2.requestedAssignment)
            assertEquals(listOf("Fungible(400)"), xfer2.assignments)
            assertNotNull(xfer2.txid)
            assertNotNull(xfer2.recipientId)
            assertNull(xfer2.receiveUtxo)
            assertNotNull(xfer2.changeUtxo)
            assertNull(xfer2.expiration)
            assertTrue(xfer2.transportEndpoints.isNotEmpty())

            val xfer3 = transfers.first { it.idx == 3 }
            assertEquals("Settled", xfer3.status)
            assertEquals("ReceiveWitness", xfer3.kind)
            assertEquals(listOf("Fungible(550)"), xfer3.assignments)
            assertNotNull(xfer3.txid)
            assertNotNull(xfer3.recipientId)
            assertNotNull(xfer3.receiveUtxo)
            assertNull(xfer3.changeUtxo)
            assertNull(xfer3.expiration)
            assertTrue(xfer3.transportEndpoints.isNotEmpty())

            log("SUCCESS: Android payment parity flow completed")
        } finally {
            safeShutdown(nodeA)
            safeShutdown(nodeB)
            safeShutdown(nodeC)
            Thread.sleep(1_000L)
        }
    }
}
