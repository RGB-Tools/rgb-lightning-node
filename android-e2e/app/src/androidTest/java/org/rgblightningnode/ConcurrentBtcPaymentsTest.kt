package org.rgblightningnode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.utexo.rgblightningnode.Channel
import org.utexo.rgblightningnode.HtlcStatus
import org.utexo.rgblightningnode.InvoiceStatus
import org.utexo.rgblightningnode.LnInvoiceRequest
import org.utexo.rgblightningnode.Payment
import org.utexo.rgblightningnode.PaymentHash
import org.utexo.rgblightningnode.PaymentType
import org.utexo.rgblightningnode.RlnException
import org.utexo.rgblightningnode.SdkCreateUtxosRequest
import org.utexo.rgblightningnode.SdkInitRequest
import org.utexo.rgblightningnode.SdkNode
import org.utexo.rgblightningnode.SdkOpenChannelRequest
import org.utexo.rgblightningnode.SdkSendPaymentRequest
import org.utexo.rgblightningnode.SdkSendPaymentResponse
import org.utexo.rgblightningnode.SdkUnlockRequest
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class ConcurrentBtcPaymentsTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val storageBase = context.filesDir.absolutePath

    private val bitcoindHost = "10.0.2.2"
    private val bitcoindPort = 18443
    private val bitcoindUser = "user"
    private val bitcoindPass = "password"
    private val proxyEndpoint = "rpc://10.0.2.2:3000/json-rpc"

    private val nodeADaemonPort: UShort = 4211u
    private val nodeBDaemonPort: UShort = 4212u
    private val nodeCDaemonPort: UShort = 4213u
    private val nodeDDaemonPort: UShort = 4214u
    private val nodeAPeerPort: UShort = 13611u
    private val nodeBPeerPort: UShort = 13612u
    private val nodeCPeerPort: UShort = 13613u
    private val nodeDPeerPort: UShort = 13614u

    private val channelCapacitySat: ULong = 100_000u
    private val channelPushMsat: ULong = 0u
    private val invoiceAmtMsat1: ULong = 4_000_000u
    private val invoiceAmtMsat2: ULong = 5_000_000u
    private val utxosNum: UByte = 10u
    private val utxosFeeRate: ULong = 7u
    private val channelReadyTimeoutSec: Long = 60L

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
        val addr = bitcoindRpc("getnewaddress").getString("result")
        bitcoindRpc("generatetoaddress", blocks, addr)
        log("mined $blocks block(s)")
    }

    private fun getTxOut(txid: String): String {
        return bitcoindRpc("gettxout", txid, 0).opt("result")?.toString() ?: ""
    }

    private fun sendToAddress(address: String, amountBtc: String) {
        bitcoindRpc("sendtoaddress", address, amountBtc.toDouble())
        log("sent $amountBtc BTC to $address")
    }

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

    // Align with Python E2E: pass explicit UTXO size (100k sat)
    // instead of null to ensure deterministic UTXO layout for channel funding.
    private fun fundAndCreateUtxos(node: SdkNode, name: String) {
        ensureFunded(node, name, 1u, "1")
        node.createutxos(
            SdkCreateUtxosRequest(
                upTo = false,
                num = utxosNum,
                size = 100_000u,
                feeRate = utxosFeeRate,
                skipSync = false,
            )
        )
        log("$name: createutxos done")
        mine(1)
        node.sync()
    }

    private fun connectPeer(node: SdkNode, peerPubkey: String, peerPort: UShort, name: String) {
        val peerUri = "$peerPubkey@127.0.0.1:${peerPort.toInt()}"
        try {
            node.connectpeer(peerUri)
            log("$name connectpeer: ok")
        } catch (_: RlnException.Conflict) {
            log("$name connectpeer: already connected")
        }
    }

    private fun waitForChannelFundingTx(
        node: SdkNode,
        peerNode: SdkNode,
        matcher: (Channel) -> Boolean,
        timeoutSec: Long,
    ): String {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        while (System.currentTimeMillis() < deadline) {
            node.sync()
            peerNode.sync()
            val opening = node.listChannels().firstOrNull { matcher(it) && it.fundingTxid != null }
            if (opening != null) {
                val fundingTxid = requireNotNull(opening.fundingTxid)
                log("channel funding tx found: $fundingTxid")
                return fundingTxid
            }
            log("waiting for channel funding tx...")
            Thread.sleep(1_000L)
        }
        error("no channel funding tx after ${timeoutSec}s")
    }

    private fun mineUntilTxConfirmed(txid: String, timeoutSec: Long = 180L) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        while (System.currentTimeMillis() < deadline) {
            val txOut = getTxOut(txid)
            if (txOut.isNotBlank()) {
                log("funding tx confirmed in block: $txid")
                return
            }
            log("waiting for funding tx to be included in a block...")
            mine(1)
            Thread.sleep(1_000L)
        }
        error("funding tx was not confirmed before timeout: txid=$txid")
    }

    private fun waitForUsableChannel(
        node: SdkNode,
        peerNode: SdkNode,
        matcher: (Channel) -> Boolean,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var polls = 0
        while (System.currentTimeMillis() < deadline) {
            polls++
            node.sync()
            peerNode.sync()
            val usable = node.listChannels().any { matcher(it) && it.isUsable }
            if (usable) {
                log("channel is usable")
                return
            }
            if (polls % 5 == 0) {
                log("mining 1 block...")
                mine(1)
            }
            log("waiting for usable channel... (poll $polls)")
            Thread.sleep(2_000L)
        }
        error("channel not usable after ${timeoutSec}s")
    }

    private fun waitForObservedPayments(
        node: SdkNode,
        paymentHashes: List<PaymentHash>,
        paymentType: PaymentType,
        timeoutSec: Long,
    ): List<Payment> {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastPayments = emptyList<Payment>()
        while (System.currentTimeMillis() < deadline) {
            node.sync()
            val payments = node.listPayments()
            lastPayments = payments
            val observed = payments.filter {
                it.paymentHash in paymentHashes && it.paymentType == paymentType
            }
            if (observed.size == paymentHashes.size && observed.none { it.status == HtlcStatus.FAILED }) {
                return observed
            }
            Thread.sleep(1_000L)
        }
        error(
            "did not observe ${paymentHashes.size} payments after ${timeoutSec}s; " +
                "last_count=${lastPayments.size} last_hashes=${lastPayments.map { it.paymentHash }} " +
                "last_statuses=${lastPayments.map { it.status.name }}"
        )
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

    private fun waitForInvoiceStatus(
        node: SdkNode,
        invoice: String,
        expected: InvoiceStatus,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var last = InvoiceStatus.PENDING
        while (System.currentTimeMillis() < deadline) {
            node.sync()
            val status = node.invoiceStatus(invoice)
            last = status
            if (status == expected) {
                return
            }
            Thread.sleep(1_000L)
        }
        error("invoice did not reach $expected after ${timeoutSec}s, last=$last")
    }

    private fun waitForChannelLocalBalanceMsat(
        node: SdkNode,
        channelId: String,
        expectedMsat: ULong,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastMsat: ULong? = null
        while (System.currentTimeMillis() < deadline) {
            node.sync()
            val channel = node.listChannels().firstOrNull { it.channelId == channelId }
            lastMsat = channel?.localBalanceSat?.times(1000u)
            if (lastMsat == expectedMsat) {
                return
            }
            Thread.sleep(1_000L)
        }
        error("channel local balance did not become expected=$expectedMsat actual=$lastMsat")
    }

    private fun log(msg: String) {
        android.util.Log.i("ConcurrentBtcPaymentsTest", msg)
    }

    private fun dumpNodeState(node: SdkNode, name: String) {
        try {
            val channels = node.listChannels().joinToString(separator = "; ") {
                "id=${it.channelId},peer=${it.peerPubkey},ready=${it.ready},usable=${it.isUsable},status=${it.status},funding=${it.fundingTxid},localSat=${it.localBalanceSat},outboundMsat=${it.outboundBalanceMsat},inboundMsat=${it.inboundBalanceMsat}"
            }.ifEmpty { "no channels" }
            log("$name channels: $channels")
        } catch (t: Throwable) {
            log("$name channels dump failed: ${t::class.java.simpleName}: ${t.message}")
        }

        try {
            val payments = node.listPayments().joinToString(separator = "; ") {
                "hash=${it.paymentHash},status=${it.status},amtMsat=${it.amtMsat},assetId=${it.assetId},assetAmount=${it.assetAmount}"
            }.ifEmpty { "no payments" }
            log("$name payments: $payments")
        } catch (t: Throwable) {
            log("$name payments dump failed: ${t::class.java.simpleName}: ${t.message}")
        }
    }

    private fun safeShutdown(node: SdkNode?) {
        try {
            node?.shutdown()
        } catch (_: Exception) {
        }
    }

    @Test
    fun concurrentBtcPayments() {
        File("$storageBase/concurrent_btc_payments/node_a").deleteRecursively()
        File("$storageBase/concurrent_btc_payments/node_b").deleteRecursively()
        File("$storageBase/concurrent_btc_payments/node_c").deleteRecursively()
        File("$storageBase/concurrent_btc_payments/node_d").deleteRecursively()

        val nodeA = makeNode("concurrent_btc_payments/node_a", nodeADaemonPort, nodeAPeerPort)
        val nodeB = makeNode("concurrent_btc_payments/node_b", nodeBDaemonPort, nodeBPeerPort)
        val nodeC = makeNode("concurrent_btc_payments/node_c", nodeCDaemonPort, nodeCPeerPort)
        val nodeD = makeNode("concurrent_btc_payments/node_d", nodeDDaemonPort, nodeDPeerPort)
        try {
            initNode(nodeA, "nodeApass", "node A")
            initNode(nodeB, "nodeBpass", "node B")
            initNode(nodeC, "nodeCpass", "node C")
            initNode(nodeD, "nodeDpass", "node D")
            unlockNode(nodeA, "nodeApass", "node A")
            unlockNode(nodeB, "nodeBpass", "node B")
            unlockNode(nodeC, "nodeCpass", "node C")
            unlockNode(nodeD, "nodeDpass", "node D")

            fundAndCreateUtxos(nodeA, "node A")
            fundAndCreateUtxos(nodeB, "node B")
            fundAndCreateUtxos(nodeC, "node C")
            fundAndCreateUtxos(nodeD, "node D")

            val infoA = nodeA.nodeInfo()
            val infoB = nodeB.nodeInfo()
            log("node A pubkey: ${infoA.pubkey}")
            log("node B pubkey: ${infoB.pubkey}")

            connectPeer(nodeB, infoA.pubkey, nodeAPeerPort, "node B")
            connectPeer(nodeC, infoB.pubkey, nodeBPeerPort, "node C")
            connectPeer(nodeD, infoB.pubkey, nodeBPeerPort, "node D")

            val openBtoA = nodeB.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = "${infoA.pubkey}@127.0.0.1:${nodeAPeerPort.toInt()}",
                    capacitySat = channelCapacitySat,
                    pushMsat = channelPushMsat,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = null,
                    assetAmount = null,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            val fundingTxidBtoA = waitForChannelFundingTx(
                nodeB,
                nodeA,
                { it.peerPubkey == infoA.pubkey && it.assetId == null },
                120L,
            )
            log("Mining blocks one by one until funding tx is confirmed...")
            mineUntilTxConfirmed(fundingTxidBtoA)
            mine(6)
            waitForUsableChannel(
                nodeB,
                nodeA,
                { it.channelId == nodeB.getChannelId(openBtoA.temporaryChannelId) },
                channelReadyTimeoutSec,
            )

            val openCtoB = nodeC.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = "${infoB.pubkey}@127.0.0.1:${nodeBPeerPort.toInt()}",
                    capacitySat = channelCapacitySat,
                    pushMsat = channelPushMsat,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = null,
                    assetAmount = null,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            val fundingTxidCtoB = waitForChannelFundingTx(
                nodeC,
                nodeB,
                { it.peerPubkey == infoB.pubkey && it.assetId == null },
                120L,
            )
            log("Mining blocks one by one until funding tx is confirmed...")
            mineUntilTxConfirmed(fundingTxidCtoB)
            mine(6)
            waitForUsableChannel(
                nodeC,
                nodeB,
                { it.channelId == nodeC.getChannelId(openCtoB.temporaryChannelId) },
                channelReadyTimeoutSec,
            )

            val openDtoB = nodeD.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = "${infoB.pubkey}@127.0.0.1:${nodeBPeerPort.toInt()}",
                    capacitySat = channelCapacitySat,
                    pushMsat = channelPushMsat,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = null,
                    assetAmount = null,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            val fundingTxidDtoB = waitForChannelFundingTx(
                nodeD,
                nodeB,
                { it.peerPubkey == infoB.pubkey && it.assetId == null },
                120L,
            )
            log("Mining blocks one by one until funding tx is confirmed...")
            mineUntilTxConfirmed(fundingTxidDtoB)
            mine(6)
            waitForUsableChannel(
                nodeD,
                nodeB,
                { it.channelId == nodeD.getChannelId(openDtoB.temporaryChannelId) },
                channelReadyTimeoutSec,
            )

            val channelsA = nodeA.listChannels()
            assertEquals(1, channelsA.size)
            val channelA = channelsA.first()
            assertEquals(0uL, channelA.localBalanceSat)

            val invoice1 = nodeA.lnInvoice(
                LnInvoiceRequest(
                    amtMsat = invoiceAmtMsat1,
                    expirySec = 900u,
                    assetId = null,
                    assetAmount = null,
                    descriptionHash = null,
                    paymentHash = null,
                )
            ).invoice

            val invoice2 = nodeA.lnInvoice(
                LnInvoiceRequest(
                    amtMsat = invoiceAmtMsat2,
                    expirySec = 900u,
                    assetId = null,
                    assetAmount = null,
                    descriptionHash = null,
                    paymentHash = null,
                )
            ).invoice
            val decoded1 = nodeA.decodeLnInvoice(invoice1)
            val decoded2 = nodeA.decodeLnInvoice(invoice2)

            log("sending payment 1 from node C")
            val response1 = nodeC.sendpayment(
                SdkSendPaymentRequest(
                    invoice = invoice1,
                    amtMsat = null,
                    assetId = null,
                    assetAmount = null,
                )
            )
            log("sendpayment 1 returned status=${response1.status} hash=${response1.paymentHash}")

            log("sending payment 2 from node D")
            val response2 = nodeD.sendpayment(
                SdkSendPaymentRequest(
                    invoice = invoice2,
                    amtMsat = null,
                    assetId = null,
                    assetAmount = null,
                )
            )
            log("sendpayment 2 returned status=${response2.status} hash=${response2.paymentHash}")
            assertEquals(HtlcStatus.PENDING, response1.status)
            assertEquals(HtlcStatus.PENDING, response2.status)

            log("waiting for receiver to observe both payments")
            val receiverPayments = waitForObservedPayments(
                nodeA,
                listOf(decoded1.paymentHash, decoded2.paymentHash),
                PaymentType.INBOUND_AUTO_CLAIM,
                30L,
            )
            dumpNodeState(nodeA, "node A after receiver observation")
            assertEquals(2, receiverPayments.size)
            assertTrue(receiverPayments.none { it.status == HtlcStatus.FAILED })

            log("waiting for sender-side payment success")
            val payment1Sender =
                waitForPaymentStatus(nodeC, response1.paymentHash!!, PaymentType.OUTBOUND, 60L)
            val payment2Sender =
                waitForPaymentStatus(nodeD, response2.paymentHash!!, PaymentType.OUTBOUND, 60L)
            dumpNodeState(nodeC, "node C after sender success")
            dumpNodeState(nodeD, "node D after sender success")
            assertEquals(HtlcStatus.SUCCEEDED, payment1Sender.status)
            assertEquals(HtlcStatus.SUCCEEDED, payment2Sender.status)

            log("waiting for receiver invoice success")
            waitForInvoiceStatus(nodeA, invoice1, InvoiceStatus.SUCCEEDED, 60L)
            waitForInvoiceStatus(nodeA, invoice2, InvoiceStatus.SUCCEEDED, 60L)
            dumpNodeState(nodeA, "node A after invoice success")

            val payments = nodeA.listPayments()
            val payment1 = payments.first { it.paymentHash == decoded1.paymentHash }
            val payment2 = payments.first { it.paymentHash == decoded2.paymentHash }
            assertEquals(invoiceAmtMsat1, payment1.amtMsat)
            assertEquals(invoiceAmtMsat2, payment2.amtMsat)
            assertEquals(HtlcStatus.SUCCEEDED, payment1.status)
            assertEquals(HtlcStatus.SUCCEEDED, payment2.status)

            waitForChannelLocalBalanceMsat(nodeA, channelA.channelId, invoiceAmtMsat1 + invoiceAmtMsat2, 30L)
            val channelsAfter = nodeA.listChannels()
            assertEquals(1, channelsAfter.size)
            assertEquals(invoiceAmtMsat1 + invoiceAmtMsat2, channelsAfter.first().localBalanceSat * 1000u)
        } finally {
            Thread.sleep(1_000L)
            safeShutdown(nodeD)
            safeShutdown(nodeC)
            safeShutdown(nodeB)
            safeShutdown(nodeA)
        }
    }
}
