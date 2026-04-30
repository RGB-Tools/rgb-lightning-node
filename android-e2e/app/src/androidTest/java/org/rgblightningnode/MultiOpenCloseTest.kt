package org.rgblightningnode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.utexo.rgblightningnode.AssetRecipients
import org.utexo.rgblightningnode.AssignmentKind
import org.utexo.rgblightningnode.ContractId
import org.utexo.rgblightningnode.HtlcStatus
import org.utexo.rgblightningnode.LnInvoiceRequest
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
import org.utexo.rgblightningnode.SdkUnlockRequest
import org.utexo.rgblightningnode.SendRgbRequest
import org.utexo.rgblightningnode.Txid
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class MultiOpenCloseTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val storageBase = context.filesDir.absolutePath

    private val bitcoindHost = "10.0.2.2"
    private val bitcoindPort = 18443
    private val bitcoindUser = "user"
    private val bitcoindPass = "password"
    private val proxyEndpoint = "rpc://10.0.2.2:3000/json-rpc"

    private val nodeADaemonPort: UShort = 3811u
    private val nodeBDaemonPort: UShort = 3812u
    private val nodeCDaemonPort: UShort = 3813u
    private val nodeAPeerPort: UShort = 13211u
    private val nodeBPeerPort: UShort = 13212u
    private val nodeCPeerPort: UShort = 13213u

    private val openChannelCapacitySat: ULong = 100_000u
    private val openChannelConfirmBlocks = 6
    private val paymentMsat: ULong = 3_000_000u
    private val utxosNum: UByte = 10u
    private val utxosFeeRate: ULong = 7u
    private val assetSupply: ULong = 1000u
    private val channelReadyTimeoutSec: Long = 60L

    private fun bitcoindRpc(method: String, vararg params: Any): JSONObject {
        val url = URL("http://$bitcoindHost:$bitcoindPort/")
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        val creds =
            Base64.getEncoder().encodeToString("$bitcoindUser:$bitcoindPass".toByteArray())
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

    private fun fundAndCreateUtxos(node: SdkNode, name: String, amountBtc: String = "1") {
        ensureFunded(node, name, 1u, amountBtc)
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

    private fun issueAssetNia(node: SdkNode, name: String): ContractId {
        val assetId = node.issueassetnia(
            SdkIssueAssetNiaRequest(
                amounts = listOf(assetSupply),
                ticker = "USDT",
                name = "Tether",
                precision = 0u,
            )
        ).assetId
        log("$name: issued asset_id=$assetId")
        return assetId
    }

    private fun assetBalanceSpendable(node: SdkNode, assetId: ContractId): ULong {
        return node.assetBalance(assetId).spendable
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
        error("spendable balance did not become expected=$expected actual=$lastBalance")
    }

    private fun waitForChannelFundingTx(nodeA: SdkNode, nodeB: SdkNode, assetId: ContractId, timeoutSec: Long): Txid {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        while (System.currentTimeMillis() < deadline) {
            nodeA.sync()
            nodeB.sync()
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
            nodeA.sync()
            nodeB.sync()
            val usable = nodeA.listChannels().any { it.isUsable && it.assetId == assetId }
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

    private fun waitForPaymentStatus(
        node: SdkNode,
        paymentHash: PaymentHash,
        paymentType: PaymentType,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var last = "not found"
        while (System.currentTimeMillis() < deadline) {
            val payment = node.listPayments().firstOrNull {
                it.paymentHash == paymentHash && it.paymentType == paymentType
            }
            if (payment != null) {
                last = payment.status.name
                if (payment.status == HtlcStatus.SUCCEEDED) {
                    return
                }
            }
            Thread.sleep(1_000L)
        }
        error("payment did not succeed after ${timeoutSec}s, paymentType=$paymentType, last=$last")
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
                amtMsat = amtMsat ?: paymentMsat,
                assetId = assetId,
                assetAmount = assetAmount,
            )
        )
        assertTrue(
            "unexpected keysend status: ${response.status}",
            response.status == HtlcStatus.PENDING || response.status == HtlcStatus.SUCCEEDED
        )
        waitForPaymentStatus(sender, response.paymentHash, PaymentType.OUTBOUND, 60L)
        return response.paymentHash
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

    private fun refreshTransfers(node: SdkNode) {
        node.refreshtransfers(SdkRefreshTransfersRequest(skipSync = false))
    }

    private fun sendRgb(node: SdkNode, assetId: ContractId, recipientId: String, amount: ULong) {
        node.sendRgb(
            SendRgbRequest(
                donation = true,
                feeRate = utxosFeeRate,
                minConfirmations = 1u,
                skipSync = false,
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

    private fun log(msg: String) {
        android.util.Log.i("MultiOpenCloseTest", msg)
    }

    private fun safeShutdown(node: SdkNode?) {
        try {
            node?.shutdown()
        } catch (_: Exception) {
        }
    }

    @Test
    fun multiOpenClose() {
        File("$storageBase/multi_open_close/node_a").deleteRecursively()
        File("$storageBase/multi_open_close/node_b").deleteRecursively()
        File("$storageBase/multi_open_close/node_c").deleteRecursively()

        val nodeA = makeNode("multi_open_close/node_a", nodeADaemonPort, nodeAPeerPort)
        var nodeB: SdkNode? = null
        var nodeC: SdkNode? = null
        try {
            initNode(nodeA, "nodeApass", "node A")
            unlockNode(nodeA, "nodeApass", "node A")

            nodeB = makeNode("multi_open_close/node_b", nodeBDaemonPort, nodeBPeerPort)
            initNode(nodeB, "nodeBpass", "node B")
            unlockNode(nodeB, "nodeBpass", "node B")

            nodeC = makeNode("multi_open_close/node_c", nodeCDaemonPort, nodeCPeerPort)
            initNode(nodeC, "nodeCpass", "node C")
            unlockNode(nodeC, "nodeCpass", "node C")

            val nodeBReady = requireNotNull(nodeB)
            val nodeCReady = requireNotNull(nodeC)

            fundAndCreateUtxos(nodeA, "node A")
            fundAndCreateUtxos(nodeBReady, "node B")
            fundAndCreateUtxos(nodeCReady, "node C")

            val assetId = issueAssetNia(nodeA, "node A")
            mine(1)
            nodeA.sync()

            val nodeBPubkey = nodeBReady.nodeInfo().pubkey
            val peerUri = "$nodeBPubkey@127.0.0.1:${nodeBPeerPort.toInt()}"
            try {
                nodeA.connectpeer(peerUri)
                log("connectpeer: ok")
            } catch (_: RlnException.Conflict) {
                log("connectpeer: already connected")
            }

            val firstOpen = nodeA.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = peerUri,
                    capacitySat = openChannelCapacitySat,
                    pushMsat = 0u,
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
            var fundingTxid = waitForChannelFundingTx(nodeA, nodeBReady, assetId, 120L)
            log("Mining blocks one by one until funding tx is confirmed...")
            mineUntilTxConfirmed(nodeA, fundingTxid)
            mine(openChannelConfirmBlocks)
            waitForUsableChannel(nodeA, nodeBReady, assetId, channelReadyTimeoutSec)

            assertEquals(400uL, assetBalanceSpendable(nodeA, assetId))

            keysend(nodeA, nodeBPubkey, null, assetId, 100u)

            val firstChannelId = nodeA.getChannelId(firstOpen.temporaryChannelId)
            closeChannel(nodeA, firstChannelId, nodeBPubkey)
            waitForBalance(nodeA, assetId, 900uL, 70L)
            waitForBalance(nodeBReady, assetId, 100uL, 70L)

            val secondOpen = nodeA.openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = peerUri,
                    capacitySat = openChannelCapacitySat,
                    pushMsat = 0u,
                    `public` = true,
                    withAnchors = true,
                    feeBaseMsat = null,
                    feeProportionalMillionths = null,
                    temporaryChannelId = null,
                    assetId = assetId,
                    assetAmount = 500u,
                    pushAssetAmount = null,
                    virtualOpenMode = null,
                )
            )
            fundingTxid = waitForChannelFundingTx(nodeA, nodeBReady, assetId, 120L)
            log("Mining blocks one by one until funding tx is confirmed...")
            mineUntilTxConfirmed(nodeA, fundingTxid)
            mine(openChannelConfirmBlocks)
            waitForUsableChannel(nodeA, nodeBReady, assetId, channelReadyTimeoutSec)

            assertEquals(400uL, assetBalanceSpendable(nodeA, assetId))

            keysend(nodeA, nodeBPubkey, null, assetId, 100u)

            val secondChannelId = nodeA.getChannelId(secondOpen.temporaryChannelId)
            closeChannel(nodeA, secondChannelId, nodeBPubkey)
            waitForBalance(nodeA, assetId, 800uL, 70L)
            waitForBalance(nodeBReady, assetId, 200uL, 70L)

            val recipientIdA = rgbInvoice(nodeCReady)
            sendRgb(nodeA, assetId, recipientIdA, 700u)
            mine(1)
            refreshTransfers(nodeCReady)
            refreshTransfers(nodeCReady)
            refreshTransfers(nodeA)

            val recipientIdB = rgbInvoice(nodeCReady)
            sendRgb(nodeBReady, assetId, recipientIdB, 150u)
            mine(1)
            refreshTransfers(nodeCReady)
            refreshTransfers(nodeCReady)
            refreshTransfers(nodeBReady)

            assertEquals(100uL, assetBalanceSpendable(nodeA, assetId))
            assertEquals(50uL, assetBalanceSpendable(nodeBReady, assetId))
            assertEquals(850uL, assetBalanceSpendable(nodeCReady, assetId))

            log("SUCCESS: Android multi_open_close completed")
        } finally {
            safeShutdown(nodeA)
            safeShutdown(nodeB)
            safeShutdown(nodeC)
            Thread.sleep(1_000L)
        }
    }
}
