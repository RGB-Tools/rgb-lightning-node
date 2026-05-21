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
import org.utexo.rgblightningnode.RgbRecipient
import org.utexo.rgblightningnode.SdkCloseChannelRequest
import org.utexo.rgblightningnode.SdkCreateUtxosRequest
import org.utexo.rgblightningnode.SdkInitRequest
import org.utexo.rgblightningnode.SdkIssueAssetNiaRequest
import org.utexo.rgblightningnode.SdkMakerExecuteRequest
import org.utexo.rgblightningnode.SdkMakerInitRequest
import org.utexo.rgblightningnode.SdkNode
import org.utexo.rgblightningnode.SdkOpenChannelRequest
import org.utexo.rgblightningnode.SdkRefreshTransfersRequest
import org.utexo.rgblightningnode.SdkRgbInvoiceRequest
import org.utexo.rgblightningnode.SdkTakerRequest
import org.utexo.rgblightningnode.SdkUnlockRequest
import org.utexo.rgblightningnode.SendRgbRequest
import org.utexo.rgblightningnode.Swap
import org.utexo.rgblightningnode.SwapStatus
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.Base64

@RunWith(AndroidJUnit4::class)
class SwapRoundtripBuyTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val storageBase = context.filesDir.absolutePath

    private val bitcoindHost = "10.0.2.2"
    private val bitcoindPort = 18443
    private val bitcoindUser = "user"
    private val bitcoindPass = "password"
    private val proxyEndpoint = "rpc://10.0.2.2:3000/json-rpc"

    private val nodeADaemonPort: UShort = 4011u
    private val nodeBDaemonPort: UShort = 4012u
    private val nodeCDaemonPort: UShort = 4013u
    private val nodeAPeerPort: UShort = 13411u
    private val nodeBPeerPort: UShort = 13412u
    private val nodeCPeerPort: UShort = 13413u

    private val openChannelCapacitySat: ULong = 100_000u
    private val openBtcChannelCapacitySat: ULong = 5_000_000u
    private val openBtcChannelPushMsat: ULong = 546_000u
    private val htlcMinMsat: ULong = 3_000_000u
    private val htlcMinSat: ULong = htlcMinMsat / 1000u
    private val qtyFrom: ULong = 50_000u
    private val qtyTo: ULong = 10u
    private val btcLegDiffSat: ULong = (htlcMinMsat + qtyFrom) / 1000u
    private val utxosNum: UByte = 10u
    private val utxosFeeRate: ULong = 7u
    private val assetSupply: ULong = 1000u
    private val channelReadyTimeoutSec: Long = 60L
    private var noMineCount: Int = 0

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

    private fun stopMining() {
        noMineCount += 1
    }

    private fun resumeMining() {
        if (noMineCount > 0) {
            noMineCount -= 1
        }
    }

    private fun mine(blocks: Int, resume: Boolean = false) {
        if (resume) {
            resumeMining()
        }
        val start = System.currentTimeMillis()
        while (noMineCount > 0) {
            if (System.currentTimeMillis() - start > 120_000L) {
                resumeMining()
            }
            Thread.sleep(500L)
        }
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

    private fun assetBalance(node: SdkNode, assetId: ContractId) = node.assetBalance(assetId)

    private fun assetBalanceSpendable(node: SdkNode, assetId: ContractId): ULong =
        assetBalance(node, assetId).spendable

    private fun waitForLnBalance(node: SdkNode, assetId: ContractId, expected: ULong, timeoutSec: Long) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastBalance = 0uL
        while (System.currentTimeMillis() < deadline) {
            val balance = assetBalance(node, assetId).offchainOutbound
            lastBalance = balance
            if (balance == expected) {
                return
            }
            Thread.sleep(1_000L)
        }
        error("offchain_outbound balance did not become expected=$expected actual=$lastBalance")
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

    private fun waitForAssetOffchainBalances(
        node: SdkNode,
        assetId: ContractId,
        expectedOutbound: ULong,
        expectedInbound: ULong,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastOutbound = 0uL
        var lastInbound = 0uL
        while (System.currentTimeMillis() < deadline) {
            val balance = assetBalance(node, assetId)
            lastOutbound = balance.offchainOutbound
            lastInbound = balance.offchainInbound
            if (lastOutbound == expectedOutbound && lastInbound == expectedInbound) {
                return
            }
            Thread.sleep(1_000L)
        }
        error(
            "offchain balances did not become expected: " +
                "expectedOutbound=$expectedOutbound actualOutbound=$lastOutbound " +
                "expectedInbound=$expectedInbound actualInbound=$lastInbound"
        )
    }

    private fun waitForChannelFundingTx(
        nodeA: SdkNode,
        nodeB: SdkNode,
        matcher: (org.utexo.rgblightningnode.Channel) -> Boolean,
        timeoutSec: Long,
    ): Pair<String, String> {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        while (System.currentTimeMillis() < deadline) {
            nodeA.sync()
            nodeB.sync()
            val opening = nodeA.listChannels().firstOrNull { matcher(it) && it.fundingTxid != null }
            if (opening != null) {
                val fundingTxid = requireNotNull(opening.fundingTxid)
                log("channel funding tx found: $fundingTxid")
                return opening.channelId to fundingTxid
            }
            log("waiting for channel funding tx...")
            Thread.sleep(1_000L)
        }
        error("cannot find funding tx after ${timeoutSec}s")
    }

    private fun waitForChannelReady(
        nodeA: SdkNode,
        nodeB: SdkNode,
        channelId: String,
        timeoutSec: Long,
    ) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var polls = 0
        while (System.currentTimeMillis() < deadline) {
            polls++
            nodeA.sync()
            nodeB.sync()
            val channel = nodeA.listChannels().firstOrNull { it.channelId == channelId }
            if (channel?.ready == true) {
                log("channel is ready")
                return
            }
            if (channel == null) {
                log("waiting for ready channel... (poll $polls) channel not found")
            } else {
                log(
                    "waiting for ready channel... (poll $polls) " +
                        "status=${channel.status} ready=${channel.ready} " +
                        "usable=${channel.isUsable} fundingTx=${channel.fundingTxid != null} " +
                        "shortChannelId=${channel.shortChannelId}"
                )
            }
            if (polls % 5 == 0) {
                log("mining 1 block...")
                mine(1)
            }
            Thread.sleep(1_000L)
        }
        error("channel did not become ready after ${timeoutSec}s: channelId=$channelId")
    }

    private fun mineUntilTxConfirmed(node: SdkNode, txid: String, timeoutSec: Long = 180L) {
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

    private fun waitForChannelOpen(
        node: SdkNode,
        peerNode: SdkNode,
        matcher: (org.utexo.rgblightningnode.Channel) -> Boolean,
        waitForNodeConfirmedFunding: Boolean,
        timeoutSec: Long,
    ): String {
        val (channelId, fundingTxid) = waitForChannelFundingTx(node, peerNode, matcher, timeoutSec)
        log("Mining blocks one by one until funding tx is confirmed...")
        if (waitForNodeConfirmedFunding) {
            mineUntilTxConfirmed(node, fundingTxid, 180L)
        } else {
            val deadline = System.currentTimeMillis() + 180_000L
            while (System.currentTimeMillis() < deadline) {
                val txOut = getTxOut(fundingTxid)
                if (txOut.isNotBlank()) {
                    log("funding tx confirmed in block: $fundingTxid")
                    break
                }
                log("waiting for funding tx to be included in a block...")
                mine(1)
                Thread.sleep(1_000L)
            }
        }
        mine(6)
        waitForChannelReady(node, peerNode, channelId, channelReadyTimeoutSec)
        return channelId
    }

    private fun waitForUsableChannels(node: SdkNode, expectedCount: Int, timeoutSec: Long) {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastCount = 0
        while (System.currentTimeMillis() < deadline) {
            val usable = node.nodeInfo().numUsableChannels.toInt()
            lastCount = usable
            if (usable == expectedCount) {
                return
            }
            Thread.sleep(1_000L)
        }
        error("usable channel count did not become expected=$expectedCount actual=$lastCount")
    }

    private fun waitForSwapStatus(node: SdkNode, paymentHash: org.utexo.rgblightningnode.PaymentHash, expectedStatus: SwapStatus, timeoutSec: Long): Swap {
        val deadline = System.currentTimeMillis() + timeoutSec * 1_000L
        var lastStatus: SwapStatus? = null
        while (System.currentTimeMillis() < deadline) {
            val swaps = node.`listSwaps`()
            val swap = swaps.maker.asSequence()
                .plus(swaps.taker.asSequence())
                .firstOrNull { it.paymentHash == paymentHash }
            if (swap != null) {
                lastStatus = swap.status
                if (swap.status == expectedStatus) {
                    return swap
                }
            }
            Thread.sleep(500L)
        }
        error("swap status did not become expected=$expectedStatus actual=$lastStatus")
    }

    private fun closeChannel(node: SdkNode, channelId: String, peerPubkey: String, force: Boolean = false) {
        stopMining()
        node.closechannel(
            SdkCloseChannelRequest(
                channelId = channelId,
                peerPubkey = peerPubkey,
                force = force,
            )
        )

        val deadline = System.currentTimeMillis() + 30_000L
        while (System.currentTimeMillis() < deadline) {
            val channels = node.listChannels()
            if (channels.none { it.channelId == channelId }) {
                mine(if (force) 144 else 6, resume = true)
                return
            }
            Thread.sleep(1_000L)
        }
        error("channel did not close in time: channelId=$channelId")
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

    private fun pauseAfterShutdown() {
        Thread.sleep(2_000L)
    }

    private fun log(msg: String) {
        android.util.Log.i("SwapRoundtripBuyTest", msg)
    }

    private fun safeShutdown(node: SdkNode?) {
        try {
            node?.shutdown()
        } catch (_: Exception) {
        }
    }

    @Test
    fun swapRoundtripBuy() {
        File("$storageBase/swap_roundtrip_buy/node_a").deleteRecursively()
        File("$storageBase/swap_roundtrip_buy/node_b").deleteRecursively()
        File("$storageBase/swap_roundtrip_buy/node_c").deleteRecursively()

        var nodeA: SdkNode? = makeNode("swap_roundtrip_buy/node_a", nodeADaemonPort, nodeAPeerPort)
        var nodeB: SdkNode? = makeNode("swap_roundtrip_buy/node_b", nodeBDaemonPort, nodeBPeerPort)
        val nodeC: SdkNode = makeNode("swap_roundtrip_buy/node_c", nodeCDaemonPort, nodeCPeerPort)

        try {
            initNode(requireNotNull(nodeA), "nodeApass", "node A")
            initNode(requireNotNull(nodeB), "nodeBpass", "node B")
            initNode(nodeC, "nodeCpass", "node C")
            unlockNode(requireNotNull(nodeA), "nodeApass", "node A")
            unlockNode(requireNotNull(nodeB), "nodeBpass", "node B")
            unlockNode(nodeC, "nodeCpass", "node C")

            fundAndCreateUtxos(requireNotNull(nodeA), "node A")
            fundAndCreateUtxos(requireNotNull(nodeB), "node B")
            fundAndCreateUtxos(nodeC, "node C")

            val assetId = issueAssetNia(requireNotNull(nodeA), "node A")

            val infoA = requireNotNull(nodeA).nodeInfo()
            val infoB = requireNotNull(nodeB).nodeInfo()
            val peerUriAB = "${infoB.pubkey}@127.0.0.1:${nodeBPeerPort.toInt()}"
            val peerUriBA = "${infoA.pubkey}@127.0.0.1:${nodeAPeerPort.toInt()}"

            requireNotNull(nodeA).openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = peerUriAB,
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
            val channel12Id = waitForChannelOpen(
                requireNotNull(nodeA),
                requireNotNull(nodeB),
                {
                    it.peerPubkey == infoB.pubkey &&
                        it.assetId == assetId &&
                        it.assetLocalAmount == 600uL &&
                        it.assetRemoteAmount == 0uL
                },
                true,
                120L,
            )

            requireNotNull(nodeB).openchannel(
                SdkOpenChannelRequest(
                    peerPubkeyAndOptAddr = peerUriBA,
                    capacitySat = openBtcChannelCapacitySat,
                    pushMsat = openBtcChannelPushMsat,
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
            val channel21Id = waitForChannelOpen(
                requireNotNull(nodeB),
                requireNotNull(nodeA),
                {
                    it.peerPubkey == infoA.pubkey &&
                        it.assetId == null &&
                        it.assetLocalAmount == null &&
                        it.assetRemoteAmount == null
                },
                false,
                120L,
            )

            val channelsABefore = requireNotNull(nodeA).listChannels()
            val channelsBBefore = requireNotNull(nodeB).listChannels()
            val chanA12Before = channelsABefore.first { it.channelId == channel12Id }
            val chanA21Before = channelsABefore.first { it.channelId == channel21Id }
            val chanB12Before = channelsBBefore.first { it.channelId == channel12Id }
            val chanB21Before = channelsBBefore.first { it.channelId == channel21Id }

            val makerInit = requireNotNull(nodeA).`makerinit`(
                SdkMakerInitRequest(
                    qtyFrom = qtyFrom,
                    qtyTo = qtyTo,
                    fromAsset = null,
                    toAsset = assetId,
                    timeoutSec = 3600u,
                )
            )
            requireNotNull(nodeB).taker(SdkTakerRequest(swapstring = makerInit.swapstring))

            val makerWaitingLists = requireNotNull(nodeA).`listSwaps`()
            assertTrue(makerWaitingLists.taker.isEmpty())
            assertEquals(1, makerWaitingLists.maker.size)
            val makerWaiting = makerWaitingLists.maker.first()
            assertEquals(qtyFrom, makerWaiting.qtyFrom)
            assertEquals(qtyTo, makerWaiting.qtyTo)
            assertEquals(null, makerWaiting.fromAsset)
            assertEquals(assetId, makerWaiting.toAsset)
            assertEquals(makerInit.paymentHash, makerWaiting.paymentHash)
            assertEquals(SwapStatus.WAITING, makerWaiting.status)
            val takerWaitingLists = requireNotNull(nodeB).`listSwaps`()
            assertTrue(takerWaitingLists.maker.isEmpty())
            assertEquals(1, takerWaitingLists.taker.size)
            val takerWaiting = takerWaitingLists.taker.first()
            assertEquals(qtyFrom, takerWaiting.qtyFrom)
            assertEquals(qtyTo, takerWaiting.qtyTo)
            assertEquals(null, takerWaiting.fromAsset)
            assertEquals(assetId, takerWaiting.toAsset)
            assertEquals(makerInit.paymentHash, takerWaiting.paymentHash)
            assertEquals(SwapStatus.WAITING, takerWaiting.status)

            requireNotNull(nodeA).`makerexecute`(
                SdkMakerExecuteRequest(
                    swapstring = makerInit.swapstring,
                    paymentSecret = makerInit.paymentSecret,
                    takerPubkey = infoB.pubkey,
                )
            )

            val makerPendingLists = requireNotNull(nodeA).`listSwaps`()
            assertEquals(1, makerPendingLists.maker.size)
            val makerPending = makerPendingLists.maker.first()
            assertEquals(SwapStatus.PENDING, makerPending.status)
            waitForSwapStatus(requireNotNull(nodeB), makerInit.paymentHash, SwapStatus.SUCCEEDED, 150L)

            waitForLnBalance(requireNotNull(nodeA), assetId, 590uL, 120L)
            waitForLnBalance(requireNotNull(nodeB), assetId, 10uL, 120L)

            safeShutdown(nodeA); safeShutdown(nodeB)
            pauseAfterShutdown()
            nodeA = makeNode("swap_roundtrip_buy/node_a", nodeADaemonPort, nodeAPeerPort)
            nodeB = makeNode("swap_roundtrip_buy/node_b", nodeBDaemonPort, nodeBPeerPort)
            unlockNode(requireNotNull(nodeA), "nodeApass", "node A")
            unlockNode(requireNotNull(nodeB), "nodeBpass", "node B")
            waitForUsableChannels(requireNotNull(nodeA), 2, 120L)
            waitForUsableChannels(requireNotNull(nodeB), 2, 120L)

            waitForAssetOffchainBalances(requireNotNull(nodeA), assetId, 590uL, 10uL, 120L)
            waitForAssetOffchainBalances(requireNotNull(nodeB), assetId, 10uL, 590uL, 120L)

            val makerSucceededLists = requireNotNull(nodeA).`listSwaps`()
            assertEquals(1, makerSucceededLists.maker.size)
            val makerSucceeded = makerSucceededLists.maker.first()
            assertEquals(SwapStatus.SUCCEEDED, makerSucceeded.status)
            val takerSucceededLists = requireNotNull(nodeB).`listSwaps`()
            assertEquals(1, takerSucceededLists.taker.size)
            val takerSucceeded = takerSucceededLists.taker.first()
            assertEquals(SwapStatus.SUCCEEDED, takerSucceeded.status)
            assertTrue(requireNotNull(nodeA).listPayments().isEmpty())
            assertTrue(requireNotNull(nodeB).listPayments().isEmpty())

            val channelsA = requireNotNull(nodeA).listChannels()
            val channelsB = requireNotNull(nodeB).listChannels()
            val chanA12 = channelsA.first { it.channelId == channel12Id }
            val chanA21 = channelsA.first { it.channelId == channel21Id }
            val chanB12 = channelsB.first { it.channelId == channel12Id }
            val chanB21 = channelsB.first { it.channelId == channel21Id }
            assertEquals(chanA12Before.localBalanceSat - htlcMinSat, chanA12.localBalanceSat)
            assertEquals(chanA21Before.localBalanceSat + btcLegDiffSat, chanA21.localBalanceSat)
            assertEquals(chanB12Before.localBalanceSat + htlcMinSat, chanB12.localBalanceSat)
            assertEquals(chanB21Before.localBalanceSat - btcLegDiffSat, chanB21.localBalanceSat)

            closeChannel(requireNotNull(nodeA), channel12Id, infoB.pubkey)
            waitForBalance(requireNotNull(nodeA), assetId, 990uL, 180L)
            waitForBalance(requireNotNull(nodeB), assetId, 10uL, 180L)

            closeChannel(requireNotNull(nodeB), channel21Id, infoA.pubkey)

            val recipientIdA = rgbInvoice(nodeC)
            sendRgb(requireNotNull(nodeA), assetId, recipientIdA, 200u)
            mine(1)
            refreshTransfers(nodeC)
            refreshTransfers(nodeC)
            refreshTransfers(requireNotNull(nodeA))

            val recipientIdB = rgbInvoice(nodeC)
            sendRgb(requireNotNull(nodeB), assetId, recipientIdB, 5u)
            mine(1)
            refreshTransfers(nodeC)
            refreshTransfers(nodeC)
            refreshTransfers(requireNotNull(nodeB))

            assertEquals(790uL, assetBalanceSpendable(requireNotNull(nodeA), assetId))
            assertEquals(5uL, assetBalanceSpendable(requireNotNull(nodeB), assetId))
            assertEquals(205uL, assetBalanceSpendable(nodeC, assetId))

            log("SUCCESS: Android swap_roundtrip_buy completed")
        } finally {
            safeShutdown(nodeA)
            safeShutdown(nodeB)
            safeShutdown(nodeC)
            Thread.sleep(1_000L)
        }
    }
}
