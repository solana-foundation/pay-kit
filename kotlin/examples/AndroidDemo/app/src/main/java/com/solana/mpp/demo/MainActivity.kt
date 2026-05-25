package com.solana.mpp.demo

import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.solana.mobilewalletadapter.clientlib.ActivityResultSender
import com.solana.mobilewalletadapter.clientlib.ConnectionIdentity
import com.solana.mobilewalletadapter.clientlib.MobileWalletAdapter
import com.solana.mobilewalletadapter.clientlib.Solana
import com.solana.mobilewalletadapter.clientlib.TransactionResult
import com.solana.mobilewalletadapter.clientlib.successPayload
import com.solana.mpp.client.Charge
import com.solana.mpp.client.JsonRpcClient
import com.solana.mpp.crypto.PublicKey
import com.solana.mpp.protocol.CredentialPayload
import com.solana.mpp.protocol.MppException
import com.solana.mpp.protocol.MppHeaders
import com.solana.mpp.protocol.PaymentCredential
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.Base64 as JBase64

/**
 * MPP charge demo backed by Mobile Wallet Adapter.
 *
 * Flow on Pay:
 *   1. GET the merchant URL. Expect a 402 Payment Required with a
 *      WWW-Authenticate: Payment ... challenge.
 *   2. Decode the Solana charge challenge.
 *   3. Build the unsigned transaction wire bytes via
 *      Charge.buildUnsignedChargeTransaction with the connected wallet's
 *      pubkey as fee payer.
 *   4. Hand the bytes to the wallet via
 *      walletAdapter.transact { signTransactions(...) }.
 *   5. Base64 the signed bytes, format the Authorization header, replay
 *      the GET with the credential.
 *
 * The wallet must be installed on the device. For emulator testing,
 * side-load solana-mobile/mock-mwa-wallet so MWA has a target to
 * deep-link into. See README for setup.
 */
class MainActivity : ComponentActivity() {
    private val walletAdapter = MobileWalletAdapter(
        connectionIdentity = ConnectionIdentity(
            identityUri = Uri.parse("https://402.surfnet.dev"),
            iconUri = Uri.parse("icon.png"),
            identityName = "MPP Charge Demo",
        ),
    ).apply {
        blockchain = Solana.Devnet
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val sender = ActivityResultSender(this)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DemoScreen(walletAdapter, sender)
                }
            }
        }
    }
}

@Composable
private fun DemoScreen(
    walletAdapter: MobileWalletAdapter,
    sender: ActivityResultSender,
) {
    // 10.0.2.2 is the Android emulator's loopback to the host machine.
    // For 402.surfnet.dev override the merchant URL field at runtime.
    var merchantUrl by remember { mutableStateOf("https://402.surfnet.dev/protected") }
    var rpcUrl by remember { mutableStateOf("https://402.surfnet.dev/rpc") }
    var status by remember { mutableStateOf(Status.idle()) }
    var walletPubkey by remember { mutableStateOf<PublicKey?>(null) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(text = "MPP Charge Demo", style = MaterialTheme.typography.headlineSmall)
        Text(
            text = "Pay a 402-protected route using a real wallet via Mobile Wallet Adapter.",
            style = MaterialTheme.typography.bodyMedium,
        )

        OutlinedTextField(
            value = merchantUrl,
            onValueChange = { merchantUrl = it },
            label = { Text("Merchant URL") },
            modifier = Modifier.fillMaxSize(),
        )
        OutlinedTextField(
            value = rpcUrl,
            onValueChange = { rpcUrl = it },
            label = { Text("Solana RPC URL") },
            modifier = Modifier.fillMaxSize(),
        )

        Button(
            enabled = !status.inFlight,
            onClick = {
                status = Status.running("Connecting to wallet ...")
                scope.launch {
                    when (val result = walletAdapter.connect(sender)) {
                        is TransactionResult.Success -> {
                            val pk = PublicKey(result.authResult.publicKey)
                            walletPubkey = pk
                            status = Status(
                                inFlight = false,
                                message = "Connected. Wallet pubkey: ${pk.toBase58()}",
                            )
                        }
                        is TransactionResult.NoWalletFound ->
                            status = Status(
                                false,
                                "No wallet found on device. Install Phantom, Solflare, or mock-mwa-wallet for emulator testing.",
                            )
                        is TransactionResult.Failure ->
                            status = Status(
                                false,
                                "Connect failed: ${result.e.message ?: result.e::class.simpleName}",
                            )
                    }
                }
            },
        ) {
            Text(if (walletPubkey == null) "Connect Wallet" else "Reconnect Wallet")
        }

        Button(
            enabled = !status.inFlight && walletPubkey != null,
            onClick = {
                val pk = walletPubkey ?: return@Button
                status = Status.running("Building credential ...")
                scope.launch {
                    status = runCharge(walletAdapter, sender, pk, merchantUrl, rpcUrl)
                }
            },
        ) {
            Text(if (status.inFlight) "Paying ..." else "Pay")
        }

        Text(text = status.message, style = MaterialTheme.typography.bodyMedium)
        status.signature?.let { signature ->
            Text(
                text = "Solana Explorer: https://explorer.solana.com/tx/$signature?cluster=devnet",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private data class Status(
    val inFlight: Boolean,
    val message: String,
    val signature: String? = null,
) {
    companion object {
        fun idle() = Status(false, "Idle. Press Connect Wallet to begin.")
        fun running(message: String = "Working ...") = Status(true, message)
    }
}

private val responseJson = Json { ignoreUnknownKeys = true }
private val httpClient = OkHttpClient()

/**
 * Issues the initial unauthenticated GET, parses the 402 challenge,
 * builds the unsigned transaction, asks the wallet to sign it, and
 * replays the request with the MPP Authorization header.
 *
 * Runs the OkHttp/JSON-RPC calls on Dispatchers.IO so they do not block
 * the compose recomposition thread. The walletAdapter.transact call
 * itself suspends on the wallet's user-approval flow.
 */
private suspend fun runCharge(
    walletAdapter: MobileWalletAdapter,
    sender: ActivityResultSender,
    walletPubkey: PublicKey,
    merchantUrl: String,
    rpcUrl: String,
): Status {
    return try {
        // 1. Initial GET. Expect 402 with a Solana charge challenge.
        // Read everything that touches the response body off the main thread
        // so okhttp's lazy body consumption does not raise
        // NetworkOnMainThreadException on resume.
        data class InitialResponse(val code: Int, val body: String, val wwwAuth: List<String>)
        val initialParsed = withContext(Dispatchers.IO) {
            httpClient.newCall(Request.Builder().url(merchantUrl).get().build()).execute().use { resp ->
                InitialResponse(
                    code = resp.code,
                    body = resp.body?.string().orEmpty(),
                    wwwAuth = resp.headers("WWW-Authenticate"),
                )
            }
        }
        if (initialParsed.code != 402) {
            return Status(false, "Expected 402, got HTTP ${initialParsed.code}\n${initialParsed.body}")
        }
        val challengeHeaders = initialParsed.wwwAuth
        val challenge = MppHeaders.selectSolanaChargeChallenge(challengeHeaders)
            ?: throw MppException.InvalidPaymentScheme

        // 2. Build the unsigned transaction with the wallet's pubkey as
        // signer. JsonRpcClient supplies the recent blockhash if the
        // challenge does not pin one.
        val unsignedTx = withContext(Dispatchers.IO) {
            Charge.buildUnsignedChargeTransaction(
                walletPublicKey = walletPubkey,
                request = challenge.chargeRequest(),
                blockhashProvider = JsonRpcClient(rpcUrl),
            )
        }

        // 3. Ask the wallet to sign. MWA returns the signed transaction
        // wire bytes directly; we base64-encode for the credential.
        val signResult = walletAdapter.transact(sender) { authResult ->
            // Confirm the connected account still matches the one we
            // built the transaction against. If the user switched
            // accounts inside the wallet, the wire bytes reference the
            // wrong fee payer and the signature would be rejected on
            // submission.
            val authPubkey = PublicKey(authResult.accounts.first().publicKey)
            check(authPubkey.bytes.contentEquals(walletPubkey.bytes)) {
                "wallet returned a different account than the one used to build the transaction"
            }
            signTransactions(arrayOf(unsignedTx))
        }
        val signedTxBytes = when (signResult) {
            is TransactionResult.Success ->
                signResult.successPayload?.signedPayloads?.firstOrNull()
                    ?: return Status(false, "Wallet returned no signed payload")
            is TransactionResult.NoWalletFound ->
                return Status(false, "No wallet found on device")
            is TransactionResult.Failure ->
                return Status(
                    false,
                    "Wallet sign failed: ${signResult.e.message ?: signResult.e::class.simpleName}",
                )
        }
        val signedTxBase64 = JBase64.getEncoder().encodeToString(signedTxBytes)

        // 4. Replay the request with the Authorization header.
        val authorization = MppHeaders.formatAuthorization(
            PaymentCredential(
                challenge = challenge.echo(),
                payload = CredentialPayload.transaction(signedTxBase64),
            ),
        )
        data class AuthedResponse(val code: Int, val body: String)
        val authed = withContext(Dispatchers.IO) {
            httpClient.newCall(
                Request.Builder().url(merchantUrl).get()
                    .header("Authorization", authorization)
                    .build(),
            ).execute().use { resp ->
                AuthedResponse(resp.code, resp.body?.string().orEmpty())
            }
        }
        val code = authed.code
        val body = authed.body
        Status(
            inFlight = false,
            message = "HTTP $code\n$body",
            signature = extractSignature(body),
        )
    } catch (mpp: MppException) {
        android.util.Log.e("MppDemo", "MPP error", mpp)
        Status(false, "MPP error: ${mpp.message ?: mpp::class.simpleName}")
    } catch (t: Throwable) {
        android.util.Log.e("MppDemo", "runCharge failed", t)
        Status(false, "Error: ${t.javaClass.simpleName}: ${t.message ?: "(no message)"}")
    }
}

private fun extractSignature(body: String): String? {
    if (body.isBlank()) return null
    return try {
        val parsed = responseJson.parseToJsonElement(body)
        val obj = parsed as? JsonObject ?: return null
        // Spine receipts surface the on-chain signature under different
        // key names depending on the server. Try the common shapes.
        listOf("signature", "tx_signature", "txSignature")
            .firstNotNullOfOrNull { obj[it]?.jsonPrimitive?.content }
            ?: obj["receipt"]?.let { (it as? JsonObject) }?.let { receipt ->
                listOf("signature", "tx_signature", "txSignature")
                    .firstNotNullOfOrNull { receipt[it]?.jsonPrimitive?.content }
            }
    } catch (_: Throwable) {
        null
    }
}
