package com.solana.mpp.demo

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.solana.mpp.Charge
import com.solana.mpp.JsonRpcClient
import com.solana.mpp.MemorySigner
import com.solana.mpp.MppException
import com.solana.mpp.MppHttpClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    DemoScreen()
                }
            }
        }
    }
}

@Composable
private fun DemoScreen() {
    // 10.0.2.2 is the Android emulator's loopback to the host machine.
    // For 402.surfnet.dev override the merchant URL field at runtime.
    var merchantUrl by remember { mutableStateOf("https://402.surfnet.dev/protected") }
    var rpcUrl by remember { mutableStateOf("https://402.surfnet.dev/rpc") }
    var status by remember { mutableStateOf(Status.idle()) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        DemoWarningBanner()
        Text(text = "MPP Charge Demo", style = MaterialTheme.typography.headlineSmall)
        Text(
            text = "Pay a 402-protected route using a local Ed25519 signer.",
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
                status = Status.running()
                scope.launch {
                    status = withContext(Dispatchers.IO) { runCharge(merchantUrl, rpcUrl) }
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

    LaunchedEffect(Unit) {
        // Show the demo signer pubkey on first composition so the user
        // can fund it on devnet before pressing Pay.
        status = status.copy(message = "Signer pubkey: ${DemoSigner.publicKeyBase58()}")
    }
}

@Composable
private fun DemoWarningBanner() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(Color(0xFFB71C1C))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Text(
            text = "DEMO ONLY",
            color = Color.White,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "This app uses a deterministic seed signer that is publicly known.",
            color = Color.White,
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            text = "Do NOT fund this address on mainnet or any production network.",
            color = Color.White,
            style = MaterialTheme.typography.bodySmall,
            fontWeight = FontWeight.Bold,
        )
    }
}

private data class Status(
    val inFlight: Boolean,
    val message: String,
    val signature: String? = null,
) {
    companion object {
        fun idle() = Status(false, "Idle.")
        fun running() = Status(true, "Building credential ...")
    }
}

private suspend fun runCharge(merchantUrl: String, rpcUrl: String): Status {
    return try {
        val signer = DemoSigner.signer
        val blockhashProvider = JsonRpcClient(rpcUrl)
        val client = MppHttpClient(signer = signer, blockhashProvider = blockhashProvider)
        val response = client.mppGet(merchantUrl)
        val code = response.code
        val bodyText = response.body?.string().orEmpty()
        response.close()

        val signature = extractSignature(bodyText)
        Status(
            inFlight = false,
            message = "HTTP $code\n$bodyText",
            signature = signature,
        )
    } catch (mpp: MppException) {
        Status(false, "MPP error: ${mpp.message ?: mpp::class.simpleName}")
    } catch (t: Throwable) {
        Status(false, "Error: ${t.javaClass.simpleName}: ${t.message ?: "(no message)"}")
    }
}

private val responseJson = Json { ignoreUnknownKeys = true }

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

private object DemoSigner {
    // Ephemeral seed for the demo. In a real app this would be
    // replaced by Mobile Wallet Adapter; the SDK's SolanaSigner
    // interface is the swap point (see README).
    private val seed: ByteArray = ByteArray(32).also { bytes ->
        // Deterministic for demo runs so the displayed pubkey stays
        // stable across cold starts; do not reuse for anything real.
        for (i in bytes.indices) bytes[i] = (i + 1).toByte()
    }

    val signer: MemorySigner by lazy { MemorySigner.fromSeed(seed) }

    fun publicKeyBase58(): String = signer.address
}
