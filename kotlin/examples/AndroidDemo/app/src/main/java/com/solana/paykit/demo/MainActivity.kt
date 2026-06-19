package com.solana.paykit.demo

import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.solana.paykit.client.PayKitClient
import com.solana.paykit.paycore.MemorySigner
import com.solana.paykit.paycore.Mints
import com.solana.paykit.paycore.MppException
import com.solana.paykit.paycore.Pda
import com.solana.paykit.paycore.Programs
import com.solana.paykit.paycore.PublicKey
import com.solana.paykit.paycore.SolanaSigner
import com.solana.paykit.protocols.mpp.client.JsonRpcClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.math.BigDecimal
import java.text.SimpleDateFormat
import java.util.Base64 as JBase64
import java.util.Date
import java.util.Locale

/**
 * PayKit demo backed by a local in-memory signer, mirroring the iOS SwiftUI
 * demo (`swift/Examples/PayKitDemo`).
 *
 * Flow:
 *   1. On launch, fetch `/openapi.json` from the playground and render every
 *      priced operation (those carrying an `x-payment-info` extension) as a
 *      tappable card collection.
 *   2. "Setup Account" generates an Ed25519 signer and persists its 32 byte
 *      seed. "Topup" seeds SOL + USDC on the Surfpool sandbox via surfnet
 *      cheatcodes.
 *   3. Tapping an endpoint runs the MPP 402 -> pay -> retry loop through the
 *      unified [PayKitClient] (charge interceptor) and appends the result to
 *      the Log.
 *
 * The playground (`examples/playground-api`, `pnpm dev`) serves its priced
 * routes + `/openapi.json` discovery on :3000 and routes settlement through the
 * hosted Surfpool sandbox at `402.surfnet.dev:8899`. The Android emulator
 * reaches the host machine's localhost via 10.0.2.2 (allow-listed for cleartext
 * in network_security_config.xml), so the playground base is
 * `http://10.0.2.2:3000`.
 *
 * DEMO ONLY: [MemorySigner] holds the private key in app process memory /
 * SharedPreferences. Production apps should delegate signing to Mobile Wallet
 * Adapter or Seed Vault behind a custom [SolanaSigner].
 */
class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = IosColors.GroupedBackground) {
                    DemoScreen()
                }
            }
        }
    }
}

// The playground serves priced routes + /openapi.json on :3000; the emulator
// reaches the host via 10.0.2.2. Settlement rides the hosted Surfpool sandbox.
private const val PLAYGROUND_BASE = "http://10.0.2.2:3000"
private const val RPC_URL = "https://402.surfnet.dev:8899"

@Composable
private fun DemoScreen() {
    val context = LocalContext.current
    val store = remember { AccountStore(context) }
    val scope = rememberCoroutineScope()

    var signer by remember { mutableStateOf<SolanaSigner?>(null) }
    var usdcBalance by remember { mutableStateOf<BigDecimal?>(null) }
    var endpoints by remember { mutableStateOf<List<Endpoint>>(emptyList()) }
    var endpointsError by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf<BusyKind?>(null) }
    val log = remember { mutableStateListOf<LogEntry>() }

    fun append(entry: LogEntry) = log.add(0, entry)

    suspend fun refreshBalance() {
        val s = signer ?: return
        runCatching { usdcBalance(RPC_URL, s.address) }
            .onSuccess { usdcBalance = it }
            .onFailure { append(LogEntry.system("Balance check failed: ${it.message}", success = false)) }
    }

    // Load a persisted signer and the OpenAPI endpoint collection on launch.
    LaunchedEffect(Unit) {
        runCatching { store.loadSigner() }
            .onSuccess { loaded ->
                if (loaded != null) {
                    signer = loaded
                    refreshBalance()
                }
            }
            .onFailure { append(LogEntry.system("Failed to load signer: ${it.message}", success = false)) }

        endpointsError = null
        runCatching { fetchEndpoints() }
            .onSuccess { loaded ->
                endpoints = loaded
                if (loaded.isEmpty()) endpointsError = "No priced endpoints in the OpenAPI spec."
            }
            .onFailure { endpointsError = "Could not load $PLAYGROUND_BASE/openapi.json: ${it.message}" }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Text(
            text = "PayKit Demo",
            fontSize = 34.sp,
            fontWeight = FontWeight.Bold,
            color = IosColors.Label,
        )

        // Account section.
        Section(title = "Account") {
            val s = signer
            if (s != null) {
                LabeledRow(label = "Address", value = shortAddress(s.address), mono = true)
                val balance = usdcBalance
                if (balance != null) {
                    LabeledRow(label = "Balance", value = "${formatUsdc(balance)} USDC", mono = true)
                } else {
                    ActionRow(
                        title = "Topup 1000 USDC + 100 SOL",
                        active = busy == BusyKind.Topup,
                        enabled = busy == null,
                        onClick = {
                            busy = BusyKind.Topup
                            scope.launch {
                                runCatching { topup(RPC_URL, s.address) }
                                    .onSuccess {
                                        append(LogEntry.system("Topup ok: 1000 USDC + 100 SOL", success = true))
                                        refreshBalance()
                                    }
                                    .onFailure {
                                        append(LogEntry.system("Topup failed: ${it.message}", success = false))
                                    }
                                busy = null
                            }
                        },
                    )
                }
            } else {
                ActionRow(
                    title = "Setup Account",
                    active = false,
                    enabled = busy == null,
                    onClick = {
                        runCatching { store.setupSigner() }
                            .onSuccess { created ->
                                signer = created
                                usdcBalance = null
                                append(LogEntry.system("New account: ${created.address}", success = true))
                            }
                            .onFailure {
                                append(LogEntry.system("Setup failed: ${it.message}", success = false))
                            }
                    },
                )
            }
        }

        // Endpoints section.
        Section(title = "Endpoints (${endpoints.size} from OpenAPI)") {
            val error = endpointsError
            when {
                error != null -> Text(
                    text = error,
                    fontSize = 13.sp,
                    color = IosColors.Orange,
                )
                endpoints.isEmpty() -> Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Loading $PLAYGROUND_BASE/openapi.json ...",
                        fontSize = 13.sp,
                        color = IosColors.SecondaryLabel,
                    )
                }
                else -> Row(
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    endpoints.forEach { endpoint ->
                        EndpointCard(
                            endpoint = endpoint,
                            busy = busy == BusyKind.Pay(endpoint.id),
                            enabled = busy == null && signer != null,
                            onClick = onClick@{
                                val s = signer ?: return@onClick
                                busy = BusyKind.Pay(endpoint.id)
                                scope.launch {
                                    append(consume(s, endpoint))
                                    refreshBalance()
                                    busy = null
                                }
                            },
                        )
                    }
                }
            }
            if (signer == null && endpoints.isNotEmpty()) {
                Text(
                    text = "Tap Setup Account to enable these.",
                    fontSize = 13.sp,
                    color = IosColors.SecondaryLabel,
                )
            }
        }

        // Log section.
        Section(
            title = "Log",
            trailing = {
                if (log.isNotEmpty()) {
                    TextButton(onClick = { log.clear() }) { Text("Clear", fontSize = 13.sp) }
                }
            },
        ) {
            if (log.isEmpty()) {
                Text(
                    text = "Tap an endpoint above to send a charge.",
                    fontSize = 14.sp,
                    color = IosColors.SecondaryLabel,
                )
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    log.forEach { entry -> LogRow(entry) }
                }
            }
        }
    }
}

// region UI building blocks

/** An iOS-style inset grouped section: bold gray header + a white rounded card. */
@Composable
private fun Section(
    title: String,
    trailing: @Composable (() -> Unit)? = null,
    content: @Composable () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = title.uppercase(Locale.US),
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                color = IosColors.SecondaryLabel,
                modifier = Modifier.weight(1f),
            )
            trailing?.invoke()
        }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(IosColors.Card)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content()
        }
    }
}

@Composable
private fun LabeledRow(label: String, value: String, mono: Boolean) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(text = label, fontSize = 16.sp, color = IosColors.Label, modifier = Modifier.weight(1f))
        Text(
            text = value,
            fontSize = if (mono) 14.sp else 16.sp,
            color = IosColors.SecondaryLabel,
            fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default,
        )
    }
}

@Composable
private fun ActionRow(title: String, active: Boolean, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
    ) {
        Text(text = title, fontSize = 16.sp, modifier = Modifier.weight(1f))
        if (active) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = Color.White,
            )
        }
    }
}

/** A rounded gradient card per endpoint, mirroring the iOS `EndpointCard`. */
@Composable
private fun EndpointCard(
    endpoint: Endpoint,
    busy: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    val gradient = Brush.verticalGradient(
        listOf(endpoint.tint, endpoint.tint.copy(alpha = 0.78f)),
    )
    val clickModifier = if (enabled) Modifier.clickableNoRipple(onClick) else Modifier
    Column(
        modifier = Modifier
            .width(160.dp)
            .height(132.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(gradient)
            .then(clickModifier)
            .padding(12.dp),
        verticalArrangement = Arrangement.SpaceBetween,
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(text = "$", fontSize = 22.sp, fontWeight = FontWeight.Bold, color = Color.White)
            if (busy) {
                CircularProgressIndicator(
                    modifier = Modifier.size(16.dp),
                    strokeWidth = 2.dp,
                    color = Color.White,
                )
            } else {
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(50))
                        .background(Color.White.copy(alpha = 0.25f))
                        .padding(horizontal = 6.dp, vertical = 2.dp),
                ) {
                    Text(
                        text = endpoint.method,
                        fontSize = 10.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                    )
                }
            }
        }
        Column {
            Text(
                text = endpoint.label,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold,
                color = Color.White,
                maxLines = 2,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                text = endpoint.priceUsd,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                color = Color.White.copy(alpha = 0.9f),
            )
        }
    }
}

@Composable
private fun LogRow(entry: LogEntry) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(modifier = Modifier.size(10.dp).clip(RoundedCornerShape(50)).background(entry.accent))
            Spacer(Modifier.width(8.dp))
            Text(
                text = entry.title,
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = IosColors.Label,
                modifier = Modifier.weight(1f),
            )
            Text(
                text = entry.time,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                color = IosColors.SecondaryLabel,
            )
        }
        entry.signature?.let { sig ->
            Text(
                text = sig,
                fontSize = 13.sp,
                fontFamily = FontFamily.Monospace,
                color = IosColors.Label,
                maxLines = 2,
            )
        }
        entry.detail?.let { detail ->
            Text(
                text = detail,
                fontSize = 13.sp,
                fontFamily = if (entry.monoDetail) FontFamily.Monospace else FontFamily.Default,
                color = IosColors.SecondaryLabel,
                maxLines = 6,
            )
        }
    }
}

/** Clickable without the Material ripple, to keep the gradient card clean. */
@Composable
private fun Modifier.clickableNoRipple(onClick: () -> Unit): Modifier {
    val interactionSource = remember { MutableInteractionSource() }
    return this.clickable(
        interactionSource = interactionSource,
        indication = null,
        onClick = onClick,
    )
}

// endregion

// region Log model

private data class LogEntry(
    val title: String,
    val time: String,
    val accent: Color,
    val signature: String? = null,
    val detail: String? = null,
    val monoDetail: Boolean = true,
) {
    companion object {
        private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

        private fun now(): String = timeFormat.format(Date())

        fun success(endpoint: Endpoint, signature: String?, body: String): LogEntry = LogEntry(
            title = "${endpoint.label} — 200 OK",
            time = now(),
            accent = IosColors.Green,
            signature = signature,
            detail = when {
                body.isNotBlank() -> body
                signature == null -> "No Payment-Receipt header in response."
                else -> null
            },
        )

        fun failure(endpoint: Endpoint?, message: String): LogEntry = LogEntry(
            title = endpoint?.let { "${it.label} — failed" } ?: "Error",
            time = now(),
            accent = IosColors.Red,
            detail = message,
        )

        fun system(message: String, success: Boolean): LogEntry = LogEntry(
            title = "System",
            time = now(),
            accent = if (success) IosColors.Blue else IosColors.Orange,
            detail = message,
            monoDetail = false,
        )
    }
}

private sealed interface BusyKind {
    data object Topup : BusyKind
    data class Pay(val endpointId: String) : BusyKind
}

// endregion

// region iOS-like palette

private object IosColors {
    val GroupedBackground = Color(0xFFF2F2F7)
    val Card = Color(0xFFFFFFFF)
    val Label = Color(0xFF1C1C1E)
    val SecondaryLabel = Color(0xFF8E8E93)
    val Blue = Color(0xFF0A84FF)
    val Green = Color(0xFF34C759)
    val Red = Color(0xFFFF3B30)
    val Orange = Color(0xFFFF9500)
}

// endregion

// region Consume flow (SDK)

private val responseJson = Json { ignoreUnknownKeys = true }
private val httpClient = OkHttpClient()

/**
 * Consumes a priced endpoint through the unified [PayKitClient], mirroring the
 * iOS demo's `pay(_:)`. Builds an MPP-charge-enabled client bound to the
 * persisted signer, issues the request against `PLAYGROUND_BASE + endpoint.path`,
 * and lets the charge interceptor run the 402 -> pay -> retry loop. The on-chain
 * signature is pulled from the `Payment-Receipt` envelope on success.
 */
private suspend fun consume(signer: SolanaSigner, endpoint: Endpoint): LogEntry = withContext(Dispatchers.IO) {
    val url = "$PLAYGROUND_BASE${endpoint.path}"
    try {
        val client = PayKitClient.Builder()
            .signer(signer)
            .charge(blockhashProvider = JsonRpcClient(RPC_URL))
            .build()

        val payResponse = if (endpoint.method == "POST") {
            client.post(
                url = url,
                body = "{}".toByteArray(),
                contentType = "application/json",
                headers = mapOf("Accept" to "application/json"),
            )
        } else {
            client.get(url = url, headers = mapOf("Accept" to "application/json"))
        }

        val settlement = payResponse.settlement
        payResponse.use { body ->
            val text = body.orEmpty()
            if (payResponse.status in 200..299) {
                LogEntry.success(
                    endpoint = endpoint,
                    signature = settlement?.let { signatureFromReceiptHeader(it) },
                    body = text,
                )
            } else {
                LogEntry.failure(endpoint, "HTTP ${payResponse.status}\n$text")
            }
        }
    } catch (mpp: MppException) {
        android.util.Log.e("PayKitDemo", "MPP error", mpp)
        LogEntry.failure(endpoint, "MPP error: ${mpp.message ?: mpp::class.simpleName}")
    } catch (t: Throwable) {
        android.util.Log.e("PayKitDemo", "consume failed", t)
        LogEntry.failure(endpoint, "${t.javaClass.simpleName}: ${t.message ?: "(no message)"}")
    }
}

/**
 * Decode a `Payment-Receipt` header (base64url-no-pad JSON envelope produced by
 * the gateway's `format_receipt`) and return the `reference` field — the
 * on-chain signature. Mirrors the iOS `signatureFromReceiptHeader`.
 */
private fun signatureFromReceiptHeader(header: String): String? {
    return try {
        val decoded = JBase64.getUrlDecoder().decode(header.padBase64Url())
        val json = responseJson.parseToJsonElement(String(decoded)) as? JsonObject ?: return null
        json["reference"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotEmpty() }
    } catch (_: Throwable) {
        null
    }
}

private fun String.padBase64Url(): String {
    val pad = (4 - length % 4) % 4
    return this + "=".repeat(pad)
}

// endregion

// region OpenAPI fetch

/** Fetch and parse the playground's `/openapi.json` off the main thread. */
private suspend fun fetchEndpoints(): List<Endpoint> = withContext(Dispatchers.IO) {
    val request = Request.Builder().url("$PLAYGROUND_BASE/openapi.json").get().build()
    httpClient.newCall(request).execute().use { resp ->
        val body = resp.body?.string().orEmpty()
        if (resp.code !in 200..299) {
            throw OpenApiException("openapi.json returned HTTP ${resp.code}")
        }
        OpenApi.endpoints(body)
    }
}

// endregion

// region Account store + topup/balance

/** Surfpool sandbox cheatcode targets and demo topup amounts (mirror DemoSigner.swift). */
private const val USDC_MINT = Mints.USDC_MAINNET
private const val SYSTEM_PROGRAM = "11111111111111111111111111111111"
private const val TOPUP_LAMPORTS = 100_000_000_000L
private const val TOPUP_USDC_BASE_UNITS = 1_000_000_000L

/**
 * Persists the demo signer's 32 byte Ed25519 seed in SharedPreferences (the
 * Android analogue of the iOS Keychain store). DEMO ONLY: the key is in
 * cleartext app storage; production apps should use the Android Keystore or a
 * wallet-backed [SolanaSigner].
 */
private class AccountStore(context: Context) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("paykit-demo", Context.MODE_PRIVATE)

    /** Load the persisted signer, or null when Setup Account has not run. */
    fun loadSigner(): SolanaSigner? {
        val encoded = prefs.getString(SEED_KEY, null) ?: return null
        val seed = JBase64.getDecoder().decode(encoded)
        require(seed.size == 32) { "stored seed is not 32 bytes; reset the account" }
        return MemorySigner.fromSeed(seed)
    }

    /** Generate a fresh signer, persist its seed, and return it. */
    fun setupSigner(): SolanaSigner {
        val signer = MemorySigner.generate()
        prefs.edit().putString(SEED_KEY, JBase64.getEncoder().encodeToString(signer.seedBytes())).apply()
        return signer
    }

    private companion object {
        const val SEED_KEY = "demo-signer-seed"
    }
}

/**
 * Seed an account on Surfpool with SOL + USDC via the surfnet cheatcodes.
 * Idempotent — re-running just resets the balances. Only works on a Surfpool
 * RPC (the hosted sandbox or local Surfpool).
 */
private suspend fun topup(rpcUrl: String, pubkey: String) = withContext(Dispatchers.IO) {
    rpcCall(
        rpcUrl,
        method = "surfnet_setAccount",
        params = buildJsonArray {
            add(JsonPrimitive(pubkey))
            add(
                buildJsonObject {
                    put("lamports", TOPUP_LAMPORTS)
                    put("data", "")
                    put("executable", false)
                    put("owner", SYSTEM_PROGRAM)
                },
            )
        },
    )
    rpcCall(
        rpcUrl,
        method = "surfnet_setTokenAccount",
        params = buildJsonArray {
            add(JsonPrimitive(pubkey))
            add(JsonPrimitive(USDC_MINT))
            add(buildJsonObject { put("amount", TOPUP_USDC_BASE_UNITS) })
            add(JsonPrimitive(Programs.TOKEN_PROGRAM))
        },
    )
}

/**
 * Fetch the USDC balance (in decimal USDC, 6-decimal mint) for [pubkey] on the
 * given Surfpool RPC. Returns null when the ATA does not exist yet (the account
 * has not been topped up). Mirrors `DemoSigner.usdcBalance`.
 */
private suspend fun usdcBalance(rpcUrl: String, pubkey: String): BigDecimal? = withContext(Dispatchers.IO) {
    val ata = Pda.associatedTokenAddress(
        owner = PublicKey.fromBase58(pubkey),
        mint = PublicKey.fromBase58(USDC_MINT),
        tokenProgram = PublicKey.fromBase58(Programs.TOKEN_PROGRAM),
    )
    val response = try {
        rpcCall(
            rpcUrl,
            method = "getTokenAccountBalance",
            params = buildJsonArray { add(JsonPrimitive(ata.toBase58())) },
        )
    } catch (e: Throwable) {
        if (e.message?.contains("could not find account") == true) return@withContext null
        throw e
    }
    val ui = response["result"]?.jsonObject?.get("value")?.jsonObject
        ?.get("uiAmountString")?.jsonPrimitive?.contentOrNull
        ?: return@withContext null
    ui.toBigDecimalOrNull()
}

/** Minimal JSON-RPC POST; throws on a JSON-RPC `error` field or non-2xx status. */
private fun rpcCall(
    rpcUrl: String,
    method: String,
    params: kotlinx.serialization.json.JsonArray,
): JsonObject {
    val payload = buildJsonObject {
        put("jsonrpc", "2.0")
        put("id", 1)
        put("method", method)
        put("params", params)
    }
    val body = responseJson.encodeToString(JsonObject.serializer(), payload)
        .toRequestBody("application/json".toMediaType())
    val request = Request.Builder().url(rpcUrl).post(body).build()
    httpClient.newCall(request).execute().use { resp ->
        val text = resp.body?.string().orEmpty()
        if (resp.code !in 200..299) {
            throw IllegalStateException("RPC HTTP ${resp.code}: $text")
        }
        val parsed = responseJson.parseToJsonElement(text) as? JsonObject
            ?: throw IllegalStateException("non-object RPC response")
        parsed["error"]?.let { throw IllegalStateException("RPC error: $it") }
        return parsed
    }
}

private fun String.toBigDecimalOrNull(): BigDecimal? =
    try {
        BigDecimal(this)
    } catch (_: NumberFormatException) {
        null
    }

// region formatting helpers

/** Truncate a base58 pubkey to `first6…last6`, like the iOS `shortAddress`. */
private fun shortAddress(address: String): String =
    if (address.length > 14) "${address.take(6)}…${address.takeLast(6)}" else address

/** Format a USDC decimal, trimming trailing zeros (max 6 fraction digits). */
private fun formatUsdc(amount: BigDecimal): String {
    val stripped = amount.stripTrailingZeros()
    return if (stripped.scale() <= 0) stripped.toBigInteger().toString() else stripped.toPlainString()
}

// endregion
