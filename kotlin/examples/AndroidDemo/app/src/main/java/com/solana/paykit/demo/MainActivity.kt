package com.solana.paykit.demo

import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowCircleDown
import androidx.compose.material.icons.filled.Dangerous
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MonetizationOn
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
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
    // Per-endpoint protocol the user picked to settle over (endpoint id -> method).
    var protocolChoice by remember { mutableStateOf<Map<String, String>>(emptyMap()) }
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
            .padding(vertical = 24.dp),
        verticalArrangement = Arrangement.spacedBy(32.dp),
    ) {
        Text(
            text = "PayKit Demo",
            fontSize = 34.sp,
            fontWeight = FontWeight.Bold,
            color = IosColors.Label,
            modifier = Modifier.padding(start = 16.dp),
        )

        // Account section.
        Section(title = "Account") {
            val s = signer
            if (s != null) {
                LabeledRow(label = "Address") {
                    Text(
                        text = shortAddress(s.address),
                        fontSize = 13.sp,
                        fontFamily = FontFamily.Monospace,
                        color = IosColors.SecondaryLabel,
                    )
                }
                val balance = usdcBalance
                if (balance != null) {
                    SectionDivider()
                    LabeledRow(label = "Balance") {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                imageVector = Icons.Filled.MonetizationOn,
                                contentDescription = null,
                                tint = IosColors.Green,
                                modifier = Modifier.size(17.dp),
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                text = "${formatUsdc(balance)} USDC",
                                fontSize = 17.sp,
                                fontFamily = FontFamily.Monospace,
                                color = IosColors.Label,
                            )
                        }
                    }
                } else {
                    SectionDivider()
                    ActionRow(
                        title = "Topup 1000 USDC + 100 SOL",
                        icon = Icons.Filled.ArrowCircleDown,
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
                    icon = Icons.Filled.VpnKey,
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

        // Endpoints section. The card carries no internal padding so the
        // LazyRow can bleed its 12dp content insets to the card edges.
        Section(
            title = "Endpoints (${endpoints.size} from OpenAPI)",
            contentPadding = PaddingValues(0.dp),
        ) {
            val error = endpointsError
            when {
                error != null -> Text(
                    text = error,
                    fontSize = 13.sp,
                    color = IosColors.Orange,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 11.dp),
                )
                endpoints.isEmpty() -> Row(
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 11.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                    Text(
                        text = "Loading $PLAYGROUND_BASE/openapi.json ...",
                        fontSize = 13.sp,
                        color = IosColors.SecondaryLabel,
                    )
                }
                else -> LazyRow(
                    contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(endpoints, key = { it.id }) { endpoint ->
                        EndpointCard(
                            endpoint = endpoint,
                            busy = busy == BusyKind.Pay(endpoint.id),
                            enabled = busy == null && signer != null,
                            selected = protocolChoice[endpoint.id] ?: endpoint.selectedProtocol,
                            onSelectProtocol = { protocolChoice = protocolChoice + (endpoint.id to it) },
                            onClick = onClick@{
                                val s = signer ?: return@onClick
                                when (endpoint.intent) {
                                    // One-shot charge: the 402 -> sign -> retry loop, over the
                                    // protocol the user picked (default: the advertised mpp).
                                    "charge" -> {
                                        busy = BusyKind.Pay(endpoint.id)
                                        val proto = protocolChoice[endpoint.id] ?: endpoint.selectedProtocol
                                        scope.launch {
                                            append(consume(s, endpoint, proto))
                                            refreshBalance()
                                            busy = null
                                        }
                                    }
                                    // Session: open a payment channel, stream metered SSE
                                    // deliveries, sign + commit a voucher, settle.
                                    "session" -> {
                                        busy = BusyKind.Pay(endpoint.id)
                                        scope.launch {
                                            append(consumeSession(s, endpoint))
                                            refreshBalance()
                                            busy = null
                                        }
                                    }
                                    // Other intents (subscription, x402 upto) use dedicated
                                    // pay-kit APIs the tap demo doesn't drive.
                                    else -> append(
                                        LogEntry.failure(
                                            endpoint,
                                            "${endpoint.label} is an mpp/${endpoint.intent} flow this demo doesn't drive; use the matching pay-kit API.",
                                        )
                                    )
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
                    modifier = Modifier.padding(horizontal = 16.dp).padding(bottom = 11.dp),
                )
            }
        }

        // Log section.
        Section(
            title = "Log",
            trailing = {
                if (log.isNotEmpty()) {
                    TextButton(
                        onClick = { log.clear() },
                        contentPadding = PaddingValues(0.dp),
                    ) {
                        Text(
                            text = "Clear",
                            fontSize = 13.sp,
                            fontWeight = FontWeight.Normal,
                            color = IosColors.Blue,
                        )
                    }
                }
            },
            contentPadding = PaddingValues(horizontal = 16.dp),
        ) {
            if (log.isEmpty()) {
                Text(
                    text = "Tap an endpoint above to send a charge.",
                    fontSize = 17.sp,
                    color = IosColors.SecondaryLabel,
                    modifier = Modifier.padding(vertical = 11.dp),
                )
            } else {
                log.forEachIndexed { index, entry ->
                    if (index > 0) SectionDivider()
                    LogRow(entry)
                }
            }
        }
    }
}

// region UI building blocks

/** An iOS-style inset grouped section: a gray uppercase header + a white
 *  rounded card (10dp radius, 16dp inset, no shadow). The optional [trailing]
 *  sits at the header's trailing edge (the Log's "Clear" button). */
@Composable
private fun Section(
    title: String,
    trailing: @Composable (() -> Unit)? = null,
    contentPadding: PaddingValues = PaddingValues(horizontal = 16.dp),
    content: @Composable () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = title.uppercase(Locale.US),
                fontSize = 13.sp,
                fontWeight = FontWeight.Normal,
                color = IosColors.SecondaryLabel,
                modifier = Modifier.weight(1f),
            )
            trailing?.invoke()
        }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .clip(RoundedCornerShape(10.dp))
                .background(IosColors.Card)
                .padding(contentPadding),
        ) {
            content()
        }
    }
}

/** Hairline separator between in-card rows (#C6C6C8). */
@Composable
private fun SectionDivider() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(IosColors.Separator),
    )
}

/** A label-left / value-right grouped row with 11dp vertical, 16dp horizontal
 *  padding handled by the caller's card insets (here only vertical). */
@Composable
private fun LabeledRow(label: String, value: @Composable () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 11.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontSize = 17.sp,
            fontWeight = FontWeight.Normal,
            color = IosColors.Label,
            modifier = Modifier.weight(1f),
        )
        value()
    }
}

/** A full-width plain tinted row (icon + text left, spinner right when busy):
 *  Setup Account / Topup. No filled pill background, ~44dp tall. */
@Composable
private fun ActionRow(
    title: String,
    icon: ImageVector,
    active: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 44.dp)
            .clickableNoRipple(enabled = enabled, onClick = onClick),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = null,
            tint = IosColors.Blue,
            modifier = Modifier.size(20.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text(
            text = title,
            fontSize = 17.sp,
            fontWeight = FontWeight.Normal,
            color = IosColors.Blue,
            modifier = Modifier.weight(1f),
        )
        if (active) {
            CircularProgressIndicator(
                modifier = Modifier.size(18.dp),
                strokeWidth = 2.dp,
                color = IosColors.Blue,
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
    selected: String?,
    onClick: () -> Unit,
    onSelectProtocol: (String) -> Unit,
) {
    // Charge endpoints advertising more than one protocol let the user pick which
    // to settle over by tapping a method chip.
    val selectable = endpoint.intent == "charge" && endpoint.methods.size > 1
    val gradient = Brush.verticalGradient(
        listOf(endpoint.tint, endpoint.tint.darkenBy(0.12f)),
    )
    Column(
        modifier = Modifier
            .width(150.dp)
            .height(130.dp)
            .clip(RoundedCornerShape(14.dp))
            .background(gradient)
            .clickableNoRipple(enabled = enabled, onClick = onClick)
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = endpoint.icon,
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.size(22.dp),
            )
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
                        text = endpoint.method.uppercase(Locale.US),
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color.White,
                    )
                }
            }
        }
        Spacer(Modifier.weight(1f))
        Text(
            text = endpoint.label,
            fontSize = 15.sp,
            fontWeight = FontWeight.SemiBold,
            color = Color.White,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
        )
        Text(
            text = endpoint.priceUsd,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = Color.White.copy(alpha = 0.9f),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(3.dp)) {
            endpoint.methods.forEachIndexed { index, method ->
                if (index > 0) {
                    Text("·", fontSize = 11.sp, color = Color.White.copy(alpha = 0.45f))
                }
                val isSelected = method == selected
                Text(
                    text = method,
                    fontSize = 11.sp,
                    fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Normal,
                    textDecoration = if (isSelected && selectable) TextDecoration.Underline else null,
                    color = Color.White.copy(alpha = if (isSelected) 1f else 0.55f),
                    modifier = if (selectable) {
                        Modifier.clickableNoRipple(enabled = true) { onSelectProtocol(method) }
                    } else {
                        Modifier
                    },
                )
            }
            if (endpoint.intent != "charge") {
                Text("·", fontSize = 11.sp, color = Color.White.copy(alpha = 0.45f))
                Text(endpoint.intent, fontSize = 11.sp, color = Color.White.copy(alpha = 0.55f))
            }
        }
    }
}

@Composable
private fun LogRow(entry: LogEntry) {
    val context = LocalContext.current
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Icon(
                imageVector = entry.statusIcon,
                contentDescription = null,
                tint = entry.statusTint,
                modifier = Modifier.size(17.dp),
            )
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
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "View receipt on pay.sh",
                fontSize = 13.sp,
                fontWeight = FontWeight.Normal,
                color = IosColors.Blue,
                modifier = Modifier.clickableNoRipple {
                    val uri = Uri.parse("https://pay.sh/receipt/$sig?network=sandbox")
                    runCatching { context.startActivity(Intent(Intent.ACTION_VIEW, uri)) }
                },
            )
        }
        entry.detail?.let { detail ->
            Text(
                text = detail,
                fontSize = 13.sp,
                fontFamily = if (entry.monoDetail) FontFamily.Monospace else FontFamily.Default,
                color = IosColors.SecondaryLabel,
                maxLines = entry.detailMaxLines,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** Clickable without the Material ripple, to keep the surrounding cells clean. */
@Composable
private fun Modifier.clickableNoRipple(enabled: Boolean = true, onClick: () -> Unit): Modifier {
    val interactionSource = remember { MutableInteractionSource() }
    return this.clickable(
        interactionSource = interactionSource,
        indication = null,
        enabled = enabled,
        onClick = onClick,
    )
}

// endregion

// region Log model

private data class LogEntry(
    val title: String,
    val time: String,
    val statusIcon: ImageVector,
    val statusTint: Color,
    val signature: String? = null,
    val detail: String? = null,
    val monoDetail: Boolean = true,
    val detailMaxLines: Int = 6,
) {
    companion object {
        private val timeFormat = SimpleDateFormat("HH:mm:ss", Locale.US)

        private fun now(): String = timeFormat.format(Date())

        fun success(endpoint: Endpoint, signature: String?, body: String): LogEntry = LogEntry(
            title = "${endpoint.label} — 200 OK",
            time = now(),
            statusIcon = Icons.Filled.Verified,
            statusTint = IosColors.Green,
            signature = signature,
            detail = when {
                body.isNotBlank() -> body
                signature == null -> "Settled. No settlement signature in response."
                else -> null
            },
            detailMaxLines = 4,
        )

        fun failure(endpoint: Endpoint?, message: String): LogEntry = LogEntry(
            title = endpoint?.let { "${it.label} — failed" } ?: "Error",
            time = now(),
            statusIcon = Icons.Filled.Dangerous,
            statusTint = IosColors.Red,
            detail = message,
            detailMaxLines = 6,
        )

        fun system(message: String, success: Boolean): LogEntry = LogEntry(
            title = "System",
            time = now(),
            statusIcon = if (success) Icons.Filled.Info else Icons.Filled.Warning,
            statusTint = if (success) IosColors.Blue else IosColors.Orange,
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
    val Label = Color(0xFF000000)
    val SecondaryLabel = Color(0xFF8E8E93)
    val Separator = Color(0xFFC6C6C8)
    val Blue = Color(0xFF007AFF)
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
/**
 * Drive the full payment-channel **session** for a session endpoint: open the
 * channel, stream the metered SSE deliveries, sign + commit a voucher, and poll
 * the settle signature (see [SessionStream]). Mirrors the iOS demo's session path.
 */
private suspend fun consumeSession(signer: SolanaSigner, endpoint: Endpoint): LogEntry = withContext(Dispatchers.IO) {
    try {
        val client = OkHttpClient.Builder()
            .readTimeout(60, java.util.concurrent.TimeUnit.SECONDS)
            .build()
        val result = SessionStream.consume(client, "$PLAYGROUND_BASE${endpoint.path}", signer)
        LogEntry.success(
            endpoint = endpoint,
            signature = result.settleSignature,
            body = result.steps.joinToString("\n"),
        )
    } catch (t: Throwable) {
        android.util.Log.e("PayKitDemo", "session consume failed", t)
        LogEntry.failure(endpoint, "${t.javaClass.simpleName}: ${t.message ?: "(no message)"}")
    }
}

private suspend fun consume(signer: SolanaSigner, endpoint: Endpoint, protocol: String?): LogEntry = withContext(Dispatchers.IO) {
    val url = "$PLAYGROUND_BASE${endpoint.path}"
    try {
        // Settle over the protocol the user picked (default: the advertised mpp).
        val client = if (protocol == "x402") {
            PayKitClient.Builder().signer(signer).x402(rpc = RPC_URL, network = "devnet").build()
        } else {
            PayKitClient.Builder().signer(signer).charge(blockhashProvider = JsonRpcClient(RPC_URL)).build()
        }

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
                    // Decode the settlement envelope; if it isn't a recognized
                // envelope, fall back to the raw header string (mirrors the
                // Swift demo's `?? response.settlementSignature`).
                signature = settlement?.let { signatureFromReceiptHeader(it) ?: it.takeIf { s -> s.isNotEmpty() } },
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
 * Decode a settlement header (base64url-no-pad JSON envelope) and return the
 * on-chain signature. MPP's `Payment-Receipt` carries it in `reference`;
 * x402's `X-PAYMENT-RESPONSE` carries it in `transaction`. Mirrors the iOS
 * `signatureFromReceiptHeader`.
 */
private fun signatureFromReceiptHeader(header: String): String? {
    return try {
        // MPP's `Payment-Receipt` is base64url; x402's `X-PAYMENT-RESPONSE` is
        // standard base64 (`btoa`). Normalize to url-safe so one decoder fits both.
        val normalized = header.replace('+', '-').replace('/', '_').trimEnd('=')
        val decoded = JBase64.getUrlDecoder().decode(normalized.padBase64Url())
        val json = responseJson.parseToJsonElement(String(decoded)) as? JsonObject ?: return null
        // MPP's `Payment-Receipt` carries the on-chain signature in `reference`;
        // x402's `X-PAYMENT-RESPONSE` carries it in `transaction`.
        (json["reference"] ?: json["transaction"])?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotEmpty() }
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
