package com.rmail.app.ui.screens

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.rmail.app.crypto.Crypto
import com.rmail.app.data.MailboxConfig
import com.rmail.app.ui.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

// Update this once the docs are published on GitHub
private const val SETUP_GUIDE_URL = "https://github.com/gabrilend/r-mail/blob/main/docs/android-instructions.md"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetupScreen(
    vm: MainViewModel,
    editConfig: MailboxConfig? = null,
    onSetupComplete: (String) -> Unit
) {
    val context = LocalContext.current
    var host by remember { mutableStateOf(editConfig?.host ?: "") }
    var port by remember { mutableStateOf(editConfig?.port?.toString() ?: "8025") }
    var token by remember { mutableStateOf(editConfig?.token ?: "") }
    var connecting by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var scanProgress by remember { mutableStateOf(0f) }
    var scanMessage by remember { mutableStateOf<String?>(null) }

    // Network info for port-forwarding help
    var publicIp by remember { mutableStateOf<String?>(null) }
    var gateway by remember { mutableStateOf<String?>(null) }
    var loadingNetwork by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun loadNetworkInfo() {
        scope.launch {
            loadingNetwork = true
            gateway = getDefaultGateway(context)
            publicIp = getPublicIpAddress()
            if (host.isBlank() && publicIp != null) host = publicIp!!
            loadingNetwork = false
        }
    }

    LaunchedEffect(Unit) { loadNetworkInfo() }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("r-mail setup") })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(24.dp)
                .fillMaxSize()
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "Connect to your home r-mail server.",
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f)
                )
                TextButton(onClick = {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(SETUP_GUIDE_URL)))
                }) {
                    Text("Setup guide →", style = MaterialTheme.typography.labelMedium)
                }
            }

            OutlinedTextField(
                value = host,
                onValueChange = { host = it; errorMessage = null; scanMessage = null },
                label = { Text("Home router IP") },
                placeholder = { Text("e.g. 203.0.113.42") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            // Token first — needed to scan for the port
            OutlinedTextField(
                value = token,
                onValueChange = { token = it.replace("\"", ""); errorMessage = null },
                label = { Text("Device token") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                prefix = { Text("\"") },
                suffix = { Text("\"") },
                modifier = Modifier.fillMaxWidth()
            )

            Text(
                "Add this to your contacts file on the home server\n(token value must be in quotes):\n\n" +
                "myphone.token = \"<your-token>\"\n" +
                "myphone.own   = true",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )

            // Port — with detect button
            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter { c -> c.isDigit() }; errorMessage = null; scanMessage = null },
                label = { Text("Home computer's port") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedButton(
                onClick = {
                    if (token.isBlank()) {
                        scanMessage = "Please ensure the token is the same on both the home server computer and in the token field"
                        return@OutlinedButton
                    }
                    scanning = true
                    scanProgress = 0f
                    scanMessage = null
                    scope.launch {
                        // Try the entered host first
                        val found = scanForRmailPort(host.trim(), token.trim()) { scanProgress = it * 0.5f }
                        if (found != null) {
                            port = found.toString()
                            scanMessage = "Found on port $found"
                            scanning = false
                            return@launch
                        }
                        // If not found and we know the gateway, try LAN IPs
                        if (gateway != null) {
                            scanMessage = "Trying local network..."
                            val lanPrefix = gateway!!.substringBeforeLast('.') + "."
                            val lanFound = scanLanForRmailPort(lanPrefix, token.trim()) { scanProgress = 0.5f + it * 0.5f }
                            if (lanFound != null) {
                                host = lanFound.first
                                port = lanFound.second.toString()
                                scanMessage = "Found at ${lanFound.first}:${lanFound.second} (local network)"
                                scanning = false
                                return@launch
                            }
                        }
                        scanMessage = "No r-mail server found. Make sure your phone is connected to the same WiFi as your home server."
                        scanning = false
                    }
                },
                enabled = !scanning,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (scanning) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                    Spacer(Modifier.width(8.dp))
                    Text("Scanning…")
                } else {
                    Icon(Icons.Default.Search, contentDescription = null,
                        modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text("Detect port")
                }
            }
            if (scanning) {
                LinearProgressIndicator(
                    progress = { scanProgress },
                    modifier = Modifier.fillMaxWidth()
                )
            }
            if (scanMessage != null) {
                Text(
                    scanMessage!!,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (scanMessage!!.startsWith("Found"))
                        MaterialTheme.colorScheme.primary
                    else
                        MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                )
            }

            // ── Network info ───────────────────────────────────────────────
            HorizontalDivider()
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    "Network info",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.primary
                )
                if (loadingNetwork) {
                    CircularProgressIndicator(modifier = Modifier.size(16.dp), strokeWidth = 2.dp)
                } else {
                    IconButton(onClick = { loadNetworkInfo() }, modifier = Modifier.size(32.dp)) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh",
                            modifier = Modifier.size(16.dp))
                    }
                }
            }
            NetworkInfoRow(
                label = "Your router's public IP",
                value = publicIp,
                hint = "Use this as the router IP above if your Android is currently connected to your home wifi"
            )
            NetworkInfoRow(
                label = "Default gateway",
                value = gateway,
                hint = "Open this in a browser to access your router's settings"
            )
            // ── End network info ───────────────────────────────────────────

            if (errorMessage != null) {
                Text(
                    errorMessage!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Spacer(modifier = Modifier.height(8.dp))

            Button(
                onClick = {
                    val portInt = port.toIntOrNull()
                    if (host.isBlank()) { errorMessage = "Server address is required"; return@Button }
                    if (portInt == null) { errorMessage = "Enter a valid port number"; return@Button }
                    if (token.isBlank()) { errorMessage = "Device token is required"; return@Button }

                    connecting = true
                    errorMessage = null

                    val config = if (editConfig != null) {
                        editConfig.copy(
                            host = host.trim(),
                            port = portInt,
                            token = token.trim()
                        )
                    } else {
                        MailboxConfig(
                            host = host.trim(),
                            port = portInt,
                            token = token.trim()
                        )
                    }

                    if (editConfig != null) vm.updateMailbox(config)
                    else vm.addMailbox(config)

                    connecting = false
                    onSetupComplete(config.id)
                },
                enabled = !connecting && !scanning,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (connecting) {
                    CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Text("Connect")
                }
            }
        }
    }
}

@Composable
private fun NetworkInfoRow(label: String, value: String?, hint: String) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                "$label:",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
            Text(
                value ?: "—",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                color = if (value != null) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f)
            )
        }
        Text(
            hint,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
        )
    }
}

private suspend fun scanForRmailPort(
    host: String,
    token: String,
    onProgress: (Float) -> Unit
): Int? = withContext(Dispatchers.IO) {
    val ports = (1024..65535).toList()
    val total = ports.size
    val semaphore = Semaphore(150)
    val result = AtomicReference<Int?>(null)
    val scanned = AtomicInteger(0)

    coroutineScope {
        ports.forEach { port ->
            launch {
                semaphore.withPermit {
                    if (result.get() == null && probeRmailPort(host, port, token)) {
                        result.compareAndSet(null, port)
                    }
                    onProgress(scanned.incrementAndGet().toFloat() / total)
                }
            }
        }
    }
    result.get()
}

/**
 * Scan LAN IPs (x.x.x.1-254) on common rmail ports.
 * Returns Pair(ip, port) or null.
 */
private suspend fun scanLanForRmailPort(
    lanPrefix: String,
    token: String,
    onProgress: (Float) -> Unit
): Pair<String, Int>? = withContext(Dispatchers.IO) {
    // Common ports: low range (8000-8100) + install.sh range (50000-65000)
    val commonPorts = (8000..8100) + (50000..65000)
    val ips = (1..254).map { "$lanPrefix$it" }
    val total = ips.size * commonPorts.size
    val semaphore = Semaphore(200)
    val result = AtomicReference<Pair<String, Int>?>(null)
    val scanned = AtomicInteger(0)

    coroutineScope {
        for (ip in ips) {
            for (p in commonPorts) {
                launch {
                    semaphore.withPermit {
                        if (result.get() == null && probeRmailPort(ip, p, token)) {
                            result.compareAndSet(null, Pair(ip, p))
                        }
                        onProgress(scanned.incrementAndGet().toFloat() / total)
                    }
                }
            }
        }
    }
    result.get()
}

private fun probeRmailPort(host: String, port: Int, token: String): Boolean {
    return try {
        val socket = Socket()
        socket.connect(InetSocketAddress(host, port), 800)
        socket.soTimeout = 2000
        val key = Crypto.keyFromToken(token)
        val req = "GET /api/myaddress HTTP/1.0\r\nContent-Length: 0\r\n\r\n".toByteArray()
        socket.getOutputStream().write(Crypto.encryptFrame(req, key))
        socket.getOutputStream().flush()
        // decryptFrame returns null if the GCM auth tag fails — wrong server or wrong token
        val result = Crypto.decryptFrame(socket.getInputStream(), key)
        socket.close()
        result != null
    } catch (_: Exception) {
        false
    }
}

private suspend fun getPublicIpAddress(): String? = withContext(Dispatchers.IO) {
    listOf("https://ifconfig.me/ip", "https://icanhazip.com").firstNotNullOfOrNull { url ->
        try { URL(url).readText().trim().takeIf { it.isNotBlank() } } catch (_: Exception) { null }
    }
}

private fun getDefaultGateway(context: Context): String? {
    return try {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val lp = cm.getLinkProperties(cm.activeNetwork) ?: return null
        lp.routes.firstOrNull { it.isDefaultRoute && it.gateway != null }
            ?.gateway?.hostAddress
    } catch (_: Exception) {
        null
    }
}
