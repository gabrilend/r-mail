package com.rmail.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.rmail.app.ui.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetupScreen(vm: MainViewModel, onSetupComplete: () -> Unit) {
    var host by remember { mutableStateOf(vm.settings.serverHost) }
    var port by remember { mutableStateOf(vm.settings.serverPort.toString()) }
    var token by remember { mutableStateOf(vm.settings.deviceToken) }
    var connecting by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text("r-mail setup") })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(24.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                "Connect to your home r-mail server.",
                style = MaterialTheme.typography.bodyMedium
            )

            OutlinedTextField(
                value = host,
                onValueChange = { host = it; errorMessage = null },
                label = { Text("Server address") },
                placeholder = { Text("e.g. home.example.com") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter { c -> c.isDigit() }; errorMessage = null },
                label = { Text("Port") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = token,
                onValueChange = { token = it; errorMessage = null },
                label = { Text("Device token") },
                singleLine = true,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth()
            )

            Text(
                "Add this to your contacts file on the home server:\n\n" +
                "myphone.token = \"<your-token>\"\n" +
                "myphone.own   = true",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )

            if (errorMessage != null) {
                Text(
                    errorMessage!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
            }

            Spacer(modifier = Modifier.weight(1f))

            Button(
                onClick = {
                    val portInt = port.toIntOrNull()
                    if (host.isBlank()) { errorMessage = "Server address is required"; return@Button }
                    if (portInt == null) { errorMessage = "Enter a valid port number"; return@Button }
                    if (token.isBlank()) { errorMessage = "Device token is required"; return@Button }

                    vm.settings.serverHost = host.trim()
                    vm.settings.serverPort = portInt
                    vm.settings.deviceToken = token.trim()
                    connecting = true
                    errorMessage = null

                    vm.triggerSync()
                    // Report success optimistically — sync errors are shown on inbox
                    connecting = false
                    onSetupComplete()
                },
                enabled = !connecting,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (connecting) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Connect")
                }
            }
        }
    }
}
