package com.rmail.app.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.rmail.app.ui.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(vm: MainViewModel, onBack: () -> Unit) {
    var host by remember { mutableStateOf(vm.settings.serverHost) }
    var port by remember { mutableStateOf(vm.settings.serverPort.toString()) }
    var token by remember { mutableStateOf(vm.settings.deviceToken) }
    var swipeToDelete by remember { mutableStateOf(vm.settings.swipeToDelete) }
    var bgSyncInterval by remember { mutableStateOf(vm.settings.bgSyncIntervalMinutes.toString()) }
    var notifDetail by remember { mutableStateOf(vm.settings.notificationDetail) }
    var bgColor by remember { mutableStateOf(Color(vm.settings.bgColor.toLong() and 0xFFFFFFFFL)) }
    var fgColor by remember { mutableStateOf(Color(vm.settings.fgColor.toLong() and 0xFFFFFFFFL)) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings") },
                navigationIcon = {
                    IconButton(onClick = {
                        // Save all settings
                        vm.settings.serverHost = host.trim()
                        vm.settings.serverPort = port.toIntOrNull() ?: 8787
                        vm.settings.deviceToken = token.trim()
                        vm.settings.swipeToDelete = swipeToDelete
                        vm.settings.bgSyncIntervalMinutes = bgSyncInterval.toIntOrNull() ?: 15
                        vm.settings.notificationDetail = notifDetail
                        vm.settings.bgColor = bgColor.toArgb()
                        vm.settings.fgColor = fgColor.toArgb()
                        vm.onSettingsSaved()
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Save and back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            SettingsSection("Connection") {
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text("Server address") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it.filter { c -> c.isDigit() } },
                    label = { Text("Port") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = token,
                    onValueChange = { token = it.replace("\"", "") },
                    label = { Text("Device token") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    prefix = { Text("\"") },
                    suffix = { Text("\"") },
                    modifier = Modifier.fillMaxWidth()
                )
            }

            SettingsSection("Appearance") {
                ColorPickerRow(label = "Background color", color = bgColor, onColorChange = { bgColor = it })
                ColorPickerRow(label = "Text color", color = fgColor, onColorChange = { fgColor = it })
            }

            SettingsSection("Behavior") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text("Swipe to delete", modifier = Modifier.weight(1f))
                    Switch(checked = swipeToDelete, onCheckedChange = { swipeToDelete = it })
                }

                OutlinedTextField(
                    value = bgSyncInterval,
                    onValueChange = { bgSyncInterval = it.filter { c -> c.isDigit() } },
                    label = { Text("Background sync interval (min 15)") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth()
                )
            }

            SettingsSection("Notifications") {
                Text("Notification detail", style = MaterialTheme.typography.bodySmall)
                listOf(
                    "full" to "Sender + subject",
                    "sender" to "Sender only",
                    "none" to "No preview"
                ).forEach { (value, label) ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { notifDetail = value }
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RadioButton(
                            selected = notifDetail == value,
                            onClick = { notifDetail = value }
                        )
                        Text(label, modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun SettingsSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.primary)
        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))
        content()
        Spacer(Modifier.height(8.dp))
    }
}

/**
 * Minimal color picker: shows a colored swatch and lets the user enter a hex value.
 * A full color wheel is outside scope for v1.
 */
@Composable
private fun ColorPickerRow(label: String, color: Color, onColorChange: (Color) -> Unit) {
    var hexInput by remember(color) {
        mutableStateOf("%06X".format(color.toArgb() and 0xFFFFFF))
    }
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(
            modifier = Modifier
                .size(32.dp)
                .background(color)
                .border(1.dp, MaterialTheme.colorScheme.outline)
        )
        OutlinedTextField(
            value = hexInput,
            onValueChange = { v ->
                hexInput = v.filter { it.isLetterOrDigit() }.take(6).uppercase()
                if (hexInput.length == 6) {
                    val argb = (0xFF000000.toInt() or hexInput.toInt(16))
                    onColorChange(Color(argb))
                }
            },
            label = { Text(label) },
            prefix = { Text("#") },
            singleLine = true,
            modifier = Modifier.weight(1f)
        )
    }
}
