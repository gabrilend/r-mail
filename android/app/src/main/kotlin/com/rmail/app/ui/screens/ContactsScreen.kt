package com.rmail.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rmail.app.ui.MainViewModel
import com.rmail.app.ui.SyncStatus

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(
    vm: MainViewModel,
    onBack: () -> Unit,
    onCompose: (String) -> Unit
) {
    var content by remember { mutableStateOf(vm.readContacts()) }
    var modified by remember { mutableStateOf(false) }
    val myAddress by vm.myAddress.collectAsState()
    val syncStatus by vm.syncStatus.collectAsState()
    val daemonName by vm.daemonName.collectAsState()

    val isConnected = syncStatus != SyncStatus.ERROR && vm.settings.isConfigured
    var showOfflineDialog by remember { mutableStateOf(false) }

    if (showOfflineDialog) {
        AlertDialog(
            onDismissRequest = { showOfflineDialog = false },
            title = { Text("Can't edit contacts") },
            text = {
                Text(
                    "The contacts file can only be edited while connected to your home server.\n\n" +
                    "To add a contact now, send yourself a message with the details " +
                    "and update the contacts file from your computer."
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    showOfflineDialog = false
                    val to = daemonName ?: ""
                    onCompose("to: $to\nsubject: new contact details\n")
                }) {
                    Text("New message")
                }
            },
            dismissButton = {
                TextButton(onClick = { showOfflineDialog = false }) {
                    Text("Close")
                }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Contacts") },
                navigationIcon = {
                    IconButton(onClick = {
                        if (modified && isConnected) vm.saveContacts(content)
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (!isConnected) {
                        IconButton(onClick = { showOfflineDialog = true }) {
                            Icon(Icons.Default.Info, contentDescription = "Offline info")
                        }
                    }
                    if (modified && isConnected) {
                        IconButton(onClick = {
                            vm.saveContacts(content)
                            modified = false
                        }) {
                            Icon(Icons.Default.Check, contentDescription = "Save")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            // My address — shown for reference when adding new contacts
            Surface(
                color = MaterialTheme.colorScheme.surfaceVariant,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    if (myAddress != null) "My address: $myAddress"
                    else if (!vm.settings.isConfigured) "Not configured"
                    else "Connecting...",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
                )
            }

            if (isConnected) {
                BasicTextField(
                    value = content,
                    onValueChange = { content = it; modified = true },
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(16.dp),
                    textStyle = TextStyle(
                        color = MaterialTheme.colorScheme.onBackground,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp,
                        lineHeight = 19.sp
                    ),
                    cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                )
            } else {
                // Read-only: selectable text, no editing
                SelectionContainer {
                    Text(
                        text = content.ifEmpty { "(no contacts)" },
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        style = TextStyle(
                            color = MaterialTheme.colorScheme.onBackground.copy(
                                alpha = 0.7f
                            ),
                            fontFamily = FontFamily.Monospace,
                            fontSize = 13.sp,
                            lineHeight = 19.sp
                        )
                    )
                }
            }
        }
    }
}
