package com.rmail.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(vm: MainViewModel, onBack: () -> Unit) {
    var content by remember { mutableStateOf(vm.readContacts()) }
    var modified by remember { mutableStateOf(false) }
    var myAddress by remember { mutableStateOf<String?>(null) }
    var showAddressDialog by remember { mutableStateOf(false) }
    var isFetchingAddress by remember { mutableStateOf(false) }

    if (showAddressDialog) {
        AlertDialog(
            onDismissRequest = { showAddressDialog = false },
            title = { Text("My address") },
            text = {
                Text(myAddress ?: "Fetching from home server...")
            },
            confirmButton = {
                TextButton(onClick = { showAddressDialog = false }) { Text("OK") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Contacts") },
                navigationIcon = {
                    IconButton(onClick = {
                        if (modified) vm.saveContacts(content)
                        onBack()
                    }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    // "My address" button — queries daemon for public IP
                    if (isFetchingAddress) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp).padding(end = 8.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        IconButton(onClick = {
                            isFetchingAddress = true
                            vm.getMyAddress { addr ->
                                myAddress = addr ?: "Could not reach home server"
                                isFetchingAddress = false
                                showAddressDialog = true
                            }
                        }) {
                            Icon(Icons.Default.Info, contentDescription = "My address")
                        }
                    }
                    if (modified) {
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
            if (!vm.settings.isConfigured) {
                Surface(
                    color = MaterialTheme.colorScheme.surfaceVariant,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        "Offline — contacts are read-only until the home server is reachable.",
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(8.dp)
                    )
                }
            }

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
        }
    }
}
