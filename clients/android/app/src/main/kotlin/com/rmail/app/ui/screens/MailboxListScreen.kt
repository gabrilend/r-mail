package com.rmail.app.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.rmail.app.data.MailboxConfig
import com.rmail.app.ui.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MailboxListScreen(
    vm: MainViewModel,
    onSelect: (String) -> Unit,
    onAdd: () -> Unit
) {
    val mailboxes by vm.mailboxes.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Mailboxes") },
                actions = {
                    IconButton(onClick = onAdd) {
                        Icon(Icons.Default.Add, contentDescription = "Add mailbox")
                    }
                }
            )
        }
    ) { padding ->
        if (mailboxes.isEmpty()) {
            Box(
                Modifier.padding(padding).fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(
                        "No mailboxes configured",
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                    )
                    Spacer(Modifier.height(16.dp))
                    Button(onClick = onAdd) {
                        Icon(Icons.Default.Add, contentDescription = null)
                        Spacer(Modifier.width(8.dp))
                        Text("Add mailbox")
                    }
                }
            }
        } else {
            LazyColumn(modifier = Modifier.padding(padding)) {
                items(mailboxes, key = { it.id }) { config ->
                    MailboxItem(
                        config = config,
                        onClick = { onSelect(config.id) }
                    )
                    HorizontalDivider(thickness = 0.5.dp)
                }
            }
        }
    }
}

@Composable
private fun MailboxItem(config: MailboxConfig, onClick: () -> Unit) {
    var showInfo by remember { mutableStateOf(false) }

    if (showInfo) {
        AlertDialog(
            onDismissRequest = { showInfo = false },
            title = { Text(config.name.ifBlank { "Mailbox" }) },
            text = {
                Column {
                    Text("Host: ${config.host}")
                    Text("Port: ${config.port}")
                    SelectionContainer {
                        Text("ID: ${config.id}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showInfo = false }) { Text("Close") }
            }
        )
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Default.Email,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.size(24.dp)
        )
        Spacer(Modifier.width(16.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                config.name.ifBlank { config.host },
                style = MaterialTheme.typography.bodyLarge
            )
            if (config.name.isNotBlank()) {
                Text(
                    "${config.host}:${config.port}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
        IconButton(onClick = { showInfo = true }) {
            Icon(
                Icons.Default.MoreVert,
                contentDescription = "Info",
                tint = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
