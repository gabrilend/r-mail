package com.rmail.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Reply
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.rmail.app.data.MailMessage
import com.rmail.app.ui.MainViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ReadScreen(
    filename: String,
    vm: MainViewModel,
    isOutbox: Boolean = false,
    onBack: () -> Unit,
    // #358: signatures carry enough context for the caller to seed a
    // composer draft — sender (for Reply's "to:"), subject (for the
    // Re:/Fwd: prefix), and the pre-quoted body built by buildReply /
    // buildForward on this screen.
    onReply: (sender: String, subject: String, body: String) -> Unit,
    onForward: (subject: String, body: String) -> Unit
) {
    // For outbox files, re-read periodically to show upload progress
    var message by remember(filename) {
        mutableStateOf(if (isOutbox) vm.loadOutboxMessage(filename) else vm.loadMessage(filename))
    }
    if (isOutbox) {
        LaunchedEffect(filename) {
            while (true) {
                kotlinx.coroutines.delay(1000)
                message = vm.loadOutboxMessage(filename)
            }
        }
    }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var menuExpanded by remember { mutableStateOf(false) }

    val msg = message
    if (msg == null) {
        LaunchedEffect(Unit) { onBack() }
        return
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text(if (isOutbox) "Cancel send?" else "Delete message?") },
            text = { Text(if (isOutbox) "Remove this message from your outbox?" else "This will delete the message from your inbox and notify the sender.") },
            confirmButton = {
                TextButton(onClick = {
                    if (isOutbox) vm.deleteOutboxFile(filename) else vm.deleteInboxMessage(filename)
                    showDeleteDialog = false
                    onBack()
                }) { Text("Delete") }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) { Text("Cancel") }
            }
        )
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(filename) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    if (isOutbox) {
                        IconButton(onClick = { showDeleteDialog = true }) {
                            Icon(Icons.Default.Delete, contentDescription = "Delete")
                        }
                    } else {
                        IconButton(onClick = {
                            onReply(vm.senderOfInbox(filename), filename, buildQuoted(msg))
                        }) {
                            Icon(Icons.AutoMirrored.Filled.Reply, contentDescription = "Reply")
                        }
                        Box {
                            IconButton(onClick = { menuExpanded = true }) {
                                Icon(Icons.Default.MoreVert, contentDescription = "More")
                            }
                            DropdownMenu(
                                expanded = menuExpanded,
                                onDismissRequest = { menuExpanded = false }
                            ) {
                                DropdownMenuItem(
                                    text = { Text("Forward") },
                                    onClick = {
                                        menuExpanded = false
                                        onForward(filename, buildQuoted(msg))
                                    }
                                )
                                DropdownMenuItem(
                                    text = { Text("Delete") },
                                    onClick = {
                                        menuExpanded = false
                                        showDeleteDialog = true
                                    }
                                )
                            }
                        }
                    }
                }
            )
        }
    ) { padding ->
        if (msg.isConsent) {
            ConsentView(
                message = msg,
                onAccept = {
                    vm.saveOutboxFile(filename, "accept")
                    vm.triggerSync()
                    onBack()
                },
                onDeny = {
                    vm.saveOutboxFile(filename, "deny")
                    vm.triggerSync()
                    onBack()
                },
                modifier = Modifier.padding(padding)
            )
        } else {
            Column(modifier = Modifier.padding(padding).fillMaxSize()) {
                Column(
                    modifier = Modifier
                        .weight(1f)
                        .padding(16.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    Text(
                        text = msg.content,
                        style = MaterialTheme.typography.bodyMedium,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
                    )
                }
                if (isOutbox) {
                    Button(
                        onClick = { vm.triggerSync() },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                        shape = androidx.compose.ui.graphics.RectangleShape,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = Color(0xFF00BCD4)
                        )
                    ) {
                        Text("Update", style = MaterialTheme.typography.titleMedium, color = Color.White)
                    }
                }
            }
        }
    }
}

@Composable
private fun ConsentView(
    message: MailMessage,
    onAccept: () -> Unit,
    onDeny: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxSize()) {
        // Message body above
        Box(
            modifier = Modifier
                .weight(1f)
                .padding(16.dp)
                .verticalScroll(rememberScrollState())
        ) {
            Text(
                text = message.content,
                style = MaterialTheme.typography.bodyMedium,
                fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace
            )
        }

        // Half-and-half accept/deny buttons
        Row(modifier = Modifier.fillMaxWidth().height(120.dp)) {
            Button(
                onClick = onDeny,
                modifier = Modifier.weight(1f).fillMaxHeight(),
                shape = androidx.compose.ui.graphics.RectangleShape,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                )
            ) {
                Text("✗  Deny", style = MaterialTheme.typography.titleLarge)
            }
            Button(
                onClick = onAccept,
                modifier = Modifier.weight(1f).fillMaxHeight(),
                shape = androidx.compose.ui.graphics.RectangleShape,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.primary
                )
            ) {
                Text("✓  Accept", style = MaterialTheme.typography.titleLarge,
                    color = MaterialTheme.colorScheme.onPrimary)
            }
        }
    }
}

// #358: single helper that produces the "quoted original" portion of a
// reply or forward.  Recipients and subject are handled by the caller
// (MainActivity wires the ReadScreen callbacks to seed the composer's
// draftRecipients and draftSubject directly), so this only needs to
// return the body content.
private fun buildQuoted(msg: MailMessage): String {
    val quoted = msg.content.lines().joinToString("\n") { "| $it" }
    return "\n\n$quoted"
}
