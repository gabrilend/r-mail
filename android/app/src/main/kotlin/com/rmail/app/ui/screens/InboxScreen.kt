package com.rmail.app.ui.screens

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import com.rmail.app.ui.MainViewModel
import com.rmail.app.ui.SyncStatus

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InboxScreen(
    vm: MainViewModel,
    initialShowOutbox: Boolean = false,
    onOpen: (String) -> Unit,
    onOpenOutbox: (String) -> Unit,
    onCompose: () -> Unit,
    onContacts: () -> Unit,
    onAttachments: () -> Unit,
    onSettings: () -> Unit
) {
    val inboxFiles by vm.inboxFiles.collectAsState()
    val syncStatus by vm.syncStatus.collectAsState()
    val syncError by vm.syncError.collectAsState()
    var showOutbox by remember { mutableStateOf(initialShowOutbox) }
    val outboxFiles by vm.outboxFiles.collectAsState()
    var menuExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { vm.refreshLocal() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(if (showOutbox) "Outbox" else "Inbox") },
                actions = {
                    // Sync indicator
                    when (syncStatus) {
                        SyncStatus.SYNCING -> CircularProgressIndicator(
                            modifier = Modifier.size(24.dp).padding(end = 8.dp),
                            strokeWidth = 2.dp
                        )
                        SyncStatus.ERROR -> IconButton(onClick = { vm.triggerSync() }) {
                            Icon(Icons.Default.Warning, contentDescription = "Sync error — tap to retry")
                        }
                        SyncStatus.IDLE -> IconButton(onClick = { vm.triggerSync() }) {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                        }
                    }
                    // Overflow menu
                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "Menu")
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text(if (showOutbox) "Show inbox" else "Show outbox") },
                                onClick = { showOutbox = !showOutbox; menuExpanded = false }
                            )
                            DropdownMenuItem(
                                text = { Text("Contacts") },
                                onClick = { onContacts(); menuExpanded = false }
                            )
                            DropdownMenuItem(
                                text = { Text("Attachments") },
                                onClick = { onAttachments(); menuExpanded = false }
                            )
                            DropdownMenuItem(
                                text = { Text("Settings") },
                                onClick = { onSettings(); menuExpanded = false }
                            )
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onCompose) {
                Icon(Icons.Default.Edit, contentDescription = "Compose")
            }
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding)) {
            if (syncError != null) {
                Surface(
                    color = MaterialTheme.colorScheme.error.copy(alpha = 0.15f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        syncError!!,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(8.dp),
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }

            val files = if (showOutbox) outboxFiles else inboxFiles

            if (files.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        if (showOutbox) "Outbox is empty" else "No messages",
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                    )
                }
            } else {
                LazyColumn {
                    items(files, key = { it }) { filename ->
                        if (showOutbox) {
                            SwipeToDismissMessageItem(
                                filename = filename,
                                onDelete = { vm.deleteOutboxFile(filename) },
                                onClick = { onOpenOutbox(filename) }
                            )
                        } else if (vm.settings.swipeToDelete) {
                            SwipeToDismissMessageItem(
                                filename = filename,
                                onDelete = { vm.deleteInboxMessage(filename) },
                                onClick = { onOpen(filename) }
                            )
                        } else {
                            MessageListItem(
                                filename = filename,
                                onClick = { onOpen(filename) }
                            )
                        }
                        HorizontalDivider(thickness = 0.5.dp)
                    }
                }
            }
        }
    }
}

@Composable
private fun MessageListItem(filename: String, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = filename,
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.weight(1f)
        )
        Icon(
            Icons.Default.ChevronRight,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f)
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SwipeToDismissMessageItem(
    filename: String,
    onDelete: () -> Unit,
    onClick: () -> Unit
) {
    val dismissState = rememberSwipeToDismissBoxState(
        confirmValueChange = { value ->
            if (value == SwipeToDismissBoxValue.EndToStart) { onDelete(); true }
            else false
        }
    )
    SwipeToDismissBox(
        state = dismissState,
        backgroundContent = {
            val color by animateColorAsState(
                if (dismissState.targetValue == SwipeToDismissBoxValue.EndToStart)
                    MaterialTheme.colorScheme.error else Color.Transparent,
                label = "swipe_bg"
            )
            Box(
                Modifier.fillMaxSize().background(color),
                contentAlignment = Alignment.CenterEnd
            ) {
                Icon(
                    Icons.Default.Delete,
                    contentDescription = "Delete",
                    modifier = Modifier.padding(end = 16.dp),
                    tint = MaterialTheme.colorScheme.onError
                )
            }
        }
    ) {
        Surface(color = MaterialTheme.colorScheme.background) {
            MessageListItem(filename = filename, onClick = onClick)
        }
    }
}
