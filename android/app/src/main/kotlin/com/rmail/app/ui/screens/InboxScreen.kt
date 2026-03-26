package com.rmail.app.ui.screens

import android.content.Intent
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.automirrored.filled.TextSnippet
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.rmail.app.data.AttachmentInfo
import com.rmail.app.ui.MainViewModel
import com.rmail.app.ui.SyncStatus
import java.io.File

private enum class Tab { INBOX, OUTBOX, ATTACHMENTS }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun InboxScreen(
    vm: MainViewModel,
    initialShowOutbox: Boolean = false,
    onBack: () -> Unit,
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
    val outboxFiles by vm.outboxFiles.collectAsState()
    val attachments by vm.attachments.collectAsState()
    var currentTab by remember { mutableStateOf(if (initialShowOutbox) Tab.OUTBOX else Tab.INBOX) }
    var menuExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) { vm.refreshLocal() }
    LaunchedEffect(currentTab) {
        if (currentTab == Tab.ATTACHMENTS) vm.loadAttachmentList()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Mailboxes")
                    }
                },
                title = {
                    val activeId by vm.activeMailboxId.collectAsState()
                    val config = activeId?.let { vm.registry.get(it) }
                    Text(config?.name?.ifBlank { null } ?: config?.host ?: "Mailbox")
                },
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
                    // Overflow menu (contacts + settings only)
                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "Menu")
                        }
                        DropdownMenu(
                            expanded = menuExpanded,
                            onDismissRequest = { menuExpanded = false }
                        ) {
                            DropdownMenuItem(
                                text = { Text("Contacts") },
                                onClick = { onContacts(); menuExpanded = false }
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
            FloatingActionButton(
                onClick = onCompose,
                modifier = Modifier.padding(bottom = 56.dp) // above the tab bar
            ) {
                Icon(Icons.Default.Edit, contentDescription = "Compose")
            }
        },
        bottomBar = {
            Row(modifier = Modifier.fillMaxWidth()) {
                Tab.entries.forEach { tab ->
                    val selected = currentTab == tab
                    Surface(
                        color = if (selected)
                            MaterialTheme.colorScheme.primaryContainer
                        else
                            MaterialTheme.colorScheme.surfaceVariant,
                        modifier = Modifier
                            .weight(1f)
                            .clickable { currentTab = tab }
                    ) {
                        Box(
                            contentAlignment = Alignment.Center,
                            modifier = Modifier.padding(vertical = 14.dp)
                        ) {
                            Text(
                                when (tab) {
                                    Tab.INBOX -> "Inbox"
                                    Tab.OUTBOX -> "Outbox"
                                    Tab.ATTACHMENTS -> "Files"
                                },
                                style = MaterialTheme.typography.labelLarge,
                                fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
                                color = if (selected)
                                    MaterialTheme.colorScheme.onPrimaryContainer
                                else
                                    MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
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

            when (currentTab) {
                Tab.INBOX -> MessageList(
                    files = inboxFiles,
                    emptyText = "No messages",
                    swipeToDelete = vm.swipeToDelete,
                    onDelete = { vm.deleteInboxMessage(it) },
                    onClick = { onOpen(it) }
                )
                Tab.OUTBOX -> MessageList(
                    files = outboxFiles,
                    emptyText = "Outbox is empty",
                    swipeToDelete = true,
                    onDelete = { vm.deleteOutboxFile(it) },
                    onClick = { onOpenOutbox(it) }
                )
                Tab.ATTACHMENTS -> AttachmentList(vm = vm, attachments = attachments)
            }
        }
    }
}

// ── Message list (shared by inbox and outbox) ───────────────────────────────

@Composable
private fun MessageList(
    files: List<String>,
    emptyText: String,
    swipeToDelete: Boolean,
    onDelete: (String) -> Unit,
    onClick: (String) -> Unit
) {
    if (files.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(emptyText, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
    } else {
        LazyColumn {
            items(files, key = { it }) { filename ->
                if (swipeToDelete) {
                    SwipeToDismissMessageItem(
                        filename = filename,
                        onDelete = { onDelete(filename) },
                        onClick = { onClick(filename) }
                    )
                } else {
                    MessageListItem(filename = filename, onClick = { onClick(filename) })
                }
                HorizontalDivider(thickness = 0.5.dp)
            }
        }
    }
}

// ── Attachment list (inlined from AttachmentsScreen) ────────────────────────

@Composable
private fun AttachmentList(vm: MainViewModel, attachments: List<AttachmentInfo>) {
    var downloadingFile by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current

    if (attachments.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(
                "No attachments on home server",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
            )
        }
    } else {
        LazyColumn {
            items(attachments, key = { it.filename }) { info ->
                AttachmentItem(
                    info = info,
                    isDownloading = downloadingFile == info.filename,
                    isCached = vm.store?.isAttachmentCached(info.filename) ?: false,
                    onDownload = {
                        downloadingFile = info.filename
                        vm.downloadAttachment(info) { file ->
                            downloadingFile = null
                            if (file != null) shareFile(context, file)
                        }
                    },
                    onOpen = {
                        val file = vm.store?.cachedAttachmentFile(info.filename) ?: return@AttachmentItem
                        if (file.exists()) shareFile(context, file)
                    }
                )
                HorizontalDivider(thickness = 0.5.dp)
            }
        }
    }
}

@Composable
private fun AttachmentItem(
    info: AttachmentInfo,
    isDownloading: Boolean,
    isCached: Boolean,
    onDownload: () -> Unit,
    onOpen: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = if (isCached) onOpen else onDownload)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            imageVector = when (info.category) {
                "image" -> Icons.Default.Image
                "audio" -> Icons.Default.AudioFile
                "text" -> Icons.AutoMirrored.Filled.TextSnippet
                else -> Icons.Default.AttachFile
            },
            contentDescription = null,
            modifier = Modifier.size(24.dp)
        )
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(info.filename, style = MaterialTheme.typography.bodyMedium)
            Text(
                formatSize(info.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }
        when {
            isDownloading -> CircularProgressIndicator(
                modifier = Modifier.size(24.dp), strokeWidth = 2.dp
            )
            isCached -> Icon(
                Icons.Default.CheckCircle, contentDescription = "Cached",
                tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp)
            )
            else -> Icon(
                Icons.Default.Download, contentDescription = "Download",
                modifier = Modifier.size(20.dp)
            )
        }
    }
}

private fun shareFile(context: android.content.Context, file: File) {
    val uri = FileProvider.getUriForFile(
        context, "${context.packageName}.fileprovider", file
    )
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, context.contentResolver.getType(uri) ?: "*/*")
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    context.startActivity(Intent.createChooser(intent, "Open with"))
}

private fun formatSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
}

// ── Shared components ───────────────────────────────────────────────────────

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
