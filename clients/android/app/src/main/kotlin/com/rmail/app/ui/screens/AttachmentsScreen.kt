package com.rmail.app.ui.screens

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.TextSnippet
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.FileProvider
import com.rmail.app.data.AttachmentInfo
import com.rmail.app.ui.MainViewModel
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AttachmentsScreen(vm: MainViewModel, onBack: () -> Unit) {
    val attachments by vm.attachments.collectAsState()
    var downloadingFile by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current

    LaunchedEffect(Unit) { vm.loadAttachmentList() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Attachments") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { vm.loadAttachmentList() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                    }
                }
            )
        }
    ) { padding ->
        if (attachments.isEmpty()) {
            Box(
                Modifier.padding(padding).fillMaxSize(),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    "No attachments on home server",
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                )
            }
        } else {
            LazyColumn(modifier = Modifier.padding(padding)) {
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
                modifier = Modifier.size(24.dp),
                strokeWidth = 2.dp
            )
            isCached -> Icon(Icons.Default.CheckCircle, contentDescription = "Cached",
                tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
            else -> Icon(Icons.Default.Download, contentDescription = "Download",
                modifier = Modifier.size(20.dp))
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
