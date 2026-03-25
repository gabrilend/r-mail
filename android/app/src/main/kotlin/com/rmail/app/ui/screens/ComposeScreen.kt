package com.rmail.app.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.automirrored.filled.Send
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
fun ComposeScreen(
    vm: MainViewModel,
    initialContent: String,
    onCancel: () -> Unit,
    onSent: () -> Unit
) {
    var content by remember { mutableStateOf(initialContent) }
    var isSending by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // File picker for attach: lines
    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            // Insert attach: line at end of content (before trailing newlines)
            val trimmed = content.trimEnd('\n')
            content = "$trimmed\nattach: $uri\n"
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("New message") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.Default.Close, contentDescription = "Cancel")
                    }
                },
                actions = {
                    IconButton(
                        onClick = {
                            isSending = true
                            errorMessage = null
                            val filename = vm.newOutboxFilename()
                            // Upload local attach: URIs before saving
                            val lines = content.lines().toMutableList()
                            val attachIndices = lines.indices.filter { i ->
                                lines[i].startsWith("attach: ") &&
                                (lines[i].removePrefix("attach: ").startsWith("content://") ||
                                 lines[i].removePrefix("attach: ").startsWith("file://"))
                            }
                            if (attachIndices.isEmpty()) {
                                vm.saveOutboxFile(filename, content)
                                isSending = false
                                onSent()
                            } else {
                                // Upload each local URI and replace with server path
                                var remaining = attachIndices.size
                                var failed = false
                                attachIndices.forEach { idx ->
                                    val uriStr = lines[idx].removePrefix("attach: ")
                                    val uri = Uri.parse(uriStr)
                                    vm.uploadAttachmentUri(uri) { serverPath ->
                                        if (serverPath != null) {
                                            lines[idx] = "attach: $serverPath"
                                        } else {
                                            failed = true
                                        }
                                        remaining--
                                        if (remaining == 0) {
                                            if (failed) {
                                                errorMessage = "Failed to upload one or more attachments"
                                                isSending = false
                                            } else {
                                                vm.saveOutboxFile(filename, lines.joinToString("\n"))
                                                isSending = false
                                                onSent()
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        enabled = !isSending
                    ) {
                        if (isSending) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                        }
                    }
                }
            )
        }
    ) { padding ->
        Column(modifier = Modifier.padding(padding).fillMaxSize()) {
            // Attach button in a small toolbar
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                TextButton(onClick = { filePicker.launch("*/*") }) {
                    Icon(Icons.Default.AttachFile, contentDescription = null,
                        modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(4.dp))
                    Text("Attach file", style = MaterialTheme.typography.bodySmall)
                }
            }

            if (errorMessage != null) {
                Text(
                    errorMessage!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp)
                )
            }

            HorizontalDivider()

            // Editor — monospace, full screen
            BasicTextField(
                value = content,
                onValueChange = { content = it },
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp),
                textStyle = TextStyle(
                    color = MaterialTheme.colorScheme.onBackground,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    lineHeight = 20.sp
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
            )
        }
    }
}
