package com.rmail.app.ui.screens

import android.graphics.BitmapFactory
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.documentfile.provider.DocumentFile
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.rmail.app.ui.MainViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private data class ComposeAttachmentEntry(
    val uri: Uri,
    val displayName: String,
    val mimeType: String?
)

private data class ParsedDraft(
    val recipients: List<String>,
    val attachUris: List<String>,
    val subject: String,
    val body: String
)

private fun parseInitialContent(content: String): ParsedDraft {
    val recipients = mutableListOf<String>()
    val attachUris = mutableListOf<String>()
    val bodyLines = mutableListOf<String>()
    var subject = ""

    for (line in content.lines()) {
        val trimmed = line.trim()
        val lower = trimmed.lowercase()
        when {
            lower.startsWith("to:") -> {
                val name = trimmed.substringAfter(":").trim()
                if (name.isNotEmpty()) recipients.add(name)
            }
            lower.startsWith("attach:") -> {
                val path = trimmed.substringAfter(":").trim()
                if (path.isNotEmpty()) attachUris.add(path)
            }
            lower.startsWith("subject:") -> {
                subject = trimmed.substringAfter(":").trim()
            }
            else -> bodyLines.add(line)
        }
    }

    return ParsedDraft(
        recipients = recipients,
        attachUris = attachUris,
        subject = subject,
        body = bodyLines.joinToString("\n").trim()
    )
}

/** Mirror the Lua daemon's sanitize_filename(): strip path components, leading dots, control chars. */
private fun sanitizeFilename(name: String): String {
    if (name.isBlank()) return "untitled"
    var s = name.substringAfterLast('/').substringAfterLast('\\')
    s = s.trimStart('.')
    s = s.replace(Regex("[\\x00-\\x1f/\\\\]"), "_")
    s = s.replace(' ', '-')
    return s.ifBlank { "untitled" }
}

private fun buildOutboxContent(
    recipients: List<String>,
    attachPaths: List<String>,
    body: String
): String {
    val sb = StringBuilder()
    for (r in recipients) sb.appendLine("to: $r")
    for (p in attachPaths) sb.appendLine("attach: $p")
    sb.appendLine()
    sb.append(body)
    return sb.toString()
}

private fun resolveDisplayName(context: android.content.Context, uri: Uri): String? {
    return try {
        context.contentResolver.query(
            uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null
        )?.use { cursor ->
            if (cursor.moveToFirst()) cursor.getString(0) else null
        }
    } catch (_: Exception) { null }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ComposeScreen(
    vm: MainViewModel,
    initialContent: String,
    onCancel: () -> Unit,
    onSent: () -> Unit
) {
    val context = LocalContext.current
    val parsed = remember { parseInitialContent(initialContent) }

    val recipients = remember {
        mutableStateListOf<String>().apply {
            addAll(parsed.recipients.ifEmpty { listOf("") })
        }
    }
    val attachments = remember { mutableStateListOf<ComposeAttachmentEntry>() }
    var subject by remember { mutableStateOf(parsed.subject) }
    var body by remember { mutableStateOf(parsed.body) }
    val daemonName by vm.daemonName.collectAsState()
    val contactNames = remember(daemonName) {
        val names = vm.getContactNames().toMutableList()
        if (daemonName != null && daemonName !in names) names.add(0, daemonName!!)
        names
    }

    var errorMessage by remember { mutableStateOf<String?>(null) }
    val scrollState = rememberScrollState()

    // Resolve initial attach: URIs from draft into AttachmentEntry objects
    LaunchedEffect(Unit) {
        for (uriStr in parsed.attachUris) {
            val uri = Uri.parse(uriStr)
            val name = resolveDisplayName(context, uri) ?: uriStr.substringAfterLast('/')
            val mime = try { context.contentResolver.getType(uri) } catch (_: Exception) { null }
            attachments.add(ComposeAttachmentEntry(uri, name, mime))
        }
    }

    // File picker for adding attachments
    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            val name = resolveDisplayName(context, uri) ?: uri.lastPathSegment ?: "attachment"
            val mime = try { context.contentResolver.getType(uri) } catch (_: Exception) { null }
            attachments.add(ComposeAttachmentEntry(uri, name, mime))
        }
    }

    // Directory picker for attaching folders
    val dirPicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree()
    ) { treeUri: Uri? ->
        if (treeUri != null) {
            val tree = DocumentFile.fromTreeUri(context, treeUri) ?: return@rememberLauncherForActivityResult
            fun addChildren(dir: DocumentFile) {
                for (child in dir.listFiles()) {
                    if (child.isDirectory) {
                        addChildren(child)
                    } else if (child.uri != null) {
                        val name = child.name ?: child.uri.lastPathSegment ?: "attachment"
                        val mime = child.type
                        attachments.add(ComposeAttachmentEntry(child.uri, name, mime))
                    }
                }
            }
            addChildren(tree)
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
                            errorMessage = null

                            val validRecipients = recipients.filter { it.isNotBlank() }
                            if (validRecipients.isEmpty()) {
                                errorMessage = "Add at least one recipient"
                                return@IconButton
                            }

                            val filename = if (subject.isNotBlank())
                                sanitizeFilename(subject)
                            else
                                vm.newOutboxFilename()

                            // Save immediately with local URIs, navigate away
                            val localPaths = attachments.map { it.uri.toString() }
                            val content = buildOutboxContent(validRecipients, localPaths, body)
                            vm.saveOutboxFile(filename, content)
                            // Upload attachments in background, updating the file as each completes
                            vm.uploadAttachmentsInBackground(filename, attachments.map { it.uri })
                            onSent()
                        }
                    ) {
                        Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                    }
                }
            )
        }
    ) { padding ->
        val coroutineScope = rememberCoroutineScope()
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(scrollState)
        ) {
            // ── Recipients section ──────────────────────────────────────────
            Text(
                "To",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 4.dp)
            )

            recipients.forEachIndexed { index, selected ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp)
                ) {
                    ContactPicker(
                        contacts = contactNames,
                        selected = selected,
                        onSelect = { recipients[index] = it },
                        modifier = Modifier.weight(1f)
                    )
                    if (index == recipients.lastIndex) {
                        IconButton(onClick = { recipients.add("") }) {
                            Icon(Icons.Default.Add, contentDescription = "Add recipient")
                        }
                    } else {
                        IconButton(onClick = { recipients.removeAt(index) }) {
                            Icon(Icons.Default.Remove, contentDescription = "Remove recipient")
                        }
                    }
                }
            }

            Spacer(Modifier.height(4.dp))

            // ── Attachments section ─────────────────────────────────────────
            Text(
                "Attachments",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(start = 16.dp, top = 4.dp, bottom = 4.dp)
            )

            attachments.forEachIndexed { index, entry ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Column(Modifier.weight(1f).padding(start = 8.dp)) {
                        Text(entry.displayName, style = MaterialTheme.typography.bodyMedium, maxLines = 1)
                        Text(entry.mimeType?.substringAfter('/') ?: "file",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    IconButton(onClick = { attachments.removeAt(index) }) {
                        Icon(Icons.Default.Remove, contentDescription = "Remove")
                    }
                }
            }
            // Placeholder row — always present, opens file picker
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 8.dp)
            ) {
                Text(
                    if (attachments.isEmpty()) "None" else "Add another",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier
                        .weight(1f)
                        .padding(start = 8.dp)
                )
                IconButton(onClick = { dirPicker.launch(null) }) {
                    Icon(Icons.Default.Folder, contentDescription = "Attach folder")
                }
                IconButton(onClick = { filePicker.launch(arrayOf("*/*")) }) {
                    Icon(Icons.Default.Add, contentDescription = "Attach file")
                }
            }

            // ── Subject field ────────────────────────────────────────────
            OutlinedTextField(
                value = subject,
                onValueChange = { subject = it },
                placeholder = { Text("Subject (optional)", fontSize = 14.sp) },
                singleLine = true,
                textStyle = TextStyle(fontSize = 14.sp),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 4.dp)
            )

            if (errorMessage != null) {
                Text(
                    errorMessage!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }

            HorizontalDivider(modifier = Modifier.padding(top = 4.dp))

            // ── Body editor ─────────────────────────────────────────────────
            BasicTextField(
                value = body,
                onValueChange = { body = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .defaultMinSize(minHeight = 300.dp)
                    .padding(16.dp)
                    .onFocusChanged { focus ->
                        if (focus.isFocused) {
                            coroutineScope.launch { scrollState.animateScrollTo(scrollState.maxValue) }
                        }
                    },
                textStyle = TextStyle(
                    color = MaterialTheme.colorScheme.onBackground,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    lineHeight = 20.sp
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                decorationBox = { innerTextField ->
                    Box {
                        if (body.isEmpty()) {
                            Text(
                                "Message",
                                style = TextStyle(
                                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
                                    fontFamily = FontFamily.Monospace,
                                    fontSize = 14.sp
                                )
                            )
                        }
                        innerTextField()
                    }
                }
            )
        }
    }
}

// ���─ Contact picker dropdown ─────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactPicker(
    contacts: List<String>,
    selected: String,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }

    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier
    ) {
        OutlinedTextField(
            value = selected,
            onValueChange = {},
            readOnly = true,
            placeholder = { Text("Select contact", fontSize = 14.sp) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .menuAnchor()
                .fillMaxWidth(),
            singleLine = true,
            textStyle = TextStyle(fontSize = 14.sp),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false }
        ) {
            if (contacts.isEmpty()) {
                DropdownMenuItem(
                    text = {
                        Text(
                            "No contacts",
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                        )
                    },
                    onClick = { expanded = false },
                    enabled = false
                )
            } else {
                contacts.forEach { name ->
                    DropdownMenuItem(
                        text = { Text(name) },
                        onClick = {
                            onSelect(name)
                            expanded = false
                        }
                    )
                }
            }
        }
    }
}

// ── Attachment preview ──────────────────────────────────────────────────────

@Composable
private fun AttachmentPreview(entry: AttachmentEntry, modifier: Modifier = Modifier) {
    val isImage = entry.mimeType?.startsWith("image/") == true

    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = modifier.padding(start = 8.dp)
    ) {
        if (isImage) {
            AttachmentThumbnail(entry.uri)
            Spacer(Modifier.width(10.dp))
        }
        Column {
            Text(
                entry.displayName,
                style = MaterialTheme.typography.bodyMedium,
                maxLines = 1
            )
            val typeLabel = entry.mimeType?.substringAfter('/') ?: "file"
            Text(
                typeLabel,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AttachmentThumbnail(uri: Uri) {
    val context = LocalContext.current
    var bitmap by remember(uri) { mutableStateOf<ImageBitmap?>(null) }

    LaunchedEffect(uri) {
        bitmap = withContext(Dispatchers.IO) {
            try {
                context.contentResolver.openInputStream(uri)?.use { stream ->
                    BitmapFactory.decodeStream(
                        stream, null,
                        BitmapFactory.Options().apply { inSampleSize = 4 }
                    )?.asImageBitmap()
                }
            } catch (_: Exception) { null }
        }
    }

    if (bitmap != null) {
        Image(
            bitmap!!,
            contentDescription = null,
            modifier = Modifier.size(48.dp),
            contentScale = ContentScale.Crop
        )
    } else {
        Surface(
            modifier = Modifier.size(48.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
            content = {}
        )
    }
}
