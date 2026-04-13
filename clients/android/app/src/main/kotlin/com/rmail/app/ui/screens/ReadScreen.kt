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
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
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
                    if (!isOutbox && !msg.isConsent) {
                        // #318: width controls (expand / shrink by 20 cols).
                        // Persisted as GlobalSettings.readerColumns.
                        IconButton(onClick = {
                            vm.globalSettings.readerColumns =
                                (vm.globalSettings.readerColumns - 20).coerceAtLeast(40)
                            vm.bumpReaderColumns()
                        }) {
                            Icon(Icons.Default.Remove, contentDescription = "Narrower columns")
                        }
                        IconButton(onClick = {
                            vm.globalSettings.readerColumns =
                                (vm.globalSettings.readerColumns + 20).coerceAtMost(200)
                            vm.bumpReaderColumns()
                        }) {
                            Icon(Icons.Default.Add, contentDescription = "Wider columns")
                        }
                    }
                    if (isOutbox) {
                        // #321: Edit kicks off the in-place edit flow —
                        // parse this outbox file's headers and body,
                        // queue a PendingDraft tagged with this
                        // filename, pop back to the InboxScreen which
                        // observes the draft and switches to Write
                        // panel in edit mode.
                        IconButton(onClick = {
                            val parsed = parseOutbox(msg.content)
                            vm.queuePendingDraft(MainViewModel.PendingDraft(
                                recipients = parsed.recipients.ifEmpty { listOf("") },
                                subject = filename,
                                body = parsed.body,
                                editingOutboxFilename = filename,
                                attachLines = parsed.attachLines
                            ))
                            onBack()
                        }) {
                            Icon(Icons.Default.Edit, contentDescription = "Edit")
                        }
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
                // #318: monospace text sized so exactly `columns`
                // characters fit the container width.  BoxWithConstraints
                // gives us the viewport's maxWidth; TextMeasurer gives us
                // the real rendered width of a row of `columns` "M"s at a
                // reference size; we scale the font to make those match.
                // Recomputed whenever the user adjusts columns via the
                // +/- buttons (observed through vm.readerColumns).
                val columns by vm.readerColumns.collectAsState()
                BoxWithConstraints(
                    modifier = Modifier
                        .weight(1f)
                        .padding(horizontal = 8.dp)
                        .verticalScroll(rememberScrollState())
                ) {
                    val refSize = 14.sp
                    val measurer = rememberTextMeasurer()
                    val referenceLine = "M".repeat(columns)
                    val measured = measurer.measure(
                        text = referenceLine,
                        style = TextStyle(
                            fontFamily = FontFamily.Monospace,
                            fontSize = refSize
                        )
                    )
                    val density = LocalDensity.current
                    val widthAtRef = with(density) { measured.size.width.toDp() }
                    val scale: Float = maxWidth / widthAtRef
                    val scaled = refSize * scale
                    Text(
                        text = msg.content,
                        fontFamily = FontFamily.Monospace,
                        fontSize = scaled,
                        lineHeight = scaled * 1.2f
                    )
                }
                // #321: removed the standalone "Update" button.  In its
                // earlier incarnation it just retriggered the sync,
                // which is also what every other touch on this screen
                // (Edit, Reply, Forward) implicitly does and what the
                // top-bar refresh icon in InboxScreen does explicitly.
                // The spec asks for an Update *progress* indicator
                // here when there's an in-flight transfer; that's a
                // separate visualisation we can add later, distinct
                // from the misleading "tap to do something" button.
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

// #321: parse an outbox file into its constituent parts so the
// composer can reload it for editing.  Mirrors the daemon's
// parse_outbox_file logic: contiguous to:/attach: lines at the top
// are the header block, everything after the first non-header line
// is the body.
private data class ParsedOutbox(
    val recipients: List<String>,
    val attachLines: List<String>,
    val body: String
)
private fun parseOutbox(content: String): ParsedOutbox {
    val recipients = mutableListOf<String>()
    val attachLines = mutableListOf<String>()
    val lines = content.lines()
    var bodyStart = lines.size
    for ((i, line) in lines.withIndex()) {
        val lower = line.trimStart().lowercase()
        when {
            lower.startsWith("to:") ->
                recipients.add(line.substringAfter(":").trim())
            lower.startsWith("attach:") ->
                attachLines.add(line.trim())
            else -> { bodyStart = i; break }
        }
    }
    val body = lines.drop(bodyStart).joinToString("\n").trimStart('\n')
    return ParsedOutbox(recipients, attachLines, body)
}
