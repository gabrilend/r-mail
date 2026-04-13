package com.rmail.app.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.documentfile.provider.DocumentFile
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.automirrored.filled.TextSnippet
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.input.OffsetMapping
import androidx.compose.ui.text.input.TransformedText
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.FileProvider
import com.rmail.app.data.AttachmentInfo
import com.rmail.app.ui.MainViewModel
import com.rmail.app.ui.SyncStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File

private enum class Panel { INBOX, OUTBOX, FILES, CONTACTS, SETTINGS, WRITE }
private enum class FilesMode { NORMAL, DELETE, FORWARD }

@Composable
private fun rememberKeyboardOpen(): Boolean {
    val view = LocalView.current
    var isOpen by remember { mutableStateOf(false) }
    DisposableEffect(view) {
        val listener = android.view.ViewTreeObserver.OnGlobalLayoutListener {
            val rect = android.graphics.Rect()
            view.getWindowVisibleDisplayFrame(rect)
            val screenHeight = view.rootView.height
            isOpen = (screenHeight - rect.bottom) > screenHeight * 0.15
        }
        view.viewTreeObserver.addOnGlobalLayoutListener(listener)
        onDispose { view.viewTreeObserver.removeOnGlobalLayoutListener(listener) }
    }
    return isOpen
}

// Side-channel for settings save/clear — SettingsPanel registers these here
private var settingsSaveFn: (() -> Unit)? = null
private var settingsClearFn: (() -> Unit)? = null

// Vibrant button colors
private val ButtonColors = mapOf(
    Panel.INBOX to Color(0xFF2E7D32),       // deep green
    Panel.OUTBOX to Color(0xFFFF9800),      // orange
    Panel.FILES to Color(0xFF1565C0),       // deep blue
    Panel.CONTACTS to Color(0xFFE53935),    // red
    Panel.SETTINGS to Color(0xFFD81B60),    // magenta
    Panel.WRITE to Color(0xFF26A69A),       // teal
)

internal data class AttachmentEntry(
    val uri: Uri,
    val displayName: String,
    val mimeType: String?
)

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
    var currentPanel by remember { mutableStateOf(if (initialShowOutbox) Panel.OUTBOX else Panel.INBOX) }

    // Compose draft state in RAM
    var draftRecipients by remember { mutableStateOf(listOf("")) }
    var draftAttachments = remember { mutableStateListOf<AttachmentEntry>() }
    var draftSubject by remember { mutableStateOf("") }
    var draftBody by remember { mutableStateOf("") }

    // #358: pick up a forward/reply draft queued by ReadScreen, seed the
    // composer state with it, and jump to the Write panel.  Consume the
    // pending value so a back-and-forth navigation doesn't refill again.
    val pendingDraft by vm.pendingDraft.collectAsState()
    LaunchedEffect(pendingDraft) {
        val d = pendingDraft ?: return@LaunchedEffect
        draftRecipients = d.recipients.ifEmpty { listOf("") }
        draftSubject = d.subject
        draftBody = d.body
        draftAttachments.clear()
        currentPanel = Panel.WRITE
        vm.consumePendingDraft()
    }

    // Contacts state
    var contactsContent by remember { mutableStateOf(vm.readContacts()) }
    val savedContacts = remember { mutableStateOf(vm.readContacts()) }
    val contactsModified by remember(contactsContent, savedContacts.value) {
        mutableStateOf(contactsContent != savedContacts.value)
    }

    // Settings modified tracking
    var settingsModified by remember { mutableStateOf(false) }

    // #315: duplicate-subject warning dialog.  Keeps the draft intact
    // so the user can tweak the subject and resend.
    var duplicateSubjectWarning by remember { mutableStateOf<String?>(null) }

    // Contact editor state
    var showContactEditor by remember { mutableStateOf(false) }

    // Files panel selection mode
    var filesMode by remember { mutableStateOf(FilesMode.NORMAL) }
    val selectedFiles = remember { mutableStateListOf<String>() }

    val context = LocalContext.current

    // File picker for compose attachments
    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            val name = resolveDisplayName(context, uri) ?: uri.lastPathSegment ?: "attachment"
            val mime = try { context.contentResolver.getType(uri) } catch (_: Exception) { null }
            draftAttachments.add(AttachmentEntry(uri, name, mime))
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
                        draftAttachments.add(AttachmentEntry(child.uri, name, mime))
                    }
                }
            }
            addChildren(tree)
        }
    }

    val isKeyboardOpen = rememberKeyboardOpen()
    val focusManager = LocalFocusManager.current

    // Clear focus (hides cursor) whenever keyboard closes
    LaunchedEffect(isKeyboardOpen) {
        if (!isKeyboardOpen) focusManager.clearFocus()
    }

    LaunchedEffect(Unit) { vm.refreshLocal() }
    // Re-read contacts from disk when switching to contacts panel (picks up sync changes)
    LaunchedEffect(currentPanel) {
        if (currentPanel == Panel.CONTACTS && !contactsModified) {
            val fresh = vm.readContacts()
            contactsContent = fresh
            savedContacts.value = fresh
        }
    }
    LaunchedEffect(currentPanel) {
        if (currentPanel == Panel.FILES) vm.loadAttachmentList()
        else { filesMode = FilesMode.NORMAL; selectedFiles.clear() }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                navigationIcon = {
                    // #359: only show the ← arrow when it truly means
                    // "back one step" — i.e. the contact-editor sub-view.
                    // At the top level, tapping the mailbox name (title)
                    // jumps to the mailbox list; an arrow there misled
                    // users into thinking it meant "previous screen".
                    if (showContactEditor) {
                        IconButton(onClick = { showContactEditor = false }) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack,
                                contentDescription = "Back to contacts")
                        }
                    }
                },
                title = {
                    val activeId by vm.activeMailboxId.collectAsState()
                    val config = activeId?.let { vm.registry.get(it) }
                    val label = config?.name?.ifBlank { null } ?: config?.host ?: "Mailbox"
                    if (showContactEditor) {
                        Text(label)
                    } else {
                        // #359: title doubles as the "go to mailbox list"
                        // tap target.  A subtle underline signals it's
                        // interactive without shouting about it.
                        Text(
                            label,
                            textDecoration = androidx.compose.ui.text.style.TextDecoration.Underline,
                            modifier = Modifier.clickable(onClick = onBack)
                        )
                    }
                },
                actions = {
                    // Only show refresh on data panels (inbox, outbox, files)
                    val showRefresh = currentPanel in listOf(Panel.INBOX, Panel.OUTBOX, Panel.FILES, Panel.CONTACTS)
                        && !showContactEditor
                    if (showRefresh) {
                        when (syncStatus) {
                            SyncStatus.SYNCING -> CircularProgressIndicator(
                                modifier = Modifier.size(24.dp).padding(end = 8.dp),
                                strokeWidth = 2.dp
                            )
                            SyncStatus.ERROR -> IconButton(onClick = { vm.triggerSync() }) {
                                Icon(Icons.Default.Warning, contentDescription = "Sync error")
                            }
                            SyncStatus.IDLE -> IconButton(onClick = {
                                vm.triggerSync()
                                if (currentPanel == Panel.FILES) vm.loadAttachmentList()
                            }) {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                            }
                        }
                    }
                    // Contacts: + button opens structured contact editor (not shown in editor)
                    if (currentPanel == Panel.CONTACTS && !showContactEditor) {
                        IconButton(onClick = { showContactEditor = true }) {
                            Icon(Icons.Default.Add, contentDescription = "Add contact")
                        }
                    }
                    // Outbox: + button as shortcut to Write panel.
                    // This intentional redundancy exists because users instinctively
                    // look to the top-right to compose, even though the Write tab
                    // in the bottom bar does the same thing.
                    if (currentPanel == Panel.OUTBOX) {
                        IconButton(onClick = { currentPanel = Panel.WRITE }) {
                            Icon(Icons.Default.Add, contentDescription = "Write new message")
                        }
                    }
                    // Files: + button opens file picker pre-addressed to this mailbox.
                    // Sends user through the compose workflow to reinforce the message
                    // passing paradigm — they can review, edit, or redirect before sending.
                    if (currentPanel == Panel.FILES) {
                        IconButton(onClick = {
                            val activeId = vm.activeMailboxId.value
                            val config = activeId?.let { vm.registry.get(it) }
                            val name = config?.name ?: ""
                            draftRecipients = listOf(name)
                            draftAttachments.clear()
                            draftSubject = ""
                            draftBody = ""
                            currentPanel = Panel.WRITE
                            // Immediately open the file picker
                            filePicker.launch(arrayOf("*/*"))
                        }) {
                            Icon(Icons.Default.Add, contentDescription = "Upload file")
                        }
                    }
                    if (currentPanel == Panel.WRITE) {
                        // #319: the old "+" (clear-form) action was removed.
                        // With an empty draft it looked like it did nothing,
                        // and with a filled draft it silently wiped work —
                        // both surprising.  Users who want a fresh draft can
                        // just tap the fields to edit or navigate away and
                        // back.  Only the Send button stays here.
                        IconButton(onClick = {
                            val validRecipients = draftRecipients.filter { it.isNotBlank() }
                            if (validRecipients.isEmpty()) return@IconButton
                            val filename = if (draftSubject.isNotBlank())
                                sanitizeFilename(draftSubject) else vm.newOutboxFilename()
                            // #315: catch the collision on the *converted*
                            // filename, not the raw subject.  "hello world"
                            // and "hello-world" both sanitise to
                            // "hello-world"; neither should silently
                            // overwrite an existing outbox file of that
                            // name.  If there's a collision, show a dialog
                            // and keep the draft intact so the user can
                            // adjust the subject.
                            if (draftSubject.isNotBlank() &&
                                vm.outboxFiles.value.contains(filename)) {
                                duplicateSubjectWarning = filename
                                return@IconButton
                            }
                            val localPaths = draftAttachments.map { it.uri.toString() }
                            val sb = StringBuilder()
                            for (r in validRecipients) sb.appendLine("to: $r")
                            for (p in localPaths) sb.appendLine("attach: $p")
                            sb.appendLine()
                            sb.append(draftBody)
                            vm.saveOutboxFile(filename, sb.toString())
                            vm.uploadAttachmentsInBackground(filename, draftAttachments.map { it.uri })
                            // #322: trigger the top-bar sending animation
                            vm.markSendingStart(filename)
                            draftRecipients = listOf("")
                            draftAttachments.clear()
                            draftSubject = ""
                            draftBody = ""
                            currentPanel = Panel.OUTBOX
                            vm.triggerSync()
                        }) {
                            Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                        }
                    }
                }
            )
        },
        bottomBar = {
            if (!isKeyboardOpen) {
            val gridColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.25f)
            val gridWidth = 0.5.dp
            // 2x3 grid with gray internal separators
            Column(modifier = Modifier.fillMaxWidth()) {
                val hasFilesRow = currentPanel == Panel.FILES
                val cornerRadius = 16.dp
                // Files action row — above the main rows so navigation stays stable
                if (hasFilesRow) {
                    val deleteColor = Color(0xFFD32F2F)
                    val forwardColor = Color(0xFF7B1FA2)
                    val uploadColor = ButtonColors[Panel.WRITE]!!
                    val filesRowGray = Color(0xFF9E9E9E)  // light gray for unselected files actions
                    HorizontalDivider(thickness = gridWidth, color = gridColor)
                    Row(modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
                        BottomBarButton("Delete", filesMode == FilesMode.DELETE, deleteColor,
                            Modifier.weight(1f), unselectedColor = filesRowGray) {
                            if (filesMode == FilesMode.DELETE) {
                                filesMode = FilesMode.NORMAL; selectedFiles.clear()
                            } else {
                                filesMode = FilesMode.DELETE; selectedFiles.clear()
                            }
                        }
                        VerticalDivider(gridWidth, gridColor, filesMode == FilesMode.DELETE, filesMode == FilesMode.FORWARD)
                        BottomBarButton("Forward", filesMode == FilesMode.FORWARD, forwardColor,
                            Modifier.weight(1f), unselectedColor = filesRowGray) {
                            if (filesMode == FilesMode.FORWARD) {
                                filesMode = FilesMode.NORMAL; selectedFiles.clear()
                            } else {
                                filesMode = FilesMode.FORWARD; selectedFiles.clear()
                            }
                        }
                        VerticalDivider(gridWidth, gridColor, filesMode == FilesMode.FORWARD, false)
                        BottomBarButton("Upload", false, uploadColor, Modifier.weight(1f),
                            unselectedColor = filesRowGray) {
                            val activeId = vm.activeMailboxId.value
                            val config = activeId?.let { vm.registry.get(it) }
                            draftRecipients = listOf(config?.name ?: "")
                            draftAttachments.clear()
                            draftSubject = ""
                            draftBody = ""
                            currentPanel = Panel.WRITE
                            filePicker.launch(arrayOf("*/*"))
                        }
                    }
                }
                // Top row (always present)
                HorizontalDivider(thickness = gridWidth, color = gridColor)
                Row(modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
                    BottomBarButton("Contacts", currentPanel == Panel.CONTACTS,
                        ButtonColors[Panel.CONTACTS]!!, Modifier.weight(1f)) { currentPanel = Panel.CONTACTS }
                    VerticalDivider(gridWidth, gridColor, currentPanel == Panel.CONTACTS, currentPanel == Panel.SETTINGS)
                    BottomBarButton("Settings", currentPanel == Panel.SETTINGS,
                        ButtonColors[Panel.SETTINGS]!!, Modifier.weight(1f)) { currentPanel = Panel.SETTINGS }
                    VerticalDivider(gridWidth, gridColor, currentPanel == Panel.SETTINGS, currentPanel == Panel.WRITE)
                    BottomBarButton("Write", currentPanel == Panel.WRITE,
                        ButtonColors[Panel.WRITE]!!, Modifier.weight(1f)) { currentPanel = Panel.WRITE }
                }
                // Bottom row (always present, always at the bottom)
                HorizontalDivider(thickness = gridWidth, color = gridColor)
                Row(modifier = Modifier.fillMaxWidth().height(IntrinsicSize.Min)) {
                    BottomBarButton("Inbox", currentPanel == Panel.INBOX,
                        ButtonColors[Panel.INBOX]!!, Modifier.weight(1f),
                        shape = RoundedCornerShape(bottomStart = cornerRadius)
                    ) { currentPanel = Panel.INBOX }
                    VerticalDivider(gridWidth, gridColor, currentPanel == Panel.INBOX, currentPanel == Panel.OUTBOX)
                    BottomBarButton("Outbox", currentPanel == Panel.OUTBOX,
                        ButtonColors[Panel.OUTBOX]!!, Modifier.weight(1f)) { currentPanel = Panel.OUTBOX }
                    VerticalDivider(gridWidth, gridColor, currentPanel == Panel.OUTBOX, currentPanel == Panel.FILES)
                    BottomBarButton("Files", currentPanel == Panel.FILES,
                        ButtonColors[Panel.FILES]!!, Modifier.weight(1f),
                        shape = RoundedCornerShape(bottomEnd = cornerRadius)
                    ) { currentPanel = Panel.FILES }
                }
            }
            } // end if (!isKeyboardOpen)
        }
    ) { padding ->
        // #315: duplicate-subject dialog.  Shown when Send would produce
        // a filename that collides with an existing outbox file.  Draft
        // state is preserved; user picks Cancel (tweak the subject) or
        // Replace (overwrite the existing file deliberately).
        duplicateSubjectWarning?.let { collidingFilename ->
            AlertDialog(
                onDismissRequest = { duplicateSubjectWarning = null },
                title = { Text("Subject already in outbox") },
                text = {
                    Text("Your outbox already has a message named " +
                        "\"$collidingFilename\". Sending with the same " +
                        "subject would overwrite it. Change the subject " +
                        "to send a new message, or choose Replace to " +
                        "overwrite the existing one.")
                },
                confirmButton = {
                    TextButton(onClick = {
                        // User chose to replace — re-do the Send path
                        // but skip the collision check this time.
                        val validRecipients = draftRecipients.filter { it.isNotBlank() }
                        val localPaths = draftAttachments.map { it.uri.toString() }
                        val sb = StringBuilder()
                        for (r in validRecipients) sb.appendLine("to: $r")
                        for (p in localPaths) sb.appendLine("attach: $p")
                        sb.appendLine()
                        sb.append(draftBody)
                        vm.saveOutboxFile(collidingFilename, sb.toString())
                        vm.uploadAttachmentsInBackground(
                            collidingFilename, draftAttachments.map { it.uri })
                        vm.markSendingStart(collidingFilename)
                        draftRecipients = listOf("")
                        draftAttachments.clear()
                        draftSubject = ""
                        draftBody = ""
                        currentPanel = Panel.OUTBOX
                        vm.triggerSync()
                        duplicateSubjectWarning = null
                    }) { Text("Replace") }
                },
                dismissButton = {
                    TextButton(onClick = { duplicateSubjectWarning = null }) {
                        Text("Cancel")
                    }
                }
            )
        }
        Column(modifier = Modifier.padding(padding)) {
            if (syncError != null) {
                Surface(
                    color = MaterialTheme.colorScheme.error.copy(alpha = 0.15f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(syncError!!, style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(8.dp), color = MaterialTheme.colorScheme.error)
                }
            }
            // #322: post-Send animation bar — renders only when there's
            // an in-flight send, shows dots counting down, then reports
            // "sent" (delivered) or "ready" (queued, will retry).
            SendingProgressBar(vm)
            // Action bar: clear/save for contacts or settings (hidden when keyboard is open)
            if (!isKeyboardOpen) {
                val showContactsActions = currentPanel == Panel.CONTACTS && contactsModified &&
                    syncStatus != SyncStatus.ERROR && vm.isActiveConfigured
                if (showContactsActions) {
                    ActionBar(
                        onClear = { contactsContent = savedContacts.value },
                        onSave = {
                            vm.saveContacts(contactsContent)
                            savedContacts.value = contactsContent
                        }
                    )
                }
                if (currentPanel == Panel.SETTINGS && settingsModified) {
                    ActionBar(
                        onClear = { settingsClearFn?.invoke(); settingsModified = false },
                        onSave = { settingsSaveFn?.invoke() }
                    )
                }
            }

            when (currentPanel) {
                Panel.INBOX -> MessageList(inboxFiles, "No messages", vm.swipeToDelete,
                    { vm.deleteInboxMessage(it) }, { onOpen(it) })
                Panel.OUTBOX -> MessageList(outboxFiles, "Outbox is empty", true,
                    { vm.deleteOutboxFile(it) }, { onOpenOutbox(it) })
                Panel.FILES -> {
                    // Box overlay: action bars float on top of the list
                    Box(Modifier.fillMaxSize()) {
                        AttachmentList(
                            vm = vm,
                            attachments = attachments,
                            selectionMode = filesMode != FilesMode.NORMAL,
                            selectedFiles = selectedFiles,
                            onDeleteServer = { filenames -> filenames.forEach { vm.deleteAttachmentFromServer(it) } },
                            onDeleteDevice = { filenames -> filenames.forEach { vm.deleteAttachmentFromDevice(it) } },
                            onForward = { /* handled by bar below */ }
                        )
                        // Overlay action bars at top
                        if (filesMode == FilesMode.DELETE && selectedFiles.isNotEmpty()) {
                            val teal = ButtonColors[Panel.WRITE]!!
                            Row(Modifier.fillMaxWidth().align(Alignment.TopCenter)) {
                                Surface(color = teal, modifier = Modifier.weight(1f).clickable {
                                    val valid = selectedFiles.filter { fn ->
                                        attachments.find { it.filename == fn }?.onServer == true
                                    }
                                    if (valid.size < selectedFiles.size) {
                                        selectedFiles.clear(); selectedFiles.addAll(valid)
                                    } else {
                                        vm.run { valid.forEach { deleteAttachmentFromServer(it) } }
                                        selectedFiles.clear(); filesMode = FilesMode.NORMAL
                                    }
                                }) {
                                    Box(contentAlignment = Alignment.Center,
                                        modifier = Modifier.padding(vertical = 10.dp)) {
                                        Text("Delete on server", fontWeight = FontWeight.Bold,
                                            color = Color.Black)
                                    }
                                }
                                Surface(color = MaterialTheme.colorScheme.errorContainer,
                                    modifier = Modifier.weight(1f).clickable {
                                    val valid = selectedFiles.filter { fn ->
                                        attachments.find { it.filename == fn }?.onDevice == true
                                    }
                                    if (valid.size < selectedFiles.size) {
                                        selectedFiles.clear(); selectedFiles.addAll(valid)
                                    } else {
                                        vm.run { valid.forEach { deleteAttachmentFromDevice(it) } }
                                        selectedFiles.clear(); filesMode = FilesMode.NORMAL
                                    }
                                }) {
                                    Box(contentAlignment = Alignment.Center,
                                        modifier = Modifier.padding(vertical = 10.dp)) {
                                        Text("Delete on device", fontWeight = FontWeight.Bold,
                                            color = Color.Black)
                                    }
                                }
                            }
                        }
                        if (filesMode == FilesMode.FORWARD && selectedFiles.isNotEmpty()) {
                            Surface(color = Color(0xFF7B1FA2),
                                modifier = Modifier.fillMaxWidth().align(Alignment.TopCenter).clickable {
                                    draftRecipients = listOf("")
                                    draftAttachments.clear()
                                    draftSubject = ""
                                    // Split: device files go in attachment field,
                                    // server-only files go as attach: lines in the body
                                    val serverOnlyLines = mutableListOf<String>()
                                    val activeId = vm.activeMailboxId.value
                                    val mailboxPath = activeId?.let { vm.registry.get(it) }?.mailboxPath ?: ""
                                    for (fn in selectedFiles.toList()) {
                                        val info = attachments.find { it.filename == fn }
                                        val cached = vm.store?.cachedAttachmentFile(fn)
                                        if (info?.onDevice == true && cached != null && cached.exists()) {
                                            // On device (possibly also on server) — put in attachment field
                                            draftAttachments.add(AttachmentEntry(
                                                uri = android.net.Uri.fromFile(cached),
                                                displayName = fn,
                                                mimeType = info.category
                                            ))
                                        } else if (info?.onServer == true && mailboxPath.isNotBlank()) {
                                            // Server-only — attach: line with full server path
                                            serverOnlyLines.add("attach: $mailboxPath/attachments/$fn")
                                        }
                                    }
                                    draftBody = serverOnlyLines.joinToString("\n")
                                    currentPanel = Panel.WRITE
                                    filesMode = FilesMode.NORMAL
                                    selectedFiles.clear()
                                }
                            ) {
                                Box(contentAlignment = Alignment.Center,
                                    modifier = Modifier.padding(vertical = 10.dp)) {
                                    Text("Tap to forward", fontWeight = FontWeight.Bold,
                                        color = Color.Black)
                                }
                            }
                        }
                    }
                }
                Panel.CONTACTS -> if (showContactEditor) {
                    ContactEditorPanel(
                        existingContacts = contactsContent,
                        accentColor = Color(vm.globalSettings.accentColor.toLong() and 0xFFFFFFFFL),
                        onSave = { newEntry ->
                            // Append new contact to contacts content (shown in accent until file is saved)
                            val separator = if (contactsContent.endsWith("\n") || contactsContent.isEmpty()) "" else "\n"
                            contactsContent = contactsContent + separator + "\n" + newEntry
                            showContactEditor = false
                        },
                        onCancel = { showContactEditor = false }
                    )
                } else {
                    ContactsPanel(
                        vm = vm,
                        content = contactsContent,
                        savedContent = savedContacts.value,
                        onContentChange = { contactsContent = it }
                    )
                }
                Panel.SETTINGS -> SettingsPanel(vm,
                    onModified = { settingsModified = true },
                    onSaved = { settingsModified = false },
                    onDeleteMailbox = {
                        val id = vm.activeMailboxId.value
                        if (id != null) {
                            vm.removeMailbox(id)
                            onBack()
                        }
                    })
                Panel.WRITE -> ComposePanel(
                    vm = vm,
                    recipients = draftRecipients,
                    onRecipientsChange = { draftRecipients = it },
                    attachments = draftAttachments,
                    filePicker = { filePicker.launch(arrayOf("*/*")) },
                    dirPicker = { dirPicker.launch(null) },
                    subject = draftSubject,
                    onSubjectChange = { draftSubject = it },
                    body = draftBody,
                    onBodyChange = { draftBody = it }
                )
            }
        }
    }
}

// ── Grid divider (disappears when neighbor is selected) ─────────────────────

@Composable
private fun RowScope.VerticalDivider(
    width: androidx.compose.ui.unit.Dp,
    color: Color,
    leftSelected: Boolean,
    rightSelected: Boolean
) {
    if (!leftSelected && !rightSelected) {
        Box(Modifier.width(width).fillMaxHeight().background(color))
    }
}

// ── Bottom bar button ────────────────────────────────────────────────────────

@Composable
private fun BottomBarButton(
    label: String, selected: Boolean, color: Color,
    modifier: Modifier = Modifier,
    shape: androidx.compose.ui.graphics.Shape = androidx.compose.ui.graphics.RectangleShape,
    unselectedColor: Color? = null,  // override unselected text color
    onClick: () -> Unit
) {
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .clip(shape)
            .clickable(onClick = onClick)
            .then(if (selected) Modifier.background(color) else Modifier)
            .padding(vertical = 16.dp)
    ) {
        Text(
            label,
            style = MaterialTheme.typography.labelLarge,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            color = if (selected) Color.Black else (unselectedColor ?: color)
        )
    }
}

// ── Action bar (reusable clear/save strip) ──────────────────────────────────

@OptIn(ExperimentalComposeUiApi::class)
@Composable
private fun ActionBar(onClear: () -> Unit, onSave: () -> Unit) {
    val focusManager = LocalFocusManager.current
    val keyboard = LocalSoftwareKeyboardController.current
    fun dismissAndRun(action: () -> Unit) {
        keyboard?.hide()
        focusManager.clearFocus()
        action()
    }
    Row(modifier = Modifier.fillMaxWidth()) {
        Surface(
            color = MaterialTheme.colorScheme.errorContainer,
            modifier = Modifier.weight(1f).clickable { dismissAndRun(onClear) }
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(vertical = 10.dp)) {
                Text("Clear changes", fontWeight = FontWeight.Bold,
                    color = Color.Black)
            }
        }
        Surface(
            color = MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.weight(1f).clickable { dismissAndRun(onSave) }
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(vertical = 10.dp)) {
                Text("Save changes", fontWeight = FontWeight.Bold,
                    color = Color.Black)
            }
        }
    }
}

// ── Contacts panel ──────────────────────────────────────────────────────────

@Composable
private fun ContactsPanel(
    vm: MainViewModel,
    content: String,
    savedContent: String,
    onContentChange: (String) -> Unit
) {
    val myAddress by vm.myAddress.collectAsState()
    val syncStatus by vm.syncStatus.collectAsState()
    val isConnected = syncStatus != SyncStatus.ERROR && vm.isActiveConfigured
    val accentColor = Color(vm.globalSettings.accentColor.toLong() and 0xFFFFFFFFL)

    Column(modifier = Modifier.fillMaxSize()) {
        Surface(color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxWidth()) {
            Text(
                if (myAddress != null) "My address: $myAddress"
                else if (!vm.isActiveConfigured) "Not configured"
                else "Connecting...",
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp)
            )
        }

        if (isConnected) {
            // Per-character diff: color changed characters in accent + bold
            val diffTransformation = remember(savedContent, accentColor) {
                ContactsDiffTransformation(savedContent, accentColor)
            }

            BasicTextField(
                value = content,
                onValueChange = onContentChange,
                modifier = Modifier.fillMaxSize().padding(16.dp),
                textStyle = TextStyle(
                    color = MaterialTheme.colorScheme.onBackground,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp, lineHeight = 19.sp
                ),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                visualTransformation = diffTransformation,
            )
        } else {
            SelectionContainer {
                Text(
                    text = content.ifEmpty { "(no contacts)" },
                    modifier = Modifier.fillMaxSize().padding(16.dp),
                    style = TextStyle(
                        color = MaterialTheme.colorScheme.onBackground.copy(alpha = 0.7f),
                        fontFamily = FontFamily.Monospace,
                        fontSize = 13.sp, lineHeight = 19.sp
                    )
                )
            }
        }
    }
}

// ── Contact editor panel ─────────────────────────────────────────────────────

@Composable
private fun ContactEditorPanel(
    existingContacts: String,
    accentColor: Color,
    onSave: (String) -> Unit,
    onCancel: () -> Unit
) {
    var contactName by remember { mutableStateOf("") }
    var ipOctets by remember { mutableStateOf(listOf("", "", "", "")) }
    var port by remember { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    var customFields by remember { mutableStateOf(listOf<Pair<String, String>>()) }
    var errorMessage by remember { mutableStateOf<String?>(null) }

    // Parse existing contact names for duplicate detection
    val existingNames = remember(existingContacts) {
        existingContacts.lines()
            .mapNotNull { line ->
                val dotIdx = line.indexOf('.')
                val eqIdx = line.indexOf('=')
                if (dotIdx > 0 && eqIdx > dotIdx) line.substring(0, dotIdx).trim() else null
            }
            .toSet()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header with cancel/save
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = onCancel) {
                Text("Cancel", color = accentColor)
            }
            Text("New contact", style = MaterialTheme.typography.titleMedium)
            TextButton(onClick = {
                // Validate
                val name = contactName.trim()
                if (name.isEmpty()) { errorMessage = "Name is required"; return@TextButton }
                if (!name.matches(Regex("^[a-zA-Z0-9_-]+$"))) {
                    errorMessage = "Name: letters, numbers, hyphens, underscores only"
                    return@TextButton
                }
                if (name in existingNames) {
                    errorMessage = "Contact '$name' already exists"
                    return@TextButton
                }
                val ip = ipOctets.joinToString(".")
                if (ipOctets.any { it.isEmpty() }) { errorMessage = "IP address is required"; return@TextButton }
                if (port.isEmpty()) { errorMessage = "Port is required"; return@TextButton }
                if (token.isEmpty()) { errorMessage = "Token is required"; return@TextButton }

                // Build aligned contact entry — find longest field name for padding
                val allFields = mutableListOf(
                    "ip" to ip,
                    "port" to port,
                    "token" to "\"$token\""
                )
                for ((fn, fv) in customFields) {
                    if (fn.isNotBlank() && fv.isNotBlank()) {
                        allFields.add(fn to "\"$fv\"")
                    }
                }
                val maxFieldLen = allFields.maxOf { it.first.length }
                val lines = allFields.map { (field, value) ->
                    val padded = field.padEnd(maxFieldLen)
                    "$name.$padded = $value"
                }
                onSave(lines.joinToString("\n"))
            }) { Text("Save", color = accentColor) }
        }

        if (errorMessage != null) {
            Text(errorMessage!!, color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall)
        }

        // Contact name
        Text("Name", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        BasicTextField(
            value = contactName,
            onValueChange = { contactName = it.filter { c -> c.isLetterOrDigit() || c == '-' || c == '_' }; errorMessage = null },
            singleLine = true,
            textStyle = TextStyle(fontSize = 16.sp, color = MaterialTheme.colorScheme.onBackground),
            cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            decorationBox = { inner ->
                Box {
                    if (contactName.isEmpty()) Text("e.g. alice",
                        style = TextStyle(fontSize = 16.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)))
                    inner()
                }
            }
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

        // IP address — 4 octet fields with auto-advance
        Text("IP address", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        IpAddressField(octets = ipOctets, onOctetsChange = { ipOctets = it; errorMessage = null })

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

        // Port
        Text("Port", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        BasicTextField(
            value = port,
            onValueChange = { port = it.filter { c -> c.isDigit() }.take(5); errorMessage = null },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            textStyle = TextStyle(fontSize = 16.sp, color = MaterialTheme.colorScheme.onBackground),
            cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
            decorationBox = { inner ->
                Box {
                    if (port.isEmpty()) Text("e.g. 8025",
                        style = TextStyle(fontSize = 16.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)))
                    inner()
                }
            }
        )

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

        // Token
        Text("Token", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("\"", style = TextStyle(fontSize = 16.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant))
            BasicTextField(
                value = token,
                onValueChange = { token = it.replace("\"", ""); errorMessage = null },
                singleLine = true,
                textStyle = TextStyle(fontSize = 16.sp, color = MaterialTheme.colorScheme.onBackground),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                modifier = Modifier.weight(1f).padding(vertical = 4.dp),
                decorationBox = { inner ->
                    Box {
                        if (token.isEmpty()) Text("e.g. apple-boat-racecar",
                            style = TextStyle(fontSize = 16.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)))
                        inner()
                    }
                }
            )
            Text("\"", style = TextStyle(fontSize = 16.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant))
        }

        HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

        // Custom fields — each entry is a name+value pair sharing one +/- button
        Text("Custom fields", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant)

        customFields.forEachIndexed { index, (fieldName, fieldValue) ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                // Field name and value stacked
                Column(modifier = Modifier.weight(1f)) {
                    BasicTextField(
                        value = fieldName,
                        onValueChange = { v ->
                            val new = customFields.toMutableList()
                            new[index] = v.filter { c -> c.isLetterOrDigit() || c == '_' || c == '-' } to fieldValue
                            customFields = new
                        },
                        singleLine = true,
                        textStyle = TextStyle(fontSize = 14.sp, color = accentColor),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        decorationBox = { inner ->
                            Box {
                                if (fieldName.isEmpty()) Text("field name",
                                    style = TextStyle(fontSize = 14.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)))
                                inner()
                            }
                        }
                    )
                    BasicTextField(
                        value = fieldValue,
                        onValueChange = { v ->
                            val new = customFields.toMutableList()
                            new[index] = fieldName to v
                            customFields = new
                        },
                        singleLine = true,
                        textStyle = TextStyle(fontSize = 14.sp, color = MaterialTheme.colorScheme.onBackground),
                        cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
                        decorationBox = { inner ->
                            Box {
                                if (fieldValue.isEmpty()) Text("value",
                                    style = TextStyle(fontSize = 14.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f)))
                                inner()
                            }
                        }
                    )
                }
                // Single - button removes both the name and value
                IconButton(onClick = {
                    customFields = customFields.filterIndexed { i, _ -> i != index }
                }) {
                    Icon(Icons.Default.Remove, contentDescription = "Remove field")
                }
            }
            if (index < customFields.lastIndex) {
                HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.15f))
            }
        }

        // + button adds a new empty name+value pair
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                if (customFields.isEmpty()) "None" else "Add another",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = {
                customFields = customFields + ("" to "")
            }) {
                Icon(Icons.Default.Add, contentDescription = "Add custom field")
            }
        }
    }
}

// ── IP address field (4 octets with auto-advance) ───────────────────────────

@Composable
private fun IpAddressField(
    octets: List<String>,
    onOctetsChange: (List<String>) -> Unit
) {
    val focusRequesters = remember { List(4) { androidx.compose.ui.focus.FocusRequester() } }

    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        for (i in 0..3) {
            BasicTextField(
                value = octets[i],
                onValueChange = { v ->
                    val filtered = v.filter { it.isDigit() }.take(3)
                    val new = octets.toMutableList()
                    new[i] = filtered
                    onOctetsChange(new)
                    if (filtered.length == 3 && i < 3) {
                        focusRequesters[i + 1].requestFocus()
                    }
                    if ('.' in v && i < 3) {
                        focusRequesters[i + 1].requestFocus()
                    }
                },
                singleLine = true,
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Number,
                    imeAction = if (i < 3) ImeAction.Next else ImeAction.Done
                ),
                keyboardActions = KeyboardActions(
                    onNext = { if (i < 3) focusRequesters[i + 1].requestFocus() }
                ),
                textStyle = TextStyle(fontSize = 16.sp, color = MaterialTheme.colorScheme.onBackground,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center),
                cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
                modifier = Modifier
                    .weight(1f)
                    .background(
                        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                        RoundedCornerShape(4.dp)
                    )
                    .padding(vertical = 8.dp, horizontal = 4.dp)
                    .focusRequester(focusRequesters[i]),
                decorationBox = { inner ->
                    Box(contentAlignment = Alignment.Center) {
                        if (octets[i].isEmpty()) Text(
                            when (i) { 0 -> "192"; 1 -> "168"; 2 -> "0"; else -> "1" },
                            style = TextStyle(fontSize = 16.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.25f),
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center)
                        )
                        inner()
                    }
                }
            )
            if (i < 3) {
                Text(".", style = TextStyle(fontSize = 20.sp, fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurfaceVariant))
            }
        }
    }
}

// ── Settings panel ──────────────────────────────────────────────────────────

@Composable
private fun SettingsPanel(
    vm: MainViewModel,
    onModified: () -> Unit,
    onSaved: () -> Unit,
    onDeleteMailbox: () -> Unit
) {
    val activeConfig = vm.activeMailboxId.collectAsState().value?.let { vm.registry.get(it) }
    var host by remember(activeConfig) { mutableStateOf(activeConfig?.host ?: "") }
    var port by remember(activeConfig) { mutableStateOf(activeConfig?.port?.toString() ?: "8025") }
    var token by remember(activeConfig) { mutableStateOf(activeConfig?.token ?: "") }
    var swipeToDelete by remember(activeConfig) { mutableStateOf(activeConfig?.swipeToDelete ?: true) }
    var bgSyncInterval by remember(activeConfig) { mutableStateOf(activeConfig?.bgSyncIntervalMinutes?.toString() ?: "15") }
    var notifDetail by remember(activeConfig) { mutableStateOf(activeConfig?.notificationDetail ?: "full") }
    var bgColor by remember { mutableStateOf(Color(vm.globalSettings.bgColor.toLong() and 0xFFFFFFFFL)) }
    var fgColor by remember { mutableStateOf(Color(vm.globalSettings.fgColor.toLong() and 0xFFFFFFFFL)) }
    var accentColor by remember { mutableStateOf(Color(vm.globalSettings.accentColor.toLong() and 0xFFFFFFFFL)) }

    fun markModified() { onModified() }

    // The ActionBar calls this via the settings save callback
    // We expose it by saving when the action bar's save is triggered
    // This is done by making the settings panel save on recomposition when onSaved triggers
    // Actually, let's use a LaunchedEffect approach — but simpler: the ActionBar in the parent
    // needs to call save. Let's use a side-channel.

    // Save function exposed to parent
    val saveSettings = {
        if (activeConfig != null) {
            vm.updateMailbox(activeConfig.copy(
                host = host.trim(), port = port.toIntOrNull() ?: 8025,
                token = token.trim(), swipeToDelete = swipeToDelete,
                bgSyncIntervalMinutes = bgSyncInterval.toIntOrNull() ?: 15,
                notificationDetail = notifDetail
            ))
        }
        vm.globalSettings.bgColor = bgColor.toArgb()
        vm.globalSettings.fgColor = fgColor.toArgb()
        vm.globalSettings.accentColor = accentColor.toArgb()
        vm.onSettingsSaved()
        onSaved()
    }

    val clearSettings = {
        host = activeConfig?.host ?: ""
        port = activeConfig?.port?.toString() ?: "8025"
        token = activeConfig?.token ?: ""
        swipeToDelete = activeConfig?.swipeToDelete ?: true
        bgSyncInterval = activeConfig?.bgSyncIntervalMinutes?.toString() ?: "15"
        notifDetail = activeConfig?.notificationDetail ?: "full"
        bgColor = Color(vm.globalSettings.bgColor.toLong() and 0xFFFFFFFFL)
        fgColor = Color(vm.globalSettings.fgColor.toLong() and 0xFFFFFFFFL)
        accentColor = Color(vm.globalSettings.accentColor.toLong() and 0xFFFFFFFFL)
    }

    DisposableEffect(Unit) {
        settingsSaveFn = saveSettings
        settingsClearFn = clearSettings
        onDispose { settingsSaveFn = null; settingsClearFn = null }
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(16.dp).verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        if (activeConfig != null) {
            Text("Connection", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            OutlinedTextField(value = host, onValueChange = { host = it; markModified() },
                label = { Text("Server address") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = port, onValueChange = { port = it.filter { c -> c.isDigit() }; markModified() },
                label = { Text("Port") }, singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(value = token, onValueChange = { token = it.replace("\"", ""); markModified() },
                label = { Text("Device token") }, singleLine = true,
                prefix = { Text("\"") }, suffix = { Text("\"") }, modifier = Modifier.fillMaxWidth())

            Spacer(Modifier.height(4.dp))
            Text("Behavior", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text("Swipe to delete", modifier = Modifier.weight(1f))
                Switch(checked = swipeToDelete, onCheckedChange = { swipeToDelete = it; markModified() })
            }
            OutlinedTextField(value = bgSyncInterval,
                onValueChange = { bgSyncInterval = it.filter { c -> c.isDigit() }; markModified() },
                label = { Text("Background sync (min 15 minutes)") }, singleLine = true, modifier = Modifier.fillMaxWidth())

            Spacer(Modifier.height(4.dp))
            Text("Notifications", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
            listOf("full" to "Sender + subject", "sender" to "Sender only", "none" to "No preview", "off" to "No notifications")
                .forEach { (value, label) ->
                    Row(Modifier.fillMaxWidth().clickable { notifDetail = value; markModified() }
                        .padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = notifDetail == value, onClick = { notifDetail = value; markModified() })
                        Text(label, modifier = Modifier.padding(start = 8.dp))
                    }
                }
        }

        Spacer(Modifier.height(4.dp))
        Text("Appearance", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
        ColorField("Background color", bgColor) { bgColor = it; markModified() }
        ColorField("Text color", fgColor) { fgColor = it; markModified() }
        ColorField("Accent color", accentColor) { accentColor = it; markModified() }

        // #357: destructive action — delete the mailbox from this device.
        // Placed at the very bottom and wrapped in a confirmation dialog
        // that enumerates unsynced items so the user knows what (if
        // anything) they'd lose by disconnecting now.
        if (activeConfig != null) {
            Spacer(Modifier.height(16.dp))
            Text("Danger zone", style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.error)
            var showDeleteDialog by remember { mutableStateOf(false) }
            OutlinedButton(
                onClick = { showDeleteDialog = true },
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                ),
                border = androidx.compose.foundation.BorderStroke(
                    1.dp, MaterialTheme.colorScheme.error
                ),
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Delete mailbox")
            }
            if (showDeleteDialog) {
                val unsynced = remember { vm.unsyncedSummary() }
                AlertDialog(
                    onDismissRequest = { showDeleteDialog = false },
                    title = { Text("Delete this mailbox?") },
                    text = {
                        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                            Text("This will permanently sever your connection " +
                                "to your mailbox from this device. It will not " +
                                "delete anything on the home server.")
                            if (unsynced.isEmpty()) {
                                Text("Your mailbox files are safe on the home " +
                                    "server.",
                                    style = MaterialTheme.typography.bodyMedium)
                            } else {
                                Text("Your mailbox files should be safe on the " +
                                    "home server, unless they haven't synced " +
                                    "yet. Here are the files that haven't " +
                                    "synced yet:",
                                    style = MaterialTheme.typography.bodyMedium)
                                Column(
                                    modifier = Modifier.padding(start = 8.dp),
                                    verticalArrangement = Arrangement.spacedBy(2.dp)
                                ) {
                                    unsynced.forEach {
                                        Text("  $it",
                                            style = MaterialTheme.typography.bodySmall)
                                    }
                                }
                            }
                        }
                    },
                    confirmButton = {
                        TextButton(
                            onClick = {
                                showDeleteDialog = false
                                onDeleteMailbox()
                            },
                            colors = ButtonDefaults.textButtonColors(
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) { Text("Delete") }
                    },
                    dismissButton = {
                        TextButton(onClick = { showDeleteDialog = false }) {
                            Text("Cancel")
                        }
                    }
                )
            }
        }
    }
}

@Composable
private fun ColorField(label: String, color: Color, onChange: (Color) -> Unit) {
    var hex by remember(color) { mutableStateOf("%06X".format(color.toArgb() and 0xFFFFFF)) }
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        Box(Modifier.size(32.dp).background(color))
        OutlinedTextField(
            value = hex,
            onValueChange = { v ->
                hex = v.filter { it.isLetterOrDigit() }.take(6).uppercase()
                if (hex.length == 6) onChange(Color(0xFF000000.toInt() or hex.toInt(16)))
            },
            label = { Text(label) }, prefix = { Text("#") },
            singleLine = true, modifier = Modifier.weight(1f)
        )
    }
}

// ── Compose panel ───────────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ComposePanel(
    vm: MainViewModel,
    recipients: List<String>,
    onRecipientsChange: (List<String>) -> Unit,
    attachments: MutableList<AttachmentEntry>,
    filePicker: () -> Unit,
    dirPicker: () -> Unit,
    subject: String,
    onSubjectChange: (String) -> Unit,
    body: String,
    onBodyChange: (String) -> Unit
) {
    val daemonName by vm.daemonName.collectAsState()
    val contactNames = remember(daemonName) {
        val names = vm.getContactNames().toMutableList()
        if (daemonName != null && daemonName !in names) names.add(0, daemonName!!)
        names
    }
    val scrollState = rememberScrollState()
    val coroutineScope = rememberCoroutineScope()

    Column(modifier = Modifier.fillMaxSize().verticalScroll(scrollState)) {
        // Recipients
        Text("To", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 4.dp))
        recipients.forEachIndexed { index, selected ->
            Row(verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
                ContactPicker(contactNames, selected, {
                    val new = recipients.toMutableList(); new[index] = it; onRecipientsChange(new)
                }, Modifier.weight(1f))
                if (index == recipients.lastIndex) {
                    IconButton(onClick = { onRecipientsChange(recipients + "") }) {
                        Icon(Icons.Default.Add, contentDescription = "Add")
                    }
                } else {
                    IconButton(onClick = { onRecipientsChange(recipients.filterIndexed { i, _ -> i != index }) }) {
                        Icon(Icons.Default.Remove, contentDescription = "Remove")
                    }
                }
            }
        }

        Spacer(Modifier.height(4.dp))

        // Attachments
        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp),
            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))
        Text("Attachments", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 16.dp, top = 4.dp, bottom = 4.dp))
        attachments.forEachIndexed { index, entry ->
            Row(verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp, vertical = 2.dp)) {
                // Image thumbnail or file type icon
                val isImage = entry.mimeType?.startsWith("image") == true ||
                    entry.displayName.lowercase().let {
                        it.endsWith(".jpg") || it.endsWith(".jpeg") || it.endsWith(".png") ||
                        it.endsWith(".gif") || it.endsWith(".webp") || it.endsWith(".bmp")
                    }
                val uriStr = entry.uri.toString()
                if (isImage && (uriStr.startsWith("file://") || uriStr.startsWith("content://"))) {
                    // Try loading thumbnail from URI
                    val ctx = LocalContext.current
                    var bitmap by remember(entry.uri) {
                        mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null)
                    }
                    LaunchedEffect(entry.uri) {
                        bitmap = kotlinx.coroutines.withContext(Dispatchers.IO) {
                            try {
                                if (uriStr.startsWith("file://")) {
                                    val file = java.io.File(entry.uri.path!!)
                                    android.graphics.BitmapFactory.decodeFile(
                                        file.absolutePath,
                                        android.graphics.BitmapFactory.Options().apply { inSampleSize = 8 }
                                    )?.asImageBitmap()
                                } else {
                                    ctx.contentResolver.openInputStream(entry.uri)?.use { stream ->
                                        android.graphics.BitmapFactory.decodeStream(
                                            stream, null,
                                            android.graphics.BitmapFactory.Options().apply { inSampleSize = 8 }
                                        )?.asImageBitmap()
                                    }
                                }
                            } catch (_: Exception) { null }
                        }
                    }
                    if (bitmap != null) {
                        Image(bitmap!!, null, Modifier.size(36.dp).padding(end = 4.dp),
                            contentScale = ContentScale.Crop)
                    } else {
                        Icon(Icons.Default.Image, null, Modifier.size(24.dp).padding(end = 4.dp))
                    }
                } else {
                    val ext = entry.displayName.substringAfterLast('.', "").lowercase()
                    Icon(when {
                        isImage -> Icons.Default.Image
                        ext in listOf("mp4", "mkv", "avi", "mov", "webm") -> Icons.Default.PlayCircle
                        ext in listOf("mp3", "wav", "ogg", "flac", "aac") -> Icons.Default.AudioFile
                        ext in listOf("txt", "md", "log", "csv", "json") -> Icons.AutoMirrored.Filled.TextSnippet
                        else -> Icons.Default.AttachFile
                    }, null, Modifier.size(24.dp).padding(end = 4.dp))
                }
                Column(Modifier.weight(1f).padding(start = 4.dp)) {
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
        Row(verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
            Text(if (attachments.isEmpty()) "None" else "Add another",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.weight(1f).padding(start = 8.dp))
            IconButton(onClick = dirPicker) { Icon(Icons.Default.Folder, contentDescription = "Attach folder") }
            IconButton(onClick = filePicker) { Icon(Icons.Default.Add, contentDescription = "Attach file") }
        }

        // Subject
        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp),
            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))
        Text("Subject", style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = 16.dp, bottom = 4.dp))
        BasicTextField(
            value = subject, onValueChange = onSubjectChange,
            singleLine = true,
            textStyle = TextStyle(fontSize = 14.sp,
                color = MaterialTheme.colorScheme.onBackground),
            cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 4.dp),
            decorationBox = { inner ->
                Box {
                    if (subject.isEmpty()) Text("Optional",
                        style = TextStyle(fontSize = 14.sp,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)))
                    inner()
                }
            }
        )

        var bodyYOffset by remember { mutableIntStateOf(0) }
        HorizontalDivider(
            modifier = Modifier.padding(top = 8.dp)
                .onGloballyPositioned { bodyYOffset = it.positionInParent().y.toInt() },
            thickness = 1.5.dp,
            color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))

        // Body
        BasicTextField(
            value = body, onValueChange = onBodyChange,
            modifier = Modifier.fillMaxWidth().defaultMinSize(minHeight = 300.dp).padding(16.dp)
                .onFocusChanged { focus ->
                    if (focus.isFocused) coroutineScope.launch { scrollState.animateScrollTo(bodyYOffset) }
                },
            textStyle = TextStyle(color = MaterialTheme.colorScheme.onBackground,
                fontFamily = FontFamily.Monospace, fontSize = 14.sp, lineHeight = 20.sp),
            cursorBrush = SolidColor(MaterialTheme.colorScheme.primary),
            decorationBox = { innerTextField ->
                Box {
                    if (body.isEmpty()) Text("Message", style = TextStyle(
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f),
                        fontFamily = FontFamily.Monospace, fontSize = 14.sp))
                    innerTextField()
                }
            }
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ContactPicker(
    contacts: List<String>, selected: String,
    onSelect: (String) -> Unit, modifier: Modifier = Modifier
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }, modifier = modifier) {
        OutlinedTextField(
            value = selected, onValueChange = {}, readOnly = true,
            placeholder = { Text("Select contact", fontSize = 14.sp) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
            singleLine = true, textStyle = TextStyle(fontSize = 14.sp),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            if (contacts.isEmpty()) {
                DropdownMenuItem(text = { Text("No contacts",
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)) },
                    onClick = { expanded = false }, enabled = false)
            } else {
                contacts.forEach { name ->
                    DropdownMenuItem(text = { Text(name) },
                        onClick = { onSelect(name); expanded = false })
                }
            }
        }
    }
}

private fun resolveDisplayName(context: android.content.Context, uri: Uri): String? {
    return try {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { if (it.moveToFirst()) it.getString(0) else null }
    } catch (_: Exception) { null }
}

private fun sanitizeFilename(name: String): String {
    if (name.isBlank()) return "untitled"
    var s = name.substringAfterLast('/').substringAfterLast('\\').trimStart('.')
    s = s.replace(Regex("[\\x00-\\x1f/\\\\]"), "_")
    s = s.replace(' ', '-')
    return s.ifBlank { "untitled" }
}

// ── Image thumbnail from file ────────────────────────────────────────────────

@Composable
private fun AttachmentThumbnail(file: File, modifier: Modifier = Modifier) {
    var bitmap by remember(file.absolutePath) { mutableStateOf<androidx.compose.ui.graphics.ImageBitmap?>(null) }
    LaunchedEffect(file.absolutePath) {
        bitmap = kotlinx.coroutines.withContext(Dispatchers.IO) {
            try {
                val options = android.graphics.BitmapFactory.Options().apply { inSampleSize = 8 }
                android.graphics.BitmapFactory.decodeFile(file.absolutePath, options)
                    ?.asImageBitmap()
            } catch (_: Exception) { null }
        }
    }
    if (bitmap != null) {
        Image(bitmap!!, contentDescription = null, modifier = modifier,
            contentScale = ContentScale.Crop)
    } else {
        Icon(Icons.Default.Image, null, modifier)
    }
}

// ── Contacts diff visual transformation ─────────────────────────────────────

/**
 * Per-line, per-word diff. Each line is compared against its corresponding saved
 * line by splitting into whitespace-delimited tokens. Only words that differ are
 * highlighted. If the line itself is entirely new (no saved counterpart), the
 * whole line is highlighted.
 * Uses FontWeight.W600 (semibold) to avoid changing line spacing.
 */
private class ContactsDiffTransformation(
    private val saved: String,
    private val accentColor: Color
) : VisualTransformation {
    private val savedLines = saved.lines()
    private val accentStyle = SpanStyle(color = accentColor, fontWeight = FontWeight.W600)

    override fun filter(text: AnnotatedString): TransformedText {
        val current = text.text
        val currentLines = current.lines()
        val annotated = buildAnnotatedString {
            append(current)
            var offset = 0
            for (lineIdx in currentLines.indices) {
                val curLine = currentLines[lineIdx]
                val savLine = savedLines.getOrNull(lineIdx)
                if (curLine != savLine) {
                    if (savLine == null) {
                        if (curLine.isNotEmpty()) addStyle(accentStyle, offset, offset + curLine.length)
                    } else {
                        val curWords = tokenize(curLine)
                        val savWords = tokenize(savLine)
                        // Find which current words are NOT in the longest common subsequence
                        val matched = lcsMatchedIndices(curWords.map { it.first }, savWords.map { it.first })
                        for (i in curWords.indices) {
                            if (i !in matched) {
                                val (_, start, end) = curWords[i]
                                addStyle(accentStyle, offset + start, offset + end)
                            }
                        }
                    }
                }
                offset += curLine.length + 1
            }
        }
        return TransformedText(annotated, OffsetMapping.Identity)
    }

    /**
     * Returns the set of indices in `current` that are part of the longest
     * common subsequence with `saved`. Words at these indices are unchanged.
     */
    private fun lcsMatchedIndices(current: List<String>, saved: List<String>): Set<Int> {
        val m = current.size
        val n = saved.size
        // Build LCS table
        val dp = Array(m + 1) { IntArray(n + 1) }
        for (i in m - 1 downTo 0) {
            for (j in n - 1 downTo 0) {
                dp[i][j] = if (current[i] == saved[j]) dp[i + 1][j + 1] + 1
                           else maxOf(dp[i + 1][j], dp[i][j + 1])
            }
        }
        // Backtrack to find which current indices are matched
        val matched = mutableSetOf<Int>()
        var i = 0; var j = 0
        while (i < m && j < n) {
            if (current[i] == saved[j]) {
                matched.add(i)
                i++; j++
            } else if (dp[i + 1][j] >= dp[i][j + 1]) {
                i++
            } else {
                j++
            }
        }
        return matched
    }

    private fun isSeparator(c: Char) = c.isWhitespace() || c == '.' || c == '-' || c == '_'

    /** Split a line into (word, startIndex, endIndex) triples, treating
     *  whitespace, dots, dashes, and underscores as word boundaries. */
    private fun tokenize(line: String): List<Triple<String, Int, Int>> {
        val tokens = mutableListOf<Triple<String, Int, Int>>()
        var i = 0
        while (i < line.length) {
            while (i < line.length && isSeparator(line[i])) i++
            if (i >= line.length) break
            val start = i
            while (i < line.length && !isSeparator(line[i])) i++
            tokens.add(Triple(line.substring(start, i), start, i))
        }
        return tokens
    }
}

// ── Message list ────────────────────────────────────────────────────────────

@Composable
private fun MessageList(
    files: List<String>, emptyText: String, swipeToDelete: Boolean,
    onDelete: (String) -> Unit, onClick: (String) -> Unit
) {
    if (files.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text(emptyText, color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
    } else {
        LazyColumn {
            items(files, key = { it }) { filename ->
                if (swipeToDelete) {
                    SwipeToDismissMessageItem(filename, { onDelete(filename) }, { onClick(filename) })
                } else {
                    MessageListItem(filename, { onClick(filename) })
                }
                HorizontalDivider(thickness = 0.5.dp)
            }
        }
    }
}

// ── Attachment list ─────────────────────────────────────────────────────────

@Composable
private fun AttachmentList(
    vm: MainViewModel,
    attachments: List<AttachmentInfo>,
    selectionMode: Boolean,
    selectedFiles: MutableList<String>,
    onDeleteServer: (List<String>) -> Unit,
    onDeleteDevice: (List<String>) -> Unit,
    onForward: (List<String>) -> Unit
) {
    val context = LocalContext.current
    val downloadProgress by vm.downloadProgress.collectAsState()
    val deletingFiles by vm.deletingFiles.collectAsState()
    val accentColor = Color(vm.globalSettings.accentColor.toLong() and 0xFFFFFFFFL)
    val activeId by vm.activeMailboxId.collectAsState()
    val config = activeId?.let { vm.registry.get(it) }
    val daemonLabel = config?.name?.ifBlank { null } ?: config?.host ?: "server"

    Column(Modifier.fillMaxSize()) {
        // Delete action bar (when in delete selection mode with selections)
        if (selectionMode && selectedFiles.isNotEmpty()) {
            // Handled by parent via action bar
        }

        if (attachments.isEmpty()) {
            Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                Text("No files",
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(attachments, key = { it.filename }) { info ->
                    val progress = downloadProgress[info.filename]
                    val isSelected = info.filename in selectedFiles
                    val isDeleting = info.filename in deletingFiles

                    Column {
                        Row(Modifier.fillMaxWidth()
                            .then(if (isSelected) Modifier.background(
                                accentColor.copy(alpha = 0.1f)) else Modifier)
                            .clickable {
                                if (selectionMode) {
                                    if (isSelected) selectedFiles.remove(info.filename)
                                    else selectedFiles.add(info.filename)
                                } else if (info.onDevice) {
                                    val file = vm.store?.cachedAttachmentFile(info.filename)
                                        ?: return@clickable
                                    if (file.exists()) openFile(context, file)
                                } else if (info.onServer && progress == null) {
                                    vm.downloadAttachment(info) { file ->
                                        if (file != null) openFile(context, file)
                                    }
                                }
                            }
                            .padding(horizontal = 16.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // File type icon, image thumbnail, or checkbox
                            if (selectionMode) {
                                Checkbox(
                                    checked = isSelected,
                                    onCheckedChange = {
                                        if (it) selectedFiles.add(info.filename)
                                        else selectedFiles.remove(info.filename)
                                    },
                                    modifier = Modifier.size(36.dp)
                                )
                            } else if (info.category == "image" && info.onDevice) {
                                // Image thumbnail from cached file
                                val cachedFile = vm.store?.cachedAttachmentFile(info.filename)
                                if (cachedFile != null && cachedFile.exists()) {
                                    AttachmentThumbnail(cachedFile, Modifier.size(36.dp))
                                } else {
                                    Icon(Icons.Default.Image, null, Modifier.size(24.dp))
                                }
                            } else {
                                Icon(when (info.category) {
                                    "image" -> Icons.Default.Image
                                    "video" -> Icons.Default.PlayCircle
                                    "audio" -> Icons.Default.AudioFile
                                    "text" -> Icons.AutoMirrored.Filled.TextSnippet
                                    else -> Icons.Default.AttachFile
                                }, null, Modifier.size(24.dp))
                            }
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)) {
                                Text(info.filename, style = MaterialTheme.typography.bodyMedium)
                                if (progress != null) {
                                    Text("${formatSize(progress.first)} / ${formatSize(progress.second)}",
                                        style = MaterialTheme.typography.bodySmall, color = accentColor)
                                } else {
                                    Text(formatSize(info.size),
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                                }
                                // Presence info
                                val locations = mutableListOf<String>()
                                if (info.onServer) locations.add(daemonLabel)
                                if (info.onDevice) locations.add("android")
                                Text("Present on: ${locations.joinToString(", ")}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f))
                            }
                            when {
                                isDeleting -> CircularProgressIndicator(
                                    modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                                progress != null -> {
                                    IconButton(onClick = { vm.cancelDownload(info.filename) }) {
                                        Icon(Icons.Default.Close, "Cancel",
                                            tint = MaterialTheme.colorScheme.error,
                                            modifier = Modifier.size(20.dp))
                                    }
                                }
                                info.onDevice -> Icon(Icons.Default.CheckCircle, "On device",
                                    tint = MaterialTheme.colorScheme.primary,
                                    modifier = Modifier.size(20.dp))
                                info.onServer -> Icon(Icons.Default.Download, "Download",
                                    modifier = Modifier.size(20.dp))
                            }
                        }
                        if (progress != null && progress.second > 0) {
                            LinearProgressIndicator(
                                progress = { (progress.first.toFloat() / progress.second).coerceIn(0f, 1f) },
                                modifier = Modifier.fillMaxWidth().height(3.dp),
                                color = accentColor,
                                trackColor = accentColor.copy(alpha = 0.15f)
                            )
                        }
                    }
                    HorizontalDivider(thickness = 0.5.dp)
                }
            }
        }
    }
}

/**
 * Open a file using ACTION_VIEW. Android remembers the user's app choice per
 * mime type via the system chooser's "Always" option.
 */
private fun openFile(context: android.content.Context, file: File) {
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
    val mime = context.contentResolver.getType(uri) ?: "*/*"
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, mime)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
    // ACTION_VIEW with a specific mime type lets Android use the user's default app
    // if they've set one (e.g. gallery for images). No chooser is shown in that case.
    try {
        context.startActivity(intent)
    } catch (_: Exception) {
        // No app can handle this type — fall back to chooser
        context.startActivity(Intent.createChooser(intent, "Open with"))
    }
}

private fun formatSize(bytes: Long): String = when {
    bytes < 1024 -> "$bytes B"
    bytes < 1024 * 1024 -> "${bytes / 1024} KB"
    else -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
}

@Composable
private fun MessageListItem(filename: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().clickable(onClick = onClick)
        .padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(filename, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
        Icon(Icons.Default.ChevronRight, null, tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SwipeToDismissMessageItem(filename: String, onDelete: () -> Unit, onClick: () -> Unit) {
    val dismissState = rememberSwipeToDismissBoxState(
        confirmValueChange = { if (it == SwipeToDismissBoxValue.EndToStart) { onDelete(); true } else false }
    )
    SwipeToDismissBox(state = dismissState, backgroundContent = {
        val color by animateColorAsState(
            if (dismissState.targetValue == SwipeToDismissBoxValue.EndToStart)
                MaterialTheme.colorScheme.error else Color.Transparent, label = "swipe_bg")
        Box(Modifier.fillMaxSize().background(color), contentAlignment = Alignment.CenterEnd) {
            Icon(Icons.Default.Delete, "Delete", Modifier.padding(end = 16.dp), tint = MaterialTheme.colorScheme.onError)
        }
    }) {
        Surface(color = MaterialTheme.colorScheme.background) { MessageListItem(filename, onClick) }
    }
}

// ── #322 Sending progress bar ──────────────────────────────────────────────
//
// Green bar slides in when the user hits Send.  A row of 15 dots empties
// out left-to-right (randomised among positions 0..11) at 5 dots/sec,
// ~2.4 s total.  The rightmost 3 dots stay visible while sync is still
// running.  When syncStatus reports done, the last 3 slide off the
// right edge and the text settles on "sent" (success) or "ready"
// (failure — message queued locally, will retry).  Bar auto-dismisses
// 1.5 s after the final text appears so it doesn't pile up on repeat
// sends.
@Composable
private fun SendingProgressBar(vm: MainViewModel) {
    val bar by vm.sendingBar.collectAsState()
    val syncStatus by vm.syncStatus.collectAsState()
    val b = bar ?: return

    val totalDots = 15
    val safeTail = 3  // last N dots reserved for the "still working" hold
    val tickMs = 200L

    // Ticks ~5 times per second, driving both the countdown state and
    // the final-slide timing.
    var tick by remember(b.startedAtMs) { mutableStateOf(0) }
    LaunchedEffect(b.startedAtMs) {
        while (true) {
            kotlinx.coroutines.delay(tickMs)
            tick += 1
        }
    }

    // Which dots have been hidden so far.  Picked randomly from the
    // first (totalDots - safeTail) positions each tick until that pool
    // is exhausted; after that we wait for the sync to settle.
    val hidden = remember(b.startedAtMs) { mutableStateListOf<Int>() }
    LaunchedEffect(tick) {
        if (hidden.size < totalDots - safeTail) {
            val candidates = (0 until totalDots - safeTail).filter { it !in hidden }
            if (candidates.isNotEmpty()) hidden.add(candidates.random())
        }
    }

    val countdownDone = hidden.size >= totalDots - safeTail
    val syncSettled = syncStatus == SyncStatus.IDLE ||
                      syncStatus == SyncStatus.ERROR
    val finalPhase = countdownDone && syncSettled
    val text = when {
        !finalPhase -> "sending…"
        syncStatus == SyncStatus.ERROR -> "ready"
        else -> "sent"
    }

    // Auto-dismiss 1.5 s after we've settled (unless it's "ready" —
    // keep that visible so the user knows the message is queued
    // locally).
    LaunchedEffect(finalPhase, syncStatus) {
        if (finalPhase && syncStatus != SyncStatus.ERROR) {
            kotlinx.coroutines.delay(1500)
            vm.clearSendingBar()
        }
    }

    Surface(color = Color(0xFF2E7D32), modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text,
                color = Color.White,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(end = 12.dp).widthIn(min = 64.dp)
            )
            Row(
                modifier = Modifier.weight(1f).clipToBounds(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                for (i in 0 until totalDots) {
                    val isTail = i >= totalDots - safeTail
                    // During the countdown, non-tail dots disappear
                    // (alpha fades out) as their index is added to
                    // `hidden`; tail dots stay lit.  In the final
                    // phase, tail dots physically slide off the right
                    // edge (kept at alpha 1 so the exit is visible),
                    // while the already-hidden non-tail dots just stay
                    // invisible.
                    val visible = isTail || i !in hidden
                    val slideOff = finalPhase && isTail
                    val offset by animateDpAsState(
                        targetValue = if (slideOff) 240.dp else 0.dp,
                        animationSpec = tween(
                            durationMillis = 550,
                            delayMillis = (i - (totalDots - safeTail)).coerceAtLeast(0) * 120
                        ),
                        label = "dot-slide"
                    )
                    val alpha by animateFloatAsState(
                        targetValue = if (visible) 1f else 0f,
                        animationSpec = tween(durationMillis = 150),
                        label = "dot-alpha"
                    )
                    Box(
                        Modifier
                            .size(6.dp)
                            .offset(x = offset)
                            .graphicsLayer { this.alpha = alpha }
                            .background(Color.White, androidx.compose.foundation.shape.CircleShape)
                    )
                }
            }
        }
    }
}
