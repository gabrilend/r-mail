package com.rmail.app.ui.screens

import android.content.Intent
import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.positionInParent
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.graphics.Color
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
import kotlinx.coroutines.launch
import java.io.File

private enum class Panel { INBOX, OUTBOX, FILES, CONTACTS, SETTINGS, WRITE }

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
    Panel.CONTACTS to Color(0xFFE91E63),    // pink
    Panel.SETTINGS to Color(0xFF9C27B0),    // purple
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

    // Contacts state
    var contactsContent by remember { mutableStateOf(vm.readContacts()) }
    val savedContacts = remember { mutableStateOf(vm.readContacts()) }
    var contactsModified by remember { mutableStateOf(false) }

    // Settings modified tracking
    var settingsModified by remember { mutableStateOf(false) }

    val context = LocalContext.current

    // File picker for compose attachments
    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        if (uri != null) {
            val name = resolveDisplayName(context, uri) ?: uri.lastPathSegment ?: "attachment"
            val mime = try { context.contentResolver.getType(uri) } catch (_: Exception) { null }
            draftAttachments.add(AttachmentEntry(uri, name, mime))
        }
    }

    val isKeyboardOpen = rememberKeyboardOpen()

    LaunchedEffect(Unit) { vm.refreshLocal() }
    LaunchedEffect(currentPanel) {
        if (currentPanel == Panel.FILES) vm.loadAttachmentList()
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
                    when (syncStatus) {
                        SyncStatus.SYNCING -> CircularProgressIndicator(
                            modifier = Modifier.size(24.dp).padding(end = 8.dp),
                            strokeWidth = 2.dp
                        )
                        SyncStatus.ERROR -> IconButton(onClick = { vm.triggerSync() }) {
                            Icon(Icons.Default.Warning, contentDescription = "Sync error")
                        }
                        SyncStatus.IDLE -> IconButton(onClick = { vm.triggerSync() }) {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                        }
                    }
                    if (currentPanel == Panel.WRITE) {
                        // New (clear) button
                        IconButton(onClick = {
                            draftRecipients = listOf("")
                            draftAttachments.clear()
                            draftSubject = ""
                            draftBody = ""
                        }) {
                            Icon(Icons.Default.Add, contentDescription = "New message")
                        }
                        // Send button
                        IconButton(onClick = {
                            val validRecipients = draftRecipients.filter { it.isNotBlank() }
                            if (validRecipients.isEmpty()) return@IconButton
                            val filename = if (draftSubject.isNotBlank())
                                sanitizeFilename(draftSubject) else vm.newOutboxFilename()
                            val localPaths = draftAttachments.map { it.uri.toString() }
                            val sb = StringBuilder()
                            for (r in validRecipients) sb.appendLine("to: $r")
                            for (p in localPaths) sb.appendLine("attach: $p")
                            sb.appendLine()
                            sb.append(draftBody)
                            vm.saveOutboxFile(filename, sb.toString())
                            vm.uploadAttachmentsInBackground(filename, draftAttachments.map { it.uri })
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
                // Horizontal separator between rows
                HorizontalDivider(thickness = gridWidth, color = gridColor)
                // Top row
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
                // Horizontal separator
                HorizontalDivider(thickness = gridWidth, color = gridColor)
                // Bottom row — corner buttons get rounded corners for curved screens
                val cornerRadius = 16.dp
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
            // Action bar: clear/save for contacts or settings (hidden when keyboard is open)
            if (!isKeyboardOpen) {
                val showContactsActions = currentPanel == Panel.CONTACTS && contactsModified &&
                    syncStatus != SyncStatus.ERROR && vm.isActiveConfigured
                if (showContactsActions) {
                    ActionBar(
                        onClear = { contactsContent = savedContacts.value; contactsModified = false },
                        onSave = {
                            vm.saveContacts(contactsContent)
                            savedContacts.value = contactsContent
                            contactsModified = false
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
                Panel.FILES -> AttachmentList(vm, attachments)
                Panel.CONTACTS -> ContactsPanel(
                    vm = vm,
                    content = contactsContent,
                    savedContent = savedContacts.value,
                    onContentChange = { contactsContent = it; contactsModified = true }
                )
                Panel.SETTINGS -> SettingsPanel(vm,
                    onModified = { settingsModified = true },
                    onSaved = { settingsModified = false })
                Panel.WRITE -> ComposePanel(
                    vm = vm,
                    recipients = draftRecipients,
                    onRecipientsChange = { draftRecipients = it },
                    attachments = draftAttachments,
                    filePicker = { filePicker.launch("*/*") },
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
            color = if (selected) Color.Black else color
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
                    color = MaterialTheme.colorScheme.onErrorContainer)
            }
        }
        Surface(
            color = MaterialTheme.colorScheme.primaryContainer,
            modifier = Modifier.weight(1f).clickable { dismissAndRun(onSave) }
        ) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.padding(vertical = 10.dp)) {
                Text("Save changes", fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onPrimaryContainer)
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

// ── Settings panel ──────────────────────────────────────────────────────────

@Composable
private fun SettingsPanel(vm: MainViewModel, onModified: () -> Unit, onSaved: () -> Unit) {
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
            listOf("full" to "Sender + subject", "sender" to "Sender only", "none" to "No preview")
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
        Row(verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth().padding(horizontal = 8.dp)) {
            Text(if (attachments.isEmpty()) "None" else "Add another",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                modifier = Modifier.weight(1f).padding(start = 8.dp))
            IconButton(onClick = filePicker) { Icon(Icons.Default.Add, contentDescription = "Attach") }
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
    return s.ifBlank { "untitled" }
}

// ── Contacts diff visual transformation ─────────────────────────────────────

/**
 * Per-character diff: compares current text against saved text character by character.
 * Characters that differ from the saved version are shown in the accent color + bold.
 * Uses FontWeight.W600 (semibold) to avoid changing line spacing.
 */
private class ContactsDiffTransformation(
    private val saved: String,
    private val accentColor: Color
) : VisualTransformation {
    override fun filter(text: AnnotatedString): TransformedText {
        val current = text.text
        val annotated = buildAnnotatedString {
            append(current)
            // Find ranges that differ from saved
            val minLen = minOf(current.length, saved.length)
            var i = 0
            while (i < current.length) {
                if (i >= saved.length || current[i] != saved[i]) {
                    // Find the end of this changed range
                    var end = i + 1
                    while (end < current.length && (end >= saved.length || current[end] != saved[end])) {
                        end++
                    }
                    addStyle(SpanStyle(color = accentColor, fontWeight = FontWeight.W600), i, end)
                    i = end
                } else {
                    i++
                }
            }
        }
        return TransformedText(annotated, OffsetMapping.Identity)
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
private fun AttachmentList(vm: MainViewModel, attachments: List<AttachmentInfo>) {
    var downloadingFile by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    if (attachments.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Text("No attachments on home server",
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
    } else {
        LazyColumn {
            items(attachments, key = { it.filename }) { info ->
                AttachmentItem(info, downloadingFile == info.filename,
                    vm.store?.isAttachmentCached(info.filename) ?: false,
                    onDownload = {
                        downloadingFile = info.filename
                        vm.downloadAttachment(info) { file -> downloadingFile = null
                            if (file != null) shareFile(context, file) }
                    },
                    onOpen = {
                        val file = vm.store?.cachedAttachmentFile(info.filename) ?: return@AttachmentItem
                        if (file.exists()) shareFile(context, file)
                    })
                HorizontalDivider(thickness = 0.5.dp)
            }
        }
    }
}

@Composable
private fun AttachmentItem(
    info: AttachmentInfo, isDownloading: Boolean, isCached: Boolean,
    onDownload: () -> Unit, onOpen: () -> Unit
) {
    Row(Modifier.fillMaxWidth().clickable(onClick = if (isCached) onOpen else onDownload)
        .padding(horizontal = 16.dp, vertical = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Icon(when (info.category) {
            "image" -> Icons.Default.Image; "audio" -> Icons.Default.AudioFile
            "text" -> Icons.AutoMirrored.Filled.TextSnippet; else -> Icons.Default.AttachFile
        }, null, Modifier.size(24.dp))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Text(info.filename, style = MaterialTheme.typography.bodyMedium)
            Text(formatSize(info.size), style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
        }
        when {
            isDownloading -> CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            isCached -> Icon(Icons.Default.CheckCircle, "Cached", tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
            else -> Icon(Icons.Default.Download, "Download", modifier = Modifier.size(20.dp))
        }
    }
}

private fun shareFile(context: android.content.Context, file: File) {
    val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
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
