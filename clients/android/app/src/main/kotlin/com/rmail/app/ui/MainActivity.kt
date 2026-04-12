package com.rmail.app.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.rmail.app.ui.screens.ComposeScreen
import com.rmail.app.ui.screens.ContactsScreen
import com.rmail.app.ui.screens.InboxScreen
import com.rmail.app.ui.screens.MailboxListScreen
import com.rmail.app.ui.screens.ReadScreen
import com.rmail.app.ui.screens.SettingsScreen
import com.rmail.app.ui.screens.SetupScreen
import com.rmail.app.ui.theme.RmailTheme
import androidx.compose.ui.graphics.Color

class MainActivity : ComponentActivity() {

    private val vm: MainViewModel by viewModels()

    private var pendingAttachLines: List<String>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingAttachLines = parseShareIntent(intent)

        setContent {
            val bgColor = Color(vm.globalSettings.bgColor.toLong() and 0xFFFFFFFFL)
            val fgColor = Color(vm.globalSettings.fgColor.toLong() and 0xFFFFFFFFL)
            RmailTheme(bgColor = bgColor, fgColor = fgColor) {
                val navController = rememberNavController()
                var initialComposeDraft by remember {
                    mutableStateOf(pendingAttachLines?.let { buildDraft(it) } ?: "")
                }

                val hasMailboxes = vm.mailboxes.value.isNotEmpty()
                val startDest = if (hasMailboxes) "mailboxList" else "setup"

                NavHost(navController = navController, startDestination = startDest) {

                    // ── Mailbox list (entry point) ──────────────────────────
                    composable("mailboxList") {
                        MailboxListScreen(
                            vm = vm,
                            onSelect = { id ->
                                vm.selectMailbox(id)
                                navController.navigate("inbox")
                            },
                            onAdd = { navController.navigate("setup") }
                        )
                    }

                    // ── Setup / add mailbox ─────────────────────────────────
                    composable("setup") {
                        SetupScreen(vm = vm) { mailboxId ->
                            vm.selectMailbox(mailboxId)
                            navController.navigate("inbox") {
                                popUpTo("mailboxList")
                            }
                        }
                    }

                    // ── Inbox (unified screen with bottom bar) ──────────
                    composable("inbox?showOutbox={showOutbox}") { back ->
                        val showOutbox = back.arguments?.getString("showOutbox") == "true"
                        InboxScreen(
                            vm = vm,
                            initialShowOutbox = showOutbox,
                            onBack = {
                                vm.deselectMailbox()
                                navController.navigate("mailboxList") {
                                    popUpTo("mailboxList") { inclusive = true }
                                }
                            },
                            onOpen = { navController.navigate("read/$it") },
                            onOpenOutbox = { navController.navigate("outbox-read/$it") },
                            onCompose = {}, onContacts = {},
                            onAttachments = {}, onSettings = {}
                        )
                    }

                    composable("inbox") {
                        InboxScreen(
                            vm = vm,
                            onBack = {
                                vm.deselectMailbox()
                                navController.navigate("mailboxList") {
                                    popUpTo("mailboxList") { inclusive = true }
                                }
                            },
                            onOpen = { navController.navigate("read/$it") },
                            onOpenOutbox = { navController.navigate("outbox-read/$it") },
                            onCompose = {}, onContacts = {},
                            onAttachments = {}, onSettings = {}
                        )
                    }

                    // ── Read message ────────────────────────────────────────
                    composable("read/{filename}") { back ->
                        val filename = back.arguments?.getString("filename") ?: return@composable
                        ReadScreen(
                            filename = filename, vm = vm,
                            onBack = { navController.popBackStack() },
                            onReply = {}, onForward = {}
                        )
                    }

                    composable("outbox-read/{filename}") { back ->
                        val filename = back.arguments?.getString("filename") ?: return@composable
                        ReadScreen(
                            filename = filename, vm = vm, isOutbox = true,
                            onBack = { navController.popBackStack() },
                            onReply = {}, onForward = {}
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val lines = parseShareIntent(intent)
        if (lines != null) pendingAttachLines = lines
    }

    @Suppress("DEPRECATION")
    private fun parseShareIntent(intent: Intent?): List<String>? {
        if (intent == null) return null
        return when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
                } ?: return null
                listOf(uriToAttachLine(uri))
            }
            Intent.ACTION_SEND_MULTIPLE -> {
                val uris = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("UNCHECKED_CAST")
                    intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
                } ?: return null
                uris.map { uriToAttachLine(it) }
            }
            else -> null
        }
    }

    private fun uriToAttachLine(uri: Uri): String {
        val path = uri.path ?: uri.toString()
        return "attach: $path"
    }

    private fun buildDraft(attachLines: List<String>): String =
        "to: \n\n" + attachLines.joinToString("\n")
}
