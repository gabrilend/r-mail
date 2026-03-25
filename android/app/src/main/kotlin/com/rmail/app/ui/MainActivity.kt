package com.rmail.app.ui

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Parcelable
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.rmail.app.ui.screens.AttachmentsScreen
import com.rmail.app.ui.screens.ComposeScreen
import com.rmail.app.ui.screens.ContactsScreen
import com.rmail.app.ui.screens.InboxScreen
import com.rmail.app.ui.screens.ReadScreen
import com.rmail.app.ui.screens.SettingsScreen
import com.rmail.app.ui.screens.SetupScreen
import com.rmail.app.ui.theme.RmailTheme
import androidx.compose.ui.graphics.Color

class MainActivity : ComponentActivity() {

    private val vm: MainViewModel by viewModels()

    // Attach lines from an incoming share intent, held until navigation is ready
    private var pendingAttachLines: List<String>? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        pendingAttachLines = parseShareIntent(intent)

        setContent {
            val bgColor = Color(vm.settings.bgColor.toLong() and 0xFFFFFFFFL)
            val fgColor = Color(vm.settings.fgColor.toLong() and 0xFFFFFFFFL)
            RmailTheme(bgColor = bgColor, fgColor = fgColor) {
                val navController = rememberNavController()
                val isConfigured = vm.settings.isConfigured
                var initialComposeDraft by remember {
                    mutableStateOf(pendingAttachLines?.let { buildDraft(it) } ?: "")
                }

                val startDest = if (isConfigured) "inbox" else "setup"

                NavHost(navController = navController, startDestination = startDest) {

                    composable("setup") {
                        SetupScreen(vm = vm) {
                            // After setup completes, check for pending share intent
                            if (pendingAttachLines != null) {
                                initialComposeDraft = buildDraft(pendingAttachLines!!)
                                pendingAttachLines = null
                                navController.navigate("compose?draft=${Uri.encode(initialComposeDraft)}")
                            } else {
                                navController.navigate("inbox") {
                                    popUpTo("setup") { inclusive = true }
                                }
                            }
                        }
                    }

                    composable("inbox") {
                        // Check for pending share intent after first configure
                        val pending = pendingAttachLines
                        if (pending != null) {
                            pendingAttachLines = null
                            initialComposeDraft = buildDraft(pending)
                            navController.navigate("compose?draft=${Uri.encode(initialComposeDraft)}")
                        }
                        InboxScreen(
                            vm = vm,
                            onOpen = { filename -> navController.navigate("read/$filename") },
                            onOpenOutbox = { filename -> navController.navigate("outbox-read/$filename") },
                            onCompose = { navController.navigate("compose") },
                            onContacts = { navController.navigate("contacts") },
                            onAttachments = { navController.navigate("attachments") },
                            onSettings = { navController.navigate("settings") }
                        )
                    }

                    composable("read/{filename}") { back ->
                        val filename = back.arguments?.getString("filename") ?: return@composable
                        ReadScreen(
                            filename = filename,
                            vm = vm,
                            onBack = { navController.popBackStack() },
                            onReply = { replyDraft ->
                                navController.navigate("compose?draft=${Uri.encode(replyDraft)}")
                            },
                            onForward = { forwardDraft ->
                                navController.navigate("compose?draft=${Uri.encode(forwardDraft)}")
                            }
                        )
                    }

                    composable("outbox-read/{filename}") { back ->
                        val filename = back.arguments?.getString("filename") ?: return@composable
                        ReadScreen(
                            filename = filename,
                            vm = vm,
                            isOutbox = true,
                            onBack = { navController.popBackStack() },
                            onReply = {},
                            onForward = {}
                        )
                    }

                    composable("compose?draft={draft}") { back ->
                        val draft = back.arguments?.getString("draft")?.let { Uri.decode(it) } ?: ""
                        ComposeScreen(
                            vm = vm,
                            initialContent = draft,
                            onCancel = { navController.popBackStack() },
                            onSent = {
                                navController.popBackStack()
                                vm.triggerSync()
                            }
                        )
                    }

                    composable("compose") {
                        ComposeScreen(
                            vm = vm,
                            initialContent = "",
                            onCancel = { navController.popBackStack() },
                            onSent = {
                                navController.popBackStack()
                                vm.triggerSync()
                            }
                        )
                    }

                    composable("contacts") {
                        ContactsScreen(
                            vm = vm,
                            onBack = { navController.popBackStack() }
                        )
                    }

                    composable("attachments") {
                        AttachmentsScreen(
                            vm = vm,
                            onBack = { navController.popBackStack() }
                        )
                    }

                    composable("settings") {
                        SettingsScreen(
                            vm = vm,
                            onBack = { navController.popBackStack() }
                        )
                    }
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // Handle share intents arriving while the app is already running
        val lines = parseShareIntent(intent)
        if (lines != null) {
            pendingAttachLines = lines
        }
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
        // Prefer a real filesystem path; fall back to the content URI string
        val path = uri.path ?: uri.toString()
        return "attach: $path"
    }

    private fun buildDraft(attachLines: List<String>): String =
        "to: \n\n" + attachLines.joinToString("\n")
}
