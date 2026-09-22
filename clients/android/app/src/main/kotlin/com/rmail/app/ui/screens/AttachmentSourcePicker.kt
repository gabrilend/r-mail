package com.rmail.app.ui.screens

import android.app.Activity
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import android.provider.MediaStore
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.border
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.PhotoCamera
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Every "pick a file" in the app goes through here: the Files tab's `+` and
 * Upload, and attaching to a message.  Our own dialog asks Gallery, Camera or
 * File; the first time each is used, Android asks which app should do it,
 * and the answer is remembered.  Long-press a button to be asked again.
 *
 * Remembering is ours, not Android's: the system chooser has no "always", so
 * it reports the app the user picked (EXTRA_CHOSEN_COMPONENT, via the
 * PendingIntent below) and later launches go straight to it.  If that app is
 * uninstalled, the choice is forgotten and the chooser comes back.
 *
 * Newest first: no intent can ask for a sort order.  The defaults already
 * are -- gallery apps open on their timeline, and the system file picker
 * opens on Recent when not given a starting folder (so we never pass one).
 *
 * Returns a function that opens the dialog.
 */
@Composable
fun rememberAttachmentSourcePicker(onPicked: (List<Uri>) -> Unit): () -> Unit {
    val context = LocalContext.current
    var open by remember { mutableStateOf(false) }
    // Survive the activity being recreated while the camera app is up.
    var cameraOutput by rememberSaveable { mutableStateOf<Uri?>(null) }
    var lastSource by rememberSaveable { mutableStateOf("") }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode != Activity.RESULT_OK) return@rememberLauncherForActivityResult
        val uris = if (lastSource == Source.CAMERA.key) {
            // The photo was written to the file we supplied; the result
            // intent carries nothing.
            listOfNotNull(cameraOutput)
        } else urisFrom(result.data)
        if (uris.isNotEmpty()) onPicked(uris)
    }

    // Records which app the chooser handed the request to.
    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val source = i.getStringExtra(EXTRA_SOURCE) ?: return
                @Suppress("DEPRECATION")
                val chosen = i.getParcelableExtra<ComponentName>(Intent.EXTRA_CHOSEN_COMPONENT) ?: return
                prefs(c).edit().putString(source, chosen.flattenToString()).apply()
            }
        }
        ContextCompat.registerReceiver(context, receiver, IntentFilter(ACTION_CHOSEN),
            ContextCompat.RECEIVER_NOT_EXPORTED)
        onDispose { context.unregisterReceiver(receiver) }
    }

    fun launch(source: Source, ask: Boolean) {
        open = false
        lastSource = source.key
        val target = when (source) {
            Source.GALLERY -> galleryIntent()
            Source.FILE -> fileIntent()
            Source.CAMERA -> {
                val uri = newCameraFile(context)
                cameraOutput = uri
                cameraIntent(uri)
            }
        }
        val remembered = prefs(context).getString(source.key, null)
            ?.let { ComponentName.unflattenFromString(it) }
        if (!ask && remembered != null) {
            val direct = Intent(target).setComponent(remembered)
            if (direct.resolveActivity(context.packageManager) != null) {
                try { launcher.launch(direct); return }
                catch (_: android.content.ActivityNotFoundException) { }
            }
            prefs(context).edit().remove(source.key).apply()  // app gone
        }
        val report = PendingIntent.getBroadcast(
            context, source.ordinal,
            Intent(ACTION_CHOSEN).setPackage(context.packageName).putExtra(EXTRA_SOURCE, source.key),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )
        launcher.launch(Intent.createChooser(target, source.chooserTitle, report.intentSender))
    }

    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text("Add from") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        for (src in Source.values()) {
                            SourceButton(src.label, src.icon, Modifier.weight(1f),
                                onClick = { launch(src, ask = false) },
                                onLongClick = { launch(src, ask = true) })
                        }
                    }
                    Text("Long press to change default app",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f))
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { open = false }) { Text("Cancel") } }
        )
    }
    return { open = true }
}

private enum class Source(val key: String, val label: String, val icon: ImageVector,
                          val chooserTitle: String) {
    GALLERY("gallery", "Gallery", Icons.Default.PhotoLibrary, "Choose a gallery app"),
    CAMERA("camera", "Camera", Icons.Default.PhotoCamera, "Choose a camera app"),
    FILE("file", "File", Icons.Default.Description, "Choose a file app"),
}

private const val ACTION_CHOSEN = "com.rmail.app.ATTACH_SOURCE_CHOSEN"
private const val EXTRA_SOURCE = "source"

private fun prefs(c: Context) = c.getSharedPreferences("attachment_sources", Context.MODE_PRIVATE)

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun SourceButton(
    label: String, icon: ImageVector, modifier: Modifier,
    onClick: () -> Unit, onLongClick: () -> Unit
) {
    val shape = RoundedCornerShape(16.dp)
    Box(
        modifier
            .height(96.dp)
            .clip(shape)
            .border(1.dp, MaterialTheme.colorScheme.outline, shape)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(32.dp),
                tint = MaterialTheme.colorScheme.primary)
            Text(label, color = MaterialTheme.colorScheme.primary)
        }
    }
}

/** Photos and videos, answered by whichever gallery apps are installed. */
private fun galleryIntent(): Intent =
    Intent(Intent.ACTION_PICK).apply {
        setDataAndType(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, "image/*")
        putExtra(Intent.EXTRA_MIME_TYPES, arrayOf("image/*", "video/*"))
        putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
    }

/**
 * Any file, answered by whichever file apps are installed.  GET_CONTENT
 * rather than OPEN_DOCUMENT: OPEN_DOCUMENT always goes to the system picker,
 * so there would be nothing for the user to choose between.
 */
private fun fileIntent(): Intent =
    Intent(Intent.ACTION_GET_CONTENT).apply {
        type = "*/*"
        addCategory(Intent.CATEGORY_OPENABLE)
        putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
    }

/**
 * A photo from whichever camera app, written to a file we own.  No CAMERA
 * permission: the camera app takes the picture, we only receive the file.
 * The write grant rides on ClipData so it survives the chooser.
 */
private fun cameraIntent(output: Uri): Intent =
    Intent(MediaStore.ACTION_IMAGE_CAPTURE).apply {
        putExtra(MediaStore.EXTRA_OUTPUT, output)
        clipData = ClipData.newRawUri("", output)
        addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION or Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }

/**
 * A fresh file for the camera to fill, in app storage.  Photos are copied
 * into Files (or a message) once taken, so ones older than a week are
 * leftovers -- a shot the user backed out of -- and are cleared here.
 */
private fun newCameraFile(context: Context): Uri {
    val dir = File(context.filesDir, "camera").also { it.mkdirs() }
    val weekAgo = System.currentTimeMillis() - 7L * 24 * 60 * 60 * 1000
    dir.listFiles()?.filter { it.lastModified() < weekAgo }?.forEach { it.delete() }
    val name = "IMG_" + SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date()) + ".jpg"
    val file = File(dir, name)
    return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
}

private fun urisFrom(data: Intent?): List<Uri> {
    if (data == null) return emptyList()
    val clip = data.clipData
    if (clip != null && clip.itemCount > 0) {
        return (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
    }
    return listOfNotNull(data.data)
}
