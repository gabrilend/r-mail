package com.rmail.app.ui.screens

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.MediaStore
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.PhotoLibrary
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Every "pick a file" in the app goes through here: the Files tab's `+` and
 * Upload, and attaching to a message.  It asks first, in our own dialog,
 * whether the file is in the gallery or elsewhere, and only then hands over
 * to Android -- which asks which gallery app or which file app to use.
 *
 * Newest first: neither intent can ask for a sort order; there is no such
 * extra.  What we can do is not get in the way of the defaults, which are
 * newest-first in both cases -- gallery apps open on their timeline, and the
 * system file picker opens on Recent when not given a starting folder (so we
 * never pass one).
 *
 * Returns a function that opens the dialog.
 */
@Composable
fun rememberAttachmentSourcePicker(onPicked: (List<Uri>) -> Unit): () -> Unit {
    var open by remember { mutableStateOf(false) }
    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val uris = urisFrom(result.data)
            if (uris.isNotEmpty()) onPicked(uris)
        }
    }

    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text("Add from") },
            text = {
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    SourceButton("Gallery", Icons.Default.PhotoLibrary, Modifier.weight(1f)) {
                        open = false
                        launcher.launch(Intent.createChooser(galleryIntent(), "Choose a gallery app"))
                    }
                    SourceButton("File", Icons.Default.Description, Modifier.weight(1f)) {
                        open = false
                        launcher.launch(Intent.createChooser(fileIntent(), "Choose a file app"))
                    }
                }
            },
            confirmButton = {},
            dismissButton = { TextButton(onClick = { open = false }) { Text("Cancel") } }
        )
    }
    return { open = true }
}

@Composable
private fun SourceButton(
    label: String, icon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier, onClick: () -> Unit
) {
    OutlinedButton(onClick = onClick, modifier = modifier.height(96.dp)) {
        Column(horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(icon, contentDescription = null, modifier = Modifier.size(32.dp))
            Text(label)
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

private fun urisFrom(data: Intent?): List<Uri> {
    if (data == null) return emptyList()
    val clip = data.clipData
    if (clip != null && clip.itemCount > 0) {
        return (0 until clip.itemCount).mapNotNull { clip.getItemAt(it).uri }
    }
    return listOfNotNull(data.data)
}
