package com.rmail.app.data

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import androidx.annotation.RequiresApi
import java.io.File

/**
 * Save to device: copy a file out of the app's private storage into shared
 * storage, where the gallery and file apps can see it.  Photos go to
 * Pictures/rmail, videos to Movies/rmail, audio to Music/rmail, anything else
 * to Download/rmail.
 *
 * Android 10+ only (MediaStore with relative paths, no permission needed).
 * Android 8-9 would need storage permission for the same; the Files tab uses
 * the system "Save as" dialog there instead (see [copyTo]).
 */
object DeviceExport {

    fun mimeOf(file: File): String =
        MimeTypeMap.getSingleton().getMimeTypeFromExtension(file.extension.lowercase())
            ?: "application/octet-stream"

    /** Saves [file]; returns the folder it went to, e.g. "Pictures/rmail". */
    @RequiresApi(Build.VERSION_CODES.Q)
    fun save(context: Context, file: File): String {
        val mime = mimeOf(file)
        val volume = MediaStore.VOLUME_EXTERNAL_PRIMARY
        val (collection, dir) = when {
            mime.startsWith("image/") ->
                MediaStore.Images.Media.getContentUri(volume) to Environment.DIRECTORY_PICTURES
            mime.startsWith("video/") ->
                MediaStore.Video.Media.getContentUri(volume) to Environment.DIRECTORY_MOVIES
            mime.startsWith("audio/") ->
                MediaStore.Audio.Media.getContentUri(volume) to Environment.DIRECTORY_MUSIC
            else ->
                MediaStore.Downloads.getContentUri(volume) to Environment.DIRECTORY_DOWNLOADS
        }
        val folder = "$dir/rmail"
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, file.name)
            put(MediaStore.MediaColumns.MIME_TYPE, mime)
            put(MediaStore.MediaColumns.RELATIVE_PATH, folder)
            // Hidden from other apps until the copy is complete.
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val resolver = context.contentResolver
        val uri = resolver.insert(collection, values)
            ?: throw java.io.IOException("the system refused to create ${file.name}")
        try {
            copyTo(context, file, uri)
            resolver.update(uri, ContentValues().apply {
                put(MediaStore.MediaColumns.IS_PENDING, 0)
            }, null, null)
        } catch (e: Exception) {
            resolver.delete(uri, null, null)  // no half-written file left behind
            throw e
        }
        return folder
    }

    /** Copy [file] to a content URI -- MediaStore's, or one "Save as" returned. */
    fun copyTo(context: Context, file: File, uri: Uri) {
        context.contentResolver.openOutputStream(uri)?.use { out ->
            file.inputStream().use { it.copyTo(out) }
        } ?: throw java.io.IOException("couldn't write ${file.name}")
    }
}
