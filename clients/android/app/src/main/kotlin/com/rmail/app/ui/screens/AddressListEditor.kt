package com.rmail.app.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * An editable list of server addresses.  Each row has a `−` that asks
 * before removing, since it sits right beside the text field and is easy to
 * hit by accident.  Adding is done by [AddAddressButton] below the lists,
 * which files the address into the right list itself.  Deliberately not
 * reorderable -- the first public address is the primary.
 *
 * Blank rows are dropped on save.  Nothing is validated against the digits:
 * which list an address belongs in is the user's call (see AddAddressButton).
 */
@Composable
fun AddressListEditor(
    title: String,
    addresses: List<String>,
    onChange: (List<String>) -> Unit,
    placeholder: String,
) {
    var confirmRemove by remember { mutableStateOf<Int?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.bodyMedium)
        if (addresses.isEmpty()) {
            Text("none", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
        addresses.forEachIndexed { i, addr ->
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = addr,
                    onValueChange = { v -> onChange(addresses.toMutableList().also { it[i] = v.trim() }) },
                    placeholder = { Text(placeholder) },
                    singleLine = true,
                    modifier = Modifier.weight(1f)
                )
                IconButton(onClick = {
                    // Nothing to lose in an empty row, so no question.
                    if (addr.isBlank()) onChange(addresses.filterIndexed { j, _ -> j != i })
                    else confirmRemove = i
                }) {
                    Icon(Icons.Default.Remove, contentDescription = "Remove $addr")
                }
            }
        }
    }
    confirmRemove?.let { i ->
        val addr = addresses.getOrNull(i) ?: run { confirmRemove = null; return@let }
        AlertDialog(
            onDismissRequest = { confirmRemove = null },
            title = { Text("Remove address?") },
            text = { Text("Remove $addr from $title?  It takes effect when you save.") },
            confirmButton = {
                TextButton(onClick = {
                    onChange(addresses.filterIndexed { j, _ -> j != i })
                    confirmRemove = null
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = null }) { Text("Cancel") } }
        )
    }
}

/** What "Detect IP" found: the address, and a line saying where it came from. */
data class DetectedAddress(val address: String?, val note: String)

/**
 * Full-width "Add new IP address" button, placed below both address lists.
 * The user says which kind of address it is with the Public / Local switch;
 * nothing is inferred from the digits.  (Private ranges are reused on every
 * network, and a "private-looking" address can be the right public one
 * behind carrier NAT, so the digits cannot say which list an address
 * belongs in -- only the user knows.)
 *
 * [detect] fills the field with an address of the chosen kind; it is added
 * only when the user taps Add.
 */
@Composable
fun AddAddressButton(
    detect: suspend (local: Boolean) -> DetectedAddress,
    onAdd: (address: String, local: Boolean) -> Unit,
) {
    var open by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }
    var local by remember { mutableStateOf(false) }
    var detecting by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    OutlinedButton(onClick = { text = ""; note = null; open = true }, modifier = Modifier.fillMaxWidth()) {
        Icon(Icons.Default.Add, contentDescription = null)
        Spacer(Modifier.width(8.dp))
        Text("Add new IP address")
    }
    if (open) {
        AlertDialog(
            onDismissRequest = { open = false },
            title = { Text("Add address") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Public", style = MaterialTheme.typography.bodyMedium,
                            color = if (!local) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                        Switch(checked = local, onCheckedChange = { local = it; note = null })
                        Text("Local", style = MaterialTheme.typography.bodyMedium,
                            color = if (local) MaterialTheme.colorScheme.primary
                                    else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
                    }
                    Text(
                        if (local) "Reachable only from the server's own network, e.g. its address on your home wifi."
                        else "Reachable from anywhere: a public IP or a hostname.",
                        style = MaterialTheme.typography.bodySmall
                    )
                    OutlinedTextField(
                        value = text,
                        onValueChange = { text = it.trim(); note = null },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedButton(
                        onClick = {
                            detecting = true
                            scope.launch {
                                val found = detect(local)
                                found.address?.let { text = it }
                                note = found.note
                                detecting = false
                            }
                        },
                        enabled = !detecting,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        if (detecting) CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp)
                        else Text(if (local) "Detect local IP" else "Detect public IP")
                    }
                    note?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            },
            confirmButton = {
                TextButton(enabled = text.isNotBlank(), onClick = {
                    onAdd(text, local); open = false
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { open = false }) { Text("Cancel") } }
        )
    }
}

/** Blank rows out, duplicates out, order kept. */
fun cleanAddressList(list: List<String>): List<String> =
    list.map { it.trim() }.filter { it.isNotEmpty() }.distinct()
