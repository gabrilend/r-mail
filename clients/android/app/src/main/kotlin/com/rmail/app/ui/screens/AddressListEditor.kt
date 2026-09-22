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
import com.rmail.app.data.isPrivateIpv4

/**
 * An editable list of server addresses.  Each row has a `−` that asks
 * before removing, since it sits right beside the text field and is easy to
 * hit by accident.  Adding is done by [AddAddressButton] below the lists,
 * which files the address into the right list itself.  Deliberately not
 * reorderable -- the first public address is the primary.
 *
 * [validate] returns an error message for a bad entry, or null.  Blank rows
 * are not errors; they are dropped on save.
 */
@Composable
fun AddressListEditor(
    title: String,
    addresses: List<String>,
    onChange: (List<String>) -> Unit,
    placeholder: String,
    showErrors: Boolean,
    validate: (String) -> String? = { null },
) {
    var confirmRemove by remember { mutableStateOf<Int?>(null) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, style = MaterialTheme.typography.bodyMedium)
        if (addresses.isEmpty()) {
            Text("none", style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
        addresses.forEachIndexed { i, addr ->
            val error = if (showErrors && addr.isNotBlank()) validate(addr.trim()) else null
            Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = addr,
                    onValueChange = { v -> onChange(addresses.toMutableList().also { it[i] = v.trim() }) },
                    placeholder = { Text(placeholder) },
                    singleLine = true,
                    isError = error != null,
                    supportingText = error?.let { { Text(it) } },
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

/**
 * Full-width "Add new IP address" button, placed below both address lists.
 * Asks for the address, then [onAdd] files it: a private address goes to
 * the local list, anything else to the server list.
 */
@Composable
fun AddAddressButton(onAdd: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    var text by remember { mutableStateOf("") }
    OutlinedButton(onClick = { text = ""; open = true }, modifier = Modifier.fillMaxWidth()) {
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
                    OutlinedTextField(
                        value = text,
                        onValueChange = { text = it.trim() },
                        placeholder = { Text("203.0.113.5, host.example.com or 192.168.1.10") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    Text(
                        if (text.isBlank()) "Private (LAN) addresses go under local addresses; " +
                            "everything else under server addresses."
                        else if (isPrivateIpv4(text)) "Will be added as a local address."
                        else "Will be added as a server address.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            },
            confirmButton = {
                TextButton(enabled = text.isNotBlank(), onClick = {
                    onAdd(text); open = false
                }) { Text("Add") }
            },
            dismissButton = { TextButton(onClick = { open = false }) { Text("Cancel") } }
        )
    }
}

/** Blank rows out, duplicates out, order kept. */
fun cleanAddressList(list: List<String>): List<String> =
    list.map { it.trim() }.filter { it.isNotEmpty() }.distinct()

/**
 * Error for an entry in the local-address list, or null if it is fine.
 * Mirrors the daemon's rule (#388): local means private IPv4, because a
 * private address is only reachable from inside its own network.
 */
fun localAddressError(addr: String): String? =
    if (isPrivateIpv4(addr)) null else "Must be a private IPv4 address (10.x, 172.16–31.x, 192.168.x)"

/**
 * Error for an entry in the public-address list.  Private addresses belong
 * in the local list, where they are only tried briefly.
 */
fun publicAddressError(addr: String): String? =
    if (isPrivateIpv4(addr)) "Private address — add it under local addresses" else null
