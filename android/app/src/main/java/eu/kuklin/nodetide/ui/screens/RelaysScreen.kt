package eu.kuklin.nodetide.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.navigation.NavController
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.data.DiscoveredRelay
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RelaysScreen(navController: NavController) {
    val scope = rememberCoroutineScope()
    val settingsStore = remember { NodetideApp.instance.settingsStore }
    val discoveryService = remember { NodetideApp.instance.discoveryService }

    val currentRelayUrl by settingsStore.relayUrl.collectAsState(initial = null)

    var discoveredRelays by remember { mutableStateOf<List<DiscoveredRelay>>(emptyList()) }
    var isDiscovering by remember { mutableStateOf(false) }
    var manualUrl by remember { mutableStateOf("") }
    var showManualDialog by remember { mutableStateOf(false) }

    fun discoverRelays() {
        scope.launch {
            isDiscovering = true
            val relays = discoveryService.discoverRelaysForDuration(5000)
            discoveredRelays = relays
            isDiscovering = false
        }
    }

    fun connectToRelay(relay: DiscoveredRelay) {
        scope.launch {
            val url = "http://${relay.host}:${relay.port}"
            settingsStore.setRelayUrl(url, relay.name)
        }
    }

    fun connectToManualUrl(url: String) {
        scope.launch {
            settingsStore.setRelayUrl(url, "Manual")
        }
    }

    if (showManualDialog) {
        AlertDialog(
            onDismissRequest = { showManualDialog = false },
            title = { Text("Manual Relay URL") },
            text = {
                OutlinedTextField(
                    value = manualUrl,
                    onValueChange = { manualUrl = it },
                    label = { Text("Relay URL") },
                    placeholder = { Text("http://192.168.1.100:8080") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        connectToManualUrl(manualUrl)
                        showManualDialog = false
                    },
                    enabled = manualUrl.isNotBlank()
                ) {
                    Text("Connect")
                }
            },
            dismissButton = {
                TextButton(onClick = { showManualDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Text(
                text = "Relays",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
        }

        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "Current Relay",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Spacer(modifier = Modifier.height(8.dp))

                    if (currentRelayUrl != null) {
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                Icons.Default.Check,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.secondary
                            )
                            Text(
                                text = currentRelayUrl ?: "",
                                style = MaterialTheme.typography.bodyMedium,
                                fontFamily = FontFamily.Monospace
                            )
                        }
                        Spacer(modifier = Modifier.height(8.dp))
                        OutlinedButton(
                            onClick = {
                                scope.launch {
                                    settingsStore.setRelayUrl(null)
                                }
                            }
                        ) {
                            Text("Disconnect")
                        }
                    } else {
                        Text(
                            text = "Not connected",
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Button(
                    onClick = { discoverRelays() },
                    enabled = !isDiscovering,
                    modifier = Modifier.weight(1f)
                ) {
                    if (isDiscovering) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            color = MaterialTheme.colorScheme.onPrimary,
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Discovering...")
                    } else {
                        Icon(Icons.Default.Search, contentDescription = null)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Discover Relays")
                    }
                }

                OutlinedButton(
                    onClick = { showManualDialog = true }
                ) {
                    Text("Manual")
                }
            }
        }

        if (discoveredRelays.isEmpty() && !isDiscovering) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surface
                    )
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "No relays found",
                            style = MaterialTheme.typography.titleMedium
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Make sure a nodetide relay is running on your local network, or enter a URL manually.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        if (discoveredRelays.isNotEmpty()) {
            item {
                Text(
                    text = "Discovered Relays",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }
        }

        items(discoveredRelays) { relay ->
            DiscoveredRelayCard(
                relay = relay,
                isConnected = currentRelayUrl == "http://${relay.host}:${relay.port}",
                onConnect = { connectToRelay(relay) }
            )
        }
    }
}

@Composable
private fun DiscoveredRelayCard(
    relay: DiscoveredRelay,
    isConnected: Boolean,
    onConnect: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (isConnected)
                MaterialTheme.colorScheme.secondaryContainer
            else
                MaterialTheme.colorScheme.surface
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = relay.name,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = "${relay.host}:${relay.port}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (relay.properties.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    relay.properties.forEach { (key, value) ->
                        Text(
                            text = "$key: $value",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            if (isConnected) {
                Icon(
                    Icons.Default.Check,
                    contentDescription = "Connected",
                    tint = MaterialTheme.colorScheme.secondary
                )
            } else {
                Button(onClick = onConnect) {
                    Text("Connect")
                }
            }
        }
    }
}
