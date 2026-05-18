package eu.kuklin.nodetide.ui

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import eu.kuklin.nodetide.NodetideApp
import eu.kuklin.nodetide.ui.screens.*
import eu.kuklin.nodetide.ui.theme.NodetideTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            NodetideTheme {
                NodetideApp()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodetideApp() {
    val navController = rememberNavController()
    val currentBackStack by navController.currentBackStackEntryAsState()
    val currentRoute = currentBackStack?.destination?.route ?: Screen.Home.route

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Nodetide") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar {
                Screen.bottomNavItems.forEach { screen ->
                    NavigationBarItem(
                        icon = { Icon(screen.icon, contentDescription = screen.label) },
                        label = { Text(screen.label) },
                        selected = currentRoute == screen.route,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.startDestinationId) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = Screen.Home.route,
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            composable(Screen.Home.route) { HomeScreen(navController) }
            composable(Screen.Identity.route) { IdentityScreen(navController) }
            composable(Screen.Messages.route) { MessagesScreen(navController) }
            composable(Screen.Relays.route) { RelaysScreen(navController) }
            composable(Screen.Settings.route) { SettingsScreen(navController) }
            composable(Screen.CreateIdentity.route) { CreateIdentityScreen(navController) }
            composable(Screen.AttachDevice.route) { AttachDeviceScreen(navController) }
            composable(Screen.ScanQR.route) { ScanQRScreen(navController) }
        }
    }
}

sealed class Screen(val route: String, val label: String, val icon: androidx.compose.ui.graphics.vector.ImageVector) {
    object Home : Screen("home", "Home", Icons.Default.Home)
    object Identity : Screen("identity", "Identity", Icons.Default.Person)
    object Messages : Screen("messages", "Messages", Icons.Default.Email)
    object Relays : Screen("relays", "Relays", Icons.Default.Wifi)
    object Settings : Screen("settings", "Settings", Icons.Default.Settings)

    // Non-bottom-nav screens
    object CreateIdentity : Screen("create_identity", "Create Identity", Icons.Default.Add)
    object AttachDevice : Screen("attach_device", "Attach Device", Icons.Default.Link)
    object ScanQR : Screen("scan_qr", "Scan QR", Icons.Default.QrCodeScanner)

    companion object {
        val bottomNavItems = listOf(Home, Identity, Messages, Relays, Settings)
    }
}
