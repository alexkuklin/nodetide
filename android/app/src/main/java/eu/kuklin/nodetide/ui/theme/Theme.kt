package eu.kuklin.nodetide.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFFE94560),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFFF6B6B),
    onPrimaryContainer = Color.White,

    secondary = Color(0xFF4ECCA3),
    onSecondary = Color.Black,
    secondaryContainer = Color(0xFF3DAA8A),
    onSecondaryContainer = Color.Black,

    background = Color(0xFF1A1A2E),
    onBackground = Color(0xFFEAEAEA),

    surface = Color(0xFF16213E),
    onSurface = Color(0xFFEAEAEA),
    surfaceVariant = Color(0xFF0F3460),
    onSurfaceVariant = Color(0xFFA0A0A0),

    error = Color(0xFFFF4757),
    onError = Color.White,

    outline = Color(0xFF2A2A4A)
)

@Composable
fun NodetideTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = DarkColorScheme,
        content = content
    )
}
