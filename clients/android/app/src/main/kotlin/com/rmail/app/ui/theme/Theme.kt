package com.rmail.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val Black = Color(0xFF000000)
val Goldenrod = Color(0xFFFFD040)
val GoldenrodDim = Color(0xFFB89020)
val DarkSurface = Color(0xFF111111)
val DimText = Color(0xFF888888)

private val RmailColorScheme = darkColorScheme(
    primary = Goldenrod,
    onPrimary = Black,
    secondary = GoldenrodDim,
    onSecondary = Black,
    background = Black,
    onBackground = Goldenrod,
    surface = DarkSurface,
    onSurface = Goldenrod,
    surfaceVariant = DarkSurface,
    onSurfaceVariant = Goldenrod,
    outline = GoldenrodDim,
    error = Color(0xFFCF6679),
)

@Composable
fun RmailTheme(
    bgColor: Color = Black,
    fgColor: Color = Goldenrod,
    content: @Composable () -> Unit
) {
    val colorScheme = if (bgColor == Black && fgColor == Goldenrod) {
        RmailColorScheme
    } else {
        darkColorScheme(
            primary = fgColor,
            onPrimary = bgColor,
            secondary = fgColor.copy(alpha = 0.7f),
            onSecondary = bgColor,
            background = bgColor,
            onBackground = fgColor,
            surface = bgColor,
            onSurface = fgColor,
            surfaceVariant = bgColor,
            onSurfaceVariant = fgColor,
            outline = fgColor.copy(alpha = 0.5f),
            error = Color(0xFFCF6679),
        )
    }
    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
