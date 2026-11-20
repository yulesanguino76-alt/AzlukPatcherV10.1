package com.azluk.patcher.ui.theme

import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight

// ── AzlukPatcher V10.1 — Exact colors extracted from the logo image ──────────
//
// Source: neon king character on pure black background
// Primary neon:  #0063FF (deep electric blue)
// Mid neon:      #00A1FF (bright blue)
// Bright neon:   #04CEFF (vivid cyan-blue)
// Cyan accent:   #12FFFF (pure cyan)
// Glow whites:   #ADF2FF / #E5FBFF
// Background:    #000003 (pure black void)
// Dark surface:  #00082A / #000A39 (deep navy)

// Primary blues — exact from image
val NeonBlue       = Color(0xFF0063FF)   // core neon blue
val NeonBlueMid    = Color(0xFF00A1FF)   // mid neon
val NeonBlueBright = Color(0xFF04CEFF)   // bright cyan-blue
val NeonCyan       = Color(0xFF12FFFF)   // pure cyan
val NeonGlowLight  = Color(0xFFADF2FF)   // soft glow
val NeonWhite      = Color(0xFFE5FBFF)   // white with blue tint

// Backgrounds — from image sampling
val VoidBlack      = Color(0xFF000003)   // pure void
val VoidBlack2     = Color(0xFF010108)   // slightly lifted
val DeepNavy       = Color(0xFF00082A)   // body dark from image
val DeepNavy2      = Color(0xFF000A39)   // hand blue from image
val DeepNavy3      = Color(0xFF000D4A)   // surfaces
val DeepNavy4      = Color(0xFF001060)   // elevated surface

// Borders/lines
val NeonBorder     = Color(0xFF0036FF)   // dark neon border
val NeonBorderMid  = Color(0xFF0063FF)   // mid neon border
val NeonBorderBright= Color(0xFF00A1FF) // bright neon border

// Text
val TextPrimary    = Color(0xFFE5FBFF)   // white-blue tint
val TextSecondary  = Color(0xFF83EEFF)   // glow text
val TextDim        = Color(0xFF2A5080)   // dimmed text
val TextMuted      = Color(0xFF143050)   // very dim

// Status — keep neon theme
val NeonGreen      = Color(0xFF00FF88)   // success
val NeonRed        = Color(0xFFFF1744)   // error
val NeonOrange     = Color(0xFFFF6600)   // warning
val NeonRedDim     = Color(0xFF4A0010)

// ── Aliases used throughout the app ──────────────────────────────────────────
val AzlukBlue        = NeonBlueMid
val AzlukBlueDim     = NeonBlue
val AzlukBlueDark    = DeepNavy
val AzlukBlueGlow    = NeonBlueBright
val AzlukCyan        = NeonCyan
val AzlukCyanDim     = Color(0xFF006080)
val AzlukPurple      = Color(0xFF4400CC)
val AzlukPurpleDim   = Color(0xFF220066)
val AzlukPink        = Color(0xFF0088FF)
val AzlukGreen       = NeonGreen

val AzlukBg          = VoidBlack
val AzlukBgAlt       = VoidBlack2
val AzlukSurface     = DeepNavy
val AzlukSurface2    = DeepNavy2
val AzlukSurface3    = DeepNavy3
val AzlukSurfaceVar  = NeonBorder.copy(alpha = 0.6f)
val AzlukSurfaceHigh = NeonBorderMid.copy(alpha = 0.4f)

val AzlukOnBg        = TextPrimary
val AzlukOnBgDim     = NeonGlowLight
val AzlukOnSurface   = TextSecondary
val AzlukOnSurfaceDim= TextDim

val AzlukError       = NeonRed
val AzlukErrorDim    = NeonRedDim
val AzlukSuccess     = NeonGreen
val AzlukSuccessDim  = Color(0xFF004030)
val AzlukWarning     = NeonOrange
val AzlukWarningDim  = Color(0xFF4A2000)
val AzlukGold        = Color(0xFFFFCC00)

private val AzlukColorScheme = darkColorScheme(
    primary            = NeonBlueMid,
    onPrimary          = VoidBlack,
    primaryContainer   = DeepNavy,
    onPrimaryContainer = NeonBlueBright,
    secondary          = NeonCyan,
    onSecondary        = VoidBlack,
    secondaryContainer = Color(0xFF003040),
    tertiary           = NeonBlueBright,
    onTertiary         = VoidBlack,
    background         = VoidBlack,
    onBackground       = TextPrimary,
    surface            = DeepNavy,
    surfaceVariant     = DeepNavy2,
    onSurface          = TextSecondary,
    onSurfaceVariant   = NeonGlowLight,
    error              = NeonRed,
    onError            = Color.White,
    errorContainer     = NeonRedDim,
    outline            = NeonBorder,
    outlineVariant     = NeonBorderMid,
    inverseSurface     = TextPrimary,
    inverseOnSurface   = VoidBlack,
    scrim              = VoidBlack.copy(alpha = 0.8f),
)

@Composable
fun AzlukTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = AzlukColorScheme,
        typography  = Typography(
            displayLarge  = MaterialTheme.typography.displayLarge.copy(fontWeight  = FontWeight.Black),
            displayMedium = MaterialTheme.typography.displayMedium.copy(fontWeight = FontWeight.ExtraBold),
            headlineLarge = MaterialTheme.typography.headlineLarge.copy(fontWeight = FontWeight.Bold),
            titleLarge    = MaterialTheme.typography.titleLarge.copy(fontWeight    = FontWeight.Bold),
            titleMedium   = MaterialTheme.typography.titleMedium.copy(fontWeight   = FontWeight.SemiBold),
            titleSmall    = MaterialTheme.typography.titleSmall.copy(fontWeight    = FontWeight.SemiBold),
            labelLarge    = MaterialTheme.typography.labelLarge.copy(fontWeight    = FontWeight.SemiBold),
            labelMedium   = MaterialTheme.typography.labelMedium.copy(fontWeight   = FontWeight.Medium),
        ),
        content = content
    )
}

// ── Shared neon UI helpers ───────────────────────────────────────────────────
// Used across all screens for consistent neon look

/** Neon glow border brush — matches the logo's outer ring */
fun neonBorderBrush(alpha: Float = 1f) = androidx.compose.ui.graphics.Brush.linearGradient(
    listOf(
        NeonBlue.copy(alpha * 0.6f),
        NeonBlueMid.copy(alpha),
        NeonBlueBright.copy(alpha * 0.9f),
        NeonBlueMid.copy(alpha),
        NeonBlue.copy(alpha * 0.6f),
    )
)

/** Pure horizontal neon gradient for button fills */
val NeonButtonGradient = androidx.compose.ui.graphics.Brush.horizontalGradient(
    listOf(NeonBlue, NeonBlueMid, NeonBlueBright)
)

/** Vertical dark gradient for card backgrounds */
val CardBgGradient = androidx.compose.ui.graphics.Brush.verticalGradient(
    listOf(DeepNavy2, VoidBlack)
)

/** Radial glow effect matching the logo aura */
fun neonGlowBrush(color: Color = NeonBlueMid, intensity: Float = 0.3f) =
    androidx.compose.ui.graphics.Brush.radialGradient(
        listOf(color.copy(intensity), color.copy(intensity * 0.3f), Color.Transparent)
    )
