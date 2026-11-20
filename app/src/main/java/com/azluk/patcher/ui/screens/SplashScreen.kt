package com.azluk.patcher.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.*
import com.azluk.patcher.R
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PerformanceTier
import com.azluk.patcher.viewmodel.SystemProfile
import kotlinx.coroutines.delay

@Composable
fun SplashScreen(profile: SystemProfile, onComplete: () -> Unit) {
    val inf = rememberInfiniteTransition(label = "splash")

    val pulse by inf.animateFloat(0.3f, 1f,
        infiniteRepeatable(tween(1200, easing = FastOutSlowInEasing), RepeatMode.Reverse), "pulse")
    val ring1 by inf.animateFloat(0f, 1f,
        infiniteRepeatable(tween(2000, easing = LinearEasing), RepeatMode.Restart), "ring1")
    val ring2 by inf.animateFloat(0f, 1f,
        infiniteRepeatable(tween(2800, easing = LinearEasing), RepeatMode.Restart), "ring2")
    val scanline by inf.animateFloat(0f, 1f,
        infiniteRepeatable(tween(2500, easing = LinearEasing), RepeatMode.Restart), "scan")

    LaunchedEffect(profile.isReady) {
        if (profile.isReady) { delay(900); onComplete() }
    }

    Box(
        Modifier
            .fillMaxSize()
            .background(VoidBlack)
            .drawBehind {
                // Radial glow behind logo
                drawCircle(
                    brush  = Brush.radialGradient(
                        listOf(NeonBlue.copy(pulse * 0.15f), Color.Transparent),
                        radius = size.minDimension * 0.6f,
                        center = Offset(size.width * 0.5f, size.height * 0.3f)
                    ),
                    radius = size.minDimension * 0.6f,
                    center = Offset(size.width * 0.5f, size.height * 0.3f)
                )
                // Scanlines
                val lh = 3.dp.toPx(); val gap = 7.dp.toPx()
                val off = (scanline * (lh + gap)) % (lh + gap)
                var y = -off
                while (y < size.height) {
                    drawRect(NeonBlueMid.copy(0.015f), Offset(0f, y), Size(size.width, lh))
                    y += lh + gap
                }
            },
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {

            // ── Logo with neon rings ──────────────────────────────────────────
            Box(Modifier.size(180.dp), contentAlignment = Alignment.Center) {
                // Expanding ring 1
                Box(
                    Modifier
                        .size((120 + ring1 * 60).dp)
                        .alpha((1f - ring1) * 0.5f)
                        .drawBehind {
                            drawCircle(
                                color = NeonBlueMid,
                                style = Stroke(1.5.dp.toPx()),
                                radius = size.minDimension / 2f
                            )
                        }
                )
                // Expanding ring 2
                Box(
                    Modifier
                        .size((100 + ring2 * 80).dp)
                        .alpha((1f - ring2) * 0.4f)
                        .drawBehind {
                            drawCircle(
                                color = NeonCyan,
                                style = Stroke(1.dp.toPx()),
                                radius = size.minDimension / 2f
                            )
                        }
                )
                // Glow behind logo
                Box(
                    Modifier
                        .size(120.dp)
                        .drawBehind {
                            drawCircle(
                                brush  = Brush.radialGradient(
                                    listOf(NeonBlueMid.copy(pulse * 0.4f), Color.Transparent)
                                ),
                                radius = size.minDimension
                            )
                        }
                )
                // Logo — static, no rotation
                Image(
                    painter            = painterResource(R.mipmap.ic_launcher_foreground),
                    contentDescription = "AzlukPatcher",
                    modifier           = Modifier.size(110.dp)
                )
            }

            Spacer(Modifier.height(16.dp))

            // App name with neon glow text effect
            Text(
                "AzlukPatcher",
                color         = NeonWhite,
                fontSize      = 32.sp,
                fontWeight    = FontWeight.Black,
                letterSpacing = (-1).sp,
                modifier      = Modifier.drawBehind {
                    drawRect(
                        brush = Brush.horizontalGradient(
                            listOf(Color.Transparent, NeonBlueMid.copy(0.1f), Color.Transparent)
                        )
                    )
                }
            )

            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Box(
                    Modifier
                        .background(
                            Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)),
                            RoundedCornerShape(5.dp)
                        )
                        .padding(horizontal = 8.dp, vertical = 2.dp)
                ) {
                    Text("V10", color = VoidBlack, fontSize = 11.sp, fontWeight = FontWeight.Black)
                }
                Text("by Azluk", color = TextDim, fontSize = 11.sp)
            }

            Spacer(Modifier.height(44.dp))

            // ── System check card — neon styled ──────────────────────────────
            Box(
                Modifier
                    .width(310.dp)
                    .drawBehind {
                        drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(20.dp.toPx()))
                        drawRoundRect(
                            brush        = Brush.horizontalGradient(
                                listOf(NeonBlue.copy(0.3f), NeonBlueBright.copy(pulse * 0.6f), NeonBlue.copy(0.3f))
                            ),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(20.dp.toPx()),
                            style        = Stroke(1.dp.toPx())
                        )
                    }
                    .padding(18.dp)
            ) {
                Column(verticalArrangement = Arrangement.spacedBy(11.dp)) {
                    NeonCheckRow("System",      profile.androidApi > 0,
                        if (profile.androidApi > 0) "Android API ${profile.androidApi}" else "…")
                    NeonCheckRow("CPU",         profile.cpuCores > 0,
                        if (profile.cpuCores > 0) "${profile.cpuCores} cores · ${profile.arch}" else "…")
                    NeonCheckRow("RAM",         profile.ramTotalMb > 0,
                        if (profile.ramTotalMb > 0) "${profile.ramFreeMb}/${profile.ramTotalMb} MB" else "…")
                    NeonCheckRow("Storage",     profile.storageFreeGb > 0,
                        if (profile.storageFreeGb > 0) "${"%.1f".format(profile.storageFreeGb)} GB free" else "…")
                    NeonCheckRow("Root",        profile.isReady,
                        if (!profile.isReady) "…"
                        else if (profile.hasRoot) "✓ ${profile.rootMethod}" else "Not rooted")
                    NeonCheckRow("Performance", profile.isReady,
                        if (!profile.isReady) "…"
                        else when (profile.performanceTier) {
                            PerformanceTier.HIGH   -> "HIGH — parallel"
                            PerformanceTier.MEDIUM -> "MEDIUM"
                            PerformanceTier.LOW    -> "LOW — sequential"
                        })
                }
            }

            profile.warnings.forEach { w ->
                Spacer(Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Warning, null, tint = NeonOrange, modifier = Modifier.size(13.dp))
                    Text(w, color = NeonOrange, fontSize = 11.sp)
                }
            }

            Spacer(Modifier.height(28.dp))

            if (!profile.isReady) {
                Box(
                    Modifier
                        .width(200.dp)
                        .height(2.dp)
                        .drawBehind {
                            drawRect(DeepNavy2)
                            drawRect(
                                brush = Brush.horizontalGradient(
                                    listOf(Color.Transparent, NeonBlueBright, Color.Transparent)
                                ),
                                topLeft = Offset((1f - pulse) * size.width * 0.5f, 0f),
                                size    = Size(size.width * pulse, size.height)
                            )
                        }
                )
                Spacer(Modifier.height(10.dp))
                Text("Initializing engine…", color = TextDim, fontSize = 11.sp)
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.CheckCircle, null, tint = NeonGreen, modifier = Modifier.size(16.dp))
                    Text("READY", color = NeonGreen, fontSize = 13.sp, fontWeight = FontWeight.Black, letterSpacing = 2.sp)
                }
            }
        }
    }
}

@Composable
private fun NeonCheckRow(label: String, done: Boolean, value: String) {
    val alpha by animateFloatAsState(if (done) 1f else 0.4f, tween(400), label = "row_$label")
    Row(
        Modifier.fillMaxWidth().alpha(alpha),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment     = Alignment.CenterVertically
    ) {
        Text(label, color = TextDim, fontSize = 12.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                value,
                color      = if (done) NeonWhite else TextDim,
                fontSize   = 12.sp,
                fontWeight = if (done) FontWeight.SemiBold else FontWeight.Normal
            )
            if (done) {
                Icon(Icons.Default.CheckCircle, null, tint = NeonGreen, modifier = Modifier.size(13.dp))
            } else {
                CircularProgressIndicator(Modifier.size(11.dp), color = NeonBlueMid, strokeWidth = 1.5.dp)
            }
        }
    }
}
