package com.azluk.patcher.ui.screens

import android.graphics.drawable.Drawable
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.R
import com.azluk.patcher.core.AppInfo
import com.azluk.patcher.core.PatchStatus
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.MainViewModel
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import kotlin.random.Random

private val STICKER_DRAWABLES = listOf(
    R.drawable.azluk_sticker_greeting,
    R.drawable.azluk_sticker_determined,
    R.drawable.azluk_sticker_thinking,
    R.drawable.azluk_sticker_excited,
    R.drawable.azluk_sticker_confident,
    R.drawable.azluk_sticker_smug,
    R.drawable.azluk_sticker_processing,
    R.drawable.azluk_sticker_angry,
    R.drawable.azluk_sticker_happy,
    R.drawable.azluk_sticker_achievement,
)

private fun pickSticker(apps: List<AppInfo>, isLoading: Boolean, isScanning: Boolean): Int {
    return when {
        isLoading                                                              -> R.drawable.azluk_sticker_determined
        isScanning                                                             -> R.drawable.azluk_sticker_processing
        apps.isEmpty()                                                         -> R.drawable.azluk_sticker_angry
        apps.count { it.patchStatus == PatchStatus.PATCHABLE } > 10           -> R.drawable.azluk_sticker_achievement
        apps.count { it.patchStatus == PatchStatus.PATCHABLE } > 0            -> R.drawable.azluk_sticker_excited
        else -> STICKER_DRAWABLES[Random.nextInt(STICKER_DRAWABLES.size)]
    }
}

@Composable
fun HomeScreen(navController: NavController, vm: MainViewModel = viewModel()) {
    val state by vm.state.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { vm.load() }

    val stickerRes = remember(state.filteredApps.size, state.isLoading, state.isScanning) {
        pickSticker(state.filteredApps, state.isLoading, state.isScanning)
    }

    val inf = rememberInfiniteTransition(label = "ambient")
    val glowPulse by inf.animateFloat(
        0.4f, 0.9f,
        infiniteRepeatable(tween(2200, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "glow"
    )
    val scanlinePulse by inf.animateFloat(
        0f, 1f,
        infiniteRepeatable(tween(3000, easing = LinearEasing), RepeatMode.Restart),
        label = "scan"
    )

    Box(
        Modifier
            .fillMaxSize()
            .background(VoidBlack)
            .drawBehind {
                drawCircle(
                    brush  = Brush.radialGradient(
                        listOf(NeonBlue.copy(glowPulse * 0.08f), Color.Transparent),
                        radius = size.width * 0.7f,
                        center = Offset(size.width * 0.1f, 0f)
                    ),
                    radius = size.width * 0.7f,
                    center = Offset(size.width * 0.1f, 0f)
                )
                val lineH = 4.dp.toPx()
                val gap   = 8.dp.toPx()
                val offset = (scanlinePulse * (lineH + gap)) % (lineH + gap)
                var y = -offset
                while (y < size.height) {
                    drawRect(NeonBlueMid.copy(0.012f), Offset(0f, y), Size(size.width, lineH))
                    y += lineH + gap
                }
            }
            .systemBarsPadding()
    ) {
        Column(Modifier.fillMaxSize()) {
            NeonHeader(state, vm, stickerRes, glowPulse)

            Box(Modifier.weight(1f)) {
                when {
                    state.isLoading -> {
                        Column(
                            Modifier.fillMaxSize(),
                            verticalArrangement   = Arrangement.Center,
                            horizontalAlignment   = Alignment.CenterHorizontally
                        ) {
                            CircularProgressIndicator(color = NeonBlueMid, strokeWidth = 2.dp, modifier = Modifier.size(40.dp))
                            Spacer(Modifier.height(16.dp))
                            Text("Loading apps…", color = TextSecondary, fontSize = 13.sp)
                        }
                    }
                    state.filteredApps.isEmpty() && !state.isLoading -> {
                        Column(
                            Modifier.fillMaxSize(),
                            verticalArrangement   = Arrangement.Center,
                            horizontalAlignment   = Alignment.CenterHorizontally
                        ) {
                            Icon(Icons.Default.SearchOff, null, tint = NeonBlue.copy(0.5f), modifier = Modifier.size(56.dp))
                            Spacer(Modifier.height(12.dp))
                            Text("No apps found", color = TextSecondary, fontSize = 15.sp)
                        }
                    }
                    else -> {
                        LazyColumn(
                            contentPadding      = PaddingValues(horizontal = 14.dp, vertical = 8.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            item {
                                NeonStatsBanner(state.filteredApps)
                                Spacer(Modifier.height(4.dp))
                            }
                            items(state.filteredApps, key = { it.packageName }) { app ->
                                NeonAppCard(app) { navController.navigate("detail/${app.packageName}") }
                            }
                            item { Spacer(Modifier.height(80.dp)) }
                        }
                    }
                }
                if (state.isScanning) NeonScanBar(Modifier.align(Alignment.BottomCenter))
            }
        }
    }
}

@Composable
private fun NeonHeader(
    state:      com.azluk.patcher.viewmodel.MainUiState,
    vm:         MainViewModel,
    stickerRes: Int,
    glowPulse:  Float
) {
    Box(
        Modifier
            .fillMaxWidth()
            .background(Brush.verticalGradient(listOf(DeepNavy2.copy(0.95f), DeepNavy.copy(0.7f), Color.Transparent)))
            .drawBehind {
                drawLine(
                    brush = Brush.horizontalGradient(
                        listOf(
                            Color.Transparent,
                            NeonBlue.copy(glowPulse * 0.5f),
                            NeonBlueBright.copy(glowPulse * 0.8f),
                            NeonBlueMid.copy(glowPulse),
                            NeonBlueBright.copy(glowPulse * 0.8f),
                            NeonBlue.copy(glowPulse * 0.5f),
                            Color.Transparent
                        )
                    ),
                    start       = Offset(0f, size.height),
                    end         = Offset(size.width, size.height),
                    strokeWidth = 1.5.dp.toPx()
                )
            }
    ) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {

            Row(
                Modifier.fillMaxWidth(),
                verticalAlignment     = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                    Box(
                        Modifier.size(58.dp).drawBehind {
                            drawCircle(
                                brush  = Brush.radialGradient(listOf(NeonBlueMid.copy(glowPulse * 0.35f), Color.Transparent)),
                                radius = size.minDimension * 0.75f
                            )
                        },
                        contentAlignment = Alignment.Center
                    ) {
                        Image(
                            painter            = painterResource(stickerRes),
                            contentDescription = "Azluk",
                            modifier           = Modifier.size(52.dp)
                        )
                    }
                    Column {
                        Text("AzlukPatcher", color = NeonWhite, fontSize = 22.sp, fontWeight = FontWeight.Black, letterSpacing = (-0.5).sp)
                        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier.background(Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)), RoundedCornerShape(4.dp))
                                    .padding(horizontal = 6.dp, vertical = 1.dp)
                            ) {
                                Text("V10", color = VoidBlack, fontSize = 10.sp, fontWeight = FontWeight.Black)
                            }
                            Text("by Azluk", color = TextDim, fontSize = 10.sp)
                        }
                    }
                }
                Box(
                    Modifier.size(38.dp).drawBehind {
                        drawCircle(brush = Brush.radialGradient(listOf(NeonBlueMid.copy(0.2f), Color.Transparent)), radius = size.minDimension)
                    }.clip(CircleShape).clickable { vm.refresh() },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.Refresh, null, tint = NeonBlueMid, modifier = Modifier.size(20.dp))
                }
            }

            Spacer(Modifier.height(14.dp))

            // Search bar
            Box(
                Modifier.fillMaxWidth().height(44.dp).drawBehind {
                    drawRoundRect(
                        brush        = Brush.horizontalGradient(listOf(NeonBlue.copy(0.4f), NeonBlueBright.copy(0.7f), NeonBlue.copy(0.4f))),
                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(22.dp.toPx()),
                        style        = Stroke(1.5.dp.toPx())
                    )
                    drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(22.dp.toPx()))
                }
            ) {
                Row(Modifier.fillMaxSize().padding(horizontal = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Search, null, tint = NeonBlueMid, modifier = Modifier.size(17.dp))
                    Spacer(Modifier.width(10.dp))
                    BasicTextField(
                        value         = state.query,
                        onValueChange = vm::setQuery,
                        singleLine    = true,
                        textStyle     = TextStyle(color = NeonWhite, fontSize = 14.sp),
                        modifier      = Modifier.weight(1f),
                        decorationBox = @Composable { inner ->
                            if (state.query.isEmpty()) Text("Search apps, packages…", color = TextDim, fontSize = 14.sp)
                            inner()
                        }
                    )
                    if (state.query.isNotEmpty()) {
                        Icon(Icons.Default.Close, null, tint = TextDim, modifier = Modifier.size(16.dp).clickable { vm.setQuery("") })
                    }
                }
            }

            Spacer(Modifier.height(10.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                listOf("User", "System", "All").forEachIndexed { i, label ->
                    val sel = state.filter == i
                    Box(
                        Modifier.drawBehind {
                            if (sel) drawRoundRect(Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)), cornerRadius = androidx.compose.ui.geometry.CornerRadius(20.dp.toPx()))
                            else {
                                drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(20.dp.toPx()))
                                drawRoundRect(NeonBlue.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(20.dp.toPx()), style = Stroke(1.dp.toPx()))
                            }
                        }.clickable { vm.setFilter(i) }.padding(horizontal = 14.dp, vertical = 7.dp)
                    ) {
                        Text(label, color = if (sel) VoidBlack else TextSecondary, fontSize = 12.sp, fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal)
                    }
                }
                Spacer(Modifier.weight(1f))
                Text("${state.filteredApps.size} apps", color = TextDim, fontSize = 11.sp, modifier = Modifier.align(Alignment.CenterVertically))
            }
        }
    }
}

@Composable
private fun NeonStatsBanner(apps: List<AppInfo>) {
    val patchable = apps.count { it.patchStatus == PatchStatus.PATCHABLE }
    val likely    = apps.count { it.patchStatus == PatchStatus.LIKELY }
    val complex   = apps.count { it.patchStatus == PatchStatus.COMPLEX }

    Box(
        Modifier.fillMaxWidth().drawBehind {
            drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()))
            drawRoundRect(
                Brush.horizontalGradient(listOf(NeonBlue.copy(0.3f), NeonBlueBright.copy(0.5f), NeonBlue.copy(0.3f))),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                style        = Stroke(1.dp.toPx())
            )
        }.padding(horizontal = 14.dp, vertical = 12.dp)
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
            NeonStat("$patchable", "Patchable", NeonGreen)
            Box(Modifier.width(1.dp).height(30.dp).background(NeonBlue.copy(0.25f)))
            NeonStat("$likely",   "Likely",    NeonBlueBright)
            Box(Modifier.width(1.dp).height(30.dp).background(NeonBlue.copy(0.25f)))
            NeonStat("$complex",  "Complex",   NeonOrange)
        }
    }
}

@Composable
private fun NeonStat(value: String, label: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Text(value, color = color, fontSize = 24.sp, fontWeight = FontWeight.Black,
            modifier = Modifier.drawBehind {
                drawCircle(brush = Brush.radialGradient(listOf(color.copy(0.2f), Color.Transparent)), radius = size.maxDimension * 0.9f)
            })
        Text(label, color = TextDim, fontSize = 10.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
fun NeonAppCard(app: AppInfo, onClick: () -> Unit) {
    val statusColor = when (app.patchStatus) {
        PatchStatus.PATCHABLE -> NeonGreen
        PatchStatus.LIKELY    -> NeonBlueMid
        PatchStatus.COMPLEX   -> NeonOrange
        PatchStatus.UNKNOWN   -> TextDim
    }

    Box(
        Modifier.fillMaxWidth().drawBehind {
            drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(18.dp.toPx()))
            drawRoundRect(statusColor.copy(0.4f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(18.dp.toPx()), style = Stroke(1.dp.toPx()))
            drawRoundRect(
                statusColor.copy(0.85f),
                topLeft      = Offset(0f, size.height * 0.2f),
                size         = Size(3.dp.toPx(), size.height * 0.6f),
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx())
            )
            drawRect(
                brush   = Brush.horizontalGradient(listOf(statusColor.copy(0.07f), Color.Transparent), endX = size.width * 0.3f),
                topLeft = Offset(3.dp.toPx(), 0f),
                size    = Size(size.width * 0.3f, size.height)
            )
        }.clickable(onClick = onClick)
    ) {
        Row(Modifier.padding(start = 14.dp, top = 11.dp, bottom = 11.dp, end = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Box(contentAlignment = Alignment.Center, modifier = Modifier.size(50.dp)) {
                Box(Modifier.size(50.dp).drawBehind {
                    drawCircle(brush = Brush.radialGradient(listOf(statusColor.copy(0.18f), Color.Transparent)), radius = size.minDimension)
                })
                Box(Modifier.size(44.dp).clip(RoundedCornerShape(12.dp)).background(DeepNavy2), contentAlignment = Alignment.Center) {
                    if (app.icon != null) {
                        Image(painter = rememberDrawablePainter(app.icon), contentDescription = app.appName, modifier = Modifier.size(40.dp))
                    } else {
                        Icon(Icons.Default.Android, null, tint = NeonBlueMid, modifier = Modifier.size(24.dp))
                    }
                }
            }
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Text(app.appName, color = NeonWhite, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(app.packageName, color = TextDim, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Spacer(Modifier.height(4.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                    NeonStatusChip(app.patchStatus, app.opportunityCount)
                    if (app.isSystemApp) NeonMiniTagHome("SYS", NeonOrange)
                    if (app.apkSizeMb > 0) NeonMiniTagHome("%.0fM".format(app.apkSizeMb), TextDim)
                }
            }
            Icon(Icons.Default.ChevronRight, null, tint = statusColor.copy(0.6f), modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun NeonMiniTagHome(text: String, color: Color) {
    Box(
        Modifier.drawBehind {
            drawRoundRect(color.copy(0.1f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(5.dp.toPx()))
            drawRoundRect(color.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(5.dp.toPx()), style = Stroke(0.5.dp.toPx()))
        }.padding(horizontal = 5.dp, vertical = 2.dp)
    ) {
        Text(text, color = color, fontSize = 9.sp, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
fun NeonStatusChip(status: PatchStatus, count: Int) {
    val (color, label, icon) = when (status) {
        PatchStatus.PATCHABLE -> Triple(NeonGreen,   "Patchable${if (count > 0) " ($count)" else ""}", Icons.Default.CheckCircle)
        PatchStatus.LIKELY    -> Triple(NeonBlueMid, "Likely",     Icons.Default.TipsAndUpdates)
        PatchStatus.COMPLEX   -> Triple(NeonOrange,  "Complex",    Icons.Default.Warning)
        PatchStatus.UNKNOWN   -> Triple(TextDim,     "Scanning",   Icons.Default.HourglassEmpty)
    }
    Box(
        Modifier.drawBehind {
            drawRoundRect(color.copy(0.1f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()))
            drawRoundRect(color.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()), style = Stroke(0.5.dp.toPx()))
        }.padding(horizontal = 6.dp, vertical = 3.dp)
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = color, modifier = Modifier.size(10.dp))
            Text(label, color = color, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}

@Composable
private fun NeonScanBar(modifier: Modifier = Modifier) {
    val inf = rememberInfiniteTransition(label = "scan")
    val progress by inf.animateFloat(
        0f, 1f,
        infiniteRepeatable(tween(2000, easing = LinearEasing), RepeatMode.Restart),
        label = "prog"
    )
    Box(
        modifier.fillMaxWidth().drawBehind {
            drawRect(DeepNavy.copy(0.97f))
            drawLine(
                brush = Brush.horizontalGradient(listOf(Color.Transparent, NeonBlueBright, Color.Transparent)),
                start = Offset(0f, 0f), end = Offset(size.width, 0f), strokeWidth = 1.dp.toPx()
            )
        }.padding(horizontal = 16.dp, vertical = 9.dp)
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            CircularProgressIndicator(Modifier.size(13.dp), color = NeonBlueBright, strokeWidth = 2.dp)
            LinearProgressIndicator(
                progress   = { progress },
                modifier   = Modifier.weight(1f).height(2.dp).clip(CircleShape),
                color      = NeonBlueBright,
                trackColor = DeepNavy2
            )
            Text("Scanning…", color = NeonBlueMid, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
        }
    }
}
