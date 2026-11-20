package com.azluk.patcher.ui.screens

import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.*
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PatchViewModel

private fun patchIcon(type: PatchType) = when (type) {
    PatchType.LICENSE_BYPASS        -> Icons.Default.VerifiedUser
    PatchType.IAP_BYPASS            -> Icons.Default.ShoppingCart
    PatchType.SIGNATURE_BYPASS      -> Icons.Default.Fingerprint
    PatchType.GOOGLE_PLAY_BYPASS    -> Icons.Default.Shop
    PatchType.REMOVE_ADS            -> Icons.Default.Block
    PatchType.BLOCK_AD_DOMAINS      -> Icons.Default.Domain
    PatchType.SSL_BYPASS            -> Icons.Default.LockOpen
    PatchType.ROOT_BYPASS           -> Icons.Default.Security
    PatchType.SAFETYNET_BYPASS      -> Icons.Default.Shield
    PatchType.FRIDA_BYPASS          -> Icons.Default.BugReport
    PatchType.EMULATOR_BYPASS       -> Icons.Default.PhoneAndroid
    PatchType.FORCE_DEBUGGABLE      -> Icons.Default.Code
    PatchType.DISABLE_FLAG_SECURE   -> Icons.Default.ScreenshotMonitor
    PatchType.EXPORT_ALL_COMPONENTS -> Icons.Default.OpenInNew
    PatchType.ALLOW_BACKUP          -> Icons.Default.Backup
    PatchType.DISABLE_ANALYTICS     -> Icons.Default.Analytics
    PatchType.OPTIMIZE_ZIP          -> Icons.Default.Compress
    PatchType.REMOVE_TELEMETRY      -> Icons.Default.VisibilityOff
}

private fun catNeonColor(cat: String) = when (cat) {
    "bypass"   -> NeonBlueBright
    "ads"      -> NeonOrange
    "security" -> NeonRed
    "dev"      -> NeonCyan
    "util"     -> NeonGreen
    else       -> TextSecondary
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatchScreen(
    pkg: String,
    navController: NavController,
    vm: PatchViewModel = viewModel(LocalContext.current as ComponentActivity)
) {
    val state by vm.state.collectAsStateWithLifecycle()
    val inf   = rememberInfiniteTransition(label = "patch_inf")
    val pulse by inf.animateFloat(0.4f, 0.9f,
        infiniteRepeatable(tween(1800, easing = FastOutSlowInEasing), RepeatMode.Reverse), "pulse")

    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        uri?.let { vm.importAndScan(it) }
    }

    LaunchedEffect(pkg) { vm.ensureScanned(pkg) }

    val categories   = PatchType.values().groupBy { it.category }
    val catOrder     = listOf("bypass", "ads", "security", "dev", "util")
    val catLabels    = mapOf("bypass" to "Bypass", "ads" to "Ads & Tracking",
        "security" to "Anti-Detection", "dev" to "Developer", "util" to "Utility")
    val detectedTypes = state.scanResults
        .mapNotNull { runCatching { PatchType.valueOf(it.patchType) }.getOrNull() }.toSet()

    Scaffold(
        containerColor = VoidBlack,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(state.scannedFileName ?: "Select Patches",
                            color = NeonWhite, fontWeight = FontWeight.Bold)
                        Text(state.scannedFileName ?: pkg,
                            color = TextDim, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, null, tint = NeonBlueMid)
                    }
                },
                actions = {
                    IconButton(onClick = { filePicker.launch("*/*") }, enabled = !state.isScanning) {
                        Icon(Icons.Default.FolderOpen, null, tint = NeonBlueBright)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = DeepNavy,
                    titleContentColor = NeonWhite
                )
            )
        },
        bottomBar = {
            Box(
                Modifier
                    .fillMaxWidth()
                    .drawBehind {
                        drawRect(DeepNavy)
                        drawLine(
                            brush = Brush.horizontalGradient(
                                listOf(Color.Transparent, NeonBlueBright.copy(pulse * 0.8f), Color.Transparent)
                            ),
                            start = Offset(0f, 0f), end = Offset(size.width, 0f),
                            strokeWidth = 1.dp.toPx()
                        )
                    }
                    .navigationBarsPadding()
                    .padding(14.dp)
            ) {
                Column {
                    if (state.scanResults.isNotEmpty()) {
                        Row(
                            Modifier.fillMaxWidth().padding(bottom = 10.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(Icons.Default.Analytics, null, tint = NeonBlueBright, modifier = Modifier.size(15.dp))
                            Text("${state.scanResults.size} targets detected",
                                color = NeonBlueBright, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                        // Scan button
                        Box(
                            Modifier
                                .weight(1f)
                                .height(46.dp)
                                .drawBehind {
                                    drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                                    drawRoundRect(
                                        NeonBlue.copy(0.5f),
                                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()),
                                        style = Stroke(1.dp.toPx())
                                    )
                                }
                                .clickable(enabled = !state.isScanning && state.scannedFile == null) { vm.scan(pkg) },
                            contentAlignment = Alignment.Center
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                if (state.isScanning) {
                                    CircularProgressIndicator(Modifier.size(14.dp), color = NeonBlueBright, strokeWidth = 2.dp)
                                } else {
                                    Icon(Icons.Default.Search, null, tint = NeonBlueBright, modifier = Modifier.size(16.dp))
                                }
                                Text("Scan", color = NeonBlueBright, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }

                        // Patch button
                        val patchEnabled = state.selectedPatches.isNotEmpty() && !state.isScanning
                        Box(
                            Modifier
                                .weight(2f)
                                .height(46.dp)
                                .drawBehind {
                                    if (patchEnabled) {
                                        drawRoundRect(
                                            Brush.horizontalGradient(listOf(NeonBlue, NeonBlueMid, NeonBlueBright)),
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx())
                                        )
                                    } else {
                                        drawRoundRect(
                                            DeepNavy2,
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx())
                                        )
                                    }
                                }
                                .clickable(enabled = patchEnabled) {
                                    vm.resetPatch()
                                    vm.patchActiveSource(pkg)
                                    navController.navigate("patchlog/$pkg")
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Build, null,
                                    tint     = if (patchEnabled) VoidBlack else TextDim,
                                    modifier = Modifier.size(16.dp))
                                Text(
                                    "Patch (${state.selectedPatches.size})",
                                    color      = if (patchEnabled) VoidBlack else TextDim,
                                    fontWeight = FontWeight.Bold,
                                    fontSize   = 14.sp
                                )
                            }
                        }
                    }
                }
            }
        }
    ) { padding ->
        LazyColumn(
            modifier            = Modifier.fillMaxSize().padding(padding).background(VoidBlack),
            contentPadding      = PaddingValues(14.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            // Imported file banner
            state.scannedFileName?.let { fn ->
                item {
                    NeonInfoBanner(NeonOrange, Icons.Default.FolderZip, "Imported: $fn")
                }
            }

            // Auto-detected banner
            if (detectedTypes.isNotEmpty()) {
                item {
                    Box(
                        Modifier
                            .fillMaxWidth()
                            .drawBehind {
                                drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()))
                                drawRoundRect(
                                    NeonBlueBright.copy(0.4f),
                                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                                    style = Stroke(1.dp.toPx())
                                )
                            }
                            .padding(14.dp)
                    ) {
                        Row(
                            Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.AutoAwesome, null, tint = NeonBlueBright, modifier = Modifier.size(18.dp))
                                Column {
                                    Text("${detectedTypes.size} patches detected",
                                        color = NeonBlueBright, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                    Text(detectedTypes.take(3).joinToString(", ") { it.displayName } +
                                        if (detectedTypes.size > 3) "…" else "",
                                        color = TextDim, fontSize = 10.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                }
                            }
                            Box(
                                Modifier
                                    .drawBehind {
                                        drawRoundRect(
                                            NeonBlueBright.copy(0.15f),
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx())
                                        )
                                    }
                                    .clickable { vm.selectAll(detectedTypes) }
                                    .padding(horizontal = 10.dp, vertical = 5.dp)
                            ) {
                                Text("Select All", color = NeonBlueBright, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }
                }
            }

            // Scan error
            state.scanError?.let { err ->
                item { NeonInfoBanner(NeonRed, Icons.Default.Warning, "Scan failed: $err") }
            }

            // Categories
            for (cat in catOrder) {
                val types = categories[cat] ?: continue
                val color = catNeonColor(cat)

                item {
                    Row(
                        verticalAlignment     = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(6.dp),
                        modifier              = Modifier.padding(top = 8.dp, bottom = 4.dp)
                    ) {
                        Box(Modifier.width(3.dp).height(14.dp).background(
                            Brush.verticalGradient(listOf(color, color.copy(0.3f))),
                            RoundedCornerShape(2.dp)
                        ))
                        Text(catLabels[cat] ?: cat.uppercase(),
                            color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 1.sp)
                        Spacer(Modifier.weight(1f))
                        Text("${types.size}", color = TextDim, fontSize = 10.sp)
                    }
                }

                items(types) { type ->
                    val selected    = type in state.selectedPatches
                    val wasDetected = type in detectedTypes
                    val color2      = catNeonColor(type.category)
                    val scale by animateFloatAsState(
                        if (selected) 1f else 0.98f,
                        spring(Spring.DampingRatioMediumBouncy), label = "s_${type.name}"
                    )

                    Box(
                        Modifier
                            .fillMaxWidth()
                            .graphicsLayer { scaleX = scale; scaleY = scale }
                            .drawBehind {
                                drawRoundRect(
                                    if (selected) color2.copy(0.12f) else DeepNavy,
                                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx())
                                )
                                drawRoundRect(
                                    if (selected) color2.copy(0.6f) else NeonBlue.copy(0.2f),
                                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                                    style = Stroke(if (selected) 1.5.dp.toPx() else 0.5.dp.toPx())
                                )
                                if (selected) {
                                    // Neon left bar
                                    drawRoundRect(
                                        color2,
                                        topLeft = Offset(0f, size.height * 0.15f),
                                        size    = Size(3.dp.toPx(), size.height * 0.7f),
                                        cornerRadius = androidx.compose.ui.geometry.CornerRadius(2.dp.toPx())
                                    )
                                }
                            }
                            .clickable { vm.togglePatch(type) }
                    ) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier
                                    .size(44.dp)
                                    .drawBehind {
                                        drawRoundRect(
                                            color2.copy(0.14f),
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx())
                                        )
                                        drawRoundRect(
                                            color2.copy(0.3f),
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx()),
                                            style = Stroke(0.5.dp.toPx())
                                        )
                                    },
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(patchIcon(type), null, tint = color2, modifier = Modifier.size(22.dp))
                            }

                            Spacer(Modifier.width(12.dp))

                            Column(Modifier.weight(1f)) {
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Text(type.displayName, color = NeonWhite, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                                    if (wasDetected) {
                                        Box(
                                            Modifier
                                                .drawBehind {
                                                    drawRoundRect(NeonGreen.copy(0.15f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(4.dp.toPx()))
                                                    drawRoundRect(NeonGreen.copy(0.4f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(4.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                                                }
                                                .padding(horizontal = 5.dp, vertical = 2.dp)
                                        ) {
                                            Text("FOUND", color = NeonGreen, fontSize = 9.sp, fontWeight = FontWeight.Black, letterSpacing = 0.5.sp)
                                        }
                                    }
                                }
                                Text(type.description, color = TextDim, fontSize = 11.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            }

                            Checkbox(
                                checked         = selected,
                                onCheckedChange = { vm.togglePatch(type) },
                                colors          = CheckboxDefaults.colors(
                                    checkedColor   = color2,
                                    uncheckedColor = TextDim.copy(0.4f),
                                    checkmarkColor = VoidBlack
                                )
                            )
                        }
                    }
                }
            }
            item { Spacer(Modifier.height(10.dp)) }
        }
    }
}

@Composable
fun NeonInfoBanner(color: Color, icon: androidx.compose.ui.graphics.vector.ImageVector, text: String) {
    Box(
        Modifier
            .fillMaxWidth()
            .drawBehind {
                drawRoundRect(color.copy(0.08f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                drawRoundRect(color.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(1.dp.toPx()))
            }
            .padding(12.dp)
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, tint = color, modifier = Modifier.size(16.dp))
            Text(text, color = color.copy(0.9f), fontSize = 12.sp, modifier = Modifier.weight(1f), maxLines = 2, overflow = TextOverflow.Ellipsis)
        }
    }
}
