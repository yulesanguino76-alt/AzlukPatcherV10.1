package com.azluk.patcher.ui.screens

import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.net.Uri
import android.provider.Settings
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.navigation.NavController
import com.google.accompanist.drawablepainter.rememberDrawablePainter
import com.azluk.patcher.core.*
import com.azluk.patcher.engine.ApkEngine
import com.azluk.patcher.ui.theme.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

data class AppDetails(
    val name: String, val pkg: String, val version: String, val versionCode: Long,
    val apkSize: Long, val installDate: Long, val updateDate: Long,
    val isSystem: Boolean, val isDebuggable: Boolean,
    val dataDir: String, val nativeLibDir: String,
    val targetSdk: Int, val minSdk: Int,
    val permissions: List<String>, val activities: List<String>,
    val services: List<String>, val receivers: List<String>,
    val icon: Drawable?
)

data class DetailScanUi(
    val loading: Boolean = false,
    val error: String? = null,
    val results: List<ScanResult> = emptyList()
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DetailScreen(pkg: String, navController: NavController) {
    val ctx = LocalContext.current
    val pm  = ctx.packageManager
    val inf = rememberInfiniteTransition(label = "detail_inf")
    val pulse by inf.animateFloat(
        0.4f, 0.9f,
        infiniteRepeatable(tween(1800, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "pulse"
    )

    val details = remember(pkg) {
        try {
            val ai = pm.getApplicationInfo(pkg, PackageManager.GET_META_DATA)
            val pi = pm.getPackageInfo(
                pkg,
                PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS
            )
            AppDetails(
                name         = pm.getApplicationLabel(ai).toString(),
                pkg          = pkg,
                version      = pi.versionName ?: "?",
                versionCode  = if (android.os.Build.VERSION.SDK_INT >= 28) pi.longVersionCode
                               else @Suppress("DEPRECATION") pi.versionCode.toLong(),
                apkSize      = File(ai.sourceDir).length(),
                installDate  = pi.firstInstallTime,
                updateDate   = pi.lastUpdateTime,
                isSystem     = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                isDebuggable = (ai.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
                dataDir      = ai.dataDir ?: "N/A",
                nativeLibDir = ai.nativeLibraryDir ?: "N/A",
                targetSdk    = ai.targetSdkVersion,
                minSdk       = if (android.os.Build.VERSION.SDK_INT >= 24) ai.minSdkVersion else 0,
                permissions  = pi.requestedPermissions?.toList() ?: emptyList(),
                activities   = pi.activities?.map { it.name.substringAfterLast(".") } ?: emptyList(),
                services     = pi.services?.map { it.name.substringAfterLast(".") } ?: emptyList(),
                receivers    = pi.receivers?.map { it.name.substringAfterLast(".") } ?: emptyList(),
                icon         = try { pm.getApplicationIcon(ai) } catch (_: Exception) { null }
            )
        } catch (e: Exception) { null }
    }

    if (details == null) {
        Box(Modifier.fillMaxSize().background(VoidBlack), contentAlignment = Alignment.Center) {
            Text("App not found", color = NeonRed)
        }
        return
    }

    val engine = remember(pkg) { ApkEngine(ctx) }
    var scanUi by remember(pkg) { mutableStateOf(DetailScanUi()) }
    LaunchedEffect(pkg) {
        scanUi = DetailScanUi(loading = true)
        scanUi = withContext(Dispatchers.IO) { runCatching { engine.scan(pkg) } }.fold(
            onSuccess = { DetailScanUi(results = it) },
            onFailure = { DetailScanUi(error = it.message ?: "Scan failed") }
        )
    }

    var activeTab by remember { mutableStateOf(0) }
    val fmt = remember { SimpleDateFormat("MMM d, yyyy", Locale.getDefault()) }

    Scaffold(
        containerColor = VoidBlack,
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        details.name, color = NeonWhite, fontWeight = FontWeight.Bold,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, null, tint = NeonBlueMid)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DeepNavy)
            )
        },
        bottomBar = {
            Box(
                Modifier
                    .fillMaxWidth()
                    .drawBehind {
                        drawRect(DeepNavy)
                        drawLine(
                            Brush.horizontalGradient(
                                listOf(Color.Transparent, NeonBlueBright.copy(pulse * 0.6f), Color.Transparent)
                            ),
                            Offset(0f, 0f), Offset(size.width, 0f), 1.dp.toPx()
                        )
                    }
                    .navigationBarsPadding()
                    .padding(12.dp)
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    // Launch
                    Box(
                        Modifier.weight(1f).height(44.dp)
                            .drawBehind {
                                drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                                drawRoundRect(NeonGreen.copy(0.4f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                            }
                            .clickable {
                                try { ctx.startActivity(pm.getLaunchIntentForPackage(pkg) ?: return@clickable) }
                                catch (_: Exception) {}
                            },
                        contentAlignment = Alignment.Center
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.PlayArrow, null, tint = NeonGreen, modifier = Modifier.size(16.dp))
                            Text("Launch", color = NeonGreen, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                    // Settings
                    Box(
                        Modifier.weight(1f).height(44.dp)
                            .drawBehind {
                                drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                                drawRoundRect(NeonBlue.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                            }
                            .clickable {
                                ctx.startActivity(
                                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$pkg"))
                                )
                            },
                        contentAlignment = Alignment.Center
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Settings, null, tint = TextSecondary, modifier = Modifier.size(15.dp))
                            Text("Settings", color = TextSecondary, fontSize = 13.sp)
                        }
                    }
                    // Patch
                    Box(
                        Modifier.weight(1.5f).height(44.dp)
                            .drawBehind {
                                drawRoundRect(
                                    Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)),
                                    cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx())
                                )
                            }
                            .clickable { navController.navigate("patch/$pkg") },
                        contentAlignment = Alignment.Center
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.Build, null, tint = VoidBlack, modifier = Modifier.size(16.dp))
                            Text("Patch", color = VoidBlack, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        }
                    }
                }
            }
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).background(VoidBlack)) {

            // App header
            Box(
                Modifier
                    .fillMaxWidth()
                    .drawBehind {
                        drawRect(Brush.verticalGradient(listOf(DeepNavy2, VoidBlack)))
                        drawLine(
                            Brush.horizontalGradient(
                                listOf(Color.Transparent, NeonBlueMid.copy(pulse * 0.5f), Color.Transparent)
                            ),
                            Offset(0f, size.height), Offset(size.width, size.height), 1.dp.toPx()
                        )
                    }
                    .padding(16.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier.size(66.dp).drawBehind {
                            drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(18.dp.toPx()))
                            drawRoundRect(NeonBlueMid.copy(0.4f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(18.dp.toPx()), style = Stroke(1.dp.toPx()))
                        },
                        contentAlignment = Alignment.Center
                    ) {
                        if (details.icon != null) {
                            androidx.compose.foundation.Image(
                                painter = rememberDrawablePainter(details.icon),
                                contentDescription = null, modifier = Modifier.size(56.dp)
                            )
                        } else {
                            Icon(Icons.Default.Android, null, Modifier.size(36.dp), tint = NeonBlueMid)
                        }
                    }
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(details.name, color = NeonWhite, fontWeight = FontWeight.Bold, fontSize = 16.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Text(details.pkg, color = TextDim, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
                        Spacer(Modifier.height(6.dp))
                        Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                            NeonDetailChip("v${details.version}", NeonBlueMid)
                            NeonDetailChip(fmtSz(details.apkSize), TextDim)
                            if (details.isSystem) NeonDetailChip("SYS", NeonOrange)
                            if (details.isDebuggable) NeonDetailChip("DEBUG", NeonGreen)
                        }
                    }
                }
            }

            // Tabs
            val tabs = listOf("Info", "Patches", "Permissions", "Components")
            Row(
                Modifier.fillMaxWidth().background(DeepNavy).padding(horizontal = 8.dp)
            ) {
                tabs.forEachIndexed { i, t ->
                    val sel = activeTab == i
                    Box(
                        Modifier.weight(1f)
                            .drawBehind {
                                if (sel) drawLine(
                                    Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)),
                                    Offset(0f, size.height), Offset(size.width, size.height), 2.dp.toPx()
                                )
                            }
                            .clickable { activeTab = i }
                            .padding(vertical = 12.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Text(
                            t,
                            color      = if (sel) NeonBlueBright else TextDim,
                            fontSize   = 12.sp,
                            fontWeight = if (sel) FontWeight.Bold else FontWeight.Normal
                        )
                    }
                }
            }

            when (activeTab) {
                0 -> DetailInfoTab(details, fmt)
                1 -> DetailPatchesTab(scanUi)
                2 -> DetailPermsTab(details.permissions)
                3 -> DetailComponentsTab(details)
            }
        }
    }
}

@Composable
private fun DetailInfoTab(d: AppDetails, fmt: SimpleDateFormat) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        NeonInfoSection("Package") {
            NeonInfoRow("Package",   d.pkg)
            NeonInfoRow("Version",   "${d.version} (${d.versionCode})")
            NeonInfoRow("APK Size",  fmtSz(d.apkSize))
            NeonInfoRow("Target SDK","API ${d.targetSdk}")
            NeonInfoRow("Min SDK",   "API ${d.minSdk}")
            NeonInfoRow("Type",      if (d.isSystem) "System" else "User App")
            NeonInfoRow("Debuggable",if (d.isDebuggable) "Yes" else "No")
        }
        NeonInfoSection("Timeline") {
            NeonInfoRow("Installed", fmt.format(Date(d.installDate)))
            NeonInfoRow("Updated",   fmt.format(Date(d.updateDate)))
        }
        NeonInfoSection("Paths") {
            NeonInfoRow("Data",   d.dataDir)
            NeonInfoRow("Native", d.nativeLibDir)
        }
    }
}

@Composable
private fun DetailPatchesTab(ui: DetailScanUi) {
    when {
        ui.loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                CircularProgressIndicator(Modifier.size(28.dp), color = NeonBlueBright, strokeWidth = 2.5.dp)
                Spacer(Modifier.height(10.dp))
                Text("Scanning DEX…", color = TextDim, fontSize = 12.sp)
            }
        }
        ui.error != null -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Icon(Icons.Default.ErrorOutline, null, Modifier.size(32.dp), tint = NeonRed)
                Spacer(Modifier.height(8.dp))
                Text(ui.error, color = NeonRed, fontSize = 12.sp)
            }
        }
        else -> {
            val detected = ui.results.mapNotNull {
                runCatching { PatchType.valueOf(it.patchType) }.getOrNull()
            }
            Column(
                Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(14.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Box(
                    Modifier.fillMaxWidth().drawBehind {
                        val c = if (detected.isEmpty()) NeonBlue.copy(0.2f) else NeonGreen.copy(0.4f)
                        drawRoundRect(
                            if (detected.isEmpty()) DeepNavy else NeonGreen.copy(0.08f),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx())
                        )
                        drawRoundRect(c, cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                    }.padding(14.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            if (detected.isEmpty()) Icons.Default.SearchOff else Icons.Default.CheckCircle,
                            null, Modifier.size(18.dp),
                            tint = if (detected.isEmpty()) TextDim else NeonGreen
                        )
                        Spacer(Modifier.width(10.dp))
                        Text(
                            if (detected.isEmpty()) "No patches auto-detected" else "${detected.size} patches available",
                            color = if (detected.isEmpty()) TextDim else NeonGreen,
                            fontWeight = FontWeight.SemiBold, fontSize = 13.sp
                        )
                    }
                }
                ui.results.forEach { r ->
                    val type = runCatching { PatchType.valueOf(r.patchType) }.getOrNull()
                    val c    = type?.let { catNeonColorDetail(it) } ?: TextDim
                    Box(
                        Modifier.fillMaxWidth().drawBehind {
                            drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx()))
                            drawRoundRect(c.copy(0.2f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                        }.padding(12.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(Modifier.size(8.dp).clip(CircleShape).background(c))
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(type?.displayName ?: r.patchType, color = NeonWhite, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                                r.desc?.let { Text(it, color = TextDim, fontSize = 10.sp, maxLines = 2) }
                            }
                        }
                    }
                }
            }
        }
    }
}

private fun catNeonColorDetail(t: PatchType) = when (t.category) {
    "bypass"   -> NeonBlueBright
    "ads"      -> NeonOrange
    "security" -> NeonRed
    "dev"      -> NeonCyan
    else       -> NeonGreen
}

@Composable
private fun DetailPermsTab(perms: List<String>) {
    if (perms.isEmpty()) {
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text("No permissions", color = TextDim) }
        return
    }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(5.dp)
    ) {
        Text("${perms.size} permissions", color = TextDim, fontSize = 11.sp, modifier = Modifier.padding(bottom = 4.dp))
        perms.forEach { p ->
            val danger = p.contains("READ_") || p.contains("WRITE_") || p.contains("LOCATION") ||
                         p.contains("CAMERA") || p.contains("CONTACTS") || p.contains("PHONE") || p.contains("SMS")
            val c = if (danger) NeonOrange else TextDim
            Box(
                Modifier.fillMaxWidth().drawBehind {
                    drawRoundRect(c.copy(if (danger) 0.07f else 0.04f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(8.dp.toPx()))
                    if (danger) drawRoundRect(c.copy(0.2f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(8.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                }.padding(10.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(Modifier.size(5.dp).clip(CircleShape).background(c))
                    Spacer(Modifier.width(10.dp))
                    Text(p.removePrefix("android.permission."), color = c, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
private fun DetailComponentsTab(d: AppDetails) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        DetailCompSection("Activities (${d.activities.size})",  Icons.Default.Window,        d.activities, NeonBlueMid)
        DetailCompSection("Services (${d.services.size})",      Icons.Default.Dns,           d.services,   NeonGreen)
        DetailCompSection("Receivers (${d.receivers.size})",    Icons.Default.Notifications, d.receivers,  NeonOrange)
    }
}

@Composable
private fun DetailCompSection(title: String, icon: ImageVector, items: List<String>, color: Color) {
    if (items.isEmpty()) return
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, null, Modifier.size(13.dp), tint = color)
            Spacer(Modifier.width(6.dp))
            Text(title, color = color, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
        }
        items.forEach { name ->
            Box(
                Modifier.fillMaxWidth().drawBehind {
                    drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(8.dp.toPx()))
                }.padding(horizontal = 10.dp, vertical = 7.dp)
            ) {
                Text(name, color = TextSecondary, fontSize = 11.sp, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
        }
    }
}

@Composable
private fun NeonInfoSection(title: String, content: @Composable ColumnScope.() -> Unit) {
    Box(
        Modifier.fillMaxWidth().drawBehind {
            drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
            drawRoundRect(NeonBlue.copy(0.2f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(0.5.dp.toPx()))
        }.padding(14.dp)
    ) {
        Column {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.width(2.dp).height(12.dp)
                        .background(Brush.verticalGradient(listOf(NeonBlueBright, NeonBlue.copy(0.3f))), RoundedCornerShape(1.dp))
                )
                Spacer(Modifier.width(8.dp))
                Text(title, color = NeonBlueBright, fontSize = 11.sp, fontWeight = FontWeight.Bold, letterSpacing = 0.5.sp)
            }
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
private fun NeonInfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = TextDim, fontSize = 11.sp)
        Text(value, color = NeonWhite, fontSize = 11.sp, fontWeight = FontWeight.Medium,
            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(max = 220.dp))
    }
}

@Composable
private fun NeonDetailChip(text: String, color: Color) {
    Box(
        Modifier.drawBehind {
            drawRoundRect(color.copy(0.12f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()))
            drawRoundRect(color.copy(0.3f),  cornerRadius = androidx.compose.ui.geometry.CornerRadius(6.dp.toPx()), style = Stroke(0.5.dp.toPx()))
        }.padding(horizontal = 7.dp, vertical = 3.dp)
    ) {
        Text(text, color = color, fontSize = 10.sp, fontWeight = FontWeight.SemiBold)
    }
}

private fun fmtSz(b: Long) = when {
    b < 1024          -> "$b B"
    b < 1024 * 1024   -> "%.1f KB".format(b / 1024f)
    b < 1024L*1024*1024 -> "%.1f MB".format(b / (1024f * 1024))
    else              -> "%.2f GB".format(b / (1024f * 1024 * 1024))
}
