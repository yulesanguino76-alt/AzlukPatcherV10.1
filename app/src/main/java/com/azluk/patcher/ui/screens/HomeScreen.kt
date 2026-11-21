package com.azluk.patcher.ui.screens

import android.content.*
import android.content.pm.PackageInstaller
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.*
import androidx.compose.ui.draw.*
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.*
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.*
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.InstallState
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.utils.StorageUtils
import com.azluk.patcher.viewmodel.PatchViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatchedFilesScreen(navController: NavController, vm: PatchViewModel = viewModel()) {
    val ctx     = LocalContext.current
    val state   by vm.state.collectAsState()
    var files   by remember { mutableStateOf<List<File>>(emptyList()) }
    val fmt     = SimpleDateFormat("MMM d, HH:mm", Locale.getDefault())
    val mainH   = Handler(Looper.getMainLooper())
    var activeFile by remember { mutableStateOf<String?>(null) }
    val installLog = remember { mutableStateListOf<String>() }
    var showLog    by remember { mutableStateOf(false) }
    val logState   = rememberLazyListState()

    fun log(line: String) { mainH.post { installLog.add(line) } }

    val inf = rememberInfiniteTransition(label = "pf_inf")
    val pulse by inf.animateFloat(
        0.4f, 0.9f,
        infiniteRepeatable(tween(1800, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "pulse"
    )

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val r = runCatching { StorageUtils.getPatchedFiles() }.getOrDefault(emptyList())
            withContext(Dispatchers.Main) { files = r }
        }
    }
    LaunchedEffect(installLog.size) {
        if (installLog.isNotEmpty()) logState.animateScrollToItem(installLog.size - 1)
    }

    DisposableEffect(Unit) {
        val filter   = IntentFilter("com.azluk.patcher.INSTALL_RESULT_LOCAL")
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
                val msg    = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                when (status) {
                    PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                        installLog.add("⏳ Waiting for user confirmation…")
                        val confirm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                            i.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                        else @Suppress("DEPRECATION") i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                        confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        confirm?.let { ctx.startActivity(it) }
                    }
                    else -> {
                        vm.onInstallResult(status, msg)
                        installLog.add(
                            if (status == PackageInstaller.STATUS_SUCCESS) "✅ Installation complete!"
                            else "❌ Failed: ${msg ?: "code $status"}"
                        )
                        activeFile = null
                    }
                }
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            ctx.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else ctx.registerReceiver(receiver, filter)
        onDispose { ctx.unregisterReceiver(receiver) }
    }

    fun refresh() { files = runCatching { StorageUtils.getPatchedFiles() }.getOrDefault(emptyList()) }
    fun isContainer(f: File) = f.extension.lowercase() in setOf("xapk", "apkm", "apks")

    fun doInstallWithLog(file: File) {
        activeFile = file.absolutePath; installLog.clear(); showLog = true
        installLog.add("🚀 Installing: ${file.name}")
        installLog.add("📦 Size: ${"%.1f".format(file.length() / 1048576f)} MB")
        try {
            val pi     = ctx.packageManager.packageInstaller
            val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
            val sid    = pi.createSession(params)
            val s      = pi.openSession(sid)
            installLog.add("🔧 Session #$sid created")
            java.io.FileInputStream(file).use { fis ->
                s.openWrite("base.apk", 0, file.length()).use { os -> fis.copyTo(os, 65536); s.fsync(os) }
            }
            installLog.add("✅ APK written")
            val ri = Intent("com.azluk.patcher.INSTALL_RESULT").apply { setPackage(ctx.packageName) }
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_MUTABLE
            else android.app.PendingIntent.FLAG_UPDATE_CURRENT
            s.commit(android.app.PendingIntent.getBroadcast(ctx, sid, ri, flags).intentSender)
            s.close()
            installLog.add("⏳ Waiting for Android installer…")
        } catch (e: Exception) {
            installLog.add("❌ ${e.message}"); activeFile = null; vm.onInstallResult(-1, e.message)
        }
    }

    fun doInstallContainerWithLog(file: File) {
        activeFile = file.absolutePath; installLog.clear(); showLog = true
        log("🚀 Container install: ${file.name}")
        log("📦 Size: ${"%.1f".format(file.length() / 1048576f)} MB")
        Thread {
            var session: PackageInstaller.Session? = null; var sid = -1
            try {
                val pi     = ctx.packageManager.packageInstaller
                val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
                sid        = pi.createSession(params)
                val s      = pi.openSession(sid); session = s
                log("🔧 Session #$sid"); var count = 0
                java.util.zip.ZipInputStream(java.io.BufferedInputStream(java.io.FileInputStream(file), 256 * 1024)).use { zip ->
                    while (true) {
                        val e = zip.nextEntry ?: break
                        if (!e.isDirectory && e.name.endsWith(".apk", true)) {
                            s.openWrite("split_$count.apk", 0, if (e.size > 0) e.size else -1L).use { os ->
                                zip.copyTo(os, 65536); s.fsync(os)
                            }
                            count++; log("  ✅ ${e.name}")
                        }
                        zip.closeEntry()
                    }
                }
                if (count == 0) throw IllegalStateException("No APK files in container")
                log("📦 $count APKs staged")
                val ri = Intent("com.azluk.patcher.INSTALL_RESULT").apply { setPackage(ctx.packageName) }
                val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_MUTABLE
                else android.app.PendingIntent.FLAG_UPDATE_CURRENT
                s.commit(android.app.PendingIntent.getBroadcast(ctx, sid, ri, flags).intentSender)
                s.close(); session = null
                log("⏳ Waiting for Android installer…")
            } catch (e: Exception) {
                try { session?.abandon() } catch (_: Exception) {}
                log("❌ ${e.message}")
                mainH.post { activeFile = null; vm.onInstallResult(-1, e.message) }
            }
        }.start()
    }

    fun doInstallAuto(file: File) {
        if (isContainer(file)) doInstallContainerWithLog(file) else doInstallWithLog(file)
    }

    Scaffold(
        containerColor = VoidBlack,
        topBar = {
            TopAppBar(
                title = { Text("Patched Files", color = NeonWhite, fontWeight = FontWeight.Bold) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.Default.ArrowBack, null, tint = NeonBlueMid)
                    }
                },
                actions = {
                    IconButton(onClick = ::refresh) {
                        Icon(Icons.Default.Refresh, null, tint = NeonBlueMid)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = DeepNavy)
            )
        }
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).background(VoidBlack)) {

            // Install log panel
            AnimatedVisibility(showLog, enter = expandVertically() + fadeIn(), exit = shrinkVertically() + fadeOut()) {
                Box(
                    Modifier.fillMaxWidth().drawBehind {
                        drawRect(DeepNavy)
                        drawLine(
                            Brush.horizontalGradient(listOf(Color.Transparent, NeonBlueBright.copy(pulse * 0.6f), Color.Transparent)),
                            Offset(0f, size.height), Offset(size.width, size.height), 1.dp.toPx()
                        )
                    }.padding(12.dp)
                ) {
                    Column {
                        Row(
                            Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment     = Alignment.CenterVertically
                        ) {
                            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Box(Modifier.size(7.dp).background(NeonRed, RoundedCornerShape(4.dp)))
                                Box(Modifier.size(7.dp).background(NeonOrange, RoundedCornerShape(4.dp)))
                                Box(Modifier.size(7.dp).background(NeonGreen, RoundedCornerShape(4.dp)))
                                Spacer(Modifier.width(4.dp))
                                if (activeFile != null) {
                                    CircularProgressIndicator(Modifier.size(12.dp), color = NeonBlueBright, strokeWidth = 1.5.dp)
                                } else {
                                    Icon(Icons.Default.Terminal, null, tint = NeonBlueMid, modifier = Modifier.size(12.dp))
                                }
                                Text("Install Log", color = TextSecondary, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                            }
                            Icon(Icons.Default.Close, null, tint = TextDim,
                                modifier = Modifier.size(16.dp).clickable { showLog = false })
                        }
                        Spacer(Modifier.height(6.dp))
                        Box(Modifier.fillMaxWidth().height(0.5.dp).background(NeonBlue.copy(0.3f)))
                        Spacer(Modifier.height(6.dp))

                        Box(Modifier.heightIn(max = 150.dp)) {
                            LazyColumn(state = logState) {
                                items(installLog) { line ->
                                    Text(
                                        line,
                                        color = when {
                                            line.contains("✅") || line.contains("complete") -> NeonGreen
                                            line.contains("❌")                              -> NeonRed
                                            line.contains("⏳")                              -> NeonOrange
                                            line.startsWith("  ")                            -> NeonCyan
                                            else                                             -> TextSecondary
                                        },
                                        fontSize   = 10.sp,
                                        fontFamily = FontFamily.Monospace,
                                        lineHeight = 14.sp
                                    )
                                }
                            }
                        }

                        val ai = state.aiDiagnosis
                        if (ai.loading || ai.suggestion.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Box(Modifier.fillMaxWidth().height(0.5.dp).background(NeonBlue.copy(0.2f)))
                            Spacer(Modifier.height(8.dp))
                            if (ai.loading) {
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                    CircularProgressIndicator(Modifier.size(11.dp), color = NeonBlueBright, strokeWidth = 1.5.dp)
                                    Text("Analyzing error…", color = TextDim, fontSize = 11.sp)
                                }
                            } else if (ai.suggestion.isNotEmpty()) {
                                Row(
                                    Modifier.fillMaxWidth().drawBehind {
                                        drawRoundRect(NeonBlueMid.copy(0.07f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()))
                                        drawRoundRect(NeonBlueMid.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                                    }.padding(10.dp),
                                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                                ) {
                                    Icon(Icons.Default.Lightbulb, null, tint = NeonBlueBright, modifier = Modifier.size(13.dp))
                                    Text(ai.suggestion, color = NeonWhite, fontSize = 11.sp, lineHeight = 16.sp)
                                }
                            }
                        }

                        when (val ist = state.installState) {
                            is InstallState.Success -> {
                                Spacer(Modifier.height(8.dp))
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Icon(Icons.Default.CheckCircle, null, tint = NeonGreen, modifier = Modifier.size(16.dp))
                                    Text("Installed!", color = NeonGreen, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }
                            }
                            is InstallState.Failure -> {
                                if (ist.canRetry && activeFile != null) {
                                    Spacer(Modifier.height(8.dp))
                                    Box(
                                        Modifier.fillMaxWidth().height(38.dp).drawBehind {
                                            drawRoundRect(
                                                Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)),
                                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx())
                                            )
                                        }.clickable { activeFile?.let { doInstallAuto(File(it)) } },
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Text("Retry", color = VoidBlack, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                    }
                                }
                            }
                            else -> {}
                        }
                    }
                }
            }

            // File list
            if (files.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.FolderOff, null, tint = NeonBlue.copy(0.4f), modifier = Modifier.size(56.dp))
                        Spacer(Modifier.height(12.dp))
                        Text("No patched files yet", color = TextDim, fontSize = 14.sp)
                        Text("Patch an app to see it here", color = TextDim.copy(0.5f), fontSize = 11.sp)
                    }
                }
            } else {
                LazyColumn(contentPadding = PaddingValues(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    items(files, key = { it.absolutePath }) { file ->
                        val isInstalling = activeFile == file.absolutePath
                        val guessedPkg   = remember(file.name) {
                            file.nameWithoutExtension.removeSuffix("_azluk_v8").removeSuffix("_azluk")
                        }
                        val isInstalled = remember(guessedPkg) {
                            runCatching { ctx.packageManager.getPackageInfo(guessedPkg, 0); true }.getOrDefault(false)
                        }
                        NeonFileCard(
                            file         = file,
                            date         = fmt.format(Date(file.lastModified())),
                            isInstalling = isInstalling,
                            isInstalled  = isInstalled,
                            isContainer  = isContainer(file),
                            pulse        = pulse,
                            onInstall    = { doInstallAuto(file) },
                            onReinstall  = {
                                ctx.startActivity(
                                    Intent(Intent.ACTION_DELETE, Uri.parse("package:$guessedPkg")).apply {
                                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                                    }
                                )
                                Toast.makeText(ctx, "Uninstall first, then Install", Toast.LENGTH_LONG).show()
                            },
                            onDelete = { file.delete(); refresh() }
                        )
                    }
                    item { Spacer(Modifier.height(80.dp)) }
                }
            }
        }
    }
}

@Composable
private fun NeonFileCard(
    file: File, date: String,
    isInstalling: Boolean, isInstalled: Boolean, isContainer: Boolean,
    pulse: Float,
    onInstall: () -> Unit, onReinstall: () -> Unit, onDelete: () -> Unit
) {
    var expanded by remember { mutableStateOf(false) }
    val borderColor = when { isInstalling -> NeonBlueBright; isInstalled -> NeonGreen; else -> NeonBlue.copy(0.4f) }

    Box(
        Modifier.fillMaxWidth().drawBehind {
            drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(18.dp.toPx()))
            drawRoundRect(
                if (isInstalling) borderColor.copy(pulse * 0.8f) else borderColor,
                cornerRadius = androidx.compose.ui.geometry.CornerRadius(18.dp.toPx()),
                style = Stroke(1.dp.toPx())
            )
        }
    ) {
        Column {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(48.dp).drawBehind {
                        drawRoundRect(
                            if (isInstalling) NeonBlueBright.copy(0.2f) else NeonBlueMid.copy(0.1f),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx())
                        )
                    },
                    contentAlignment = Alignment.Center
                ) {
                    if (isInstalling) {
                        CircularProgressIndicator(Modifier.size(22.dp), color = NeonBlueBright, strokeWidth = 2.dp)
                    } else {
                        Icon(
                            if (isContainer) Icons.Default.FolderZip else Icons.Default.Android,
                            null, tint = NeonBlueMid, modifier = Modifier.size(24.dp)
                        )
                    }
                }

                Spacer(Modifier.width(12.dp))

                Column(Modifier.weight(1f)) {
                    Text(file.name, color = NeonWhite, fontSize = 12.sp, fontWeight = FontWeight.SemiBold,
                        fontFamily = FontFamily.Monospace, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("${"%.1f".format(file.length() / 1048576f)} MB · $date", color = TextDim, fontSize = 11.sp)
                    Spacer(Modifier.height(4.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(5.dp)) {
                        when {
                            isInstalling -> NeonMiniTagPFS("INSTALLING", NeonBlueBright)
                            isContainer  -> NeonMiniTagPFS("SPLITS",     NeonOrange)
                            isInstalled  -> NeonMiniTagPFS("INSTALLED",  NeonGreen)
                        }
                        NeonMiniTagPFS(file.extension.uppercase(), NeonBlueMid)
                    }
                }

                Icon(
                    if (expanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    null, tint = TextDim,
                    modifier = Modifier.size(20.dp).clickable { expanded = !expanded }
                )
            }

            AnimatedVisibility(expanded) {
                Row(
                    Modifier.fillMaxWidth().padding(start = 12.dp, end = 12.dp, bottom = 12.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Box(
                        Modifier.weight(1f).height(38.dp).drawBehind {
                            drawRoundRect(
                                Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)),
                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx())
                            )
                        }.clickable(enabled = !isInstalling) { expanded = false; onInstall() },
                        contentAlignment = Alignment.Center
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(5.dp), verticalAlignment = Alignment.CenterVertically) {
                            Icon(Icons.Default.InstallMobile, null, tint = VoidBlack, modifier = Modifier.size(14.dp))
                            Text("Install", color = VoidBlack, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        }
                    }

                    if (isInstalled && !isContainer) {
                        Box(
                            Modifier.weight(1.2f).height(38.dp).drawBehind {
                                drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()))
                                drawRoundRect(NeonOrange.copy(0.4f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                            }.clickable { expanded = false; onReinstall() },
                            contentAlignment = Alignment.Center
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.SwapHoriz, null, tint = NeonOrange, modifier = Modifier.size(14.dp))
                                Text("Reinstall", color = NeonOrange, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
                            }
                        }
                    }

                    Box(
                        Modifier.size(38.dp).drawBehind {
                            drawRoundRect(NeonRed.copy(0.1f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()))
                            drawRoundRect(NeonRed.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                        }.clickable { onDelete() },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(Icons.Default.DeleteOutline, null, tint = NeonRed, modifier = Modifier.size(18.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun NeonMiniTagPFS(text: String, color: Color) {
    Box(
        Modifier.drawBehind {
            drawRoundRect(color.copy(0.12f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(4.dp.toPx()))
            drawRoundRect(color.copy(0.3f),  cornerRadius = androidx.compose.ui.geometry.CornerRadius(4.dp.toPx()), style = Stroke(0.5.dp.toPx()))
        }.padding(horizontal = 5.dp, vertical = 2.dp)
    ) {
        Text(text, color = color, fontSize = 9.sp, fontWeight = FontWeight.SemiBold, letterSpacing = 0.3.sp)
    }
}
