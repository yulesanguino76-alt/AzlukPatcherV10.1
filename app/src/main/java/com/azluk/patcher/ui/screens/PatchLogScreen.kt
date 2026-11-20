package com.azluk.patcher.ui.screens

import android.app.PendingIntent
import android.content.*
import android.content.pm.PackageInstaller
import android.os.Build
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.compose.animation.*
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
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.*
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.*
import androidx.compose.ui.unit.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.azluk.patcher.core.*
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.PatchViewModel
import java.io.File
import java.io.FileInputStream

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PatchLogScreen(
    pkg: String,
    navController: NavController,
    vm: PatchViewModel = viewModel(LocalContext.current as ComponentActivity)
) {
    val state    by vm.state.collectAsStateWithLifecycle()
    val ctx       = LocalContext.current
    val logState  = rememberLazyListState()

    LaunchedEffect(pkg) { vm.patchActiveSource(pkg) }

    val logLines = when (val ps = state.patchState) {
        is PatchState.Running -> ps.log
        is PatchState.Success -> ps.log
        is PatchState.Failure -> ps.log
        else                  -> emptyList()
    }
    val isRunning = state.patchState is PatchState.Running
    val isSuccess = state.patchState is PatchState.Success
    val isFailure = state.patchState is PatchState.Failure

    LaunchedEffect(logLines.size) {
        if (logLines.isNotEmpty()) logState.animateScrollToItem(logLines.size - 1)
    }

    // Pulsing neon border animation
    val inf = rememberInfiniteTransition(label = "log_inf")
    val pulse by inf.animateFloat(0.4f, 1f,
        infiniteRepeatable(tween(1400, easing = FastOutSlowInEasing), RepeatMode.Reverse), "pulse")

    DisposableEffect(Unit) {
        val filter   = IntentFilter("com.azluk.patcher.INSTALL_RESULT_LOCAL")
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
                val msg    = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
                if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) {
                    val confirm = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                        i.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
                    else @Suppress("DEPRECATION") i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                    confirm?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    confirm?.let { ctx.startActivity(it) }
                } else vm.onInstallResult(status, msg)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
            ctx.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else ctx.registerReceiver(receiver, filter)
        onDispose { ctx.unregisterReceiver(receiver) }
    }

    val bannerColor  = when { isSuccess -> NeonGreen; isFailure -> NeonRed; else -> NeonBlueBright }
    val statusText   = when { isSuccess -> "PATCH COMPLETE"; isFailure -> "PATCH FAILED"; else -> "PATCHING…" }

    Scaffold(
        containerColor = VoidBlack,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(statusText, color = bannerColor, fontWeight = FontWeight.Black, fontSize = 15.sp, letterSpacing = 1.sp)
                        Text(pkg, color = TextDim, fontSize = 10.sp, maxLines = 1)
                    }
                },
                navigationIcon = {
                    IconButton(
                        onClick  = { if (!isRunning) { vm.resetPatch(); navController.popBackStack() } },
                        enabled  = !isRunning
                    ) {
                        Icon(
                            if (isRunning) Icons.Default.HourglassEmpty else Icons.Default.ArrowBack,
                            null,
                            tint = if (isRunning) TextDim else NeonBlueMid
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = DeepNavy
                )
            )
        }
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .background(VoidBlack)
                .padding(padding)
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Status banner ─────────────────────────────────────────────────
            Box(
                Modifier
                    .fillMaxWidth()
                    .drawBehind {
                        drawRoundRect(bannerColor.copy(0.08f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()))
                        drawRoundRect(
                            bannerColor.copy(if (isRunning) pulse * 0.7f else 0.5f),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                            style = Stroke(1.5.dp.toPx())
                        )
                        if (isRunning) {
                            // Animated glow sweep
                            drawRect(
                                brush   = Brush.horizontalGradient(
                                    listOf(Color.Transparent, bannerColor.copy(0.05f), Color.Transparent),
                                    startX = size.width * (pulse - 0.3f).coerceAtLeast(0f),
                                    endX   = size.width * pulse
                                )
                            )
                        }
                    }
                    .padding(14.dp)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    when {
                        isRunning -> CircularProgressIndicator(Modifier.size(20.dp), color = bannerColor, strokeWidth = 2.dp)
                        isSuccess -> Icon(Icons.Default.CheckCircle, null, tint = NeonGreen, modifier = Modifier.size(20.dp))
                        isFailure -> Icon(Icons.Default.Error, null, tint = NeonRed, modifier = Modifier.size(20.dp))
                        else      -> Icon(Icons.Default.HourglassEmpty, null, tint = NeonBlueMid, modifier = Modifier.size(20.dp))
                    }
                    Column {
                        Text(statusText, color = bannerColor, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        if (isRunning) Text("Background — you can leave this screen", color = TextDim, fontSize = 11.sp)
                    }
                }
            }

            // ── Live log terminal ─────────────────────────────────────────────
            Box(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .drawBehind {
                        drawRoundRect(DeepNavy, cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()))
                        drawRoundRect(
                            Brush.horizontalGradient(
                                listOf(NeonBlue.copy(0.3f), NeonBlueBright.copy(0.5f), NeonBlue.copy(0.3f))
                            ),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                            style = Stroke(1.dp.toPx())
                        )
                    }
                    .padding(12.dp)
            ) {
                Column {
                    Row(
                        verticalAlignment     = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier              = Modifier.padding(bottom = 8.dp)
                    ) {
                        Box(Modifier.size(8.dp).background(NeonRed, RoundedCornerShape(4.dp)))
                        Box(Modifier.size(8.dp).background(NeonOrange, RoundedCornerShape(4.dp)))
                        Box(Modifier.size(8.dp).background(NeonGreen, RoundedCornerShape(4.dp)))
                        Spacer(Modifier.width(8.dp))
                        Icon(Icons.Default.Terminal, null, tint = NeonBlueMid, modifier = Modifier.size(13.dp))
                        Text("azluk-engine log", color = TextDim, fontSize = 10.sp, fontFamily = FontFamily.Monospace)
                        Spacer(Modifier.weight(1f))
                        if (logLines.isNotEmpty()) Text("${logLines.size} lines", color = TextDim.copy(0.5f), fontSize = 10.sp)
                    }

                    // Terminal divider
                    Box(Modifier.fillMaxWidth().height(1.dp).background(
                        Brush.horizontalGradient(listOf(Color.Transparent, NeonBlue.copy(0.4f), Color.Transparent))
                    ))
                    Spacer(Modifier.height(8.dp))

                    if (logLines.isEmpty() && isRunning) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            CircularProgressIndicator(Modifier.size(11.dp), color = NeonBlueBright, strokeWidth = 1.5.dp)
                            Text("Starting engine…", color = TextDim, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                        }
                    } else {
                        LazyColumn(state = logState) {
                            items(logLines) { line ->
                                val lineColor = when {
                                    line.contains("[SUCCESS]") || line.contains("[OK]") -> NeonGreen
                                    line.contains("[ERROR]")  || line.startsWith("Error") -> NeonRed
                                    line.contains("Phase")    || line.contains("DEX")     -> NeonBlueBright
                                    line.contains("patched")  || line.contains("stub")    -> NeonCyan
                                    line.contains("skip")     || line.contains("no DEX")  -> NeonOrange
                                    else -> TextSecondary
                                }
                                Text(
                                    "› $line",
                                    color      = lineColor,
                                    fontSize   = 10.sp,
                                    fontFamily = FontFamily.Monospace,
                                    lineHeight = 15.sp
                                )
                            }
                        }
                    }
                }
            }

            // ── Install controls (success) ────────────────────────────────────
            if (isSuccess) {
                val outputPath = (state.patchState as PatchState.Success).outputPath

                // Output file pill
                Box(
                    Modifier
                        .fillMaxWidth()
                        .drawBehind {
                            drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx()))
                            drawRoundRect(NeonGreen.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(12.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                        }
                        .padding(10.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Default.InsertDriveFile, null, tint = NeonGreen, modifier = Modifier.size(14.dp))
                        Text(File(outputPath).name, color = NeonGreen, fontSize = 10.sp,
                            fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f), maxLines = 1)
                    }
                }

                // Install button
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(50.dp)
                        .drawBehind {
                            drawRoundRect(
                                Brush.horizontalGradient(listOf(NeonBlue, NeonBlueMid, NeonBlueBright)),
                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx())
                            )
                            // Neon glow
                            drawRoundRect(
                                NeonBlueBright.copy(pulse * 0.4f),
                                cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx()),
                                style = Stroke(2.dp.toPx())
                            )
                        }
                        .clickable { installFileAuto(ctx, File(outputPath), vm) },
                    contentAlignment = Alignment.Center
                ) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.InstallMobile, null, tint = VoidBlack, modifier = Modifier.size(18.dp))
                        Text("INSTALL", color = VoidBlack, fontWeight = FontWeight.Black, fontSize = 15.sp, letterSpacing = 2.sp)
                    }
                }

                // System installer
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(42.dp)
                        .drawBehind {
                            drawRoundRect(DeepNavy2, cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                            drawRoundRect(NeonBlue.copy(0.3f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(0.5.dp.toPx()))
                        }
                        .clickable { systemInstall(ctx, File(outputPath)) },
                    contentAlignment = Alignment.Center
                ) {
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.OpenInNew, null, tint = TextSecondary, modifier = Modifier.size(14.dp))
                        Text("System Installer", color = TextSecondary, fontSize = 13.sp)
                    }
                }

                // Install result
                when (val ist = state.installState) {
                    is InstallState.Success -> {
                        Box(
                            Modifier
                                .fillMaxWidth()
                                .drawBehind {
                                    drawRoundRect(NeonGreen.copy(0.08f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                                    drawRoundRect(NeonGreen.copy(0.4f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(1.dp.toPx()))
                                }
                                .padding(14.dp)
                        ) {
                            Row(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.CheckCircle, null, tint = NeonGreen, modifier = Modifier.size(20.dp))
                                Text("Installed successfully!", color = NeonGreen, fontWeight = FontWeight.Bold)
                            }
                        }
                    }
                    is InstallState.Failure -> {
                        Box(
                            Modifier
                                .fillMaxWidth()
                                .drawBehind {
                                    drawRoundRect(NeonRed.copy(0.08f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                                    drawRoundRect(NeonRed.copy(0.35f), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()), style = Stroke(1.dp.toPx()))
                                }
                                .padding(14.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.Error, null, tint = NeonRed, modifier = Modifier.size(16.dp))
                                    Text(ist.code, color = NeonRed, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                }
                                Text(ist.message, color = NeonWhite, fontSize = 12.sp)
                                Text(ist.description, color = TextSecondary, fontSize = 11.sp)
                                val ai = state.aiDiagnosis
                                if (ai.loading) {
                                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        CircularProgressIndicator(Modifier.size(11.dp), color = NeonBlueBright, strokeWidth = 1.5.dp)
                                        Text("Analyzing…", color = TextDim, fontSize = 11.sp)
                                    }
                                } else if (ai.suggestion.isNotEmpty()) {
                                    Box(Modifier.fillMaxWidth().height(0.5.dp).background(NeonRed.copy(0.3f)))
                                    Text(ai.suggestion, color = NeonWhite, fontSize = 11.sp, lineHeight = 17.sp)
                                }
                                if (ist.canRetry) {
                                    Box(
                                        Modifier
                                            .fillMaxWidth()
                                            .height(40.dp)
                                            .drawBehind {
                                                drawRoundRect(Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)), cornerRadius = androidx.compose.ui.geometry.CornerRadius(10.dp.toPx()))
                                            }
                                            .clickable { installFileAuto(ctx, File(outputPath), vm) },
                                        contentAlignment = Alignment.Center
                                    ) {
                                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                                            Icon(Icons.Default.Refresh, null, tint = VoidBlack, modifier = Modifier.size(14.dp))
                                            Text("Retry Install", color = VoidBlack, fontWeight = FontWeight.Bold)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else -> {}
                }
            }

            // Fail — try again
            if (isFailure) {
                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(46.dp)
                        .drawBehind {
                            drawRoundRect(Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)), cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()))
                        }
                        .clickable { vm.resetPatch(); navController.popBackStack() },
                    contentAlignment = Alignment.Center
                ) {
                    Text("Try Again", color = VoidBlack, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                }
            }
        }
    }
}
