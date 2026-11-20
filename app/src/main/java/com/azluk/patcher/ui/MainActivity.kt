package com.azluk.patcher.ui

import android.Manifest
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.animation.*
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavType
import androidx.navigation.compose.*
import androidx.navigation.navArgument
import com.azluk.patcher.ui.screens.*
import com.azluk.patcher.ui.theme.*
import com.azluk.patcher.viewmodel.SystemCheckViewModel

class MainActivity : ComponentActivity() {
    private val permReady = mutableStateOf(false)
    private val sysVm: SystemCheckViewModel by viewModels()
    private val permLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        permReady.value = hasPermission()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        permReady.value = hasPermission()
        sysVm.run()
        setContent {
            AzlukTheme {
                val ready by permReady
                if (ready) AzlukApp(sysVm) else PermissionScreen { requestPerm() }
            }
        }
        if (!hasPermission()) requestPerm()
    }

    override fun onResume() { super.onResume(); permReady.value = hasPermission() }

    private fun hasPermission() =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) Environment.isExternalStorageManager()
        else checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED

    private fun requestPerm() {
        if (hasPermission()) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:$packageName"))) }
                .onFailure { runCatching { startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)) } }
        } else {
            permLauncher.launch(arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE, Manifest.permission.WRITE_EXTERNAL_STORAGE))
        }
    }
}

sealed class NavItem(val route: String, val icon: ImageVector, val label: String) {
    object Home    : NavItem("home",    Icons.Default.Apps,       "Apps")
    object Patched : NavItem("patched", Icons.Default.FolderOpen, "Files")
}

@Composable
fun AzlukApp(sysVm: SystemCheckViewModel) {
    val profile by sysVm.profile.collectAsStateWithLifecycle()
    val nav = rememberNavController()
    var splashDone by remember { mutableStateOf(false) }

    if (!splashDone) {
        SplashScreen(profile = profile, onComplete = { splashDone = true })
        return
    }

    val navItems = listOf(NavItem.Home, NavItem.Patched)
    val currentEntry by nav.currentBackStackEntryAsState()
    val currentRoute = currentEntry?.destination?.route
    val showBottomBar = currentRoute in navItems.map { it.route }

    Scaffold(
        containerColor = VoidBlack,
        bottomBar = {
            AnimatedVisibility(
                visible = showBottomBar,
                enter   = slideInVertically { it } + fadeIn(),
                exit    = slideOutVertically { it } + fadeOut()
            ) {
                NeonBottomBar(navItems, currentRoute) { route ->
                    nav.navigate(route) {
                        popUpTo(nav.graph.startDestinationId) { saveState = true }
                        launchSingleTop = true
                        restoreState    = true
                    }
                }
            }
        }
    ) { inner ->
        NavHost(
            navController      = nav,
            startDestination   = "home",
            modifier           = Modifier
                .fillMaxSize()
                .padding(bottom = if (showBottomBar) inner.calculateBottomPadding() else 0.dp),
            enterTransition    = { fadeIn(tween(200)) + slideInHorizontally { it / 6 } },
            exitTransition     = { fadeOut(tween(150)) + slideOutHorizontally { -it / 6 } },
            popEnterTransition = { fadeIn(tween(200)) + slideInHorizontally { -it / 6 } },
            popExitTransition  = { fadeOut(tween(150)) + slideOutHorizontally { it / 6 } }
        ) {
            composable("home")    { HomeScreen(nav) }
            composable("patched") { PatchedFilesScreen(nav) }
            composable(
                "detail/{pkg}",
                arguments = listOf(navArgument("pkg") { type = NavType.StringType })
            ) { back ->
                val pkg = back.arguments?.getString("pkg") ?: return@composable
                DetailScreen(pkg = pkg, navController = nav)
            }
            composable(
                "patch/{pkg}",
                arguments = listOf(navArgument("pkg") { type = NavType.StringType })
            ) { back ->
                val pkg = back.arguments?.getString("pkg") ?: return@composable
                PatchScreen(pkg = pkg, navController = nav)
            }
            composable(
                "patchlog/{pkg}",
                arguments = listOf(navArgument("pkg") { type = NavType.StringType })
            ) { back ->
                val pkg = back.arguments?.getString("pkg") ?: return@composable
                PatchLogScreen(pkg = pkg, navController = nav)
            }
        }
    }
}

@Composable
fun NeonBottomBar(items: List<NavItem>, currentRoute: String?, onNavigate: (String) -> Unit) {
    val inf = rememberInfiniteTransition(label = "nav_inf")
    val glowAlpha by inf.animateFloat(
        0.3f, 0.9f,
        infiniteRepeatable(tween(1800, easing = FastOutSlowInEasing), RepeatMode.Reverse),
        label = "nav_glow"
    )

    Box(
        Modifier
            .fillMaxWidth()
            .background(
                Brush.verticalGradient(listOf(Color.Transparent, VoidBlack.copy(0.98f), VoidBlack))
            )
            .navigationBarsPadding()
    ) {
        Box(
            Modifier
                .fillMaxWidth()
                .drawBehind {
                    // Background
                    drawRect(DeepNavy.copy(0.97f))
                    // Neon top border
                    drawLine(
                        brush = Brush.horizontalGradient(
                            listOf(
                                Color.Transparent,
                                NeonBlue.copy(glowAlpha * 0.5f),
                                NeonBlueBright.copy(glowAlpha * 0.9f),
                                NeonBlueMid.copy(glowAlpha),
                                NeonBlueBright.copy(glowAlpha * 0.9f),
                                NeonBlue.copy(glowAlpha * 0.5f),
                                Color.Transparent
                            )
                        ),
                        start       = Offset(0f, 0f),
                        end         = Offset(size.width, 0f),
                        strokeWidth = 1.5.dp.toPx()
                    )
                }
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .height(66.dp)
                    .padding(horizontal = 32.dp),
                horizontalArrangement = Arrangement.SpaceEvenly,
                verticalAlignment     = Alignment.CenterVertically
            ) {
                items.forEach { item ->
                    val selected = currentRoute == item.route
                    val tint by animateColorAsState(
                        if (selected) NeonBlueBright else TextDim,
                        tween(200), label = "tint_${item.label}"
                    )

                    Column(
                        modifier            = Modifier
                            .weight(1f)
                            .clickable(
                                indication            = null,
                                interactionSource     = remember { MutableInteractionSource() }
                            ) { onNavigate(item.route) },
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Box(
                            Modifier
                                .size(44.dp)
                                .drawBehind {
                                    if (selected) {
                                        drawRoundRect(
                                            NeonBlueBright.copy(0.15f),
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx())
                                        )
                                        drawRoundRect(
                                            NeonBlueBright.copy(0.4f),
                                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(14.dp.toPx()),
                                            style = Stroke(0.5.dp.toPx())
                                        )
                                    }
                                },
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(item.icon, null, tint = tint, modifier = Modifier.size(if (selected) 24.dp else 22.dp))
                        }
                        Text(
                            item.label,
                            color      = tint,
                            fontSize   = 10.sp,
                            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun PermissionScreen(onRequest: () -> Unit) {
    Box(
        Modifier.fillMaxSize().background(VoidBlack).systemBarsPadding().padding(32.dp),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, verticalArrangement = Arrangement.spacedBy(20.dp)) {
            Icon(Icons.Default.Lock, null, tint = NeonBlueMid, modifier = Modifier.size(64.dp))
            Text("Storage Access Required", color = NeonWhite, fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.headlineSmall)
            Text("AzlukPatcher needs full storage access to read and patch APK files.",
                color = TextDim)
            Box(
                Modifier.fillMaxWidth().height(50.dp)
                    .drawBehind {
                        drawRoundRect(
                            Brush.horizontalGradient(listOf(NeonBlue, NeonBlueBright)),
                            cornerRadius = androidx.compose.ui.geometry.CornerRadius(16.dp.toPx())
                        )
                    }
                    .clickable { onRequest() },
                contentAlignment = Alignment.Center
            ) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, null, tint = VoidBlack, modifier = Modifier.size(18.dp))
                    Text("Grant Access", color = VoidBlack, fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

class InstallReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
        val msg    = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE)
        ctx.sendBroadcast(Intent("com.azluk.patcher.INSTALL_RESULT_LOCAL").apply {
            setPackage(ctx.packageName)
            putExtra(PackageInstaller.EXTRA_STATUS, status)
            putExtra(PackageInstaller.EXTRA_STATUS_MESSAGE, msg)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
                intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)?.let { putExtra(Intent.EXTRA_INTENT, it) }
            else @Suppress("DEPRECATION") intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)?.let { putExtra(Intent.EXTRA_INTENT, it) }
        })
    }
}
