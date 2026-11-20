package com.azluk.patcher.viewmodel

import android.app.ActivityManager
import android.app.Application
import android.content.Context
import android.os.Build
import android.os.Environment
import android.os.StatFs
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import java.io.File

data class SystemProfile(
    val isReady:         Boolean         = false,
    val hasRoot:         Boolean         = false,
    val rootMethod:      String          = "",
    val ramTotalMb:      Int             = 0,
    val ramFreeMb:       Int             = 0,
    val storageFreeGb:   Float           = 0f,
    val cpuCores:        Int             = 0,
    val androidApi:      Int             = 0,
    val arch:            String          = "",
    val isArmDevice:     Boolean         = false,
    val isEmulator:      Boolean         = false,
    val performanceTier: PerformanceTier = PerformanceTier.MEDIUM,
    val warnings:        List<String>    = emptyList()
)

enum class PerformanceTier { LOW, MEDIUM, HIGH }

class SystemCheckViewModel(app: Application) : AndroidViewModel(app) {

    private val _profile = MutableStateFlow(SystemProfile())
    val profile: StateFlow<SystemProfile> = _profile.asStateFlow()

    fun run() = viewModelScope.launch(Dispatchers.IO) {
        val ctx = getApplication<Application>()

        val am = ctx.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val mi = ActivityManager.MemoryInfo().also { am.getMemoryInfo(it) }
        val ramTotal  = (mi.totalMem  / 1024 / 1024).toInt()
        val ramFree   = (mi.availMem  / 1024 / 1024).toInt()

        val stat   = StatFs(Environment.getExternalStorageDirectory().path)
        val freeGb = stat.availableBlocksLong * stat.blockSizeLong / (1024f * 1024 * 1024)

        val cores = Runtime.getRuntime().availableProcessors()
        val abi   = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"

        val (hasRoot, rootMethod) = detectRoot()
        val isEmu                 = detectEmulator()

        val tier = when {
            ramTotal >= 6000 && cores >= 6 -> PerformanceTier.HIGH
            ramTotal >= 3000 && cores >= 4 -> PerformanceTier.MEDIUM
            else                           -> PerformanceTier.LOW
        }

        val warnings = buildList {
            if (freeGb < 1f)    add("Low storage — less than 1 GB free")
            if (ramFree < 300)  add("Low RAM — close background apps before patching")
            if (isEmu)          add("Emulator detected — some patches may differ")
            if (Build.VERSION.SDK_INT < 29) add("Android ${Build.VERSION.SDK_INT} — some features limited")
        }

        _profile.value = SystemProfile(
            isReady         = true,
            hasRoot         = hasRoot,
            rootMethod      = rootMethod,
            ramTotalMb      = ramTotal,
            ramFreeMb       = ramFree,
            storageFreeGb   = freeGb,
            cpuCores        = cores,
            androidApi      = Build.VERSION.SDK_INT,
            arch            = abi,
            isArmDevice     = abi.startsWith("arm"),
            isEmulator      = isEmu,
            performanceTier = tier,
            warnings        = warnings
        )
    }

    private fun detectRoot(): Pair<Boolean, String> {
        // Magisk (directory-based, fastest)
        if (File("/data/adb/magisk").exists() || File("/sbin/.magisk").exists())
            return true to "Magisk"
        // KernelSU
        if (File("/data/adb/ksu").exists())
            return true to "KernelSU"
        // APatch (newer root solution)
        if (File("/data/adb/apatch").exists())
            return true to "APatch"
        // Classic su binary
        val suPaths = listOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/sbin/su", "/vendor/bin/su", "/su/bin/su"
        )
        if (suPaths.any { File(it).exists() }) return true to "SuperSU"
        // Runtime check
        return try {
            val p   = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor()
            val ok = out.contains("uid=0")
            ok to if (ok) "su" else ""
        } catch (_: Exception) { false to "" }
    }

    private fun detectEmulator(): Boolean =
        Build.FINGERPRINT.startsWith("generic") ||
        Build.FINGERPRINT.contains("emulator") ||
        Build.MODEL.contains("Emulator") ||
        Build.MODEL.contains("Android SDK") ||
        Build.MANUFACTURER.contains("Genymotion") ||
        Build.BRAND.startsWith("generic") ||
        Build.HARDWARE.contains("goldfish") ||
        Build.HARDWARE.contains("ranchu")
}
