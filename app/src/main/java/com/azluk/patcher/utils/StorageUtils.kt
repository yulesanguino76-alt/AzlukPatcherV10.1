package com.azluk.patcher.utils

import android.os.Environment
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

object StorageUtils {

    private val PATCHED_EXTENSIONS = setOf("apk", "apks", "xapk", "apkm")

    private val ROOT = File(Environment.getExternalStorageDirectory(), "AzlukPatcher")

    fun getPatchedDir(): File = ROOT.resolve("Patched").also { if (!it.exists()) it.mkdirs() }
    fun getTempDir():    File = ROOT.resolve("Temp").also   { if (!it.exists()) it.mkdirs() }
    fun getLogsDir():    File = ROOT.resolve("Logs").also   { if (!it.exists()) it.mkdirs() }

    fun getPatchedFiles(): List<File> =
        getPatchedDir().listFiles()
            ?.filter { it.isFile && it.extension.lowercase() in PATCHED_EXTENSIONS }
            ?.sortedByDescending { it.lastModified() }
            ?: emptyList()

    /** Clears azluk-* staging dirs and imports/ from app cache. Returns count. */
    fun clearEngineArtifacts(cacheDir: File): Int =
        cacheDir.listFiles()
            ?.count { f ->
                (f.name.startsWith("azluk-") || f.name == "imports") && f.deleteRecursively()
            } ?: 0

    /** Total size of all patched files in bytes. */
    fun patchedDirSizeBytes(): Long =
        getPatchedFiles().sumOf { it.length() }

    /** Writes a patch session log to AzlukPatcher/Logs/. */
    fun writeSessionLog(pkg: String, lines: List<String>) {
        try {
            val stamp = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
            val logFile = getLogsDir().resolve("${pkg}_$stamp.log")
            logFile.writeText(lines.joinToString("\n"))
        } catch (_: Exception) {}
    }

    /** Formats bytes into human-readable string. */
    fun formatSize(bytes: Long): String = when {
        bytes < 1024                  -> "$bytes B"
        bytes < 1024L * 1024L         -> "%.1f KB".format(bytes / 1024.0)
        bytes < 1024L * 1024L * 1024L -> "%.1f MB".format(bytes / (1024.0 * 1024.0))
        else                          -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
    }
}
