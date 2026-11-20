package com.azluk.patcher.core

import android.graphics.drawable.Drawable

// ─────────────────────────────────────────────────────────────────────────────
// App info
// ─────────────────────────────────────────────────────────────────────────────

data class AppInfo(
    val packageName:      String,
    val appName:          String,
    val icon:             Drawable?,
    val isSystemApp:      Boolean,
    val apkPath:          String,
    val versionName:      String,
    val apkSizeMb:        Float,
    var patchStatus:      PatchStatus = PatchStatus.UNKNOWN,
    var opportunityCount: Int         = 0
)

enum class PatchStatus {
    UNKNOWN,    // not yet scanned
    LIKELY,     // markers only, no structural recipe confirmed
    PATCHABLE,  // at least one structural recipe matched
    COMPLEX     // heavily obfuscated / protected
}

// ─────────────────────────────────────────────────────────────────────────────
// Patch types — V10
// ─────────────────────────────────────────────────────────────────────────────

enum class PatchType(
    val key:         String,
    val displayName: String,
    val description: String,
    val category:    String,
    val risk:        PatchRisk = PatchRisk.SAFE
) {
    // ── Bypass ────────────────────────────────────────────────────────────────
    LICENSE_BYPASS(
        "LICENSE_BYPASS", "License Bypass",
        "Nullifies Play LVL. Patches ILicensingService callbacks to always return LICENSED.",
        "bypass"
    ),
    IAP_BYPASS(
        "IAP_BYPASS", "IAP Bypass",
        "Spoofs BillingClient getResponseCode() to return OK. Covers Play Billing v3–v6.",
        "bypass"
    ),
    SIGNATURE_BYPASS(
        "SIGNATURE_BYPASS", "Signature Bypass",
        "Stubs verdict methods that delegate to java.security.Signature.verify() → true.",
        "bypass"
    ),
    GOOGLE_PLAY_BYPASS(
        "GOOGLE_PLAY_BYPASS", "Play Services Bypass",
        "Stubs isGooglePlayServicesAvailable() → 0 (SUCCESS). Removes Play availability gates.",
        "bypass"
    ),

    // ── Ads ───────────────────────────────────────────────────────────────────
    REMOVE_ADS(
        "REMOVE_ADS", "Remove Ads",
        "Stubs loadAd/show/initialize on 20+ ad SDKs: AdMob, Facebook, Unity, AppLovin, IronSource, MoPub, Vungle, InMobi, Chartboost.",
        "ads"
    ),
    BLOCK_AD_DOMAINS(
        "BLOCK_AD_DOMAINS", "Block Ad Domains",
        "Stubs domain-gate boolean methods to true. Loads 79-domain blocklist from assets.",
        "ads"
    ),

    // ── Security ──────────────────────────────────────────────────────────────
    SSL_BYPASS(
        "SSL_BYPASS", "SSL Pinning Bypass",
        "Stubs OkHttp CertificatePinner.check() → void, OkHostnameVerifier.verify() → true.",
        "security",
        PatchRisk.MODERATE
    ),
    ROOT_BYPASS(
        "ROOT_BYPASS", "Root Detection Bypass",
        "Stubs RootBeer and su-binary detection methods → false.",
        "security"
    ),
    SAFETYNET_BYPASS(
        "SAFETYNET_BYPASS", "Integrity Bypass",
        "Stubs SafetyNet attest(), Play Integrity requestIntegrityToken(). isBasicIntegrity() → true.",
        "security"
    ),
    FRIDA_BYPASS(
        "FRIDA_BYPASS", "Anti-Debug Bypass",
        "Stubs isFridaPresent(), isXposedInstalled(), isBeingDebugged() → false.",
        "security"
    ),
    EMULATOR_BYPASS(
        "EMULATOR_BYPASS", "Emulator Bypass",
        "Stubs isEmulator(), runningInEmulator() → false. Removes Build.FINGERPRINT checks.",
        "security"
    ),

    // ── Dev ───────────────────────────────────────────────────────────────────
    FORCE_DEBUGGABLE(
        "FORCE_DEBUGGABLE", "Force Debuggable",
        "Sets android:debuggable=true in binary AndroidManifest. Enables ADB attach.",
        "dev"
    ),
    DISABLE_FLAG_SECURE(
        "DISABLE_FLAG_SECURE", "Disable FLAG_SECURE",
        "Stubs setSecureMode/setFlagSecure wrappers → void. Unlocks screenshots.",
        "dev"
    ),
    EXPORT_ALL_COMPONENTS(
        "EXPORT_ALL_COMPONENTS", "Export Components",
        "Patches android:exported=false → true for all activities, services, receivers.",
        "dev"
    ),
    ALLOW_BACKUP(
        "ALLOW_BACKUP", "Allow Backup",
        "Forces android:allowBackup=true, android:fullBackupOnly=false in manifest.",
        "dev"
    ),
    DISABLE_ANALYTICS(
        "DISABLE_ANALYTICS", "Kill Analytics",
        "Stubs Firebase Analytics logEvent(), Mixpanel track() → void.",
        "dev"
    ),

    // ── Util ──────────────────────────────────────────────────────────────────
    REMOVE_TELEMETRY(
        "REMOVE_TELEMETRY", "Kill Telemetry",
        "Stubs Crashlytics, Sentry, Bugsnag report methods → void.",
        "util"
    ),
    OPTIMIZE_ZIP(
        "OPTIMIZE_ZIP", "Optimize APK",
        "Repack with DEFLATE on DEX, 4-byte align resources.arsc, 16KB align .so files.",
        "util"
    );

    val isHighRisk: Boolean get() = risk == PatchRisk.HIGH
}

enum class PatchRisk { SAFE, MODERATE, HIGH }

// ─────────────────────────────────────────────────────────────────────────────
// Scan result
// ─────────────────────────────────────────────────────────────────────────────

data class ScanResult(
    val patchType: String,
    val desc:      String?,
    val dexIndex:  Int,
    val offset:    Int
)

// ─────────────────────────────────────────────────────────────────────────────
// Patch pipeline state
// ─────────────────────────────────────────────────────────────────────────────

sealed class PatchState {
    object Idle : PatchState()
    data class Running(val log: List<String>) : PatchState()
    data class Success(val outputPath: String, val log: List<String>) : PatchState()
    data class Failure(val error: String,  val log: List<String>) : PatchState()
}

val PatchState.isActive: Boolean get() = this is PatchState.Running
val PatchState.logLines: List<String> get() = when (this) {
    is PatchState.Running -> log
    is PatchState.Success -> log
    is PatchState.Failure -> log
    else                  -> emptyList()
}

// ─────────────────────────────────────────────────────────────────────────────
// Install state
// ─────────────────────────────────────────────────────────────────────────────

sealed class InstallState {
    object Idle       : InstallState()
    object Installing : InstallState()
    object Success    : InstallState()
    data class Failure(
        val code:        String,
        val message:     String,
        val description: String,
        val canRetry:    Boolean
    ) : InstallState()
}
