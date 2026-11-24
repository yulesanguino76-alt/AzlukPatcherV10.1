package com.azluk.patcher.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.Adler32;

/**
 * AzlukPatcher V10.2 — SuperDexPatcher
 *
 * ARCHITECTURE (robbed from LuckyPatcher's actual DEX analysis):
 *
 * Layer 0 — BYTE PATTERN MATCHING (LP's real technique):
 *   Scan raw DEX bytes for opcode sequences with wildcard support.
 *   This is the only technique that works on obfuscated apps because
 *   it doesn't depend on class/method name descriptors surviving ProGuard.
 *   Patterns stolen directly from LP's internal patch engine strings.
 *
 * Layer 1 — STRING POOL SCAN + INVOKE NOP (LP's ad removal technique):
 *   Find string indices in the DEX string pool that match SDK names
 *   (e.g. "gms/ads", "facebook/ads"). Then locate method_ids whose
 *   class descriptor contains those strings. Finally walk all code
 *   bodies and nop out invoke-* instructions that reference those
 *   method_ids. This is what LP/NPManager actually do for ad removal.
 *
 * Layer 2 — CALL SITE NOP (for non-obfuscated apps):
 *   Traditional approach: scan method_ids for SDK class descriptors,
 *   then nop their call sites. Works when descriptors survive in DEX.
 *
 * Layer 3 — OWNER STUB (for apps that define bypass target methods):
 *   When the target class IS defined in app DEX (e.g. app wraps RootBeer),
 *   find that method and stub it to return the desired value.
 *
 * Layer 4 — MANIFEST PATCHES:
 *   Binary AXML attribute flips (debuggable, exported, allowBackup).
 */
public final class SuperDexPatcher {

    private SuperDexPatcher() {}

    // ── Constants ─────────────────────────────────────────────────────────────
    private static final int HEADER_SIZE    = 0x70;
    private static final int CLASS_DEF_SIZE = 32;
    private static final int METHOD_ID_SIZE = 8;
    private static final int PROTO_ID_SIZE  = 12;
    private static final int TYPE_ID_SIZE   = 4;
    private static final int DEX_ENDIAN     = 0x12345678;
    private static final int ACC_NATIVE     = 0x0100;
    private static final int ACC_ABSTRACT   = 0x0400;

    // AXML constants
    private static final int ATTR_DEBUGGABLE       = 0x0101021b;
    private static final int ATTR_EXPORTED         = 0x010102d4;
    private static final int ATTR_ALLOW_BACKUP     = 0x010100d1;
    private static final int ATTR_FULL_BACKUP_ONLY = 0x010104eb;
    private static final int RES_STRING_POOL_TYPE       = 0x0001;
    private static final int RES_XML_RESOURCE_MAP_TYPE  = 0x0180;
    private static final int RES_XML_START_ELEMENT_TYPE = 0x0102;
    private static final int TYPE_INT_BOOLEAN = 0x12;

    public interface Progress { void log(String message); }

    // ── LAYER 0: Byte Patterns stolen from LuckyPatcher ───────────────────────
    //
    // Format: { original_bytes, replacement_bytes }
    // 0xFF = wildcard (any byte)
    // These are the ACTUAL patterns LP uses internally.

    // Sentinel for wildcard
    private static final int W = 0xFF;

    private static final int[][][] LICENSE_PATTERNS = {
        // LP's primary license bypass pattern:
        // iget-object vA, vB, field + if-eqz v0, +4 + const/4 v0, #1 + return-object v0
        // → const/4 v0, #1 + nop*4 + return-object v0
        {
            { 0x63, W, W, W,  0x38, 0x00, 0x04, 0x00,  0x12, 0x10,  0x0F, 0x00 },
            { 0x12, 0x10, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00,  0x0F, 0x00 }
        },
        // Variant: iget-object + if-nez (inverted check)
        {
            { 0x63, W, W, W,  0x39, 0x00, 0x04, 0x00,  0x12, 0x00,  0x0F, 0x00 },
            { 0x12, 0x10, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00,  0x0F, 0x00 }
        },
        // LP pattern 2: boolean license method → return true
        // Pattern: "12 S0" → "12 S1" (const/4 vX, #0 → const/4 vX, #1)
        // Applied contextually on license-related methods
        {
            { 0x12, 0x00,  0x0F, 0x00 }, // const/4 v0, #0 + return v0
            { 0x12, 0x10,  0x0F, 0x00 }  // const/4 v0, #1 + return v0
        },
        // License validator: if-eqz on boolean + return false → return true
        {
            { 0x38, W, W, 0x00,  0x12, 0x00,  0x0F, 0x00 },
            { 0x00, 0x00, 0x00, 0x00,  0x12, 0x10,  0x0F, 0x00 }
        },
    };

    private static final int[][][] BILLING_PATTERNS = {
        // getResponseCode() pattern: return-int 0 (BILLING_RESPONSE_RESULT_OK)
        // const/4 vX, #some_nonzero → const/4 vX, #0
        {
            { 0x12, 0x10,  0x0F, 0x00 }, // const/4 v0, #1 + return
            { 0x12, 0x00,  0x0F, 0x00 }  // const/4 v0, #0 + return (OK=0)
        },
        // Longer billing check pattern
        {
            { 0x12, 0x40,  0x0F, 0x00 }, // const/4 v0, #4 + return (error code)
            { 0x12, 0x00,  0x0F, 0x00 }  // const/4 v0, #0 (OK)
        },
        {
            { 0x12, 0x30,  0x0F, 0x00 }, // const/4 v0, #3
            { 0x12, 0x00,  0x0F, 0x00 }
        },
        {
            { 0x12, 0x60,  0x0F, 0x00 }, // const/4 v0, #6
            { 0x12, 0x00,  0x0F, 0x00 }
        },
    };

    private static final int[][][] ROOT_PATTERNS = {
        // isRooted() → return false (const/4 v0, #1 → const/4 v0, #0)
        {
            { 0x12, 0x10,  0x0F, 0x00 }, // return true
            { 0x12, 0x00,  0x0F, 0x00 }  // return false
        },
        // Longer root check: some invoke + if + return true → return false
        {
            { 0x12, 0x11,  0x0F, 0x00 },
            { 0x12, 0x00,  0x0F, 0x00 }
        },
    };

    private static final int[][][] AD_INIT_PATTERNS = {
        // LP: new-instance + invoke-direct → nop (kills ad SDK init)
        // "22 00 ?? ?? 70 10 ?? ?? 00 00" → "00 00 00 00 ?? ?? ?? ?? ?? ??"
        {
            { 0x22, 0x00, W, W,  0x70, 0x10, W, W,  0x00, 0x00 },
            { 0x00, 0x00, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00 }
        },
        // invoke-virtual void methods on ad objects → nop
        {
            { 0x6e, W, W, W,  W, 0x00 }, // invoke-virtual {vX}, method@YYYY
            { 0x00, 0x00, 0x00, 0x00,  0x00, 0x00 }
        },
        // invoke-static void ad method → nop
        {
            { 0x71, W, W, W,  W, 0x00 }, // invoke-static {vX}, method@YYYY
            { 0x00, 0x00, 0x00, 0x00,  0x00, 0x00 }
        },
    };

    // ── Layer 0: Pattern matcher ───────────────────────────────────────────────

    /**
     * Match pattern with wildcards (0xFF = any byte) against data at pos.
     */
    private static boolean matchPattern(byte[] data, int pos, int[] pattern) {
        if (pos + pattern.length > data.length) return false;
        for (int i = 0; i < pattern.length; i++) {
            if (pattern[i] != W && (data[pos + i] & 0xFF) != pattern[i]) return false;
        }
        return true;
    }

    /**
     * Apply replacement, keeping wildcard positions from original data.
     */
    private static void applyPattern(byte[] data, int pos, int[] original, int[] replacement) {
        for (int i = 0; i < replacement.length; i++) {
            if (replacement[i] == W) {
                // Keep original byte (wildcard in replacement = copy original)
                // data[pos+i] stays unchanged
            } else {
                data[pos + i] = (byte) replacement[i];
            }
        }
    }

    /**
     * Scan DEX code section for byte patterns and apply patches.
     * This is the core LP technique — works regardless of obfuscation.
     */
    private static int applyBytePatterns(byte[] dex, int[][][] patterns, Progress p) {
        int patched = 0;

        // Only scan the code section — from data_off to end
        int dataOff = readU32Checked(dex, 0x6C);
        if (dataOff <= 0 || dataOff >= dex.length) dataOff = HEADER_SIZE;

        for (int[][]  pair : patterns) {
            int[] original    = pair[0];
            int[] replacement = pair[1];

            int pos = dataOff;
            while (pos <= dex.length - original.length) {
                if (matchPattern(dex, pos, original)) {
                    applyPattern(dex, pos, original, replacement);
                    patched++;
                    pos += original.length; // skip past match
                } else {
                    pos++;
                }
            }
        }

        return patched;
    }

    // ── String pool SDK scanning (LP's ad removal technique) ──────────────────

    /**
     * SDK substrings whose presence in string pool identifies ad/analytics SDKs.
     * When found, we locate method_ids referencing those class descriptors
     * and nop out their call sites in all code bodies.
     */
    private static final Map<String, String[]> SDK_STRING_MARKERS;
    static {
        Map<String, String[]> m = new HashMap<>();
        m.put("REMOVE_ADS", new String[]{
            "gms/ads", "com/google/android/gms/ads",
            "facebook/ads", "com/facebook/ads",
            "unity3d/ads", "com/unity3d/ads",
            "applovin", "com/applovin",
            "ironsource", "com/ironsource",
            "mopub", "com/mopub",
            "chartboost", "com/chartboost",
            "vungle", "com/vungle",
            "inmobi", "com/inmobi",
            "mbridge", "com/mbridge",
            "tapjoy", "com/tapjoy",
            "startapp", "com/startapp",
            "adcolony", "com/adcolony",
            "fyber", "com/fyber",
            "ogury", "io/ogury",
            "digitalturbine", "com/digitalturbine",
        });
        m.put("DISABLE_ANALYTICS", new String[]{
            "firebase/analytics", "FirebaseAnalytics",
            "mixpanel", "MixpanelAPI",
            "amplitude", "AmplitudeClient",
            "segment", "com/segment/analytics",
            "adjust/sdk", "com/adjust",
            "flurry", "com/flurry",
            "appsflyer", "com/appsflyer",
            "branch/io", "io/branch",
            "singular/net", "com/singular",
        });
        m.put("REMOVE_TELEMETRY", new String[]{
            "io/sentry", "com/bugsnag",
            "firebase/crashlytics", "FirebaseCrashlytics",
            "datadog", "com/datadog",
            "rollbar", "com/rollbar",
            "instabug", "com/instabug",
        });
        m.put("SSL_BYPASS", new String[]{
            "okhttp3/CertificatePinner",
            "okhttp3/internal/tls/OkHostnameVerifier",
        });
        SDK_STRING_MARKERS = Collections.unmodifiableMap(m);
    }

    /**
     * Find all string indices in the DEX that contain any SDK marker substring.
     */
    private static Set<Integer> findSdkStringIndices(DexFile file, String[] markers) {
        Set<Integer> result = new HashSet<>();
        for (int i = 0; i < file.stringIdsSize; i++) {
            String s = file.getStringRaw(i);
            if (s == null) continue;
            for (String marker : markers) {
                if (s.contains(marker)) {
                    result.add(i);
                    break;
                }
            }
        }
        return result;
    }

    /**
     * Find all method_ids whose class type descriptor string index is in sdkStringIndices,
     * OR whose class descriptor string contains any of the SDK markers.
     */
    private static Set<Integer> findSdkMethodIds(DexFile file, String[] markers) {
        // First find type_ids that match
        Set<Integer> sdkTypeIds = new HashSet<>();
        for (int i = 0; i < file.typeIdsSize; i++) {
            int strIdx = readU32Checked(file.bytes, file.typeIdsOff + i * 4);
            String desc = file.getStringRaw(strIdx);
            if (desc == null) continue;
            for (String marker : markers) {
                if (desc.contains(marker)) {
                    sdkTypeIds.add(i);
                    break;
                }
            }
        }

        // Now find method_ids whose class type_idx is in sdkTypeIds
        Set<Integer> methodIds = new HashSet<>();
        for (int i = 0; i < file.methodIdsSize; i++) {
            int off = file.methodIdsOff + i * METHOD_ID_SIZE;
            int typeIdx = readU16(file.bytes, off);
            if (sdkTypeIds.contains(typeIdx)) {
                methodIds.add(i);
            }
        }
        return methodIds;
    }

    /**
     * Walk all code bodies and nop out invoke-* instructions that reference
     * any of the target method IDs.
     *
     * invoke formats (3 code units = 6 bytes):
     *   6e-72: invoke-virtual/super/direct/static/interface {vC,vD,vE,vF,vG}, meth@BBBB
     *   74-78: invoke-virtual/super/direct/static/interface/range, meth@CCCC
     */
    private static int nopSdkCallSites(DexFile file, byte[] out, Set<Integer> targetMethodIds, Progress p) {
        if (targetMethodIds.isEmpty()) return 0;
        int nopped = 0;

        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef     = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int classDataOff = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;

            ClassData cd = parseClassData(file, file.bytes, classDataOff);
            for (EncodedMethod m : cd.methods) {
                if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;

                int insnsSize   = readU32(out, m.codeOffset + 12);
                int insnsOffset = m.codeOffset + 16;

                for (int u = 0; u + 2 < insnsSize; u++) {
                    int op = readU16(out, insnsOffset + u * 2) & 0xFF;
                    // 3-unit invokes: 6e-72, 74-78
                    boolean is3UnitInvoke = (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78);
                    if (!is3UnitInvoke) continue;
                    if (u + 2 >= insnsSize) continue;

                    int methodIdx = readU16(out, insnsOffset + (u + 1) * 2);
                    if (!targetMethodIds.contains(methodIdx)) continue;

                    // Nop the invoke (3 code units = 6 bytes)
                    writeU16(out, insnsOffset + u * 2,       0x0000);
                    writeU16(out, insnsOffset + (u + 1) * 2, 0x0000);
                    writeU16(out, insnsOffset + (u + 2) * 2, 0x0000);

                    // Also nop move-result if present
                    if (u + 3 < insnsSize) {
                        int nextOp = readU16(out, insnsOffset + (u + 3) * 2) & 0xFF;
                        if (nextOp == 0x0a || nextOp == 0x0b || nextOp == 0x0c) {
                            writeU16(out, insnsOffset + (u + 3) * 2, 0x0000);
                        }
                    }

                    nopped++;
                    u += 2;
                }
            }
        }

        if (nopped > 0) log(p, "  SDK call-site nops: " + nopped);
        return nopped;
    }

    // ── Layer 2: Owner stub (for methods defined in app DEX) ──────────────────

    private static final List<Recipe> OWNER_RECIPES;
    static {
        List<Recipe> r = new ArrayList<>();

        // Root detection wrappers that apps define internally
        r.add(new Recipe("ROOT_BYPASS",
            new String[]{"Lcom/scottyab/rootbeer/RootBeer;"},
            new String[]{"isRooted","isRootedWithoutBusyBoxCheck","detectRootManagementApps",
                         "detectPotentiallyDangerousApps","detectTestKeys"},
            "Z", 0));

        // SSL — sometimes shaded into app
        r.add(new Recipe("SSL_BYPASS",
            new String[]{"Lokhttp3/CertificatePinner;"},
            new String[]{"check"}, "V", 0));
        r.add(new Recipe("SSL_BYPASS",
            new String[]{"Lokhttp3/internal/tls/OkHostnameVerifier;"},
            new String[]{"verify"}, "Z", 1));

        // License
        r.add(new Recipe("LICENSE_BYPASS",
            new String[]{"Lcom/google/android/vending/licensing/LicenseChecker;"},
            new String[]{"checkAccess"}, "V", 0));
        r.add(new Recipe("LICENSE_BYPASS",
            new String[]{"Lcom/google/android/vending/licensing/LicenseValidator;"},
            new String[]{"verify"}, "V", 0));

        // IAP
        r.add(new Recipe("IAP_BYPASS",
            new String[]{"Lcom/android/billingclient/api/BillingResult;"},
            new String[]{"getResponseCode"}, "I", 0));

        // Play Services gate
        r.add(new Recipe("GOOGLE_PLAY_BYPASS",
            new String[]{"Lcom/google/android/gms/common/GoogleApiAvailability;",
                         "Lcom/google/android/gms/common/GoogleApiAvailabilityLight;"},
            new String[]{"isGooglePlayServicesAvailable"}, "I", 0));

        // SafetyNet
        r.add(new Recipe("SAFETYNET_BYPASS",
            new String[]{"Lcom/google/android/gms/safetynet/SafetyNetApi$AttestJwsResult;"},
            new String[]{"isBasicIntegrity","isCtsProfileMatch"}, "Z", 1));

        OWNER_RECIPES = Collections.unmodifiableList(r);
    }

    // ── Caller-context: SIGNATURE_BYPASS ─────────────────────────────────────

    private static final Map<String, String[][]> CALLER_TARGETS;
    static {
        Map<String, String[][]> m = new HashMap<>();
        m.put("SIGNATURE_BYPASS", new String[][]{
            {"Ljava/security/Signature;", "verify"}
        });
        CALLER_TARGETS = Collections.unmodifiableMap(m);
    }

    // ── Markers (detection badges) ────────────────────────────────────────────

    private static final String[][] MARKERS = {
        {"LICENSE_BYPASS",      "ILicensingService"},
        {"LICENSE_BYPASS",      "com/google/android/vending/licensing"},
        {"LICENSE_BYPASS",      "LICENSED"},
        {"IAP_BYPASS",          "com/android/vending/billing"},
        {"IAP_BYPASS",          "BillingClient"},
        {"IAP_BYPASS",          "PURCHASED"},
        {"SIGNATURE_BYPASS",    "getSignatures"},
        {"SIGNATURE_BYPASS",    "signingInfo"},
        {"REMOVE_ADS",          "com/google/android/gms/ads"},
        {"REMOVE_ADS",          "com/facebook/ads"},
        {"REMOVE_ADS",          "com/unity3d/ads"},
        {"REMOVE_ADS",          "com/applovin"},
        {"REMOVE_ADS",          "com/ironsource"},
        {"REMOVE_ADS",          "com/mopub"},
        {"REMOVE_ADS",          "com/chartboost"},
        {"REMOVE_ADS",          "com/vungle"},
        {"REMOVE_ADS",          "com/inmobi"},
        {"REMOVE_ADS",          "com/mbridge"},
        {"REMOVE_ADS",          "com/tapjoy"},
        {"SSL_BYPASS",          "CertificatePinner"},
        {"SSL_BYPASS",          "checkServerTrusted"},
        {"ROOT_BYPASS",         "isRooted"},
        {"ROOT_BYPASS",         "RootBeer"},
        {"ROOT_BYPASS",         "/system/xbin/su"},
        {"SAFETYNET_BYPASS",    "SafetyNet"},
        {"SAFETYNET_BYPASS",    "com/google/android/play/core/integrity"},
        {"FRIDA_BYPASS",        "frida"},
        {"FRIDA_BYPASS",        "XposedBridge"},
        {"FRIDA_BYPASS",        "tracerpid"},
        {"EMULATOR_BYPASS",     "qemu"},
        {"EMULATOR_BYPASS",     "goldfish"},
        {"DISABLE_FLAG_SECURE", "FLAG_SECURE"},
        {"DISABLE_ANALYTICS",   "FirebaseAnalytics"},
        {"DISABLE_ANALYTICS",   "MixpanelAPI"},
        {"REMOVE_TELEMETRY",    "FirebaseCrashlytics"},
        {"REMOVE_TELEMETRY",    "io/sentry"},
        {"BLOCK_AD_DOMAINS",    "isDomainBlocked"},
        {"GOOGLE_PLAY_BYPASS",  "isGooglePlayServicesAvailable"},
    };

    private static final byte[][] MARKER_BYTES;
    static {
        MARKER_BYTES = new byte[MARKERS.length][];
        for (int i = 0; i < MARKERS.length; i++)
            MARKER_BYTES[i] = MARKERS[i][1].getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public patch API
    // ─────────────────────────────────────────────────────────────────────────

public static byte[] patch(byte[] dex, Set<String> patchKeys, Progress progress) {
        if (dex == null || dex.length < HEADER_SIZE)
            throw new IllegalArgumentException("DEX too small: " + (dex == null ? 0 : dex.length));
        if (patchKeys == null || patchKeys.isEmpty()) {
            new DexFile(dex).validate();
            return dex.clone();
        }

        DexFile file = new DexFile(dex);
        file.validate();
        byte[] out = dex.clone();

        log(progress, "DEX: " + file.classDefsSize + " classes, " +
            file.methodIdsSize + " methods, " + file.stringIdsSize + " strings");

        int patched = 0;

        // ── LAYER 0: Byte pattern matching (LP technique) ─────────────────
        if (patchKeys.contains("LICENSE_BYPASS")) {
            int n = patchLicenseByPattern(file, out, progress);
            log(progress, "  [L0] LICENSE_BYPASS patterns: " + n);
            patched += n;
        }
        if (patchKeys.contains("IAP_BYPASS")) {
            int n = patchIapByPattern(file, out, progress);
            log(progress, "  [L0] IAP_BYPASS patterns: " + n);
            patched += n;
        }
        if (patchKeys.contains("ROOT_BYPASS")) {
            int n = patchRootByPattern(file, out, progress);
            log(progress, "  [L0] ROOT_BYPASS patterns: " + n);
            patched += n;
        }

        // ── LAYER 1: String pool scan + call site nop (LP ad removal) ────
        for (Map.Entry<String, String[]> e : SDK_STRING_MARKERS.entrySet()) {
            if (!patchKeys.contains(e.getKey())) continue;
            Set<Integer> methodIds = findSdkMethodIds(file, e.getValue());
            if (!methodIds.isEmpty()) {
                int n = nopSdkCallSites(file, out, methodIds, progress);
                log(progress, "  [L1] " + e.getKey() + " SDK nops: " + n +
                    " (" + methodIds.size() + " method IDs targeted)");
                patched += n;
            }
        }

        // ── LAYER 2: Owner stub recipes ───────────────────────────────────
        int ownerPatched = patchOwnerMethods(file, out, patchKeys, progress);
        log(progress, "  [L2] owner stubs: " + ownerPatched);
        patched += ownerPatched;

        // ── LAYER 3: Caller-context (SIGNATURE_BYPASS) ────────────────────
        int callerPatched = patchCallerVerdicts(file, out, patchKeys, progress);
        patched += callerPatched;

        if (patched == 0) {
            log(progress, "  no patch targets matched in this DEX");
            return dex.clone();
        }

        recomputeChecksums(out);
        new DexFile(out).validate();
        log(progress, "  total mutations: " + patched);
        return out;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 0: Contextual byte pattern patching
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Patch LICENSE_BYPASS using byte patterns stolen from LuckyPatcher.
     * Only applies patterns WITHIN methods that reference license-related strings.
     */
    private static int patchLicenseByPattern(DexFile file, byte[] out, Progress p) {
        // Find string indices related to licensing
        Set<Integer> licenseStrings = new HashSet<>();
        String[] licenseMarkers = {"LICENSED", "NOT_LICENSED", "LicenseChecker", "checkAccess",
                                   "ILicensingService", "android/vending/licensing", "checkLicense"};
        for (int i = 0; i < file.stringIdsSize; i++) {
            String s = file.getStringRaw(i);
            if (s == null) continue;
            for (String m : licenseMarkers) {
                if (s.contains(m)) { licenseStrings.add(i); break; }
            }
        }

        int patched = 0;

        // Apply patterns in ALL methods that reference license strings
        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef     = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int classDataOff = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;

            ClassData cd = parseClassData(file, file.bytes, classDataOff);
            for (EncodedMethod m : cd.methods) {
                if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;

                int insnsSize   = readU32(out, m.codeOffset + 12);
                int insnsOffset = m.codeOffset + 16;
                int byteLen     = insnsSize * 2;

                // Check if this method references any license string
                boolean isLicenseMethod = false;
                for (int u = 0; u < insnsSize - 1; u++) {
                    int op = readU16(out, insnsOffset + u * 2) & 0xFF;
                    // const-string = 0x1a (2 units), const-string/jumbo = 0x1b (3 units)
                    if (op == 0x1a && u + 1 < insnsSize) {
                        int strIdx = readU16(out, insnsOffset + (u + 1) * 2);
                        if (licenseStrings.contains(strIdx)) { isLicenseMethod = true; break; }
                    }
                }
                // Also check by return type Z (boolean) + method name heuristics
                MethodInfo info = file.getMethodInfo(m.methodIndex);
                if ("Z".equals(info.returnDesc)) {
                    // If class contains "license" or "lvl" strings, also target
                    String cls = file.getTypeDescriptor(readU32(file.bytes, classDef));
                    if (cls.toLowerCase().contains("license") ||
                        cls.toLowerCase().contains("lvl") ||
                        info.name.toLowerCase().contains("license") ||
                        info.name.toLowerCase().contains("checkaccess") ||
                        info.name.toLowerCase().contains("isvalid") ||
                        info.name.toLowerCase().contains("isverified") ||
                        info.name.toLowerCase().contains("isregistered") ||
                        info.name.toLowerCase().contains("ispremium") ||
                        info.name.toLowerCase().contains("ispurchased") ||
                        info.name.toLowerCase().contains("islicensed")) {
                        isLicenseMethod = true;
                    }
                }

                if (!isLicenseMethod) continue;

                // Apply LP license patterns to this method's code
                byte[] codeSection = out;
                for (int[][] pair : LICENSE_PATTERNS) {
                    int[] orig = pair[0], repl = pair[1];
                    int pos = insnsOffset;
                    int end = insnsOffset + byteLen - orig.length;
                    while (pos <= end) {
                        if (matchPattern(codeSection, pos, orig)) {
                            applyPattern(codeSection, pos, orig, repl);
                            patched++;
                            pos += orig.length;
                        } else {
                            pos++;
                        }
                    }
                }
            }
        }

        // Also scan ODEX-style: apply license pattern across entire data section
        int dataOff = readU32Checked(out, 0x6C);
        if (dataOff <= 0) dataOff = HEADER_SIZE;
        // Primary LP pattern — apply globally in data section
        int[] lpOrig = { 0x63, W, W, W,  0x38, 0x00, 0x04, 0x00,  0x12, 0x10,  0x0F, 0x00 };
        int[] lpRepl = { 0x12, 0x10, 0x00, 0x00,  0x00, 0x00, 0x00, 0x00,  0x00, 0x00,  0x0F, 0x00 };
        int pos = dataOff;
        while (pos <= out.length - lpOrig.length) {
            if (matchPattern(out, pos, lpOrig)) {
                applyPattern(out, pos, lpOrig, lpRepl);
                patched++;
                pos += lpOrig.length;
            } else pos++;
        }

        return patched;
    }

    /**
     * Patch IAP bypass: in billing-related methods, ensure getResponseCode() returns 0.
     * Also patches launchBillingFlow to always succeed.
     */
    private static int patchIapByPattern(DexFile file, byte[] out, Progress p) {
        // Find billing-related string indices
        String[] billingMarkers = {"billing", "BillingClient", "Purchase", "PURCHASED",
                                   "getResponseCode", "launchBillingFlow", "queryPurchases",
                                   "consumePurchase", "acknowledgePurchase", "getSkuDetails",
                                   "ITEM_ALREADY_OWNED", "BILLING_RESPONSE", "queryProductDetails"};
        Set<Integer> billingStrings = new HashSet<>();
        for (int i = 0; i < file.stringIdsSize; i++) {
            String s = file.getStringRaw(i);
            if (s == null) continue;
            for (String m : billingMarkers) {
                if (s.contains(m)) { billingStrings.add(i); break; }
            }
        }

        int patched = 0;

        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef     = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int classDataOff = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;

            ClassData cd = parseClassData(file, file.bytes, classDataOff);
            for (EncodedMethod m : cd.methods) {
                if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;

                MethodInfo info = file.getMethodInfo(m.methodIndex);
                // Target int-returning methods named like billing checks
                if (!"I".equals(info.returnDesc) && !"Z".equals(info.returnDesc)) continue;

                int insnsSize   = readU32(out, m.codeOffset + 12);
                int insnsOffset = m.codeOffset + 16;
                int byteLen     = insnsSize * 2;

                // Check if references billing strings
                boolean isBillingMethod = false;
                for (int u = 0; u < insnsSize - 1; u++) {
                    int op = readU16(out, insnsOffset + u * 2) & 0xFF;
                    if (op == 0x1a && u + 1 < insnsSize) {
                        int strIdx = readU16(out, insnsOffset + (u + 1) * 2);
                        if (billingStrings.contains(strIdx)) { isBillingMethod = true; break; }
                    }
                }

                String methodName = info.name.toLowerCase();
                if (methodName.contains("response") || methodName.contains("billing") ||
                    methodName.contains("purchase") || methodName.contains("getcode") ||
                    methodName.contains("responseCode") || methodName.contains("billingresult")) {
                    isBillingMethod = true;
                }

                if (!isBillingMethod) continue;

                // For int-returning billing methods: ensure they return 0 (OK)
                // Find "const/4 vX, #nonzero" before return and change to #0
                for (int u = 0; u < insnsSize - 1; u++) {
                    int word = readU16(out, insnsOffset + u * 2);
                    int op   = word & 0xFF;
                    // const/4 = 0x12: format is B|A|12 where B=literal, A=reg
                    if (op == 0x12) {
                        int literal = (word >> 12) & 0xF;
                        // If literal != 0, check if followed by return
                        if (literal != 0 && u + 1 < insnsSize) {
                            int nextWord = readU16(out, insnsOffset + (u + 1) * 2);
                            int nextOp   = nextWord & 0xFF;
                            if (nextOp == 0x0F) { // return vX
                                // Change to const/4 vX, #0 + return vX
                                int reg = (word >> 8) & 0xF;
                                writeU16(out, insnsOffset + u * 2, 0x12 | (reg << 8) | (0 << 12));
                                patched++;
                            }
                        }
                    }
                }
            }
        }

        return patched;
    }

    /**
     * Patch ROOT_BYPASS: in root-detection methods, ensure they return false.
     */
    private static int patchRootByPattern(DexFile file, byte[] out, Progress p) {
        String[] rootMarkers = {"isRooted", "isDeviceRooted", "isRoot", "checkRoot",
                                "RootBeer", "detectRoot", "su", "/system/xbin",
                                "which su", "test-keys", "supersu", "magisk",
                                "busybox", "rootcloak", "chainfire"};
        int patched = 0;

        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef     = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int classDataOff = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;

            ClassData cd = parseClassData(file, file.bytes, classDataOff);
            for (EncodedMethod m : cd.methods) {
                if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;

                MethodInfo info = file.getMethodInfo(m.methodIndex);
                if (!"Z".equals(info.returnDesc)) continue; // only boolean methods

                String methodName = info.name.toLowerCase();
                boolean isRootMethod = false;
                for (String marker : rootMarkers) {
                    if (methodName.contains(marker.toLowerCase())) { isRootMethod = true; break; }
                }

                if (!isRootMethod) {
                    // Also check if method body contains root-related strings
                    int insnsSize   = readU32(out, m.codeOffset + 12);
                    int insnsOffset = m.codeOffset + 16;
                    outer:
                    for (int u = 0; u < insnsSize - 1; u++) {
                        int op = readU16(out, insnsOffset + u * 2) & 0xFF;
                        if (op == 0x1a && u + 1 < insnsSize) {
                            int strIdx = readU16(out, insnsOffset + (u + 1) * 2);
                            String s = file.getStringRaw(strIdx);
                            if (s != null) {
                                for (String marker : rootMarkers) {
                                    if (s.contains(marker)) { isRootMethod = true; break outer; }
                                }
                            }
                        }
                    }
                }

                if (!isRootMethod) continue;

                int insnsSize   = readU32(out, m.codeOffset + 12);
                int insnsOffset = m.codeOffset + 16;

                // Find all "const/4 vX, #1 + return vX" and change to return false
                for (int u = 0; u < insnsSize - 1; u++) {
                    int word = readU16(out, insnsOffset + u * 2);
                    int op   = word & 0xFF;
                    if (op == 0x12) {
                        int literal = (word >> 12) & 0xF;
                        if (literal != 0 && u + 1 < insnsSize) {
                            int nextWord = readU16(out, insnsOffset + (u + 1) * 2);
                            int nextOp   = nextWord & 0xFF;
                            if (nextOp == 0x0F) { // return vX
                                int reg = (word >> 8) & 0xF;
                                // Set to const/4 vX, #0
                                writeU16(out, insnsOffset + u * 2, 0x12 | (reg << 8) | (0 << 12));
                                patched++;
                            }
                        }
                    }
                    // Also: sget-boolean field + return → stub to false
                    // 0x60 = sget-boolean
                    if (op == 0x60 && u + 2 < insnsSize) {
                        int nextWord = readU16(out, insnsOffset + (u + 2) * 2);
                        if ((nextWord & 0xFF) == 0x0F) {
                            int reg = (word >> 8) & 0xFF;
                            // Replace sget with const/4 vX, #0
                            writeU16(out, insnsOffset + u * 2, 0x12 | (reg << 8));
                            writeU16(out, insnsOffset + (u + 1) * 2, 0x0000);
                            patched++;
                        }
                    }
                }
            }
        }

        return patched;
    }

    // ── Layer 2: Owner stubs ──────────────────────────────────────────────────

    private static int patchOwnerMethods(DexFile file, byte[] out, Set<String> patchKeys, Progress p) {
        int patched = 0;
        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef       = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int classTypeIndex = readU32(file.bytes, classDef);
            String classDesc   = file.getTypeDescriptor(classTypeIndex);
            int classDataOff   = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;

            ClassData cd = parseClassData(file, out, classDataOff);
            for (EncodedMethod m : cd.methods) {
                if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;

                MethodInfo info  = file.getMethodInfo(m.methodIndex);
                Recipe recipe    = findRecipe(patchKeys, classDesc, info.name);
                if (recipe == null) continue;

                String rt = recipe.expectedReturn == null ? "V" : recipe.expectedReturn;
                if (recipe.expectedReturn != null && !recipe.expectedReturn.equals(info.returnDesc)) continue;

                CodeItem code    = CodeItem.parse(out, m.codeOffset);
                int required     = requiredUnits(rt);
                boolean wide     = "J".equals(rt) || "D".equals(rt);
                int minRegs      = wide ? 2 : ("V".equals(rt) ? 0 : 1);
                if (code.registersSize < minRegs) continue;

                if (code.triesSize != 0) {
                    int boundary = firstBoundary(out, code.insnsOffset, code.insnsSize, required);
                    if (boundary < 0) continue;
                    for (int u = 0; u < boundary; u++) writeU16(out, code.insnsOffset + u * 2, 0x0000);
                    emitReturnStub(out, code.insnsOffset, boundary, code.registersSize, rt, recipe.stubValue);
                    patched++;
                    log(p, "  [L2] stub " + classDesc + "." + info.name + " " + rt + " (try/catch)");
                    continue;
                }

                if (code.insnsSize < required) continue;
                emitReturnStub(out, code.insnsOffset, code.insnsSize, code.registersSize, rt, recipe.stubValue);
                patched++;
                log(p, "  [L2] stub " + classDesc + "." + info.name + " → " + recipe.stubValue);
            }
        }
        return patched;
    }

    // ── Layer 3: Caller-context (SIGNATURE_BYPASS) ────────────────────────────

    private static int patchCallerVerdicts(DexFile file, byte[] out, Set<String> patchKeys, Progress p) {
        int patched = 0;
        for (Map.Entry<String, String[][]> entry : CALLER_TARGETS.entrySet()) {
            if (!patchKeys.contains(entry.getKey())) continue;

            Set<Integer> targetIds = new HashSet<>();
            for (String[] t : entry.getValue()) targetIds.addAll(findMethodIds(file, t[0], t[1]));
            if (targetIds.isEmpty()) continue;

            for (int ci = 0; ci < file.classDefsSize; ci++) {
                int classDef     = file.classDefsOff + ci * CLASS_DEF_SIZE;
                int classDataOff = readU32(file.bytes, classDef + 24);
                if (classDataOff == 0) continue;

                ClassData cd = parseClassData(file, out, classDataOff);
                for (EncodedMethod m : cd.methods) {
                    if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                    if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;
                    MethodInfo info = file.getMethodInfo(m.methodIndex);
                    if (!"Z".equals(info.returnDesc)) continue;
                    CodeItem code = CodeItem.parse(out, m.codeOffset);
                    if (code.triesSize != 0) continue;
                    if (!invokeRefsAny(out, code, targetIds)) continue;
                    if (code.registersSize < 1 || code.insnsSize < 2) continue;
                    emitReturnStub(out, code.insnsOffset, code.insnsSize, code.registersSize, "Z", 1);
                    patched++;
                    String desc = file.getTypeDescriptor(readU32(file.bytes, classDef));
                    log(p, "  [L3] caller-verdict " + desc + "." + info.name);
                }
            }
        }
        return patched;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scan API (for detection / UI badges)
    // ─────────────────────────────────────────────────────────────────────────

    public static Set<String> scanKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();
        Set<String> keys = new HashSet<>();

        // Check SDK string markers (Layer 1 detection)
        for (Map.Entry<String, String[]> e : SDK_STRING_MARKERS.entrySet()) {
            Set<Integer> ids = findSdkMethodIds(file, e.getValue());
            if (!ids.isEmpty()) keys.add(e.getKey());
        }

        // Check owner recipes (Layer 2 detection)
        for (Recipe recipe : OWNER_RECIPES)
            if (containsRecipeTarget(file, recipe)) keys.add(recipe.key);

        // Markers (badge layer)
        keys.addAll(scanMarkers(dex));
        return keys;
    }

    public static Set<String> scanStructuralKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();
        Set<String> keys = new HashSet<>();
        for (Map.Entry<String, String[]> e : SDK_STRING_MARKERS.entrySet()) {
            if (!findSdkMethodIds(file, e.getValue()).isEmpty()) keys.add(e.getKey());
        }
        for (Recipe recipe : OWNER_RECIPES)
            if (containsRecipeTarget(file, recipe)) keys.add(recipe.key);
        return keys;
    }

    public static Set<String> scanMarkers(byte[] data) {
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < MARKERS.length; i++)
            if (containsBytes(data, MARKER_BYTES[i])) keys.add(MARKERS[i][0]);
        return keys;
    }

    public static List<String[]> quickScan(InputStream input) throws IOException {
        byte[] data = readAll(input);
        Set<String> keys = scanKeys(data);
        List<String[]> result = new ArrayList<>();
        for (String key : keys) result.add(new String[]{key, describeKey(key)});
        return result;
    }

    private static String describeKey(String key) {
        switch (key) {
            case "REMOVE_ADS":          return "Ad SDK call sites detected (20+ networks)";
            case "DISABLE_ANALYTICS":   return "Analytics SDK detected";
            case "REMOVE_TELEMETRY":    return "Crash reporting SDK detected";
            case "SSL_BYPASS":          return "TLS pinning detected";
            case "ROOT_BYPASS":         return "Root detection logic detected";
            case "SAFETYNET_BYPASS":    return "SafetyNet / Play Integrity detected";
            case "FRIDA_BYPASS":        return "Anti-debug detected";
            case "EMULATOR_BYPASS":     return "Emulator detection detected";
            case "LICENSE_BYPASS":      return "Play LVL / license check detected";
            case "IAP_BYPASS":          return "Play Billing / IAP detected";
            case "SIGNATURE_BYPASS":    return "Signature verification detected";
            case "GOOGLE_PLAY_BYPASS":  return "Play Services availability gate detected";
            case "DISABLE_FLAG_SECURE": return "FLAG_SECURE usage detected";
            case "BLOCK_AD_DOMAINS":    return "Ad domain gate detected";
            default:                    return "Detected";
        }
    }

    public static byte[] applyAdsDomainBlock(byte[] dex, List<String> domains) {
        new DexFile(dex).validate();
        return dex.clone();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Manifest patching (binary AXML)
    // ─────────────────────────────────────────────────────────────────────────

    public static byte[] patchManifest(byte[] manifest, Set<String> patchKeys) {
        if (manifest == null || manifest.length < 8) throw new IllegalArgumentException("Manifest null/small");
        if (patchKeys == null || patchKeys.isEmpty()) return manifest.clone();

        byte[] out = manifest.clone();
        StringPool pool = null;
        int resourceMapOff = -1;
        int cursor = 0;

        while (cursor < out.length) {
            if (cursor + 8 > out.length) throw new IllegalArgumentException("Truncated AXML");
            int type       = readU16(out, cursor);
            int headerSize = readU16(out, cursor + 2);
            int chunkSize  = readU32Checked(out, cursor + 4);
            if (headerSize < 8 || chunkSize < headerSize) break;
            if ((long)cursor + chunkSize > out.length) break;
            if (type == RES_STRING_POOL_TYPE && pool == null) pool = StringPool.parse(out, cursor);
            else if (type == RES_XML_RESOURCE_MAP_TYPE) resourceMapOff = cursor;
            cursor += chunkSize;
        }

        if (pool == null || resourceMapOff < 0) return manifest.clone();

        boolean changed = false;
        cursor = 0;
        while (cursor < out.length) {
            int type      = readU16(out, cursor);
            int chunkSize = readU32Checked(out, cursor + 4);
            if (type == RES_XML_START_ELEMENT_TYPE)
                changed |= patchStartElement(out, cursor, chunkSize, pool, resourceMapOff, patchKeys);
            cursor += chunkSize;
        }
        return changed ? out : manifest.clone();
    }

    public static Set<String> scanManifestKeys(byte[] manifest) {
        Set<String> keys = new HashSet<>();
        if (manifest == null || manifest.length < 8) return keys;

        StringPool pool = null;
        int resourceMapOff = -1;
        int cursor = 0;

        while (cursor < manifest.length) {
            if (cursor + 8 > manifest.length) return keys;
            int type       = readU16(manifest, cursor);
            int headerSize = readU16(manifest, cursor + 2);
            int chunkSize  = readU32Checked(manifest, cursor + 4);
            if (headerSize < 8 || chunkSize < headerSize || (long)cursor + chunkSize > manifest.length) return keys;
            if (type == RES_STRING_POOL_TYPE && pool == null) pool = StringPool.parse(manifest, cursor);
            else if (type == RES_XML_RESOURCE_MAP_TYPE) resourceMapOff = cursor;
            cursor += chunkSize;
        }

        if (pool == null || resourceMapOff < 0) return keys;

        cursor = 0;
        while (cursor < manifest.length) {
            int type      = readU16(manifest, cursor);
            int chunkSize = readU32Checked(manifest, cursor + 4);
            if (type == RES_XML_START_ELEMENT_TYPE)
                scanStartElement(manifest, cursor, chunkSize, resourceMapOff, keys);
            cursor += chunkSize;
        }
        return keys;
    }

    private static void scanStartElement(byte[] data, int co, int cs, int rmo, Set<String> keys) {
        if (co + 36 > data.length) return;
        int nodeHdr = readU16(data, co + 2);
        if (nodeHdr < 16) return;
        int ext = co + nodeHdr;
        if (ext + 20 > data.length) return;
        int attrStart = readU16(data, ext + 8);
        int attrSize  = readU16(data, ext + 10);
        int attrCount = readU16(data, ext + 12);
        if (attrSize < 20 || attrCount <= 0) return;
        int attrBase = ext + attrStart;
        long end = (long)attrBase + (long)attrCount * attrSize;
        if (attrBase < 0 || end > co + cs || end > data.length) return;
        for (int i = 0; i < attrCount; i++) {
            int attr    = attrBase + i * attrSize;
            int nameIdx = readU32(data, attr + 4);
            int resId   = resolveResId(data, rmo, nameIdx);
            int dtype   = data[attr + 15] & 0xff;
            int dval    = readU32(data, attr + 16);
            if (dtype != TYPE_INT_BOOLEAN) continue;
            boolean cur = dval != 0;
            if (resId == ATTR_DEBUGGABLE      && !cur) keys.add("FORCE_DEBUGGABLE");
            if (resId == ATTR_EXPORTED        && !cur) keys.add("EXPORT_ALL_COMPONENTS");
            if (resId == ATTR_ALLOW_BACKUP    && !cur) keys.add("ALLOW_BACKUP");
            if (resId == ATTR_FULL_BACKUP_ONLY && cur) keys.add("ALLOW_BACKUP");
        }
    }

    private static boolean patchStartElement(byte[] data, int co, int cs, StringPool pool, int rmo, Set<String> keys) {
        if (co + 36 > data.length) return false;
        int nodeHdr = readU16(data, co + 2);
        if (nodeHdr < 16) return false;
        int ext = co + nodeHdr;
        if (ext + 20 > data.length) return false;
        int attrStart = readU16(data, ext + 8);
        int attrSize  = readU16(data, ext + 10);
        int attrCount = readU16(data, ext + 12);
        if (attrSize < 20) return false;
        int attrBase = ext + attrStart;
        long end = (long)attrBase + (long)attrCount * attrSize;
        if (attrBase < 0 || end > co + cs || end > data.length) return false;
        boolean changed = false;
        for (int i = 0; i < attrCount; i++) {
            int attr    = attrBase + i * attrSize;
            int nameIdx = readU32(data, attr + 4);
            int resId   = resolveResId(data, rmo, nameIdx);
            if (resId == ATTR_DEBUGGABLE       && keys.contains("FORCE_DEBUGGABLE"))       { writeBool(data, attr, true);  changed = true; }
            if (resId == ATTR_EXPORTED         && keys.contains("EXPORT_ALL_COMPONENTS"))  { writeBool(data, attr, true);  changed = true; }
            if (resId == ATTR_ALLOW_BACKUP     && keys.contains("ALLOW_BACKUP"))           { writeBool(data, attr, true);  changed = true; }
            if (resId == ATTR_FULL_BACKUP_ONLY && keys.contains("ALLOW_BACKUP"))           { writeBool(data, attr, false); changed = true; }
        }
        return changed;
    }

    private static int resolveResId(byte[] data, int rmo, int strIdx) {
        int headerSize = readU16(data, rmo + 2);
        int mapBase    = rmo + headerSize;
        long off       = (long)mapBase + (long)strIdx * 4L;
        if (off < 0 || off + 4 > data.length) return 0;
        return readU32Checked(data, (int)off);
    }

    private static void writeBool(byte[] data, int attrOff, boolean value) {
        writeU16(data, attrOff + 12, 8);
        data[attrOff + 14] = 0;
        data[attrOff + 15] = TYPE_INT_BOOLEAN;
        writeU32(data, attrOff + 16, value ? 1 : 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Checksum
    // ─────────────────────────────────────────────────────────────────────────

    public static void recomputeChecksums(byte[] dex) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            sha1.update(dex, 32, dex.length - 32);
            byte[] digest = sha1.digest();
            System.arraycopy(digest, 0, dex, 12, digest.length);
            Adler32 adler = new Adler32();
            adler.update(dex, 12, dex.length - 12);
            writeU32(dex, 8, (int)adler.getValue());
        } catch (Exception e) {
            throw new IllegalArgumentException("Checksum failed: " + e.getMessage(), e);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // DEX file model
    // ─────────────────────────────────────────────────────────────────────────

    private static final class DexFile {
        final byte[] bytes;
        final int fileSize, headerSize;
        final int stringIdsSize, stringIdsOff;
        final int typeIdsSize,   typeIdsOff;
        final int protoIdsSize,  protoIdsOff;
        final int methodIdsSize, methodIdsOff;
        final int classDefsSize, classDefsOff;
        final int dataSize,      dataOff;

        DexFile(byte[] bytes) {
            this.bytes    = bytes;
            fileSize      = readU32Checked(bytes, 0x20);
            headerSize    = readU32Checked(bytes, 0x24);
            stringIdsSize = readU32Checked(bytes, 0x38);
            stringIdsOff  = readU32Checked(bytes, 0x3C);
            typeIdsSize   = readU32Checked(bytes, 0x40);
            typeIdsOff    = readU32Checked(bytes, 0x44);
            protoIdsSize  = readU32Checked(bytes, 0x48);
            protoIdsOff   = readU32Checked(bytes, 0x4C);
            methodIdsSize = readU32Checked(bytes, 0x58);
            methodIdsOff  = readU32Checked(bytes, 0x5C);
            classDefsSize = readU32Checked(bytes, 0x60);
            classDefsOff  = readU32Checked(bytes, 0x64);
            dataSize      = readU32Checked(bytes, 0x68);
            dataOff       = readU32Checked(bytes, 0x6C);
        }

        void validate() {
            if (bytes.length < HEADER_SIZE) throw new IllegalArgumentException("DEX header truncated");
            if (bytes[0]!='d'||bytes[1]!='e'||bytes[2]!='x'||bytes[3]!='\n')
                throw new IllegalArgumentException("Bad DEX magic");
            if (bytes[7] != 0) throw new IllegalArgumentException("Bad magic terminator");
            if (headerSize != HEADER_SIZE) throw new IllegalArgumentException("Bad header size: " + headerSize);
            int endian = readU32Checked(bytes, 0x28);
            if (endian != DEX_ENDIAN) throw new IllegalArgumentException("Bad endian");
            if (fileSize != bytes.length) throw new IllegalArgumentException(
                "file_size mismatch: " + fileSize + " vs " + bytes.length);
            if (dataOff < HEADER_SIZE || (long)dataOff + dataSize > bytes.length)
                throw new IllegalArgumentException("Bad data section");
            validateTable("string_ids", stringIdsSize, stringIdsOff, 4);
            validateTable("type_ids",   typeIdsSize,   typeIdsOff,   TYPE_ID_SIZE);
            validateTable("proto_ids",  protoIdsSize,  protoIdsOff,  PROTO_ID_SIZE);
            validateTable("method_ids", methodIdsSize, methodIdsOff, METHOD_ID_SIZE);
            validateTable("class_defs", classDefsSize, classDefsOff, CLASS_DEF_SIZE);
        }

        private void validateTable(String n, int count, int off, int sz) {
            if (count == 0) return;
            if (off < HEADER_SIZE) throw new IllegalArgumentException(n + " inside header");
            if ((long)off + (long)count * sz > bytes.length) throw new IllegalArgumentException(n + " overflow");
            if ((off & 3) != 0) throw new IllegalArgumentException(n + " misaligned");
        }

        int readU32(int off) { return readU32Checked(bytes, off); }

        /** Get raw string without MUTF-8 overhead — faster for scanning */
        String getStringRaw(int idx) {
            if (idx < 0 || idx >= stringIdsSize) return null;
            int soff = readU32Checked(bytes, stringIdsOff + idx * 4);
            if (soff <= 0 || soff >= bytes.length) return null;
            try {
                // Skip ULEB128 length
                int pos = soff;
                while (pos < bytes.length && (bytes[pos] & 0x80) != 0) pos++;
                pos++; // skip last byte of ULEB128
                // Find null terminator
                int end = pos;
                while (end < bytes.length && bytes[end] != 0 && end - pos < 512) end++;
                return new String(bytes, pos, end - pos, java.nio.charset.StandardCharsets.UTF_8);
            } catch (Exception e) { return null; }
        }

        String getString(int idx) {
            String s = getStringRaw(idx);
            return s != null ? s : "";
        }

        String getTypeDescriptor(int typeIdx) {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) throw new IllegalArgumentException("type OOB: " + typeIdx);
            return getString(readU32Checked(bytes, typeIdsOff + typeIdx * 4));
        }

        MethodInfo getMethodInfo(int methodIdx) {
            if (methodIdx < 0 || methodIdx >= methodIdsSize) throw new IllegalArgumentException("method OOB");
            int off        = methodIdsOff + methodIdx * METHOD_ID_SIZE;
            int classIdx   = readU16(bytes, off);
            int protoIdx   = readU16(bytes, off + 2);
            int nameIdx    = readU32(off + 4);
            String name    = getString(nameIdx);
            if (protoIdx < 0 || protoIdx >= protoIdsSize) throw new IllegalArgumentException("proto OOB");
            int protoOff   = protoIdsOff + protoIdx * PROTO_ID_SIZE;
            int retTypeIdx = readU32(protoOff + 4);
            String retDesc = getTypeDescriptor(retTypeIdx);
            return new MethodInfo(methodIdx, classIdx, protoIdx, name, retDesc);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static boolean containsRecipeTarget(DexFile file, Recipe recipe) {
        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef  = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int typeIndex = readU32(file.bytes, classDef);
            String desc   = file.getTypeDescriptor(typeIndex);
            if (!recipe.matchesClass(desc)) continue;
            int classDataOff = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;
            ClassData cd = parseClassData(file, file.bytes, classDataOff);
            for (EncodedMethod m : cd.methods) {
                MethodInfo info = file.getMethodInfo(m.methodIndex);
                if (!recipe.matchesMethod(info.name)) continue;
                if (recipe.expectedReturn != null && !recipe.expectedReturn.equals(info.returnDesc)) continue;
                return true;
            }
        }
        return false;
    }

    private static Recipe findRecipe(Set<String> keys, String classDesc, String methodName) {
        for (Recipe recipe : OWNER_RECIPES) {
            if (!keys.contains(recipe.key)) continue;
            if (!recipe.matchesClass(classDesc)) continue;
            if (!recipe.matchesMethod(methodName)) continue;
            return recipe;
        }
        return null;
    }

    private static List<Integer> findMethodIds(DexFile file, String classDesc, String methodName) {
        List<Integer> result = new ArrayList<>();
        for (int i = 0; i < file.methodIdsSize; i++) {
            int off     = file.methodIdsOff + i * METHOD_ID_SIZE;
            int typeIdx = readU16(file.bytes, off);
            try {
                if (!classDesc.equals(file.getTypeDescriptor(typeIdx))) continue;
                int nameIdx = readU32Checked(file.bytes, off + 4);
                if (methodName.equals(file.getString(nameIdx))) result.add(i);
            } catch (Exception ignored) {}
        }
        return result;
    }

    private static boolean invokeRefsAny(byte[] data, CodeItem code, Set<Integer> ids) {
        for (int u = 0; u < code.insnsSize - 1; u++) {
            int op = readU16(data, code.insnsOffset + u * 2) & 0xFF;
            boolean inv = (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78);
            if (!inv) continue;
            int target = readU16(data, code.insnsOffset + (u + 1) * 2);
            if (ids.contains(target)) return true;
        }
        return false;
    }

    private static int requiredUnits(String rt) {
        if ("V".equals(rt)) return 1;
        if ("J".equals(rt) || "D".equals(rt)) return 3;
        return 2;
    }

    private static void emitReturnStub(byte[] data, int offset, int insnsSize, int regs, String rt, int sv) {
        for (int i = 0; i < insnsSize * 2; i++) data[offset + i] = 0;
        if ("V".equals(rt)) { writeU16(data, offset, 0x000e); return; }
        if (regs == 0) throw new IllegalArgumentException("Need register for non-void return");
        if ("J".equals(rt) || "D".equals(rt)) {
            writeU16(data, offset, 0x0016); writeU16(data, offset+2, 0); writeU16(data, offset+4, 0x0010); return;
        }
        writeU16(data, offset, 0x0012 | ((sv & 0xF) << 12));
        writeU16(data, offset + 2, (rt.startsWith("L") || rt.startsWith("[")) ? 0x0011 : 0x000f);
    }

    private static final int[] OPCODE_UNITS = buildOpcodeUnits();
    private static int[] buildOpcodeUnits() {
        int[] t = new int[256];
        t[0x00]=1; t[0x01]=1; t[0x02]=2; t[0x03]=3; t[0x04]=1; t[0x05]=2; t[0x06]=3;
        t[0x07]=1; t[0x08]=2; t[0x09]=3; t[0x0a]=1; t[0x0b]=1; t[0x0c]=1; t[0x0d]=1;
        t[0x0e]=1; t[0x0f]=1; t[0x10]=1; t[0x11]=1; t[0x12]=1; t[0x13]=2; t[0x14]=3;
        t[0x15]=2; t[0x16]=2; t[0x17]=3; t[0x18]=5; t[0x19]=2; t[0x1a]=2; t[0x1b]=3;
        t[0x1c]=2; t[0x1d]=1; t[0x1e]=1; t[0x1f]=2; t[0x20]=2; t[0x21]=1; t[0x22]=2;
        t[0x23]=2; t[0x24]=3; t[0x25]=3; t[0x26]=3; t[0x27]=1; t[0x28]=1; t[0x29]=2;
        t[0x2a]=3; t[0x2b]=3; t[0x2c]=3;
        for (int i=0x2d;i<=0x3d;i++) t[i]=2;
        for (int i=0x44;i<=0x6d;i++) t[i]=2;
        for (int i=0x6e;i<=0x72;i++) t[i]=3;
        for (int i=0x74;i<=0x78;i++) t[i]=3;
        for (int i=0x7b;i<=0x8f;i++) t[i]=1;
        for (int i=0x90;i<=0xaf;i++) t[i]=2;
        for (int i=0xb0;i<=0xcf;i++) t[i]=1;
        for (int i=0xd0;i<=0xe2;i++) t[i]=2;
        t[0xfa]=4; t[0xfb]=4; t[0xfc]=3; t[0xfd]=3; t[0xfe]=2; t[0xff]=2;
        return t;
    }

    private static int firstBoundary(byte[] data, int off, int size, int min) {
        int u = 0;
        while (u < min) {
            if (u >= size) return -1;
            int op = readU16(data, off + u * 2) & 0xFF;
            int s  = OPCODE_UNITS[op];
            if (s <= 0 || u + s > size) return -1;
            u += s;
        }
        return u;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Data models
    // ─────────────────────────────────────────────────────────────────────────

    private static final class CodeItem {
        final int registersSize, triesSize, insnsSize, insnsOffset;
        private CodeItem(int r, int t, int s, int off) {
            registersSize=r; triesSize=t; insnsSize=s; insnsOffset=off;
        }
        static CodeItem parse(byte[] data, int off) {
            checkRange(off, 16, data.length, "code_item");
            int regs  = readU16(data, off);
            int tries = readU16(data, off + 6);
            int size  = readU32Checked(data, off + 12);
            int insOff= off + 16;
            if ((long)insOff + (long)size * 2 > data.length)
                throw new IllegalArgumentException("code insns overflow");
            return new CodeItem(regs, tries, size, insOff);
        }
    }

    private static final class Recipe {
        final String key; final String[] classes; final String[] methods;
        final String expectedReturn; final int stubValue;
        Recipe(String k, String[] c, String[] m, String r, int sv) {
            key=k; classes=c; methods=m; expectedReturn=r; stubValue=sv;
        }
        boolean matchesClass(String d) { for (String c:classes) if(c.equals(d)) return true; return false; }
        boolean matchesMethod(String n) { for (String m:methods) if(m.equals(n)) return true; return false; }
    }

    private static final class MethodInfo {
        final int idx, classIdx, protoIdx; final String name, returnDesc;
        MethodInfo(int i,int ci,int pi,String n,String r){idx=i;classIdx=ci;protoIdx=pi;name=n;returnDesc=r;}
    }

    private static final class EncodedMethod {
        final int methodIndex, accessFlags, codeOffset;
        EncodedMethod(int m,int a,int c){methodIndex=m;accessFlags=a;codeOffset=c;}
    }

    private static final class ClassData {
        final List<EncodedMethod> methods;
        ClassData(List<EncodedMethod> m){methods=m;}
    }

    private static final class Cursor {
        final byte[] data; int pos;
        Cursor(byte[] d, int p){data=d;pos=p;}
        int readUleb128(){
            int r=0,s=0;
            for(int i=0;i<5;i++){
                if(pos>=data.length)return r;
                int b=data[pos++]&0xff;
                r|=(b&0x7f)<<s;
                if((b&0x80)==0)return r;
                s+=7;
            }
            return r;
        }
    }

    private static final class StringPool {
        final int chunkOff, chunkSize, stringCount, stringsStart; final int[] offsets;
        private StringPool(int co,int cs,int sc,int ss,int[]off){
            chunkOff=co;chunkSize=cs;stringCount=sc;stringsStart=ss;offsets=off;
        }
        static StringPool parse(byte[] data, int off) {
            int headerSize  = readU16(data, off + 2);
            int chunkSize   = readU32Checked(data, off + 4);
            int stringCount = readU32Checked(data, off + 8);
            int stringsStart= readU32Checked(data, off + 20);
            if (headerSize < 28 || stringCount < 0) throw new IllegalArgumentException("Bad string pool");
            int[] offsets = new int[stringCount];
            int base = off + headerSize;
            for (int i=0;i<stringCount;i++) offsets[i]=readU32Checked(data, base+i*4);
            return new StringPool(off, chunkSize, stringCount, stringsStart, offsets);
        }
    }

    private static ClassData parseClassData(DexFile file, byte[] data, int offset) {
        Cursor c = new Cursor(data, offset);
        int sf=c.readUleb128(),inst=c.readUleb128(),dm=c.readUleb128(),vm=c.readUleb128();
        for(int i=0;i<sf;i++){c.readUleb128();c.readUleb128();}
        for(int i=0;i<inst;i++){c.readUleb128();c.readUleb128();}
        List<EncodedMethod> methods=new ArrayList<>();
        int prev=0;
        for(int i=0;i<dm;i++){int d=c.readUleb128(),f=c.readUleb128(),co=c.readUleb128();prev+=d;methods.add(new EncodedMethod(prev,f,co));}
        prev=0;
        for(int i=0;i<vm;i++){int d=c.readUleb128(),f=c.readUleb128(),co=c.readUleb128();prev+=d;methods.add(new EncodedMethod(prev,f,co));}
        return new ClassData(methods);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Binary helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static int readU16(byte[] d, int off) {
        checkRange(off, 2, d.length, "u16");
        return (d[off]&0xff)|((d[off+1]&0xff)<<8);
    }
    private static int readU32Checked(byte[] d, int off) {
        checkRange(off, 4, d.length, "u32");
        return (d[off]&0xff)|((d[off+1]&0xff)<<8)|((d[off+2]&0xff)<<16)|((d[off+3]&0xff)<<24);
    }
    private static int readU32(byte[] d, int off) { return readU32Checked(d, off); }
    private static void writeU16(byte[] d, int off, int v) {
        checkRange(off, 2, d.length, "u16w");
        d[off]=(byte)v; d[off+1]=(byte)(v>>>8);
    }
    private static void writeU32(byte[] d, int off, int v) {
        checkRange(off, 4, d.length, "u32w");
        d[off]=(byte)v; d[off+1]=(byte)(v>>>8); d[off+2]=(byte)(v>>>16); d[off+3]=(byte)(v>>>24);
    }
    private static void checkRange(int off, int len, int total, String w) {
        if(off<0||len<0||(long)off+len>total)
            throw new IllegalArgumentException("Bad range "+w+": off="+off+" len="+len+" total="+total);
    }
    private static boolean containsBytes(byte[] data, byte[] pat) {
        if(pat.length==0||pat.length>data.length)return false;
        outer: for(int i=0;i<=data.length-pat.length;i++){
            for(int j=0;j<pat.length;j++) if(data[i+j]!=pat[j]) continue outer;
            return true;
        }
        return false;
    }
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        byte[] buf=new byte[65536]; int n;
        while((n=in.read(buf))!=-1) out.write(buf,0,n);
        return out.toByteArray();
    }
    private static void log(Progress p, String m) { if(p!=null) p.log(m); }
            }
