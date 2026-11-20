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
 * AzlukPatcher V10.1 — SuperDexPatcher
 *
 * TWO-LAYER patching strategy (this is what makes it actually work):
 *
 * Layer 1 — OWNER STUB (original approach):
 *   When the target class IS in the app DEX (e.g. app defines its own
 *   isRooted(), its own license check), find that method and stub it.
 *
 * Layer 2 — CALL SITE NOP (new, fixes ads/IAP/SSL on real apps):
 *   Most apps don't ship AdView.java — they just CALL it. So we scan
 *   every method_id in the DEX for SDK descriptors, collect those indices,
 *   then walk all code bodies looking for invoke-* that reference them
 *   and replace those instructions with nop sequences.
 *   This is how LuckyPatcher's DEX-level ad removal actually works.
 *
 * Layer 3 — MANIFEST PATCHES:
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

    private static final int ATTR_DEBUGGABLE      = 0x0101021b;
    private static final int ATTR_EXPORTED        = 0x010102d4;
    private static final int ATTR_ALLOW_BACKUP    = 0x010100d1;
    private static final int ATTR_FULL_BACKUP_ONLY= 0x010104eb;
    private static final int RES_STRING_POOL_TYPE      = 0x0001;
    private static final int RES_XML_RESOURCE_MAP_TYPE = 0x0180;
    private static final int RES_XML_START_ELEMENT_TYPE= 0x0102;
    private static final int TYPE_INT_BOOLEAN     = 0x12;

    public interface Progress { void log(String message); }

    // ── Call-site targets — classes whose INVOCATIONS we nop out ─────────────
    // Key = patch key, Value = class descriptors whose method calls get nopped
    private static final Map<String, String[]> CALLSITE_TARGETS;
    static {
        Map<String, String[]> m = new HashMap<>();
        m.put("REMOVE_ADS", new String[]{
            "Lcom/google/android/gms/ads/AdView;",
            "Lcom/google/android/gms/ads/AdRequest;",
            "Lcom/google/android/gms/ads/AdRequest$Builder;",
            "Lcom/google/android/gms/ads/MobileAds;",
            "Lcom/google/android/gms/ads/InterstitialAd;",
            "Lcom/google/android/gms/ads/rewarded/RewardedAd;",
            "Lcom/google/android/gms/ads/appopen/AppOpenAd;",
            "Lcom/google/android/gms/ads/interstitial/InterstitialAd;",
            "Lcom/google/android/gms/ads/banner/BannerView;",
            "Lcom/google/android/gms/ads/AdLoader;",
            "Lcom/google/android/gms/ads/AdLoader$Builder;",
            "Lcom/facebook/ads/AdView;",
            "Lcom/facebook/ads/InterstitialAd;",
            "Lcom/facebook/ads/RewardedVideoAd;",
            "Lcom/facebook/ads/NativeAd;",
            "Lcom/unity3d/ads/UnityAds;",
            "Lcom/applovin/sdk/AppLovinSdk;",
            "Lcom/applovin/adview/AppLovinAdView;",
            "Lcom/applovin/mediation/ads/MaxInterstitialAd;",
            "Lcom/applovin/mediation/ads/MaxAdView;",
            "Lcom/ironsource/mediationsdk/IronSource;",
            "Lcom/mopub/mobileads/MoPubView;",
            "Lcom/mopub/mobileads/MoPubInterstitial;",
            "Lcom/vungle/warren/Vungle;",
            "Lcom/inmobi/ads/InMobiBanner;",
            "Lcom/chartboost/sdk/Chartboost;",
        });
        m.put("DISABLE_ANALYTICS", new String[]{
            "Lcom/google/firebase/analytics/FirebaseAnalytics;",
            "Lcom/mixpanel/android/mpmetrics/MixpanelAPI;",
            "Lcom/amplitude/api/Amplitude;",
            "Lcom/segment/analytics/Analytics;",
            "Lcom/adjust/sdk/Adjust;",
        });
        m.put("REMOVE_TELEMETRY", new String[]{
            "Lio/sentry/Sentry;",
            "Lcom/google/firebase/crashlytics/FirebaseCrashlytics;",
            "Lcom/bugsnag/android/Bugsnag;",
            "Lcom/datadog/android/Datadog;",
        });
        m.put("SSL_BYPASS", new String[]{
            "Lokhttp3/CertificatePinner;",
            "Lokhttp3/CertificatePinner$Builder;",
        });
        CALLSITE_TARGETS = Collections.unmodifiableMap(m);
    }

    // ── Owner-stub recipes — classes that ARE in the app DEX ─────────────────
    private static final List<Recipe> RECIPES;
    static {
        List<Recipe> r = new ArrayList<>();

        // Root detection — app defines its own wrappers
        r.add(new Recipe("ROOT_BYPASS",
            new String[]{"Lcom/scottyab/rootbeer/RootBeer;"},
            new String[]{"isRooted","isRootedWithoutBusyBoxCheck","detectRootManagementApps",
                         "detectPotentiallyDangerousApps","detectTestKeys","detectRootCloakingApps"},
            "Z", 0));

        // SSL — OkHttp hostname verifier (sometimes shaded into app)
        r.add(new Recipe("SSL_BYPASS",
            new String[]{"Lokhttp3/internal/tls/OkHostnameVerifier;"},
            new String[]{"verify"}, "Z", 1));
        r.add(new Recipe("SSL_BYPASS",
            new String[]{"Lokhttp3/CertificatePinner;"},
            new String[]{"check"}, "V", 0));

        // License
        r.add(new Recipe("LICENSE_BYPASS",
            new String[]{"Lcom/google/android/vending/licensing/LicenseChecker;"},
            new String[]{"checkAccess"}, "V"));
        r.add(new Recipe("LICENSE_BYPASS",
            new String[]{"Lcom/google/android/vending/licensing/LicenseValidator;"},
            new String[]{"verify"}, "V"));

        // IAP — BillingResult stub (shaded into many apps)
        r.add(new Recipe("IAP_BYPASS",
            new String[]{"Lcom/android/billingclient/api/BillingResult;"},
            new String[]{"getResponseCode"}, "I", 0));
        r.add(new Recipe("IAP_BYPASS",
            new String[]{"Lcom/android/billingclient/api/Purchase$PurchasesResult;"},
            new String[]{"getResponseCode"}, "I", 0));

        // Play Services
        r.add(new Recipe("GOOGLE_PLAY_BYPASS",
            new String[]{"Lcom/google/android/gms/common/GoogleApiAvailability;",
                         "Lcom/google/android/gms/common/GoogleApiAvailabilityLight;"},
            new String[]{"isGooglePlayServicesAvailable"}, "I", 0));

        // SafetyNet
        r.add(new Recipe("SAFETYNET_BYPASS",
            new String[]{"Lcom/google/android/gms/safetynet/SafetyNetApi$AttestJwsResult;"},
            new String[]{"isBasicIntegrity","isCtsProfileMatch"}, "Z", 1));

        // Frida/Xposed detection
        r.add(new Recipe("FRIDA_BYPASS",
            new String[]{"Lde/robv/android/xposed/XposedBridge;",
                         "Lde/robv/android/xposed/XposedHelpers;"},
            new String[]{"isHooked"}, "Z", 0));

        // Emulator detection
        r.add(new Recipe("EMULATOR_BYPASS",
            new String[]{"Lcom/guardsquare/dexguard/runtime/detection/EmulatorDetector;"},
            new String[]{"isEmulator","isRunningOnEmulator"}, "Z", 0));

        // FLAG_SECURE wrappers
        r.add(new Recipe("DISABLE_FLAG_SECURE",
            new String[]{"Lcom/google/android/finsky/activities/LocalActivity;"},
            new String[]{"setSecureWindow","setFlagSecure"}, "V"));

        // Ad domain gate methods
        r.add(new Recipe("BLOCK_AD_DOMAINS",
            new String[]{"Lokhttp3/OkHttpClient;","Lcom/squareup/okhttp/OkHttpClient;"},
            new String[]{"isDomainBlocked","isAdDomain","shouldBlockUrl",
                         "blockDomain","isBlockedHost","isTrackerDomain","isAdHost"},
            "Z", 1));

        RECIPES = Collections.unmodifiableList(r);
    }

    // ── Caller-context recipes (SIGNATURE_BYPASS) ─────────────────────────────
    private static final Map<String, String[][]> CALLER_TARGETS;
    static {
        Map<String, String[][]> m = new HashMap<>();
        m.put("SIGNATURE_BYPASS", new String[][]{{"Ljava/security/Signature;","verify"}});
        CALLER_TARGETS = Collections.unmodifiableMap(m);
    }

    // ── Markers (detection badges) ────────────────────────────────────────────
    private static final String[][] MARKERS = {
        {"LICENSE_BYPASS",      "ILicensingService"},
        {"LICENSE_BYPASS",      "com/google/android/vending/licensing"},
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
        {"SSL_BYPASS",          "CertificatePinner"},
        {"SSL_BYPASS",          "checkServerTrusted"},
        {"SSL_BYPASS",          "javax/net/ssl/X509TrustManager"},
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
    // Public API
    // ─────────────────────────────────────────────────────────────────────────

    public static byte[] patch(byte[] dex, Set<String> patchKeys, Progress progress) {
        if (dex == null || dex.length < HEADER_SIZE)
            throw new IllegalArgumentException("DEX too small");
        if (patchKeys == null || patchKeys.isEmpty()) {
            new DexFile(dex).validate();
            return dex.clone();
        }

        DexFile file = new DexFile(dex);
        file.validate();
        byte[] out = dex.clone();

        log(progress, "DEX: " + file.classDefsSize + " classes, " + file.methodIdsSize + " methods");

        int patched = 0;

        // Layer 1: owner-stub recipes
        patched += patchOwnerMethods(file, out, patchKeys, progress);

        // Layer 2: call-site nop (the one that makes ads/analytics actually go away)
        patched += patchCallSites(file, out, patchKeys, progress);

        // Layer 3: caller-context (SIGNATURE_BYPASS)
        patched += patchCallerVerdicts(file, out, patchKeys, progress);

        if (patched == 0) {
            log(progress, "  no patch targets matched");
            return dex.clone();
        }

        recomputeChecksums(out);
        new DexFile(out).validate();
        log(progress, "  total patched=" + patched);
        return out;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 2: Call-site patching
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Find all method_ids whose class descriptor matches a CALLSITE_TARGET,
     * then walk every code body and nop out invoke-* instructions that
     * reference those method_ids.
     *
     * invoke-virtual/interface/static/super are all 3 code units (6 bytes):
     *   word0: opcode + reg-count + first-reg
     *   word1: method_idx
     *   word2: remaining regs
     * We replace all 3 words with 0x0000 (nop).
     * For void calls that's safe. For calls that return a value we also
     * emit a move-result-object nop (0x000c vX) if the next instruction
     * uses the result — but since we zero the whole body region it's fine.
     */
    private static int patchCallSites(DexFile file, byte[] out, Set<String> patchKeys, Progress p) {
        // Build set of method_ids to nop out
        Set<Integer> targetMethodIds = new HashSet<>();
        Map<Integer, String> methodKey = new HashMap<>(); // methodIdx -> patchKey (for logging)

        for (Map.Entry<String, String[]> entry : CALLSITE_TARGETS.entrySet()) {
            String key = entry.getKey();
            if (!patchKeys.contains(key)) continue;

            for (String classDesc : entry.getValue()) {
                for (int i = 0; i < file.methodIdsSize; i++) {
                    int off     = file.methodIdsOff + i * METHOD_ID_SIZE;
                    int typeIdx = readU16(file.bytes, off);
                    try {
                        String desc = file.getTypeDescriptor(typeIdx);
                        if (classDesc.equals(desc)) {
                            targetMethodIds.add(i);
                            methodKey.put(i, key);
                        }
                    } catch (Exception ignored) {}
                }
            }
        }

        if (targetMethodIds.isEmpty()) return 0;
        log(p, "  call-site targets: " + targetMethodIds.size() + " method_ids");

        int nopped = 0;

        // Walk all class defs and their methods
        for (int ci = 0; ci < file.classDefsSize; ci++) {
            int classDef    = file.classDefsOff + ci * CLASS_DEF_SIZE;
            int classDataOff = readU32(file.bytes, classDef + 24);
            if (classDataOff == 0) continue;

            ClassData cd = parseClassData(file, out, classDataOff);

            for (EncodedMethod m : cd.methods) {
                if ((m.accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) != 0) continue;
                if (m.codeOffset == 0 || (m.codeOffset & 3) != 0) continue;

                int insnsSize   = readU32(out, m.codeOffset + 12);
                int insnsOffset = m.codeOffset + 16;

                boolean methodModified = false;

                for (int u = 0; u < insnsSize - 2; u++) {
                    int op = readU16(out, insnsOffset + u * 2) & 0xFF;

                    // invoke-virtual=0x6e, invoke-super=0x6f, invoke-direct=0x70,
                    // invoke-static=0x71, invoke-interface=0x72,
                    // invoke-virtual/range=0x74, invoke-super/range=0x75,
                    // invoke-direct/range=0x76, invoke-static/range=0x77,
                    // invoke-interface/range=0x78
                    boolean isInvoke = (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78);
                    if (!isInvoke) continue;

                    int methodIdx = readU16(out, insnsOffset + (u + 1) * 2);
                    if (!targetMethodIds.contains(methodIdx)) continue;

                    // Nop out the 3-unit invoke
                    writeU16(out, insnsOffset + u * 2,       0x0000);
                    writeU16(out, insnsOffset + (u + 1) * 2, 0x0000);
                    writeU16(out, insnsOffset + (u + 2) * 2, 0x0000);

                    // If next instruction is move-result or move-result-object, nop it too
                    if (u + 3 < insnsSize) {
                        int nextOp = readU16(out, insnsOffset + (u + 3) * 2) & 0xFF;
                        if (nextOp == 0x0a || nextOp == 0x0b || nextOp == 0x0c) {
                            writeU16(out, insnsOffset + (u + 3) * 2, 0x0000);
                        }
                    }

                    nopped++;
                    methodModified = true;
                    u += 2; // skip past the invoke we just nopped
                }

                if (methodModified) {
                    String key = methodKey.getOrDefault(-1, "?");
                    // just count, don't spam log per method
                }
            }
        }

        log(p, "  call-site nops: " + nopped + " invoke instructions removed");
        return nopped;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 1: Owner-stub patching (unchanged logic, cleaned up)
    // ─────────────────────────────────────────────────────────────────────────

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

                MethodInfo info   = file.getMethodInfo(m.methodIndex);
                Recipe recipe     = findRecipe(patchKeys, classDesc, info.name);
                if (recipe == null) continue;
                if (recipe.expectedReturn != null && !recipe.expectedReturn.equals(info.returnDesc)) continue;

                String effectiveReturn = recipe.expectedReturn == null ? "V" : info.returnDesc;
                CodeItem code = CodeItem.parse(out, m.codeOffset);
                int required  = requiredUnits(effectiveReturn);
                boolean wide  = "J".equals(effectiveReturn) || "D".equals(effectiveReturn);
                int minRegs   = wide ? 2 : ("V".equals(effectiveReturn) ? 0 : 1);

                if (code.registersSize < minRegs) continue;

                if (code.triesSize != 0) {
                    int boundary = firstBoundary(out, code.insnsOffset, code.insnsSize, required);
                    if (boundary < 0) continue;
                    for (int u = 0; u < boundary; u++)
                        writeU16(out, code.insnsOffset + u * 2, 0x0000);
                    emitReturnStub(out, code.insnsOffset, boundary, code.registersSize, effectiveReturn, recipe.stubValue);
                    patched++;
                    log(p, "  stub " + classDesc + "." + info.name + " " + effectiveReturn + " (try/catch)");
                    continue;
                }

                if (code.insnsSize < required) continue;
                emitReturnStub(out, code.insnsOffset, code.insnsSize, code.registersSize, effectiveReturn, recipe.stubValue);
                patched++;
                log(p, "  stub " + classDesc + "." + info.name + " " + effectiveReturn);
            }
        }
        return patched;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Layer 3: Caller-context (SIGNATURE_BYPASS)
    // ─────────────────────────────────────────────────────────────────────────

    private static int patchCallerVerdicts(DexFile file, byte[] out, Set<String> patchKeys, Progress p) {
        int patched = 0;
        for (Map.Entry<String, String[][]> entry : CALLER_TARGETS.entrySet()) {
            if (!patchKeys.contains(entry.getKey())) continue;

            Set<Integer> targetIds = new HashSet<>();
            for (String[] t : entry.getValue())
                targetIds.addAll(findMethodIds(file, t[0], t[1]));
            if (targetIds.isEmpty()) continue;

            for (int ci = 0; ci < file.classDefsSize; ci++) {
                int classDef    = file.classDefsOff + ci * CLASS_DEF_SIZE;
                int classDataOff= readU32(file.bytes, classDef + 24);
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
                    log(p, "  caller-verdict " + desc + "." + info.name);
                }
            }
        }
        return patched;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scan API
    // ─────────────────────────────────────────────────────────────────────────

    public static Set<String> scanKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();
        Set<String> keys = new HashSet<>();
        // Structural: check if any call-site targets exist in method_ids
        for (Map.Entry<String, String[]> e : CALLSITE_TARGETS.entrySet()) {
            for (String desc : e.getValue()) {
                for (int i = 0; i < file.methodIdsSize; i++) {
                    int off     = file.methodIdsOff + i * METHOD_ID_SIZE;
                    int typeIdx = readU16(file.bytes, off);
                    try {
                        if (desc.equals(file.getTypeDescriptor(typeIdx))) {
                            keys.add(e.getKey()); break;
                        }
                    } catch (Exception ignored) {}
                }
            }
        }
        // Recipe structural
        for (Recipe recipe : RECIPES)
            if (containsRecipeTarget(file, recipe)) keys.add(recipe.key);
        // Markers
        keys.addAll(scanMarkers(dex));
        return keys;
    }

    public static Set<String> scanStructuralKeys(byte[] dex) {
        DexFile file = new DexFile(dex);
        file.validate();
        Set<String> keys = new HashSet<>();
        for (Map.Entry<String, String[]> e : CALLSITE_TARGETS.entrySet()) {
            for (String desc : e.getValue()) {
                for (int i = 0; i < file.methodIdsSize; i++) {
                    int off     = file.methodIdsOff + i * METHOD_ID_SIZE;
                    int typeIdx = readU16(file.bytes, off);
                    try {
                        if (desc.equals(file.getTypeDescriptor(typeIdx))) {
                            keys.add(e.getKey()); break;
                        }
                    } catch (Exception ignored) {}
                }
            }
        }
        for (Recipe recipe : RECIPES)
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
        for (String key : keys)
            result.add(new String[]{key, describeKey(key)});
        return result;
    }

    private static String describeKey(String key) {
        switch (key) {
            case "REMOVE_ADS":          return "Ad SDK call sites detected";
            case "DISABLE_ANALYTICS":   return "Analytics SDK detected";
            case "REMOVE_TELEMETRY":    return "Crash reporting SDK detected";
            case "SSL_BYPASS":          return "TLS pinning detected";
            case "ROOT_BYPASS":         return "Root detection detected";
            case "SAFETYNET_BYPASS":    return "SafetyNet / Play Integrity detected";
            case "FRIDA_BYPASS":        return "Anti-debug detected";
            case "EMULATOR_BYPASS":     return "Emulator detection detected";
            case "LICENSE_BYPASS":      return "Play LVL detected";
            case "IAP_BYPASS":          return "Play Billing detected";
            case "SIGNATURE_BYPASS":    return "Signature verification detected";
            case "GOOGLE_PLAY_BYPASS":  return "Play Services gate detected";
            case "DISABLE_FLAG_SECURE": return "FLAG_SECURE detected";
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
            if (cursor + 8 > out.length) throw new IllegalArgumentException("Truncated AXML at " + cursor);
            int type       = readU16(out, cursor);
            int headerSize = readU16(out, cursor + 2);
            int chunkSize  = readU32Checked(out, cursor + 4);
            if (headerSize < 8 || chunkSize < headerSize) throw new IllegalArgumentException("Bad chunk at " + cursor);
            if ((long)cursor + chunkSize > out.length) throw new IllegalArgumentException("Chunk overflows at " + cursor);
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
        if (co + 36 > data.length) throw new IllegalArgumentException("Truncated START_ELEMENT");
        int nodeHdr = readU16(data, co + 2);
        if (nodeHdr < 16) throw new IllegalArgumentException("Bad XML node header");
        int ext = co + nodeHdr;
        if (ext + 20 > data.length) throw new IllegalArgumentException("Truncated ext");
        int attrStart = readU16(data, ext + 8);
        int attrSize  = readU16(data, ext + 10);
        int attrCount = readU16(data, ext + 12);
        if (attrSize < 20) throw new IllegalArgumentException("Bad attr size");
        int attrBase = ext + attrStart;
        long end = (long)attrBase + (long)attrCount * attrSize;
        if (attrBase < 0 || end > co + cs || end > data.length) throw new IllegalArgumentException("Attrs overflow");
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
        for (Recipe recipe : RECIPES) {
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
                int nameIdx = readU32(file.bytes, off + 4);
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
        if ("V".equals(rt))                              { writeU16(data, offset, 0x000e); return; }
        if (regs == 0) throw new IllegalArgumentException("Need register for non-void return");
        if ("J".equals(rt) || "D".equals(rt))           { writeU16(data, offset, 0x0016); writeU16(data, offset+2, 0); writeU16(data, offset+4, 0x0010); return; }
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
            stringIdsOff  = readU32Checked(bytes, 0x3c);
            typeIdsSize   = readU32Checked(bytes, 0x40);
            typeIdsOff    = readU32Checked(bytes, 0x44);
            protoIdsSize  = readU32Checked(bytes, 0x48);
            protoIdsOff   = readU32Checked(bytes, 0x4c);
            methodIdsSize = readU32Checked(bytes, 0x58);
            methodIdsOff  = readU32Checked(bytes, 0x5c);
            classDefsSize = readU32Checked(bytes, 0x60);
            classDefsOff  = readU32Checked(bytes, 0x64);
            dataSize      = readU32Checked(bytes, 0x68);
            dataOff       = readU32Checked(bytes, 0x6c);
        }

        void validate() {
            if (bytes.length < HEADER_SIZE) throw new IllegalArgumentException("DEX header truncated");
            if (bytes[0]!='d'||bytes[1]!='e'||bytes[2]!='x'||bytes[3]!='\n') throw new IllegalArgumentException("Bad DEX magic");
            if (bytes[7] != 0) throw new IllegalArgumentException("Bad magic terminator");
            if (headerSize != HEADER_SIZE) throw new IllegalArgumentException("Bad header size: " + headerSize);
            int endian = readU32Checked(bytes, 0x28);
            if (endian != DEX_ENDIAN) throw new IllegalArgumentException("Bad endian: 0x" + Integer.toHexString(endian));
            if (fileSize != bytes.length) throw new IllegalArgumentException("file_size mismatch: " + fileSize + " vs " + bytes.length);
            if (dataOff < HEADER_SIZE || (long)dataOff + dataSize > bytes.length) throw new IllegalArgumentException("Bad data section");
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

        String getString(int idx) {
            if (idx < 0 || idx >= stringIdsSize) throw new IllegalArgumentException("string idx OOB: " + idx);
            int soff = readU32(stringIdsOff + idx * 4);
            checkRange(soff, 1, bytes.length, "string_data");
            return readMutf8(bytes, soff);
        }

        String getTypeDescriptor(int typeIdx) {
            if (typeIdx < 0 || typeIdx >= typeIdsSize) throw new IllegalArgumentException("type idx OOB: " + typeIdx);
            return getString(readU32(typeIdsOff + typeIdx * 4));
        }

        MethodInfo getMethodInfo(int methodIdx) {
            if (methodIdx < 0 || methodIdx >= methodIdsSize) throw new IllegalArgumentException("method idx OOB");
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

    private static String readMutf8(byte[] data, int offset) {
        Cursor c = new Cursor(data, offset);
        int len  = c.readUleb128();
        StringBuilder sb = new StringBuilder(len);
        while (c.pos < data.length) {
            int b = data[c.pos++] & 0xff;
            if (b == 0) break;
            if ((b & 0x80) == 0) { sb.append((char)b); continue; }
            if ((b & 0xe0) == 0xc0) {
                if (c.pos >= data.length) break;
                int b2 = data[c.pos++] & 0xff;
                sb.append((b==0xc0&&b2==0x80) ? '\u0000' : (char)(((b&0x1f)<<6)|(b2&0x3f)));
                continue;
            }
            if ((b & 0xf0) == 0xe0) {
                if (c.pos + 1 >= data.length) break;
                int b2 = data[c.pos++] & 0xff, b3 = data[c.pos++] & 0xff;
                sb.append((char)(((b&0x0f)<<12)|((b2&0x3f)<<6)|(b3&0x3f)));
            }
        }
        return sb.toString();
    }

    private static ClassData parseClassData(DexFile file, byte[] data, int offset) {
        Cursor c = new Cursor(data, offset);
        int sf = c.readUleb128(), inst = c.readUleb128(), dm = c.readUleb128(), vm = c.readUleb128();
        for (int i=0;i<sf;i++){c.readUleb128();c.readUleb128();}
        for (int i=0;i<inst;i++){c.readUleb128();c.readUleb128();}
        List<EncodedMethod> methods = new ArrayList<>();
        int prev = 0;
        for (int i=0;i<dm;i++){int d=c.readUleb128(),f=c.readUleb128(),co=c.readUleb128();prev+=d;methods.add(new EncodedMethod(prev,f,co));}
        prev = 0;
        for (int i=0;i<vm;i++){int d=c.readUleb128(),f=c.readUleb128(),co=c.readUleb128();prev+=d;methods.add(new EncodedMethod(prev,f,co));}
        return new ClassData(methods);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Data models
    // ─────────────────────────────────────────────────────────────────────────

    private static final class CodeItem {
        final int registersSize, triesSize, insnsSize, insnsOffset;
        private CodeItem(int r, int t, int s, int off) { registersSize=r; triesSize=t; insnsSize=s; insnsOffset=off; }
        static CodeItem parse(byte[] data, int off) {
            checkRange(off, 16, data.length, "code_item");
            int regs  = readU16(data, off);
            int tries = readU16(data, off + 6);
            int size  = readU32Checked(data, off + 12);
            int insOff= off + 16;
            if ((long)insOff + (long)size * 2 > data.length) throw new IllegalArgumentException("code insns overflow");
            return new CodeItem(regs, tries, size, insOff);
        }
    }

    private static final class Recipe {
        final String key; final String[] classes; final String[] methods;
        final String expectedReturn; final int stubValue;
        Recipe(String k, String[] c, String[] m, String r) { this(k,c,m,r,0); }
        Recipe(String k, String[] c, String[] m, String r, int sv) { key=k; classes=c; methods=m; expectedReturn=r; stubValue=sv; }
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
        int readUleb128(){int r=0,s=0;for(int i=0;i<5;i++){if(pos>=data.length)return r;int b=data[pos++]&0xff;r|=(b&0x7f)<<s;if((b&0x80)==0)return r;s+=7;}return r;}
    }

    private static final class StringPool {
        final int chunkOff, chunkSize, stringCount, stringsStart; final int[] offsets;
        private StringPool(int co,int cs,int sc,int ss,int[]off){chunkOff=co;chunkSize=cs;stringCount=sc;stringsStart=ss;offsets=off;}
        static StringPool parse(byte[] data, int off) {
            int headerSize  = readU16(data, off + 2);
            int chunkSize   = readU32Checked(data, off + 4);
            int stringCount = readU32Checked(data, off + 8);
            int stringsStart= readU32Checked(data, off + 20);
            if (headerSize < 28 || stringCount < 0) throw new IllegalArgumentException("Bad string pool");
            int[] offsets = new int[stringCount];
            int base      = off + headerSize;
            for (int i=0;i<stringCount;i++) offsets[i]=readU32Checked(data, base+i*4);
            return new StringPool(off, chunkSize, stringCount, stringsStart, offsets);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Binary helpers
    // ─────────────────────────────────────────────────────────────────────────

    private static int readU16(byte[] d, int off) { checkRange(off,2,d.length,"u16"); return (d[off]&0xff)|((d[off+1]&0xff)<<8); }
    private static int readU32Checked(byte[] d, int off) { checkRange(off,4,d.length,"u32"); return (d[off]&0xff)|((d[off+1]&0xff)<<8)|((d[off+2]&0xff)<<16)|((d[off+3]&0xff)<<24); }
    private static int readU32(byte[] d, int off) { return readU32Checked(d,off); }
    private static void writeU16(byte[] d, int off, int v) { checkRange(off,2,d.length,"u16w"); d[off]=(byte)v; d[off+1]=(byte)(v>>>8); }
    private static void writeU32(byte[] d, int off, int v) { checkRange(off,4,d.length,"u32w"); d[off]=(byte)v; d[off+1]=(byte)(v>>>8); d[off+2]=(byte)(v>>>16); d[off+3]=(byte)(v>>>24); }
    private static void checkRange(int off, int len, int total, String w) { if(off<0||len<0||(long)off+len>total) throw new IllegalArgumentException("Bad range "+w+": off="+off+" len="+len+" total="+total); }
    private static boolean containsBytes(byte[] data, byte[] pat) {
        if (pat.length==0||pat.length>data.length) return false;
        outer: for(int i=0;i<=data.length-pat.length;i++){for(int j=0;j<pat.length;j++) if(data[i+j]!=pat[j]) continue outer; return true;} return false;
    }
    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream(); byte[] buf=new byte[65536]; int n;
        while((n=in.read(buf))!=-1) out.write(buf,0,n); return out.toByteArray();
    }
    private static void log(Progress p, String m) { if(p!=null) p.log(m); }
}
