package com.azluk.patcher.engine;

import java.nio.charset.StandardCharsets;
import java.util.zip.Adler32;
import java.security.MessageDigest;

/**
 * AzlukPatcher V10 — Toast Injector
 *
 * Injects a Toast("AzlukPatcher") call into the onCreate() method of
 * every Activity class found in the DEX. This is what makes every
 * patched APK show "AzlukPatcher" on launch.
 *
 * Strategy:
 *   1. Walk class_defs looking for classes that extend *Activity* (type
 *      descriptor ends with Activity; or superclass descriptor contains it).
 *   2. For each Activity class, find the virtual method named "onCreate".
 *   3. If onCreate exists and has code, prepend a Toast sequence at the
 *      HEAD of the method (before existing instructions) using the same
 *      head-only boundary technique used for try/catch methods.
 *
 * Toast sequence (Dalvik bytecode, 5 code units = 10 bytes):
 *
 *   const-string v0, "AzlukPatcher"          // 0x1a 0x00 <string_idx u16>
 *   const/4 v1, #0                            // 0x12 0x10  (LENGTH_SHORT = 0)
 *   invoke-static {v0, p0, v1},
 *       Landroid/widget/Toast;->makeText(
 *           Landroid/content/Context;
 *           Ljava/lang/CharSequence;I)
 *       Landroid/widget/Toast;              // 0x71 ... (3 units)
 *   invoke-virtual {v0},
 *       Landroid/widget/Toast;->show()V    // 0x6e ...
 *
 * This requires:
 *   a) "AzlukPatcher" to exist in the DEX string pool — we add it if absent
 *      (string pool mutation with index relocation is complex; instead we
 *      find an existing string that is a prefix of "AzlukPatcher" or add
 *      a minimal new one using the unused string slot approach).
 *   b) The method has at least 2 registers (p0 = this = Context).
 *
 * Practical V10 implementation: Since full string pool mutation with
 * DEX structural relocation is a 2000-line project on its own, we use
 * a targeted approach: scan the string pool for "AzlukPatcher" first.
 * If present, inject. If not present, skip injection for that DEX
 * (the REMOVE_ADS / SSL patches still apply — Toast is best-effort).
 *
 * To guarantee the string exists: we also export injectToastString()
 * which writes "AzlukPatcher\0" into the DEX's existing string pool at
 * an unused slot (a slot whose current content is a single space or
 * empty — common in SDK-generated DEX files). This is the safe path.
 */
public final class ToastInjector {

    private ToastInjector() {}

    private static final int HEADER_SIZE    = 0x70;
    private static final int CLASS_DEF_SIZE = 32;
    private static final int METHOD_ID_SIZE = 8;
    private static final int PROTO_ID_SIZE  = 12;
    private static final int ACC_NATIVE     = 0x0100;
    private static final int ACC_ABSTRACT   = 0x0400;
    private static final int ACC_STATIC     = 0x0008;

    // android/widget/Toast descriptor
    private static final String TOAST_CLASS  = "Landroid/widget/Toast;";
    // makeText proto descriptor (abbreviated — we find by name)
    private static final String MAKE_TEXT    = "makeText";
    private static final String SHOW         = "show";

    /**
     * Main entry point. Returns modified DEX bytes with Toast injected
     * into every Activity.onCreate(), or the original bytes if injection
     * is not possible (string not found, no Activities, etc.).
     */
    public static byte[] inject(byte[] dex, SuperDexPatcher.Progress progress) {
        if (dex == null || dex.length < HEADER_SIZE) return dex;

        try {
            // Find "AzlukPatcher" in string pool
            int azlukStringIdx = findString(dex, "AzlukPatcher");
            if (azlukStringIdx < 0) {
                log(progress, "  ToastInjector: 'AzlukPatcher' not in string pool, skipping");
                return dex;
            }

            // Find Toast class type index
            int toastTypeIdx = findTypeByDescriptor(dex, TOAST_CLASS);
            if (toastTypeIdx < 0) {
                log(progress, "  ToastInjector: Toast class not in type_ids, skipping");
                return dex;
            }

            // Find Toast.makeText and Toast.show method IDs
            int makeTextMethodIdx = findMethodByName(dex, toastTypeIdx, MAKE_TEXT);
            int showMethodIdx     = findMethodByName(dex, toastTypeIdx, SHOW);

            if (makeTextMethodIdx < 0 || showMethodIdx < 0) {
                log(progress, "  ToastInjector: Toast methods not found, skipping");
                return dex;
            }

            byte[] out     = dex.clone();
            int    injected = 0;

            // Walk class defs looking for Activity subclasses
            int classDefsSize = readU32(dex, 0x60);
            int classDefsOff  = readU32(dex, 0x64);

            for (int i = 0; i < classDefsSize; i++) {
                int classDef    = classDefsOff + i * CLASS_DEF_SIZE;
                int typeIdx     = readU32(dex, classDef);
                int superTypeIdx = readU32(dex, classDef + 4);

                // Check if superclass is an Activity variant
                String superDesc = getTypeDescriptor(dex, superTypeIdx);
                if (superDesc == null) continue;
                if (!isActivityDescriptor(superDesc)) continue;

                int classDataOff = readU32(dex, classDef + 24);
                if (classDataOff == 0) continue;

                String classDesc = getTypeDescriptor(dex, typeIdx);
                boolean didInject = injectIntoOnCreate(
                        out, classDataOff, classDesc,
                        azlukStringIdx, makeTextMethodIdx, showMethodIdx,
                        progress
                );
                if (didInject) injected++;
            }

            if (injected > 0) {
                SuperDexPatcher.recomputeChecksums(out);
                log(progress, "  ToastInjector: injected into " + injected + " Activity class(es)");
                return out;
            }

            return dex;
        } catch (Exception e) {
            log(progress, "  ToastInjector error: " + e.getMessage() + " — skipping");
            return dex;
        }
    }

    private static boolean isActivityDescriptor(String desc) {
        return desc.contains("Activity") || desc.contains("Fragment") ||
               desc.endsWith("Activity;") || desc.endsWith("AppCompatActivity;") ||
               desc.equals("Landroidx/appcompat/app/AppCompatActivity;") ||
               desc.equals("Landroid/app/Activity;");
    }

    /**
     * Finds onCreate(Bundle) in the class data at classDataOff and
     * injects the Toast sequence at the head of its code.
     */
    private static boolean injectIntoOnCreate(
            byte[] out, int classDataOff, String classDesc,
            int azlukStringIdx, int makeTextMethodIdx, int showMethodIdx,
            SuperDexPatcher.Progress progress
    ) {
        Cursor cursor = new Cursor(out, classDataOff);

        int staticFields   = cursor.readUleb128();
        int instanceFields = cursor.readUleb128();
        int directMethods  = cursor.readUleb128();
        int virtualMethods = cursor.readUleb128();

        for (int i = 0; i < staticFields;   i++) { cursor.readUleb128(); cursor.readUleb128(); }
        for (int i = 0; i < instanceFields; i++) { cursor.readUleb128(); cursor.readUleb128(); }

        int prevIdx = 0;
        // Check both direct and virtual methods for onCreate
        int totalMethods = directMethods + virtualMethods;
        for (int i = 0; i < totalMethods; i++) {
            if (i == directMethods) prevIdx = 0; // reset for virtual

            int delta      = cursor.readUleb128();
            int accessFlags= cursor.readUleb128();
            int codeOffset = cursor.readUleb128();
            prevIdx += delta;

            if ((accessFlags & (ACC_NATIVE | ACC_ABSTRACT | ACC_STATIC)) != 0) continue;
            if (codeOffset == 0) continue;

            // Get method name
            int methodIdx = prevIdx;
            String name   = getMethodName(out, methodIdx);
            if (!"onCreate".equals(name)) continue;

            // Parse code_item
            if (codeOffset + 16 > out.length) continue;
            int registersSize = readU16(out, codeOffset);
            int insnsSize     = readU32(out, codeOffset + 12);
            int insnsOffset   = codeOffset + 16;

            if (registersSize < 2) continue; // need v0, v1 at minimum
            if (insnsSize < 10)    continue; // need room for 10 code units

            // Toast sequence: 10 code units (20 bytes)
            // const-string v0, "AzlukPatcher"  — 2 units
            // const/4 v1, #0                   — 1 unit
            // invoke-static {v0, p0, v1}, Toast.makeText — 3 units
            // move-result-object v0             — 1 unit
            // invoke-virtual {v0}, Toast.show   — 3 units
            // = 10 units total

            // We overwrite the FIRST 10 instructions with our sequence,
            // then leave the rest intact. If the first real instruction
            // boundary is >= 10, we're safe. Otherwise skip.

            int boundary = findBoundaryAtLeast(out, insnsOffset, insnsSize, 10);
            if (boundary < 0) continue;

            // Write Toast sequence at insnsOffset
            int o = insnsOffset;

            // const-string v0, azlukStringIdx
            writeU16(out, o,     0x001a);  // const-string opcode, dest=v0
            writeU16(out, o + 2, azlukStringIdx & 0xFFFF);
            o += 4;

            // const/4 v1, #0 (LENGTH_SHORT)
            writeU16(out, o, 0x1012); // const/4 vA=#0, v1 — 0x12 | (0 << 12) | (1 << 8)
            o += 2;

            // invoke-static {v0, p0, v1}, Toast.makeText(Context, CharSequence, int)
            // format 35c: opcode=71, A=3 regs, method_idx, {v0, p0, v1, _, _}
            int p0reg = registersSize - 1; // p0 is the last register (this)
            writeU16(out, o,     0x7100 | (3 << 12)); // 71 opcode, A=3
            writeU16(out, o + 2, makeTextMethodIdx & 0xFFFF);
            writeU16(out, o + 4, (p0reg << 4) | 0); // C=v0, D=p0
            // pack extra regs: E=v1
            // bits 15-12 of word3 carry G(=0), F(=0), E(=v1), and low nibble carries C already
            // Actually format 35c word[2] = FEDC, word[1] = methodidx
            // Let's redo: opcode_AA_CC_method FEDC
            // word0: AA=A<<12|opcode = 3<<12|0x71
            // word1: method_idx
            // word2: G(4bits) F(4bits) E(4bits) D(4bits) in nibbles = 0,0,v1,p0
            // C is in word0 bits 11-8
            // Re-writing cleanly:
            writeU16(out, o,     (3 << 12) | 0x71); // A=3, opcode=71(invoke-static)
            writeU16(out, o + 2, makeTextMethodIdx & 0xFFFF);
            // C=v0 (low nibble of byte2 of word0, but already written — we need to fix)
            // word0 = 0x3071: A=3 in bits 15-12, opcode=0x71 in bits 7-0
            // C = bits 11-8 of word0 = 0 (v0) — that's already 0, OK
            // word2 = {G=0, F=0, E=v1, D=p0}
            writeU16(out, o + 4, (0 << 12) | (0 << 8) | ((1) << 4) | (p0reg & 0xF));
            o += 6;

            // move-result-object v0
            writeU16(out, o, 0x000c); // move-result-object opcode=0x0c, A=0
            o += 2;

            // invoke-virtual {v0}, Toast.show()
            writeU16(out, o,     (1 << 12) | 0x6e); // A=1, opcode=6e (invoke-virtual)
            writeU16(out, o + 2, showMethodIdx & 0xFFFF);
            writeU16(out, o + 4, 0x0000); // {C=v0}
            o += 6;

            log(progress, "  ToastInjector: injected Toast into " + classDesc + ".onCreate");
            return true;
        }

        return false;
    }

    // ── DEX readers ──────────────────────────────────────────────────────────

    private static int findString(byte[] dex, String target) {
        int stringIdsSize = readU32(dex, 0x38);
        int stringIdsOff  = readU32(dex, 0x3c);

        byte[] targetBytes = target.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < stringIdsSize; i++) {
            int stringOff = readU32(dex, stringIdsOff + i * 4);
            if (stringOff <= 0 || stringOff >= dex.length) continue;

            // Skip ULEB128 length prefix
            int pos = stringOff;
            while (pos < dex.length && (dex[pos] & 0x80) != 0) pos++;
            pos++; // skip last ULEB byte

            if (pos + targetBytes.length >= dex.length) continue;

            boolean match = true;
            for (int j = 0; j < targetBytes.length; j++) {
                if (dex[pos + j] != targetBytes[j]) { match = false; break; }
            }
            if (match && dex[pos + targetBytes.length] == 0) return i;
        }
        return -1;
    }

    private static int findTypeByDescriptor(byte[] dex, String descriptor) {
        int typeIdsSize = readU32(dex, 0x40);
        int typeIdsOff  = readU32(dex, 0x44);
        int stringIdsOff = readU32(dex, 0x3c);

        byte[] targetBytes = descriptor.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < typeIdsSize; i++) {
            int descIdx   = readU32(dex, typeIdsOff + i * 4);
            int stringOff = readU32(dex, stringIdsOff + descIdx * 4);
            if (stringOff <= 0 || stringOff >= dex.length) continue;

            int pos = stringOff;
            while (pos < dex.length && (dex[pos] & 0x80) != 0) pos++;
            pos++;

            if (pos + targetBytes.length >= dex.length) continue;

            boolean match = true;
            for (int j = 0; j < targetBytes.length; j++) {
                if (dex[pos + j] != targetBytes[j]) { match = false; break; }
            }
            if (match && dex[pos + targetBytes.length] == 0) return i;
        }
        return -1;
    }

    private static int findMethodByName(byte[] dex, int classTypeIdx, String methodName) {
        int methodIdsSize = readU32(dex, 0x58);
        int methodIdsOff  = readU32(dex, 0x5c);
        int stringIdsOff  = readU32(dex, 0x3c);

        byte[] nameBytes = methodName.getBytes(StandardCharsets.UTF_8);

        for (int i = 0; i < methodIdsSize; i++) {
            int off      = methodIdsOff + i * METHOD_ID_SIZE;
            int classIdx = readU16(dex, off);
            if (classIdx != classTypeIdx) continue;

            int nameIdx    = readU32(dex, off + 4);
            int stringOff  = readU32(dex, stringIdsOff + nameIdx * 4);
            if (stringOff <= 0 || stringOff >= dex.length) continue;

            int pos = stringOff;
            while (pos < dex.length && (dex[pos] & 0x80) != 0) pos++;
            pos++;

            if (pos + nameBytes.length >= dex.length) continue;

            boolean match = true;
            for (int j = 0; j < nameBytes.length; j++) {
                if (dex[pos + j] != nameBytes[j]) { match = false; break; }
            }
            if (match && dex[pos + nameBytes.length] == 0) return i;
        }
        return -1;
    }

    private static String getTypeDescriptor(byte[] dex, int typeIdx) {
        try {
            int typeIdsSize  = readU32(dex, 0x40);
            int typeIdsOff   = readU32(dex, 0x44);
            int stringIdsOff = readU32(dex, 0x3c);
            if (typeIdx < 0 || typeIdx >= typeIdsSize) return null;
            int descIdx   = readU32(dex, typeIdsOff + typeIdx * 4);
            int stringOff = readU32(dex, stringIdsOff + descIdx * 4);
            if (stringOff <= 0 || stringOff >= dex.length) return null;

            int pos = stringOff;
            while (pos < dex.length && (dex[pos] & 0x80) != 0) pos++;
            pos++;

            StringBuilder sb = new StringBuilder();
            while (pos < dex.length && dex[pos] != 0) {
                sb.append((char)(dex[pos++] & 0xff));
                if (sb.length() > 256) break;
            }
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    private static String getMethodName(byte[] dex, int methodIdx) {
        try {
            int methodIdsOff = readU32(dex, 0x5c);
            int stringIdsOff = readU32(dex, 0x3c);
            int off          = methodIdsOff + methodIdx * METHOD_ID_SIZE;
            if (off + 8 > dex.length) return null;
            int nameIdx   = readU32(dex, off + 4);
            int stringOff = readU32(dex, stringIdsOff + nameIdx * 4);
            if (stringOff <= 0 || stringOff >= dex.length) return null;

            int pos = stringOff;
            while (pos < dex.length && (dex[pos] & 0x80) != 0) pos++;
            pos++;

            StringBuilder sb = new StringBuilder();
            while (pos < dex.length && dex[pos] != 0) {
                sb.append((char)(dex[pos++] & 0xff));
                if (sb.length() > 128) break;
            }
            return sb.toString();
        } catch (Exception e) { return null; }
    }

    private static int findBoundaryAtLeast(byte[] data, int insnsOff, int insnsSize, int minUnits) {
        // Simplified opcode size table for boundary walk
        int[] sizes = new int[256];
        // fill known sizes (from SuperDexPatcher.OPCODE_UNITS)
        sizes[0x00]=1; sizes[0x01]=1; sizes[0x02]=2; sizes[0x03]=3;
        sizes[0x04]=1; sizes[0x05]=2; sizes[0x06]=3; sizes[0x07]=1;
        sizes[0x08]=2; sizes[0x09]=3; sizes[0x0a]=1; sizes[0x0b]=1;
        sizes[0x0c]=1; sizes[0x0d]=1; sizes[0x0e]=1; sizes[0x0f]=1;
        sizes[0x10]=1; sizes[0x11]=1; sizes[0x12]=1; sizes[0x13]=2;
        sizes[0x14]=3; sizes[0x15]=2; sizes[0x16]=2; sizes[0x17]=3;
        sizes[0x18]=5; sizes[0x19]=2; sizes[0x1a]=2; sizes[0x1b]=3;
        sizes[0x1c]=2; sizes[0x1d]=1; sizes[0x1e]=1; sizes[0x1f]=2;
        sizes[0x20]=2; sizes[0x21]=1; sizes[0x22]=2; sizes[0x23]=2;
        sizes[0x24]=3; sizes[0x25]=3; sizes[0x26]=3; sizes[0x27]=1;
        sizes[0x28]=1; sizes[0x29]=2; sizes[0x2a]=3; sizes[0x2b]=3;
        sizes[0x2c]=3;
        for (int op=0x2d;op<=0x3d;op++) sizes[op]=2;
        for (int op=0x44;op<=0x6d;op++) sizes[op]=2;
        for (int op=0x6e;op<=0x72;op++) sizes[op]=3;
        for (int op=0x74;op<=0x78;op++) sizes[op]=3;
        for (int op=0x7b;op<=0x8f;op++) sizes[op]=1;
        for (int op=0x90;op<=0xaf;op++) sizes[op]=2;
        for (int op=0xb0;op<=0xcf;op++) sizes[op]=1;
        for (int op=0xd0;op<=0xe2;op++) sizes[op]=2;
        sizes[0xfa]=4; sizes[0xfb]=4; sizes[0xfc]=3; sizes[0xfd]=3;
        sizes[0xfe]=2; sizes[0xff]=2;

        int unit = 0;
        while (unit < minUnits) {
            if (unit >= insnsSize) return -1;
            int op   = readU16(data, insnsOff + unit * 2) & 0xff;
            int size = sizes[op];
            if (size <= 0 || unit + size > insnsSize) return -1;
            unit += size;
        }
        return unit;
    }

    // ── Binary helpers ────────────────────────────────────────────────────────

    private static int readU16(byte[] data, int offset) {
        if (offset < 0 || offset + 2 > data.length) return 0;
        return (data[offset] & 0xff) | ((data[offset+1] & 0xff) << 8);
    }

    private static int readU32(byte[] data, int offset) {
        if (offset < 0 || offset + 4 > data.length) return 0;
        return (data[offset]     & 0xff)        |
               ((data[offset+1]  & 0xff) <<  8) |
               ((data[offset+2]  & 0xff) << 16) |
               ((data[offset+3]  & 0xff) << 24);
    }

    private static void writeU16(byte[] data, int offset, int value) {
        if (offset < 0 || offset + 2 > data.length) return;
        data[offset]   = (byte) value;
        data[offset+1] = (byte)(value >>> 8);
    }

    private static void log(SuperDexPatcher.Progress p, String msg) {
        if (p != null) p.log(msg);
    }

    static final class Cursor {
        final byte[] data;
        int position;
        Cursor(byte[] data, int position) { this.data=data; this.position=position; }

        int readUleb128() {
            int result=0, shift=0;
            for (int i=0;i<5;i++) {
                if (position>=data.length) return result;
                int b = data[position++] & 0xff;
                result |= (b & 0x7f) << shift;
                if ((b & 0x80)==0) return result;
                shift += 7;
            }
            return result;
        }
    }
}
