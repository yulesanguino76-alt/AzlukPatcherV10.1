# AzlukPatcher V10

Android APK patcher — bypass, ad removal, anti-detection, dev tools.

## Setup

### 1. Fix the Gradle wrapper (required after first clone/extract)

```bash
chmod +x fix_gradle_wrapper.sh
./fix_gradle_wrapper.sh
```

This downloads `gradle/wrapper/gradle-wrapper.jar` (~60 KB) from the official Gradle repository.
Only needed once.

### 2. Build debug APK

```bash
./gradlew assembleDebug --stacktrace
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

### 3. Build with AI features

Create `local.properties` in the project root:

```properties
TOKENROUTER_API_KEY=your_key_here
TOKENROUTER_BASE_URL=https://api.groq.com/openai/v1
TOKENROUTER_MODEL=openai/gpt-oss-20b
```

Or set GitHub Actions secrets: `TOKENROUTER_API_KEY`, `TOKENROUTER_BASE_URL`, `TOKENROUTER_MODEL`.

## Alternative: install Gradle manually

If `fix_gradle_wrapper.sh` fails, install Gradle 8.2 system-wide:

```bash
# macOS
brew install gradle

# Linux (sdkman)
sdk install gradle 8.2

# Windows (scoop)
scoop install gradle
```

Then run `gradle wrapper --gradle-version 8.2` inside the project to regenerate the wrapper.

## GitHub Actions

Push a commit to `main` → debug APK built automatically.
Push a tag `v10.0` → release APK + GitHub Release created.

## What's new in V10

- Bottom navigation bar (Apps / Files / Packs / Tools)
- New neon king logo
- Toast injection — every patched APK shows "AzlukPatcher" on launch
- 5 new structural patch recipes: SafetyNet, Frida, Emulator, FLAG_SECURE, Ad Domains
- APatch root detection
- Full Material3 redesign — Deep Void palette
- Fix double-patch bug on PatchLogScreen
- SHA-256 checksums with one-tap copy
- Session log export to `AzlukPatcher/Logs/`
