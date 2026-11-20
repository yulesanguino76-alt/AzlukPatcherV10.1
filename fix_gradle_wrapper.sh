#!/bin/bash
# AzlukPatcher V10 — Fix gradle-wrapper.jar
# Run this ONCE after cloning/extracting the project.
# Requires: curl or wget + internet connection

set -e

WRAPPER_JAR="gradle/wrapper/gradle-wrapper.jar"
GRADLE_VERSION="8.2"
JAR_URL="https://raw.githubusercontent.com/gradle/gradle/v${GRADLE_VERSION}.0/gradle/wrapper/gradle-wrapper.jar"
# Fallback: get it from the official binary distribution
DIST_URL="https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"

echo "→ Fixing gradle-wrapper.jar for Gradle ${GRADLE_VERSION}..."

if command -v curl &>/dev/null; then
    # Try direct jar URL first (GitHub raw)
    curl -fL "$JAR_URL" -o "$WRAPPER_JAR" 2>/dev/null && {
        echo "✓ Downloaded via curl (direct jar)"
        exit 0
    }
    # Fallback: download full distribution and extract the jar
    echo "  Direct download failed, extracting from distribution..."
    TMP=$(mktemp -d)
    curl -fL "$DIST_URL" -o "$TMP/gradle.zip"
    unzip -j "$TMP/gradle.zip" "*/gradle-wrapper.jar" -d "$TMP/"
    cp "$TMP/gradle-wrapper.jar" "$WRAPPER_JAR"
    rm -rf "$TMP"
    echo "✓ Extracted from distribution"
elif command -v wget &>/dev/null; then
    wget -q "$JAR_URL" -O "$WRAPPER_JAR" 2>/dev/null && {
        echo "✓ Downloaded via wget"
        exit 0
    }
    TMP=$(mktemp -d)
    wget -q "$DIST_URL" -O "$TMP/gradle.zip"
    unzip -j "$TMP/gradle.zip" "*/gradle-wrapper.jar" -d "$TMP/"
    cp "$TMP/gradle-wrapper.jar" "$WRAPPER_JAR"
    rm -rf "$TMP"
    echo "✓ Extracted from distribution"
else
    echo "✗ Neither curl nor wget found."
    echo "  Manually download gradle-wrapper.jar and place it at: $WRAPPER_JAR"
    echo "  URL: $JAR_URL"
    exit 1
fi

echo ""
echo "✓ Done. Now run: ./gradlew assembleDebug"
