# Rarimo Rust SDK for Android

A streamlined guide to building, integrating, and testing the Rarimo Rust SDK for Android using UniFFI bindings.

---

## 1. Supported ABIs and Android API Level

### Target ABIs

| ABI         | Rust target triplet       | Minimum NDK API | Notes                      |
|-------------|---------------------------|-----------------|----------------------------|
| arm64-v8a   | `aarch64-linux-android`   | 21              | Primary for modern devices |
| armeabi-v7a | `armv7-linux-androideabi` | 21              | Support for older devices  |

**Guidelines:**

* Focus on `arm64-v8a` and `armeabi-v7a` to cover most devices.
* Each Rust `.so` must match the target ABI and go into `jniLibs/<abi>`.
* Supporting extra ABIs increases APK size and build complexity.

---

## 2. Prerequisites

Install and configure the following tools:

### Rust Toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://rustup.rs | sh
rustup target add aarch64-linux-android armv7-linux-androideabi
```

### Android NDK

> **Note:** The NDK must be installed **only** through Android Studio.

* Version r21 or higher.
* Set `ANDROID_NDK_HOME`:

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
```

### Android SDK & Build Tools

> **Note:** The Android SDK & Build Tools must be installed **only** through Android Studio.

* Required for Gradle.
* Set `ANDROID_SDK_ROOT` or `ANDROID_HOME` to the SDK path.

### Cargo NDK

* Simplifies cross-compilation:

```bash
cargo install cargo-ndk
```

### UniFFI Tooling

```bash
cargo install uniffi --features cli
```

**Verify setup:**

```bash
rustup target list --installed
cargo ndk --version
```

---

## 3. Build Rust `.so` Libraries

### 3.1 Configure Library Type

`Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]
```

### 3.2 Set Secure Linker Flags

```bash
export RUSTFLAGS='-C link-arg=-Wl,-z,now \
                  -C link-arg=-Wl,-z,relro \
                  -C link-arg=-Wl,--no-undefined \
                  -C link-arg=-Wl,-page_size=0x4000'
```

* `-z,now`: eager symbol binding
* `-z,relro`: read-only relocations
* `--no-undefined`: fail on unresolved symbols
* `-page_size=0x4000`: 16 KB alignment required by Android

### 3.3 Build Commands with Cargo NDK

```bash
cargo ndk --targets "aarch64-linux-android armv7-linux-androideabi" --android-platform 21 -- build --release
```

Outputs PATH: `target/<triplet>/release/lib<crate_name>.so`

### 3.4 Copy `.so` Files to Android

```bash
mkdir -p android/mylib/src/main/jniLibs/arm64-v8a
mkdir -p android/mylib/src/main/jniLibs/armeabi-v7a

cp target/aarch64-linux-android/release/lib<crate_name>.so android/mylib/src/main/jniLibs/arm64-v8a/
cp target/armv7-linux-androideabi/release/lib<crate_name>.so android/mylib/src/main/jniLibs/armeabi-v7a/
```

---

## 4. UniFFI Kotlin Bindings Integration

### 4.1 Generate Bindings

```bash
uniffi-bindgen generate uniffi/my_sdk.udl --language kotlin --out-dir target/uniffi
```

For Android-compatible bindings (point the bindgen at the compiled native library so generated code matches the actual
.so layout). Run this after you build the .so for each ABI:

```bash
# example for arm64
uniffi-bindgen generate uniffi/my_sdk.udl \
  --language kotlin \
  --library target/aarch64-linux-android/release/lib<crate_name>.so \
  --out-dir target/uniffi

# example for armeabi-v7a
uniffi-bindgen generate uniffi/my_sdk.udl \
  --language kotlin \
  --library target/armv7-linux-androideabi/release/lib<crate_name>.so \
  --out-dir target/uniffi
```

Repeat per ABI (or point to the ABI-specific .so) so the generated Kotlin code is compatible with the Android native
libraries you ship.

> Note: You can configure linker flags, targets, and other build settings in .cargo/config.toml instead of exporting
> environment variables. This helps make builds reproducible and avoids setting global environment variables for each
> session.

### 4.2 Copy to Android Module

```bash
cp -r target/uniffi/kotlin/* android/mylib/src/main/kotlin/
```

For Android-compatible bindings (point the bindgen at the compiled native library so generated code matches the actual
.so layout). Run this after you build the .so for each ABI:

```bash
# example for arm64
uniffi-bindgen generate uniffi/my_sdk.udl \
--language kotlin \
--library target/aarch64-linux-android/release/lib<crate_name>.so \
--out-dir target/uniffi

# example for armeabi-v7a
uniffi-bindgen generate uniffi/my_sdk.udl \
--language kotlin \
--library target/armv7-linux-androideabi/release/lib<crate_name>.so \
--out-dir target/uniffi
```

Repeat per ABI (or point to the ABI-specific .so) so the generated Kotlin code is compatible with the Android native
libraries you ship.

Ensure folder hierarchy matches package structure.

### 4.3 Load Native Library

```kotlin
object NativeLoader {
    init { System.loadLibrary("<crate_name>") }
}
```

Call `NativeLoader` before any API usage.

---

## 5. Build & Test Android Module

### 5.1 Build Module

```bash
cd android/mylib
./gradlew assembleDebug
```

### 5.2 Install APK

```bash
adb install -r android/mylib/build/outputs/apk/debug/mylib-debug.apk
```

### 5.3 Integration Test Example

```kotlin
@Test
fun testGetBalance() {
    val _ = NativeLoader
    val balance: Long = Wallet.getBalance()
    assertTrue(balance >= 0)
}
```

**Tips:**

* Test `.so` loading and API calls.
* Use `androidTest` for instrumentation tests.
* Run tests via Android Studio or Gradle:

```bash
./gradlew connectedAndroidTest
./gradlew testDebugUnitTest
```

---

## 6. ProGuard / R8 Rules

```proguard
-keepclasseswithmembernames,includedescriptorclasses class * { native <methods>; }
-keepclassmembers class * { native <methods>; }
-keep class com.example.mylib.uniffi.** { *; }
-keep class kotlin.Metadata
```

Enable minification in `build.gradle` for release builds:

```kotlin
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
    }
}
```

Verify functionality after minification.

---

## 7. Summary

After completing integration:

1. `.so` libraries built for supported ABIs and securely linked.
2. UniFFI Kotlin bindings compiled into the Android module.
3. Native library loader ensures safe usage.
4. Integration tests confirm Rust API functionality.
5. ProGuard / R8 rules protect bindings for release builds.

**Result:** Android apps can safely call Rust SDK APIs through Kotlin bindings across supported devices.
