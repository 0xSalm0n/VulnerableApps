# Android Application Penetration Testing Notes

A comprehensive guide for Android Penetration Testing, covering architecture, environment setup, static/dynamic analysis, and exploitation techniques.

**Reference:** Based on eLearnSecurity Mobile Application Penetration Testing (eMAPT) methodology.

## 📖 Table of Contents
1. [Android Architecture](#1-android-architecture)
2. [Lab Setup & Environment](#2-lab-setup--environment)
3. [Android Debug Bridge (ADB)](#3-android-debug-bridge-adb)
4. [Static Analysis](#4-static-analysis)
5. [Dynamic Analysis](#5-dynamic-analysis)
6. [Network Traffic Analysis](#6-network-traffic-analysis)
7. [Common Vulnerabilities & Exploitation](#7-common-vulnerabilities--exploitation)
8. [Tools Cheatsheet](#8-tools-cheatsheet)

---

## 1. Android Architecture
Understanding the Android software stack is critical for identifying attack surfaces.

### The Software Stack
Android is built on top of the Linux Kernel. The stack consists of five main sections:
1.  **Linux Kernel**: The heart of the OS. Manages hardware drivers (camera, display, memory), power management, and security (UID isolation).
2.  **Platform Libraries**: Native C/C++ libraries (SSL, libc, SQLite, OpenGL, WebKit) used by various system components.
3.  **Android Runtime (ART/Dalvik)**:
    * **Dalvik VM**: Register-based VM optimized for low memory. Runs `.dex` (Dalvik Executable) files.
    * **Core Libraries**: Java-based libraries providing standard Java API support.
4.  **Application Framework**: Java classes that manage the basic functions of the phone (Activity Manager, Content Providers, Notification Manager).
5.  **Applications**: The top layer containing system apps (Home, Contacts) and third-party apps.

### Application Sandbox (Security Model)
* **UID Isolation**: Each Android app runs as a distinct Linux user with a unique User ID (UID). By default, files created by one app cannot be read by another.
* **Process Isolation**: Each app runs in its own process and its own Virtual Machine (VM).

### App Components
Entry points into the application:
* **Activities**: The UI screens the user interacts with (e.g., Login Screen).
* **Services**: Background processes without a UI (e.g., Music Player, Data Sync).
* **Broadcast Receivers**: Listeners for system-wide events (e.g., "Battery Low", "SMS Received").
* **Content Providers**: Manage and share data between applications (SQL-like interface).

---

## 2. Lab Setup & Environment

### Essential Tools
* **Kali Linux**: Preferred OS for pentesting due to pre-installed tools.
* **Android Studio**: Required for SDK tools and creating AVDs (Android Virtual Devices).
* **Emulators (AVD)**:
    * Use **x86/x86_64** images for performance on PC.
    * Use **Google APIs** (non-Play Store) images for easier rooting capabilities.
* **Rooting**:
    * Rooting is the process of gaining administrative privileges (UID 0) to bypass the sandbox.
    * Allows you to access `/data/data/`, hook processes, and inspect memory.

---

## 3. Android Debug Bridge (ADB)
A command-line tool to communicate with the device.

### Essential Commands
| Command | Description |
| :--- | :--- |
| `adb devices` | List connected devices/emulators |
| `adb shell` | Open a remote shell on the device |
| `adb install <app.apk>` | Install an application |
| `adb pull <remote> <local>` | Copy file from device to computer |
| `adb push <local> <remote>` | Copy file from computer to device |
| `adb logcat` | View system logs (crucial for finding leaked secrets) |
| `adb shell pm list packages` | List all installed packages |
| `adb shell pm path <package>`| Get the path of the installed APK |
| `adb shell am start ...` | Start an Activity using Activity Manager |

---

## 4. Static Analysis
Analyzing the source code without executing the app.

### Decompilation Process
1.  **Extract APK**: An APK is just a ZIP file. Rename `.apk` to `.zip` to access `AndroidManifest.xml` (binary), `classes.dex`, and resources.
2.  **Decode Resources (APKTool)**:
    * Command: `apktool d app.apk`
    * Converts `AndroidManifest.xml` to readable XML and `classes.dex` to **Smali** code.
3.  **Decompile to Java (Dex2Jar + JD-GUI)**:
    * Convert `.dex` to `.jar`: `d2j-dex2jar.bat classes.dex`.
    * View `.jar` in JD-GUI or **Jadx** to read Java source code.

### What to Look For (Checklist)
* **AndroidManifest.xml**:
    * `android:debuggable="true"`: App can be debugged (Critical in production).
    * `android:allowBackup="true"`: App data can be extracted via `adb backup`.
    * `android:exported="true"`: Components accessible by other malicious apps.
* **Hardcoded Secrets**: Search code for "API_KEY", "password", "token", or crypto keys.
* **Database**: Check for raw SQL queries susceptible to SQL Injection.

---

## 5. Dynamic Analysis
Testing the app at runtime to manipulate logic and intercept data.

### Hooking & Instrumentation
* **Frida**: A dynamic instrumentation toolkit. Inject JavaScript to hook methods at runtime.
    * *Bypass Root Detection*: Hook `RootBeer` or system checks.
    * *Bypass SSL Pinning*: Hook `TrustManager` to accept any certificate.
* **Drozer**: A comprehensive Android attack framework.
    * Interact with Content Providers (SQLi detection).
    * Send malicious Intents to exported activities.

### Debugging
* **Repacking for Debugging**: If an app is not debuggable, use `apktool` to add `android:debuggable="true"` to the Manifest, rebuild, sign, and reinstall.
* **Logcat**: Watch for sensitive data (tokens, PII) printed to logs. `adb logcat | grep "keyword"`.

---

## 6. Network Traffic Analysis
Intercepting HTTP/HTTPS traffic to analyze server communication.

### Setup
1.  **Burp Suite**: Set proxy listener to `All Interfaces` on port `8080`.
2.  **Device Config**: Set Wi-Fi proxy to your PC's IP and port 8080.
3.  **CA Certificate**:
    * Export CA from Burp (`cacert.der`).
    * Rename to `.cer` and push to device.
    * Install via **Settings > Security > Install from storage**.
    * *Note*: On Android 7.0+ (Nougat), apps do not trust user certs by default. You may need to inject the cert into the system store (requires root) or use Frida to bypass validation.

---

## 7. Common Vulnerabilities & Exploitation

### 1. Tapjacking
* **Description**: An attack where a malicious app overlays a transparent window over a legitimate app (like a permission dialog) to trick the user into clicking something they didn't intend.
* **Mechanism**: Exploits `SYSTEM_ALERT_WINDOW` permission (screen overlays).
* **Detection**: Check if the app implements `filterTouchesWhenObscured="true"` in its layout files.

### 2. Insecure Data Storage
* **Shared Preferences**: Check `/data/data/<package>/shared_prefs/` for plain-text session tokens or passwords.
* **External Storage**: Data stored on SD card is globally readable.

### 3. SQL Injection (Content Providers)
* **Description**: If a Content Provider exports data via SQL queries without parameterization, it may be vulnerable.
* **Exploitation**: Use **Drozer** to query the provider:
    * `run app.provider.query content://com.target.provider/ --projection "*"`.

### 4. Component Hijacking
* **Description**: Exported activities or services can be launched by malicious apps to perform unauthorized actions.
* **Test**: `adb shell am start -n com.example/.HiddenActivity`.

---

## 8. Tools Cheatsheet

| Tool | Purpose | Command / Usage |
| :--- | :--- | :--- |
| **Apktool** | Decompile/Rebuild | `apktool d app.apk` / `apktool b folder` |
| **Jadx-GUI** | View Java Code | `jadx-gui app.apk` |
| **Dex2Jar** | Convert .dex to .jar | `d2j-dex2jar.bat classes.dex` |
| **Keytool** | Generate Certs | `keytool -genkey -v -keystore my.keystore ...` |
| **Jarsigner**| Sign APKs | `jarsigner -keystore my.keystore app.apk alias` |
| **Zipalign** | Optimize APK | `zipalign -v 4 app.apk app-aligned.apk` |
| **Drozer** | Attack Surface | `drozer console connect` |
| **Frida** | Runtime Hooking | `frida -U -f com.package -l script.js` |
| **MobSF** | Automated Analysis | Run via Docker/Localhost |
