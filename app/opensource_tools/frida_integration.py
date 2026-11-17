"""
Frida Integration - Dynamic instrumentation framework
Open source alternative to Contrast Security, Signal Sciences RASP
"""
import asyncio
import logging
import json
import tempfile
import os
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class FridaIntegration(OpenSourceToolBase):
    """Frida integration for dynamic analysis and runtime instrumentation"""
    
    def __init__(self):
        config = ToolConfig(
            name="frida",
            executable="frida",
            args=[],
            install_check="frida --version",
            timeout=300
        )
        super().__init__(config)
        self.scripts_dir = Path(__file__).parent / "frida_scripts"
        self.scripts_dir.mkdir(exist_ok=True)
        self._create_builtin_scripts()
    
    def _create_builtin_scripts(self):
        """Create built-in Frida scripts for common analysis tasks"""
        scripts = {
            "enum_classes.js": """
Java.perform(function() {
    var classes = Java.enumerateLoadedClassesSync();
    send({type: "classes", count: classes.length, classes: classes});
});
""",
            "enum_methods.js": """
Java.perform(function() {
    var targetClass = Java.use("%CLASS%");
    var methods = targetClass.class.getDeclaredMethods();
    var methodList = [];
    for (var i = 0; i < methods.length; i++) {
        methodList.push(methods[i].toString());
    }
    send({type: "methods", class: "%CLASS%", methods: methodList});
});
""",
            "hook_method.js": """
Java.perform(function() {
    var targetClass = Java.use("%CLASS%");
    var targetMethod = targetClass["%METHOD%"];
    if (targetMethod) {
        targetMethod.implementation = function() {
            var args = Array.from(arguments);
            send({type: "call", class: "%CLASS%", method: "%METHOD%", args: args});
            var ret = targetMethod.apply(this, arguments);
            send({type: "return", class: "%CLASS%", method: "%METHOD%", return: ret});
            return ret;
        };
    }
});
""",
            "ssl_pinning_bypass.js": """
Java.perform(function() {
    // Bypass common SSL pinning implementations
    var okhttp3 = Java.use("okhttp3.OkHttpClient");
    okhttp3.setCertificatePinner.implementation = function(pinner) {
        send({type: "bypass", target: "OkHttpClient.setCertificatePinner"});
        return this.setCertificatePinner(pinner);
    };
    
    var trustManager = Java.use("javax.net.ssl.X509TrustManager");
    trustManager.checkServerTrusted.implementation = function(chain, authType) {
        send({type: "bypass", target: "X509TrustManager.checkServerTrusted"});
        return;
    };
    
    var sslContext = Java.use("javax.net.ssl.SSLContext");
    sslContext.init.implementation = function(keyManagers, trustManagers, secureRandom) {
        send({type: "bypass", target: "SSLContext.init"});
        return this.init(keyManagers, trustManagers, secureRandom);
    };
    
    send({type: "bypass", status: "SSL pinning bypass applied"});
});
""",
            "root_detection_bypass.js": """
Java.perform(function() {
    // Bypass common root detection
    var rootPackages = [
        "com.noshufou.android.su",
        "com.noshufou.android.su.elite",
        "eu.chainfire.supersu",
        "com.koushikdutta.superuser",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.topjohnwu.magisk"
    ];
    
    var packageManager = Java.use("android.content.pm.PackageManager");
    packageManager.getPackageInfo.implementation = function(packageName, flags) {
        if (rootPackages.indexOf(packageName) !== -1) {
            send({type: "bypass", target: "root_package_check", package: packageName});
            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
        }
        return this.getPackageInfo(packageName, flags);
    };
    
    // Bypass su binary checks
    var file = Java.use("java.io.File");
    file.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || path.indexOf("superuser") !== -1) {
            send({type: "bypass", target: "su_binary_check", path: path});
            return false;
        }
        return this.exists();
    };
    
    send({type: "bypass", status: "Root detection bypass applied"});
});
""",
            "crypto_hooks.js": """
Java.perform(function() {
    // Hook cryptographic operations
    var cipher = Java.use("javax.crypto.Cipher");
    cipher.init.implementation = function(opmode, key, params) {
        send({type: "crypto", operation: "Cipher.init", algorithm: key.getAlgorithm()});
        return this.init(opmode, key, params);
    };
    
    cipher.doFinal.implementation = function(input) {
        var output = this.doFinal(input);
        send({type: "crypto", operation: "Cipher.doFinal", inputLength: input.length, outputLength: output.length});
        return output;
    };
    
    var messageDigest = Java.use("java.security.MessageDigest");
    messageDigest.digest.implementation = function(input) {
        var output = this.digest(input);
        send({type": "crypto", operation: "MessageDigest.digest", algorithm: this.getAlgorithm(), inputLength: input.length});
        return output;
    };
    
    send({type: "crypto", status: "Crypto hooks applied"});
});
""",
            "network_monitor.js": """
Java.perform(function() {
    // Monitor network connections
    var url = Java.use("java.net.URL");
    url.openConnection.implementation = function() {
        send({type: "network", url: this.toString()});
        return this.openConnection();
    };
    
    var httpURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    httpURLConnection.connect.implementation = function() {
        send({type: "network", url: this.getURL().toString(), type: "HTTPS"});
        return this.connect();
    };
    
    var okhttp = Java.use("okhttp3.OkHttpClient");
    okhttp.newCall.implementation = function(request) {
        send({type: "network", url: request.url().toString(), method: request.method()});
        return this.newCall(request);
    };
    
    send({type: "network", status: "Network monitoring applied"});
});
""",
            "file_access.js": """
Java.perform(function() {
    // Monitor file access
    var file = Java.use("java.io.File");
    file.exists.implementation = function() {
        var result = this.exists();
        if (result) {
            send({type: "file", operation: "exists", path: this.getAbsolutePath()});
        }
        return result;
    };
    
    var fileInputStream = Java.use("java.io.FileInputStream");
    fileInputStream.$init.overload('java.io.File').implementation = function(file) {
        send({type: "file", operation: "read", path: file.getAbsolutePath()});
        return this.$init(file);
    };
    
    var fileOutputStream = Java.use("java.io.FileOutputStream");
    fileOutputStream.$init.overload('java.io.File').implementation = function(file) {
        send({type: "file", operation: "write", path: file.getAbsolutePath()});
        return this.$init(file);
    };
    
    send({type: "file", status: "File access monitoring applied"});
});
""",
            "shared_prefs.js": """
Java.perform(function() {
    // Monitor SharedPreferences access
    var sharedPrefs = Java.use("android.app.SharedPreferencesImpl");
    sharedPrefs.getString.implementation = function(key, defValue) {
        var result = this.getString(key, defValue);
        send({type: "prefs", operation: "getString", key: key, value: result});
        return result;
    };
    
    sharedPrefs.getInt.implementation = function(key, defValue) {
        var result = this.getInt(key, defValue);
        send({type: "prefs", operation: "getInt", key: key, value: result});
        return result;
    };
    
    var editor = Java.use("android.app.SharedPreferencesImpl$Editor");
    editor.putString.implementation = function(key, value) {
        send({type: "prefs", operation: "putString", key: key, value: value});
        return this.putString(key, value);
    };
    
    send({type: "prefs", status: "SharedPreferences monitoring applied"});
});
""",
        }
        
        for name, content in scripts.items():
            script_path = self.scripts_dir / name
            if not script_path.exists():
                script_path.write_text(content)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Run Frida analysis on target"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            # Determine target type
            if target.endswith('.apk'):
                package_name = options.get('package')
                if not package_name:
                    # Extract package name from APK
                    package_name = await self._extract_package_name(target)
            else:
                package_name = target
            
            if not package_name:
                return ToolResult(
                    tool_name=self.config.name,
                    success=False,
                    error="Could not determine package name"
                )
            
            # Select scripts based on options
            scripts = options.get('scripts', [
                'ssl_pinning_bypass.js',
                'root_detection_bypass.js',
                'network_monitor.js',
                'crypto_hooks.js',
                'file_access.js',
                'shared_prefs.js'
            ])
            
            findings = []
            
            # Run Frida with each script
            for script_name in scripts:
                script_path = self.scripts_dir / script_name
                if script_path.exists():
                    result = await self._run_frida_script(package_name, script_path)
                    findings.extend(result)
            
            # Run custom script if provided
            if options.get('custom_script'):
                custom_path = Path(options['custom_script'])
                if custom_path.exists():
                    result = await self._run_frida_script(package_name, custom_path)
                    findings.extend(result)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "package": package_name,
                    "scripts_used": scripts,
                    "device": options.get('device', 'usb')
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Frida analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _extract_package_name(self, apk_path: str) -> Optional[str]:
        """Extract package name from APK using aapt"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'aapt', 'dump', 'badging', apk_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode()
            
            for line in output.split('\n'):
                if line.startswith("package: name="):
                    return line.split("name='")[1].split("'")[0]
        except Exception as e:
            logger.error(f"Failed to extract package name: {e}")
        return None
    
    async def _run_frida_script(self, package_name: str, script_path: Path) -> List[Dict]:
        """Run a Frida script against target package"""
        findings = []
        
        try:
            # Create a temporary script with package substitution
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            # Replace placeholders
            script_content = script_content.replace('%CLASS%', options.get('class', ''))
            script_content = script_content.replace('%METHOD%', options.get('method', ''))
            
            # Write temp script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
                f.write(script_content)
                temp_script = f.name
            
            try:
                # Run Frida
                cmd = ['frida', '-U', '-f', package_name, '-l', temp_script, '--no-pause']
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=60
                )
                
                # Parse output
                output = stdout.decode()
                for line in output.strip().split('\n'):
                    if line.strip():
                        try:
                            data = json.loads(line)
                            if data.get('type') != 'log':
                                findings.append({
                                    "script": script_path.name,
                                    "data": data
                                })
                        except json.JSONDecodeError:
                            pass
            finally:
                os.unlink(temp_script)
                
        except Exception as e:
            logger.error(f"Frida script {script_path.name} failed: {e}")
            findings.append({
                "script": script_path.name,
                "error": str(e)
            })
        
        return findings


# Register
frida_tool = FridaIntegration()
tool_registry.register(frida_tool)