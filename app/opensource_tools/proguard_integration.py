"""
ProGuard/R8 Integration - Code obfuscation and optimization
Open source alternative to DexGuard, Appdome
"""
import asyncio
import logging
import json
import tempfile
import os
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class ProGuardIntegration(OpenSourceToolBase):
    """ProGuard/R8 integration for code obfuscation and optimization"""
    
    def __init__(self):
        config = ToolConfig(
            name="proguard",
            executable="proguard",
            args=[],
            install_check="proguard --version",
            timeout=300
        )
        super().__init__(config)
        self.templates_dir = Path(__file__).parent / "proguard_templates"
        self.templates_dir.mkdir(exist_ok=True)
        self._create_templates()
    
    def _create_templates(self):
        """Create ProGuard configuration templates"""
        templates = {
            "android_standard.pro": """
# Android standard ProGuard configuration
-injars      input.apk
-outjars     output.apk
-libraryjars <java.home>/lib/rt.jar
-libraryjars <android.sdk>/platforms/android-30/android.jar

# Keep Android components
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.view.View
-keep public class * extends android.app.Fragment
-keep public class * extends androidx.fragment.app.Fragment

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep enum values
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep Parcelable
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}

# Keep Serializable
-keepclassmembers class * implements java.io.Serializable {
    static final long serialVersionUID;
    private static final java.io.ObjectStreamField[] serialPersistentFields;
    private void writeObject(java.io.ObjectOutputStream);
    private void readObject(java.io.ObjectInputStream);
    java.lang.Object writeReplace();
    java.lang.Object readResolve();
}

# Keep annotations
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes EnclosingMethod

# Remove logging
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Optimize
-optimizationpasses 5
-allowaccessmodification
-overloadaggressively
-repackageclasses ''
"""
,
            "android_aggressive.pro": """
# Aggressive ProGuard configuration for maximum obfuscation
-injars      input.apk
-outjars     output.apk
-libraryjars <java.home>/lib/rt.jar
-libraryjars <android.sdk>/platforms/android-30/android.jar

# Aggressive optimizations
-optimizationpasses 7
-allowaccessmodification
-overloadaggressively
-repackageclasses ''
-flattenpackagehierarchy ''

# Remove all logging
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
    public static *** w(...);
    public static *** e(...);
    public static *** wtf(...);
}

# Remove assertions
-assumenosideeffects class java.lang.System {
    public static void arraycopy(...);
}

# Keep only essential Android components
-keep public class * extends android.app.Activity {
    public protected *;
}
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Remove unused
-dontskipnonpubliclibraryclasses
-dontskipnonpubliclibraryclassmembers
"""
,
            "r8_full_mode.pro": """
# R8 Full Mode configuration (most aggressive)
# Enable R8 full mode
android {
    buildTypes {
        release {
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}

# R8 full mode options
-keepattributes SourceFile,LineNumberTable
-keepattributes Signature
-keepattributes EnclosingMethod

# Keep annotations for reflection
-keepattributes *Annotation*
-keepattributes RuntimeVisibleAnnotations
-keepattributes RuntimeVisibleParameterAnnotations
-keepattributes RuntimeVisibleTypeAnnotations

# Full mode aggressive optimizations
-optimizationpasses 10
-allowaccessmodification
-overloadaggressively
-repackageclasses ''
-flattenpackagehierarchy ''
-mergeinterfacesaggressively

# Remove unused
-dontskipnonpubliclibraryclasses
-dontskipnonpubliclibraryclassmembers
-dontpreverify

# Keep only entry points
-keep public class * extends android.app.Activity
-keep public class * extends android.app.Application
-keep public class * extends android.app.Service
-keep public class * extends android.content.BroadcastReceiver
-keep public class * extends android.content.ContentProvider
-keep public class * extends android.view.View
-keep public class * extends androidx.appcompat.app.AppCompatActivity

# Keep native
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep Parcelable
-keep class * implements android.os.Parcelable {
    public static final android.os.Parcelable$Creator *;
}
"""
        }
        
        for name, content in templates.items():
            template_path = self.templates_dir / name
            if not template_path.exists():
                template_path.write_text(content)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Analyze and obfuscate APK with ProGuard/R8"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            with tempfile.TemporaryDirectory() as work_dir:
                input_apk = Path(target)
                output_apk = Path(work_dir) / "output.apk"
                mapping_file = Path(work_dir) / "mapping.txt"
                
                # Select configuration
                config_name = options.get('config', 'android_standard.pro')
                config_path = self.templates_dir / config_name
                
                if not config_path.exists():
                    config_path = self.templates_dir / 'android_standard.pro'
                
                # Build ProGuard command
                cmd = [
                    'proguard',
                    f'@"{config_path}"',
                    f'-injars "{target}"',
                    f'-outjars "{output_apk}"',
                    f'-printmapping "{mapping_file}"',
                    f'-printusage "{work_dir}/unused.txt"',
                    f'-printseeds "{work_dir}/seeds.txt"'
                ]
                
                # Add custom options
                if options.get('verbose'):
                    cmd.append('-v')
                
                proc = await asyncio.create_subprocess_shell(
                    ' '.join(cmd),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.timeout
                )
                
                if proc.returncode != 0:
                    return ToolResult(
                        tool_name=self.config.name,
                        success=False,
                        error=stderr.decode() or stdout.decode()
                    )
                
                # Analyze results
                findings = await self._analyze_results(work_dir, mapping_file)
                
                return ToolResult(
                    tool_name=self.config.name,
                    success=True,
                    findings=findings,
                    metadata={
                        "input": target,
                        "output": str(output_apk),
                        "mapping_file": str(mapping_file),
                        "config": config_name
                    },
                    execution_time=asyncio.get_event_loop().time() - start_time
                )
            
        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error="Obfuscation timed out",
                execution_time=asyncio.get_event_loop().time() - start_time
            )
        except Exception as e:
            logger.error(f"ProGuard failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _analyze_results(self, work_dir: str, mapping_file: Path) -> List[Dict]:
        """Analyze ProGuard results"""
        findings = []
        
        # Read mapping file
        if mapping_file.exists():
            mapping_content = mapping_file.read_text()
            lines = mapping_content.strip().split('\n')
            
            findings.append({
                "type": "mapping",
                "classes_mapped": len([l for l in lines if '->' in l and not l.startswith('#')]),
                "methods_mapped": len([l for l in lines if '(' in l and ')' in l]),
                "fields_mapped": len([l for l in lines if '->' in l and '(' not in l])
            })
        
        # Read unused
        unused_file = Path(work_dir) / "unused.txt"
        if unused_file.exists():
            unused = unused_file.read_text()
            unused_count = len(unused.strip().split('\n'))
            findings.append({
                "type": "unused_code",
                "count": unused_count,
                "details": unused[:1000] if unused else ""
            })
        
        # Read seeds
        seeds_file = Path(work_dir) / "seeds.txt"
        if seeds_file.exists():
            seeds = seeds_file.read_text()
            seed_count = len(seeds.strip().split('\n'))
            findings.append({
                "type": "kept_classes",
                "count": seed_count
            })
        
        return findings
    
    async def deobfuscate(self, mapping_file: str, stack_trace: str) -> str:
        """Deobfuscate stack trace using mapping file"""
        try:
            cmd = ['retrace', mapping_file]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate(stack_trace.encode())
            
            if proc.returncode == 0:
                return stdout.decode()
            else:
                return f"Deobfuscation failed: {stderr.decode()}"
                
        except Exception as e:
            return f"Deobfuscation error: {e}"


# Register
proguard_tool = ProGuardIntegration()
tool_registry.register(proguard_tool)