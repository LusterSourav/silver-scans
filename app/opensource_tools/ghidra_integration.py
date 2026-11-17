"""
Ghidra Integration - Reverse engineering framework
Open source alternative to IDA Pro, Binary Ninja
"""
import asyncio
import logging
import json
import os
import tempfile
from typing import Dict, List, Optional, Any
from pathlib import Path

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class GhidraIntegration(OpenSourceToolBase):
    """Ghidra integration for reverse engineering"""
    
    def __init__(self, ghidra_path: str = "/opt/ghidra"):
        config = ToolConfig(
            name="ghidra",
            executable=f"{ghidra_path}/support/analyzeHeadless",
            args=[],
            install_check=f"{ghidra_path}/support/analyzeHeadless -version",
            timeout=600
        )
        super().__init__(config)
        self.ghidra_path = ghidra_path
        self.scripts_dir = Path(__file__).parent / "ghidra_scripts"
        self.scripts_dir.mkdir(exist_ok=True)
        self._create_analysis_scripts()
    
    def _create_analysis_scripts(self):
        """Create Ghidra analysis scripts"""
        scripts = {
            "ExtractInfo.java": """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;

public class ExtractInfo extends GhidraScript {
    public void run() throws Exception {
        String outputFile = getScriptArgs()[0];
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("=== PROGRAM INFO ===");
        writer.println("Name: " + currentProgram.getName());
        writer.println("Language: " + currentProgram.getLanguage().toString());
        writer.println("Compiler: " + currentProgram.getCompilerSpec().getCompilerName());
        
        writer.println("\\n=== MEMORY BLOCKS ===");
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            writer.println("Block: " + block.getName() + " " + block.getStart() + "-" + block.getEnd() 
                + " RWX=" + block.isRead() + "/" + block.isWrite() + "/" + block.isExecute());
        }
        
        writer.println("\\n=== FUNCTIONS ===");
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        int funcCount = 0;
        while (funcs.hasNext()) {
            Function f = funcs.next();
            writer.println("Func: " + f.getName() + " @ " + f.getEntryPoint() 
                + " Stack: " + f.getStackFrame().getFrameSize() 
                + " Thunk: " + f.isThunk());
            funcCount++;
        }
        writer.println("Total functions: " + funcCount);
        
        writer.println("\\n=== EXPORTS ===");
        SymbolTable st = currentProgram.getSymbolTable();
        SymbolIterator exports = st.getExternalSymbols();
        while (exports.hasNext()) {
            Symbol s = exports.next();
            writer.println("Export: " + s.getName() + " @ " + s.getAddress());
        }
        
        writer.println("\\n=== IMPORTS ===");
        SymbolIterator imports = st.getExternalSymbols();
        while (imports.hasNext()) {
            Symbol s = imports.next();
            if (s.isExternal()) {
                writer.println("Import: " + s.getName() + " @ " + s.getAddress());
            }
        }
        
        writer.println("\\n=== STRINGS ===");
        StringManager sm = currentProgram.getStringManager();
        int stringCount = 0;
        for (StringInstance si : sm.getAllStrings(true)) {
            if (stringCount < 100) {
                writer.println("String @ " + si.getAddress() + ": " + si.getString());
            }
            stringCount++;
        }
        writer.println("Total strings: " + stringCount);
        
        writer.println("\\n=== MEMORY REFERENCES ===");
        ReferenceManager rm = currentProgram.getReferenceManager();
        ReferenceIterator refs = rm.getReferencesTo(currentProgram.getMinAddress());
        int refCount = 0;
        while (refs.hasNext() && refCount < 100) {
            Reference r = refs.next();
            writer.println("Ref: " + r.getFromAddress() + " -> " + r.getToAddress() + " Type: " + r.getReferenceType());
            refCount++;
        }
        
        writer.close();
    }
}
""",
            "FindCrypto.java": """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.util.*;

public class FindCrypto extends GhidraScript {
    public void run() throws Exception {
        String outputFile = getScriptArgs()[0];
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("=== CRYPTOGRAPHIC OPERATIONS ===");
        
        // Known crypto constants
        String[] cryptoConstants = {
            "MD5", "SHA1", "SHA256", "SHA512", "SHA3",
            "AES", "DES", "3DES", "RC4", "RC2", "Blowfish", "Twofish",
            "RSA", "DSA", "ECDSA", "DiffieHellman", "ECDH",
            "PBKDF2", "bcrypt", "scrypt", "argon2",
            "HMAC", "CMAC", "GCM", "CCM", "CTR", "CBC", "ECB"
        };
        
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(true);
        
        int found = 0;
        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            String mnemonic = instr.getMnemonicString();
            
            // Look for crypto-related calls
            if (mnemonic.equals("CALL")) {
                Address target = instr.getFlowTargets()[0];
                Function func = getFunctionAt(target);
                if (func != null) {
                    String funcName = func.getName().toUpperCase();
                    for (String crypto : cryptoConstants) {
                        if (funcName.contains(crypto)) {
                            writer.println("CRYPTO CALL: " + func.getName() + " @ " + instr.getAddress());
                            found++;
                            break;
                        }
                    }
                }
            }
            
            // Check for crypto constants in memory
            writer.println("\\n=== CRYPTO CONSTANTS IN MEMORY ===");
            MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
            for (MemoryBlock block : blocks) {
                if (block.isRead()) {
                    byte[] bytes = new byte[(int) block.getSize()];
                    block.getBytes(block.getStart(), bytes);
                    String data = new String(bytes);
                    for (String crypto : cryptoConstants) {
                        int index = data.indexOf(crypto);
                        if (index >= 0) {
                            Address addr = block.getStart().add(index);
                            writer.println("Found " + crypto + " at " + addr);
                            found++;
                        }
                    }
                }
            }
            
            writer.println("Total crypto references found: " + found);
            writer.close();
        }
    }
}
""",
            "FindVulns.java": """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.util.*;

public class FindVulns extends GhidraScript {
    public void run() throws Exception {
        String outputFile = getScriptArgs()[0];
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("=== VULNERABILITY ANALYSIS ===");
        
        // Dangerous functions
        String[] dangerousFuncs = {
            "strcpy", "strcat", "sprintf", "vsprintf", "gets",
            "scanf", "fscanf", "sscanf", "vfscanf", "vscanf", "vsscanf",
            "memcpy", "memmove", "strncpy", "strncat", "snprintf",
            "malloc", "calloc", "realloc", "free",
            "system", "popen", "exec", "execl", "execle", "execlp", "execv", "execve", "execvp",
            "setuid", "setgid", "seteuid", "setegid"
        };
        
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        
        int vulnCount = 0;
        while (funcs.hasNext()) {
            Function f = funcs.next();
            String funcName = f.getName().toLowerCase();
            
            for (String dangerous : dangerousFuncs) {
                if (funcName.contains(dangerous.toLowerCase())) {
                    writer.println("DANGEROUS FUNC: " + f.getName() + " @ " + f.getEntryPoint());
                    vulnCount++;
                    break;
                }
            }
            
            // Check for format string vulnerabilities
            PcodeOp[] ops = f.getPcodeOps();
            for (PcodeOp op : ops) {
                if (op.getMnemonic() == PcodeOp.CALL) {
                    Varnode target = op.getInput(0);
                    if (target != null && target.isAddress()) {
                        Function calledFunc = getFunctionAt(target.getAddress());
                        if (calledFunc != null) {
                            String calledName = calledFunc.getName().toLowerCase();
                            if (calledName.contains("printf") || calledName.contains("sprintf") 
                                || calledName.contains("fprintf") || calledName.contains("snprintf")) {
                                // Check if format string is user-controlled
                                Varnode formatArg = op.getInput(1);
                                if (formatArg != null && !formatArg.isConstant()) {
                                    writer.println("FORMAT STRING VULN: " + f.getName() + " calls " + calledFunc.getName() + " @ " + f.getEntryPoint());
                                    vulnCount++;
                                }
                            }
                        }
                    }
                }
            }
            
            writer.println("Total potential vulnerabilities: " + vulnCount);
            writer.close();
        }
    }
}
""",
            "FindNetwork.java": """
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import java.util.*;

public class FindNetwork extends GhidraScript {
    public void run() throws Exception {
        String outputFile = getScriptArgs()[0];
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));
        
        writer.println("=== NETWORK ANALYSIS ===");
        
        // Network-related functions
        String[] networkFuncs = {
            "socket", "connect", "bind", "listen", "accept", "send", "recv",
            "sendto", "recvfrom", "sendmsg", "recvmsg",
            "http", "https", "url", "uri", "httpclient", "okhttp",
            "retrofit", "volley", "websockets", "webview"
        };
        
        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        
        int networkCount = 0;
        while (funcs.hasNext()) {
            Function f = funcs.next();
            String funcName = f.getName().toLowerCase();
            
            for (String netFunc : networkFuncs) {
                if (funcName.contains(netFunc.toLowerCase())) {
                    writer.println("NETWORK FUNC: " + f.getName() + " @ " + f.getEntryPoint());
                    networkCount++;
                    break;
                }
            }
        }
        
        writer.println("Total network functions: " + networkCount);
        writer.close();
    }
}
"""
        }
        
        for name, content in scripts.items():
            script_path = self.scripts_dir / name
            if not script_path.exists():
                script_path.write_text(content)
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Analyze target with Ghidra"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            with tempfile.TemporaryDirectory() as project_dir:
                project_name = "silver_scan_" + str(int(time.time()))
                output_file = os.path.join(project_dir, "ghidra_output.txt")
                
                # Determine input file
                input_file = target
                if target.endswith('.apk'):
                    # Extract DEX files from APK
                    dex_files = await self._extract_dex(target)
                    if dex_files:
                        input_file = dex_files[0]
                    else:
                        return ToolResult(
                            tool_name=self.config.name,
                            success=False,
                            error="No DEX files found in APK"
                        )
                
                # Run Ghidra analysis
                scripts = options.get('scripts', ['ExtractInfo.java', 'FindCrypto.java', 'FindVulns.java', 'FindNetwork.java'])
                
                all_findings = []
                
                for script in scripts:
                    script_path = self.scripts_dir / script
                    if not script_path.exists():
                        continue
                    
                    result = await self._run_ghidra_script(project_dir, project_name, input_file, script_path, output_file)
                    if result:
                        all_findings.extend(result)
                
                return ToolResult(
                    tool_name=self.config.name,
                    success=True,
                    findings=all_findings,
                    metadata={
                        "input_file": input_file,
                        "scripts_run": scripts,
                        "project_dir": project_dir
                    },
                    execution_time=asyncio.get_event_loop().time() - start_time
                )
            
        except Exception as e:
            logger.error(f"Ghidra analysis failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    async def _extract_dex(self, apk_path: str) -> List[str]:
        """Extract DEX files from APK"""
        dex_files = []
        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as apk:
                for name in apk.namelist():
                    if name.endswith('.dex'):
                        with tempfile.NamedTemporaryFile(suffix='.dex', delete=False) as f:
                            f.write(apk.read(name))
                            dex_files.append(f.name)
        except Exception as e:
            logger.error(f"DEX extraction failed: {e}")
        return dex_files
    
    async def _run_ghidra_script(self, project_dir: str, project_name: str, input_file: str, script_path: Path, output_file: str) -> List[Dict]:
        """Run a single Ghidra script"""
        try:
            cmd = [
                self.config.executable,
                project_dir,
                project_name,
                "-import", input_file,
                "-scriptPath", str(self.scripts_dir),
                "-postScript", script_path.name, output_file,
                "-deleteProject"
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=self.config.timeout
            )
            
            findings = []
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    content = f.read()
                
                # Parse output
                for line in content.split('\n'):
                    if line.strip():
                        findings.append({
                            "script": script_path.name,
                            "output": line.strip()
                        })
            
            return findings
            
        except Exception as e:
            logger.error(f"Ghidra script {script_path.name} failed: {e}")
            return []


# Register
ghidra_tool = GhidraIntegration()
tool_registry.register(ghidra_tool)