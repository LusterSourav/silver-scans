"""
Base classes for open source tool integrations
"""
import asyncio
import logging
import subprocess
import json
import os
import tempfile
import shutil
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Standardized result from open source tool"""
    tool_name: str
    success: bool
    findings: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    execution_time: float = 0.0
    error: Optional[str] = None
    raw_output: Optional[str] = None


@dataclass
class ToolConfig:
    """Configuration for open source tool"""
    name: str
    executable: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    timeout: int = 300
    working_dir: Optional[str] = None
    install_check: Optional[str] = None
    version_flag: str = "--version"


class OpenSourceToolBase(ABC):
    """Base class for all open source tool integrations"""
    
    def __init__(self, config: ToolConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.name}")
        self._verify_installation()
    
    def _verify_installation(self):
        """Verify tool is installed and accessible"""
        try:
            if self.config.install_check:
                result = subprocess.run(
                    self.config.install_check.split(),
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    raise RuntimeError(f"{self.config.name} not found: {result.stderr}")
            else:
                result = subprocess.run(
                    [self.config.executable, self.config.version_flag],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    raise RuntimeError(f"{self.config.name} not found: {result.stderr}")
            self.logger.info(f"{self.config.name} verified: {result.stdout.strip()}")
        except Exception as e:
            self.logger.warning(f"{self.config.name} verification failed: {e}")
    
    @abstractmethod
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Run analysis on target"""
        pass
    
    async def _run_command(
        self,
        args: List[str],
        input_data: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> subprocess.CompletedProcess:
        """Run command with proper error handling"""
        cmd = [self.config.executable] + args
        self.logger.debug(f"Running: {' '.join(cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, **self.config.env},
                cwd=self.config.working_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_data.encode() if input_data else None),
                timeout=timeout or self.config.timeout
            )
            
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace')
            )
        except asyncio.TimeoutError:
            self.logger.error(f"Command timed out: {' '.join(cmd)}")
            raise
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            raise
    
    def _parse_findings(self, output: str, format: str = "json") -> List[Dict]:
        """Parse tool output into standardized findings"""
        findings = []
        try:
            if format == "json":
                data = json.loads(output)
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict):
                    findings = [data]
            elif format == "sarif":
                data = json.loads(output)
                for run in data.get("runs", []):
                    for result in run.get("results", []):
                        findings.append({
                            "rule_id": result.get("ruleId"),
                            "level": result.get("level"),
                            "message": result.get("message", {}).get("text"),
                            "locations": result.get("locations", [])
                        })
            elif format == "text":
                # Parse text output line by line
                for line in output.strip().split('\n'):
                    if line.strip():
                        findings.append({"raw": line})
        except Exception as e:
            self.logger.error(f"Failed to parse findings: {e}")
            findings = [{"raw": output, "parse_error": str(e)}]
        return findings


class ToolRegistry:
    """Registry for all open source tools"""
    
    def __init__(self):
        self.tools: Dict[str, OpenSourceToolBase] = {}
    
    def register(self, tool: OpenSourceToolBase):
        self.tools[tool.config.name] = tool
    
    def get(self, name: str) -> Optional[OpenSourceToolBase]:
        return self.tools.get(name)
    
    def list_tools(self) -> List[str]:
        return list(self.tools.keys())
    
    async def run_all(self, target: str, options: Dict = None) -> Dict[str, ToolResult]:
        """Run all registered tools on target"""
        results = {}
        for name, tool in self.tools.items():
            try:
                self.logger.info(f"Running {name} on {target}")
                result = await tool.analyze(target, options)
                results[name] = result
            except Exception as e:
                self.logger.error(f"Tool {name} failed: {e}")
                results[name] = ToolResult(
                    tool_name=name,
                    success=False,
                    error=str(e)
                )
        return results


# Global registry
tool_registry = ToolRegistry()