"""
Open Source Tools Orchestrator
Coordinates all open source security tools for comprehensive analysis
"""
import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from .base import tool_registry, ToolResult

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a scan"""
    target: str
    tools: List[str] = field(default_factory=list)
    options: Dict = field(default_factory=dict)
    parallel: bool = True
    max_concurrent: int = 5
    timeout: int = 600


@dataclass
class ScanResult:
    """Complete scan result"""
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    tool_results: Dict[str, ToolResult] = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    
    @property
    def duration(self) -> float:
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return 0.0
    
    @property
    def successful_tools(self) -> int:
        return sum(1 for r in self.tool_results.values() if r.success)
    
    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.tool_results.values())


class OpenSourceOrchestrator:
    """Orchestrates open source security tools"""
    
    def __init__(self):
        self.tools = tool_registry.tools
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.logger = logging.getLogger(__name__)
    
    def list_available_tools(self) -> Dict[str, str]:
        """List all available tools with descriptions"""
        return {
            name: tool.__class__.__doc__ or "No description"
            for name, tool in self.tools.items()
        }
    
    def get_tool(self, name: str):
        """Get tool by name"""
        return self.tools.get(name)
    
    async def run_scan(self, config: ScanConfig) -> ScanResult:
        """Run a complete scan with specified tools"""
        result = ScanResult(
            target=config.target,
            started_at=datetime.now()
        )
        
        # Determine tools to run
        tools_to_run = config.tools if config.tools else list(self.tools.keys())
        
        # Filter available tools
        available_tools = {name: self.tools[name] for name in tools_to_run if name in self.tools}
        unavailable = set(tools_to_run) - set(available_tools.keys())
        
        if unavailable:
            result.errors.append(f"Unavailable tools: {', '.join(unavailable)}")
        
        if not available_tools:
            result.errors.append("No valid tools to run")
            result.completed_at = datetime.now()
            return result
        
        # Run tools
        if config.parallel:
            await self._run_parallel(result, available_tools, config)
        else:
            await self._run_sequential(result, available_tools, config)
        
        # Generate summary
        result.completed_at = datetime.now()
        result.summary = self._generate_summary(result)
        
        return result
    
    async def _run_parallel(self, result: ScanResult, tools: Dict, config: ScanConfig):
        """Run tools in parallel with concurrency limit"""
        semaphore = asyncio.Semaphore(config.max_concurrent)
        
        async def run_with_semaphore(name: str, tool):
            async with semaphore:
                try:
                    self.logger.info(f"Starting {name} on {config.target}")
                    tool_result = await tool.analyze(config.target, config.options)
                    result.tool_results[name] = tool_result
                    self.logger.info(f"Completed {name}: {'success' if tool_result.success else 'failed'}")
                except Exception as e:
                    self.logger.error(f"Tool {name} failed: {e}")
                    result.tool_results[name] = ToolResult(
                        tool_name=name,
                        success=False,
                        error=str(e)
                    )
        
        # Run all tools concurrently
        tasks = [run_with_semaphore(name, tool) for name, tool in tools.items()]
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_sequential(self, result: ScanResult, tools: Dict, config: ScanConfig):
        """Run tools sequentially"""
        for name, tool in tools.items():
            try:
                self.logger.info(f"Starting {name} on {config.target}")
                tool_result = await tool.analyze(config.target, config.options)
                result.tool_results[name] = tool_result
                self.logger.info(f"Completed {name}: {'success' if tool_result.success else 'failed'}")
            except Exception as e:
                self.logger.error(f"Tool {name} failed: {e}")
                result.tool_results[name] = ToolResult(
                    tool_name=name,
                    success=False,
                    error=str(e)
                )
    
    def _generate_summary(self, result: ScanResult) -> Dict:
        """Generate scan summary"""
        summary = {
            "target": result.target,
            "duration_seconds": result.duration,
            "tools_run": len(result.tool_results),
            "successful_tools": result.successful_tools,
            "failed_tools": len(result.tool_results) - result.successful_tools,
            "total_findings": result.total_findings,
            "findings_by_tool": {},
            "findings_by_type": {},
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        }
        
        for name, tool_result in result.tool_results.items():
            summary["findings_by_tool"][name] = len(tool_result.findings)
            
            for finding in tool_result.findings:
                # Count by type
                ftype = finding.get('type', 'unknown')
                summary["findings_by_type"][ftype] = summary["findings_by_type"].get(ftype, 0) + 1
                
                # Count by severity
                severity = finding.get('severity', 'unknown').lower()
                if severity in summary["severity_counts"]:
                    summary["severity_counts"][severity] += 1
                else:
                    summary["severity_counts"]["unknown"] += 1
        
        return summary
    
    async def quick_scan(self, target: str, tools: List[str] = None) -> ScanResult:
        """Quick scan with default settings"""
        config = ScanConfig(
            target=target,
            tools=tools or ["mobsf", "yara", "frida", "drozer", "objection", "yara", "grype", "trivy"],
            parallel=True,
            max_concurrent=3
        )
        return await self.run_scan(config)
    
    async def deep_scan(self, target: str, tools: List[str] = None) -> ScanResult:
        """Deep scan with all tools"""
        config = ScanConfig(
            target=target,
            tools=tools or list(self.tools.keys()),
            parallel=True,
            max_concurrent=5,
            timeout=1200,
            options={
                "deep": True,
                "timeout": 600
            }
        )
        return await self.run_scan(config)
    
    def export_report(self, result: ScanResult, format: str = "json") -> str:
        """Export scan report"""
        if format == "json":
            import json
            from datetime import datetime
            
            # Convert to serializable format
            data = {
                "target": result.target,
                "started_at": result.started_at.isoformat(),
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "duration": result.duration,
                "summary": result.summary,
                "errors": result.errors,
                "tool_results": {}
            }
            
            for name, tool_result in result.tool_results.items():
                data["tool_results"][name] = {
                    "tool_name": tool_result.tool_name,
                    "success": tool_result.success,
                    "findings_count": len(tool_result.findings),
                    "findings": tool_result.findings,
                    "metadata": tool_result.metadata,
                    "execution_time": tool_result.execution_time,
                    "error": tool_result.error
                }
            
            return json.dumps(data, indent=2)
        
        elif format == "markdown":
            return self._export_markdown(result)
        
        return str(result)
    
    def _export_markdown(self, result: ScanResult) -> str:
        """Export report as Markdown"""
        md = f"# Security Scan Report\n\n"
        md += f"**Target:** {result.target}\n"
        md += f"**Scan Duration:** {result.duration:.1f}s\n"
        md += f"**Tools Run:** {len(result.tool_results)}\n"
        md += f"**Successful:** {result.successful_tools}\n"
        md += f"**Findings:** {result.total_findings}\n\n"
        
        md += "## Summary\n\n"
        md += f"- **Critical:** {result.summary['severity_counts'].get('critical', 0)}\n"
        md += f"- **High:** {result.summary['severity_counts'].get('high', 0)}\n"
        md += f"- **Medium:** {result.summary['severity_counts'].get('medium', 0)}\n"
        md += f"- **Low:** {result.summary['severity_counts'].get('low', 0)}\n\n"
        
        md += "## Findings by Type\n\n"
        for ftype, count in result.summary.get('findings_by_type', {}).items():
            md += f"- **{ftype}:** {count}\n"
        md += "\n"
        
        md += "## Tool Results\n\n"
        for name, tool_result in result.tool_results.items():
            status = "✅" if tool_result.success else "❌"
            md += f"### {status} {name}\n"
            md += f"- **Findings:** {len(tool_result.findings)}\n"
            md += f"- **Duration:** {tool_result.execution_time:.1f}s\n"
            if tool_result.error:
                md += f"- **Error:** {tool_result.error}\n"
            md += "\n"
        
        if result.errors:
            md += "## Errors\n\n"
            for error in result.errors:
                md += f"- {error}\n"
        
        return md


# Global orchestrator
orchestrator = OpenSourceOrchestrator()