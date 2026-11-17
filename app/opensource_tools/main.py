"""
Open Source Security Tools - Main Entry Point
Run comprehensive security scans using open source tools
"""
import asyncio
import argparse
import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.opensource_tools.orchestrator import OpenSourceOrchestrator, ScanConfig


def setup_logging(level: str = "INFO"):
    """Setup logging configuration"""
    import logging
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Open Source Security Tools - Comprehensive security scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan with default tools
  python -m app.opensource_tools.main /path/to/app.apk

  # Deep scan with all tools
  python -m app.opensource_tools.main /path/to/app.apk --deep

  # Specific tools only
  python -m app.opensource_tools.main /path/to/app.apk --tools mobsf,yara,frida

  # Custom output
  python -m app.opensource_tools.main /path/to/app.apk --output report.json --format json

  # List available tools
  python -m app.opensource_tools.main --list-tools
        """
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        help="Target file or directory to scan"
    )
    
    parser.add_argument(
        "--tools",
        help="Comma-separated list of tools to run (default: all)"
    )
    
    parser.add_argument(
        "--deep",
        action="store_true",
        help="Run deep scan with all tools"
    )
    
    parser.add_argument(
        "--parallel",
        action="store_true",
        default=True,
        help="Run tools in parallel (default: True)"
    )
    
    parser.add_argument(
        "--max-concurrent",
        type=int,
        default=5,
        help="Maximum concurrent tools (default: 5)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Timeout per tool in seconds (default: 600)"
    )
    
    parser.add_argument(
        "--output",
        help="Output file path"
    )
    
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "text"],
        default="json",
        help="Output format (default: json)"
    )
    
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List available tools and exit"
    )
    
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Log level (default: INFO)"
    )
    
    return parser.parse_args()


async def main():
    """Main entry point"""
    args = parse_args()
    setup_logging(args.log_level)
    
    orchestrator = OpenSourceOrchestrator()
    
    # List tools and exit
    if args.list_tools:
        tools = orchestrator.list_available_tools()
        print("Available Open Source Security Tools:")
        print("=" * 50)
        for name, desc in tools.items():
            print(f"  {name}: {desc}")
        return 0
    
    # Validate target
    if not args.target:
        print("Error: Target file or directory required")
        return 1
    
    target = args.target
    if not os.path.exists(target):
        print(f"Error: Target not found: {target}")
        return 1
    
    # Parse tools
    tools = None
    if args.tools:
        tools = [t.strip() for t in args.tools.split(",")]
    
    # Create scan config
    config = ScanConfig(
        target=target,
        tools=tools,
        parallel=args.parallel,
        max_concurrent=args.max_concurrent,
        timeout=args.timeout,
        options={
            "deep": args.deep,
            "timeout": args.timeout
        }
    )
    
    # Run scan
    print(f"Starting {'deep ' if args.deep else ''}scan of {target}")
    print(f"Tools: {', '.join(config.tools) if config.tools else 'all'}")
    print(f"Parallel: {args.parallel}, Max concurrent: {args.max_concurrent}")
    print("-" * 50)
    
    try:
        result = await orchestrator.run_scan(config)
        
        # Export report
        if args.output:
            report = orchestrator.export_report(result, args.format)
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nReport saved to: {args.output}")
        else:
            # Print summary to stdout
            print("\n" + "=" * 50)
            print("SCAN COMPLETE")
            print("=" * 50)
            print(f"Target: {result.target}")
            print(f"Duration: {result.duration:.1f}s")
            print(f"Tools run: {len(result.tool_results)}")
            print(f"Successful: {result.successful_tools}")
            print(f"Failed: {len(result.tool_results) - result.successful_tools}")
            print(f"Total findings: {result.total_findings}")
            print()
            
            print("Severity breakdown:")
            for severity, count in result.summary.get('severity_counts', {}).items():
                if count > 0:
                    print(f"  {severity.capitalize()}: {count}")
            print()
            
            print("Findings by type:")
            for ftype, count in result.summary.get('findings_by_type', {}).items():
                print(f"  {ftype}: {count}")
            print()
            
            print("Tool results:")
            for name, tool_result in result.tool_results.items():
                status = "✅" if tool_result.success else "❌"
                print(f"  {status} {name}: {len(tool_result.findings)} findings ({tool_result.execution_time:.1f}s)")
            
            if result.errors:
                print("\nErrors:")
                for error in result.errors:
                    print(f"  - {error}")
        
        return 0 if result.successful_tools > 0 else 1
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return 1
    except Exception as e:
        print(f"Scan failed: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))