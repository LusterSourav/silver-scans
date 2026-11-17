"""
CVE Search Integration - CVE database search
Open source alternative to NVD API, Vulners, VulnDB
"""
import asyncio
import logging
import json
import aiohttp
import re
from typing import Dict, List, Optional, Any

from .base import OpenSourceToolBase, ToolConfig, ToolResult, tool_registry

logger = logging.getLogger(__name__)


class CVESearchIntegration(OpenSourceToolBase):
    """CVE Search integration using multiple open CVE databases"""
    
    def __init__(self):
        config = ToolConfig(
            name="cve-search",
            executable="cve-search",
            args=[],
            install_check="curl -s https://cve.circl.lu/api/",
            timeout=120
        )
        super().__init__(config)
        self.session = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if not self.session:
            self.session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            )
        return self.session
    
    async def analyze(self, target: str, options: Dict = None) -> ToolResult:
        """Search CVE databases for target"""
        start_time = asyncio.get_event_loop().time()
        options = options or {}
        
        try:
            session = await self._get_session()
            findings = []
            
            # Detect target type
            target_type = self._detect_target_type(target)
            
            if target_type == 'cve':
                # Direct CVE lookup
                cve_findings = await self._lookup_cve(session, target)
                findings.extend(cve_findings)
            elif target_type == 'package':
                # Search by package name
                package_findings = await self._search_by_package(session, target, options)
                findings.extend(package_findings)
            elif target_type == 'keyword':
                # Keyword search
                keyword_findings = await self._search_by_keyword(session, target, options)
                findings.extend(keyword_findings)
            else:
                # Try all
                cve_findings = await self._lookup_cve(session, target)
                findings.extend(cve_findings)
                
                package_findings = await self._search_by_package(session, target, options)
                findings.extend(package_findings)
            
            # Also search CIRCL CVE
            circl_findings = await self._search_circl(session, target)
            findings.extend(circl_findings)
            
            # Search NVD
            if options.get('search_nvd', True):
                nvd_findings = await self._search_nvd(session, target)
                findings.extend(nvd_findings)
            
            # Search GitHub Advisories
            if options.get('search_github', True):
                github_findings = await self._search_github_advisories(session, target)
                findings.extend(github_findings)
            
            return ToolResult(
                tool_name=self.config.name,
                success=True,
                findings=findings,
                metadata={
                    "target": target,
                    "target_type": target_type,
                    "total_findings": len(findings)
                },
                execution_time=asyncio.get_event_loop().time() - start_time
            )
            
        except Exception as e:
            logger.error(f"CVE search failed: {e}")
            return ToolResult(
                tool_name=self.config.name,
                success=False,
                error=str(e),
                execution_time=asyncio.get_event_loop().time() - start_time
            )
    
    def _detect_target_type(self, target: str) -> str:
        """Detect target type"""
        import re
        
        # CVE format
        if re.match(r'^CVE-\d{4}-\d{4,}$', target, re.IGNORECASE):
            return 'cve'
        
        # Package format (name@version or name)
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*(@[0-9.]+)?$', target):
            return 'package'
        
        return 'keyword'
    
    async def _lookup_cve(self, session: aiohttp.ClientSession, cve_id: str) -> List[Dict]:
        """Lookup specific CVE"""
        findings = []
        
        # CIRCL CVE
        try:
            async with session.get(
                f"https://cve.circl.lu/api/cve/{cve_id.upper()}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    findings.append({
                        "type": "cve",
                        "source": "circl",
                        "id": data.get('id'),
                        "summary": data.get('summary'),
                        "cvss": data.get('cvss'),
                        "cvss_v3": data.get('cvss3', {}),
                        "cvss_v2": data.get('cvss2', {}),
                        "cwe": data.get('cwe', []),
                        "references": data.get('references', []),
                        "published": data.get('Published'),
                        "modified": data.get('Modified'),
                        "vulnerable_products": data.get('vulnerable_product', []),
                        "cpe": data.get('cpe', [])
                    })
        except Exception as e:
            logger.warning(f"CIRCL CVE lookup failed: {e}")
        
        # NVD
        try:
            async with session.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id.upper()}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    vulns = data.get('vulnerabilities', [])
                    for vuln in vulns:
                        cve = vuln.get('cve', {})
                        findings.append({
                            "type": "cve",
                            "source": "nvd",
                            "id": cve.get('id'),
                            "description": cve.get('descriptions', [{}])[0].get('value', ''),
                            "cvss_v3": cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}),
                            "cvss_v2": cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}),
                            "cwe": [w.get('description', [{}])[0].get('value', '') for w in cve.get('weaknesses', [])],
                            "references": [r.get('url', '') for r in cve.get('references', [])],
                            "published": cve.get('published'),
                            "modified": cve.get('lastModified'),
                            "cpe": [c.get('criteria', '') for c in cve.get('configurations', []) for c in c.get('nodes', []) for c in c.get('cpeMatch', [])]
                        })
        except Exception as e:
            logger.warning(f"NVD CVE lookup failed: {e}")
        
        return findings
    
    async def _search_by_package(self, session: aiohttp.ClientSession, package: str, options: Dict) -> List[Dict]:
        """Search CVEs by package name"""
        findings = []
        
        # Parse package@version
        version = None
        if '@' in package:
            package, version = package.split('@', 1)
        
        # Search NVD
        try:
            params = {"keywordSearch": package}
            if version:
                params["keywordSearch"] = f"{package} {version}"
            
            async with session.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for vuln in data.get('vulnerabilities', [])[:50]:
                        cve = vuln.get('cve', {})
                        findings.append({
                            "type": "cve",
                            "source": "nvd_package",
                            "id": cve.get('id'),
                            "description": cve.get('descriptions', [{}])[0].get('value', ''),
                            "cvss_v3": cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}),
                            "cvss_v2": cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}),
                            "cwe": [w.get('description', [{}])[0].get('value', '') for w in cve.get('weaknesses', [])],
                            "references": [r.get('url', '') for r in cve.get('references', [])],
                            "published": cve.get('published'),
                            "modified": cve.get('lastModified')
                        })
        except Exception as e:
            logger.warning(f"NVD package search failed: {e}")
        
        return findings
    
    async def _search_by_keyword(self, session: aiohttp.ClientSession, keyword: str, options: Dict) -> List[Dict]:
        """Search CVEs by keyword"""
        findings = []
        
        try:
            async with session.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 50}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for vuln in data.get('vulnerabilities', []):
                        cve = vuln.get('cve', {})
                        findings.append({
                            "type": "cve",
                            "source": "nvd_keyword",
                            "id": cve.get('id'),
                            "description": cve.get('descriptions', [{}])[0].get('value', ''),
                            "cvss_v3": cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}),
                            "cvss_v2": cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('cvssData', {}),
                            "cwe": [w.get('description', [{}])[0].get('value', '') for w in cve.get('weaknesses', [])],
                            "references": [r.get('url', '') for r in cve.get('references', [])],
                            "published": cve.get('published'),
                            "modified": cve.get('lastModified')
                        })
        except Exception as e:
            logger.warning(f"NVD keyword search failed: {e}")
        
        return findings
    
    async def _search_circl(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search CIRCL CVE database"""
        findings = []
        
        try:
            # Browse by vendor/product
            async with session.get(
                "https://cve.circl.lu/api/browse/"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Could search through vendors/products
                    pass
        except Exception as e:
            logger.warning(f"CIRCL browse failed: {e}")
        
        return findings
    
    async def _search_nvd(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search NVD database"""
        return await self._search_by_keyword(session, target, {})
    
    async def _search_github_advisories(self, session: aiohttp.ClientSession, target: str) -> List[Dict]:
        """Search GitHub Security Advisories"""
        findings = []
        
        try:
            # Search GitHub advisories
            query = target
            if '@' in target:
                package, version = target.split('@', 1)
                query = f"{package} {version}"
            
            async with session.get(
                "https://api.github.com/advisories",
                params={"query": query, "per_page": 50}
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for advisory in data:
                        findings.append({
                            "type": "github_advisory",
                            "id": advisory.get('ghsa_id'),
                            "summary": advisory.get('summary'),
                            "description": advisory.get('description'),
                            "severity": advisory.get('severity'),
                            "package": advisory.get('package', {}).get('name'),
                            "ecosystem": advisory.get('package', {}).get('ecosystem'),
                            "affected_versions": advisory.get('vulnerabilities', []),
                            "references": [r.get('url') for r in advisory.get('references', [])],
                            "published_at": advisory.get('published_at'),
                            "updated_at": advisory.get('updated_at'),
                            "cvss": advisory.get('cvss')
                        })
        except Exception as e:
            logger.warning(f"GitHub advisories search failed: {e}")
        
        return findings


# Register
cve_search_tool = CVESearchIntegration()
tool_registry.register(cve_search_tool)