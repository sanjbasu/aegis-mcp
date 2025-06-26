#!/usr/bin/env python3
"""
Security Audit Script for MCP Armor

Comprehensive security audit tool that checks for vulnerabilities,
misconfigurations, and compliance issues in MCP deployments.

Usage:
    python security_audit.py --full
    python security_audit.py --service user_service
    python security_audit.py --compliance SOC2
    python security_audit.py --output-format json --output-file audit_report.json
"""

import os
import sys
import json
import time
import argparse
import logging
import socket
import ssl
import asyncio
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import re
import hashlib

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
    import yaml
    import nmap
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import jwt
    import redis
    import psutil
    import bandit
    from tabulate import tabulate
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install requests pyyaml python-nmap cryptography pyjwt redis psutil bandit tabulate colorama")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class Severity(Enum):
    """Security finding severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ComplianceFramework(Enum):
    """Compliance frameworks"""
    SOC2 = "soc2"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"

@dataclass
class SecurityFinding:
    """Represents a security finding"""
    category: str
    title: str
    description: str
    severity: Severity
    service: Optional[str] = None
    evidence: Optional[Dict] = None
    remediation: Optional[str] = None
    compliance_impact: Optional[List[str]] = None
    cve: Optional[str] = None
    cvss_score: Optional[float] = None

@dataclass
class AuditReport:
    """Complete audit report"""
    audit_id: str
    timestamp: datetime
    duration: float
    services_audited: List[str]
    total_findings: int
    findings_by_severity: Dict[str, int]
    findings: List[SecurityFinding] = field(default_factory=list)
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    executive_summary: Optional[str] = None

class SecurityAuditor:
    """Main security auditor class"""
    
    def __init__(self, config_path: str = "configs/audit_config.yaml"):
        self.config = self._load_config(config_path)
        self.findings = []
        self.services_checked = set()
        self.start_time = time.time()
        
    def _load_config(self, config_path: str) -> Dict:
        """Load audit configuration"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Get default audit configuration"""
        return {
            'services': {
                'user_service': {
                    'url': 'https://localhost:8443',
                    'health_endpoint': '/health',
                    'expected_version': '1.0.0'
                },
                'payment_service': {
                    'url': 'https://localhost:8444',
                    'health_endpoint': '/health'
                }
            },
            'checks': {
                'ssl_tls': True,
                'authentication': True,
                'authorization': True,
                'input_validation': True,
                'rate_limiting': True,
                'encryption': True,
                'logging': True,
                'dependencies': True,
                'configuration': True
            },
            'compliance': {
                'frameworks': ['SOC2', 'GDPR']
            },
            'thresholds': {
                'ssl_min_version': 'TLSv1.2',
                'password_min_length': 12,
                'session_timeout_minutes': 30,
                'max_login_attempts': 5
            }
        }
    
    async def audit_service(self, service_name: str) -> List[SecurityFinding]:
        """Audit a specific service"""
        
        logger.info(f"Starting audit of {service_name}")
        service_findings = []
        
        service_config = self.config['services'].get(service_name, {})
        if not service_config:
            logger.warning(f"No configuration found for {service_name}")
            return []
        
        # Run all checks
        if self.config['checks'].get('ssl_tls', True):
            findings = await self._check_ssl_tls(service_name, service_config)
            service_findings.extend(findings)
        
        if self.config['checks'].get('authentication', True):
            findings = await self._check_authentication(service_name, service_config)
            service_findings.extend(findings)
        
        if self.config['checks'].get('authorization', True):
            findings = await self._check_authorization(service_name, service_config)
            service_findings.extend(findings)
        
        if self.config['checks'].get('input_validation', True):
            findings = await self._check_input_validation(service_name, service_config)
            service_findings.extend(findings)
        
        if self.config['checks'].get('rate_limiting', True):
            findings = await self._check_rate_limiting(service_name, service_config)
            service_findings.extend(findings)
        
        if self.config['checks'].get('configuration', True):
            findings = await self._check_configuration(service_name, service_config)
            service_findings.extend(findings)
        
        self.services_checked.add(service_name)
        self.findings.extend(service_findings)
        
        return service_findings
    
    async def _check_ssl_tls(self, service_name: str, config: Dict) -> List[SecurityFinding]:
        """Check SSL/TLS configuration"""
        
        findings = []
        url = config.get('url', '')
        
        if not url.startswith('https://'):
            findings.append(SecurityFinding(
                category="SSL/TLS",
                title="HTTPS not enforced",
                description=f"Service {service_name} does not enforce HTTPS",
                severity=Severity.HIGH,
                service=service_name,
                remediation="Enable HTTPS and redirect all HTTP traffic"
            ))
            return findings
        
        # Parse hostname and port
        from urllib.parse import urlparse
        parsed = urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443
        
        try:
            # Create SSL context for testing
            context = ssl.create_default_context()
            
            # Test connection
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate
                    cert_der = ssock.getpeercert_bin()
                    cert = x509.load_der_x509_certificate(cert_der, default_backend())
                    
                    # Check certificate expiration
                    days_until_expiry = (cert.not_valid_after - datetime.utcnow()).days
                    if days_until_expiry < 0:
                        findings.append(SecurityFinding(
                            category="SSL/TLS",
                            title="SSL certificate expired",
                            description=f"Certificate expired {-days_until_expiry} days ago",
                            severity=Severity.CRITICAL,
                            service=service_name,
                            evidence={'days_expired': -days_until_expiry},
                            remediation="Renew SSL certificate immediately"
                        ))
                    elif days_until_expiry < 30:
                        findings.append(SecurityFinding(
                            category="SSL/TLS",
                            title="SSL certificate expiring soon",
                            description=f"Certificate expires in {days_until_expiry} days",
                            severity=Severity.MEDIUM,
                            service=service_name,
                            evidence={'days_until_expiry': days_until_expiry},
                            remediation="Plan certificate renewal"
                        ))
                    
                    # Check TLS version
                    tls_version = ssock.version()
                    min_version = self.config['thresholds']['ssl_min_version']
                    
                    if tls_version < min_version:
                        findings.append(SecurityFinding(
                            category="SSL/TLS",
                            title="Weak TLS version",
                            description=f"Service uses {tls_version}, minimum should be {min_version}",
                            severity=Severity.HIGH,
                            service=service_name,
                            evidence={'tls_version': tls_version},
                            remediation=f"Configure service to use {min_version} or higher"
                        ))
                    
                    # Check cipher suite
                    cipher = ssock.cipher()
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        findings.append(SecurityFinding(
                            category="SSL/TLS",
                            title="Weak cipher suite",
                            description=f"Service uses weak cipher: {cipher[0]}",
                            severity=Severity.HIGH,
                            service=service_name,
                            evidence={'cipher': cipher[0]},
                            remediation="Disable weak ciphers and use modern cipher suites"
                        ))
                    
        except Exception as e:
            findings.append(SecurityFinding(
                category="SSL/TLS",
                title="SSL/TLS check failed",
                description=f"Could not verify SSL/TLS: {str(e)}",
                severity=Severity.MEDIUM,
                service=service_name,
                evidence={'error': str(e)}
            ))
        
        return findings
    
    async def _check_authentication(self, service_name: str, config: Dict) -> List[SecurityFinding]:
        """Check authentication mechanisms"""
        
        findings = []
        
        # Test authentication endpoints
        auth_endpoints = ['/auth', '/login', '/api/auth', '/api/login']
        base_url = config.get('url', '')
        
        for endpoint in auth_endpoints:
            try:
                # Test for common authentication issues
                response = requests.post(
                    f"{base_url}{endpoint}",
                    json={'username': 'test', 'password': 'test'},
                    timeout=5,
                    verify=False  # For testing self-signed certs
                )
                
                # Check for information disclosure
                if 'User not found' in response.text:
                    findings.append(SecurityFinding(
                        category="Authentication",
                        title="Username enumeration possible",
                        description="Authentication endpoint reveals whether username exists",
                        severity=Severity.MEDIUM,
                        service=service_name,
                        evidence={'endpoint': endpoint, 'response': response.text[:100]},
                        remediation="Return generic error message for authentication failures"
                    ))
                
                # Check for weak password policy hints
                if 'password must be' in response.text.lower():
                    findings.append(SecurityFinding(
                        category="Authentication",
                        title="Password policy disclosed",
                        description="Authentication endpoint reveals password requirements",
                        severity=Severity.LOW,
                        service=service_name,
                        evidence={'endpoint': endpoint},
                        remediation="Avoid revealing specific password requirements in error messages"
                    ))
                    
            except requests.exceptions.ConnectionError:
                pass  # Endpoint doesn't exist, which is fine
            except Exception as e:
                logger.debug(f"Authentication check error for {endpoint}: {e}")
        
        # Check for default credentials
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('root', 'root'),
            ('test', 'test')
        ]
        
        for username, password in default_creds:
            for endpoint in auth_endpoints:
                try:
                    response = requests.post(
                        f"{base_url}{endpoint}",
                        json={'username': username, 'password': password},
                        timeout=5,
                        verify=False
                    )
                    
                    if response.status_code == 200 or 'token' in response.text:
                        findings.append(SecurityFinding(
                            category="Authentication",
                            title="Default credentials accepted",
                            description=f"Service accepts default credentials: {username}/{password}",
                            severity=Severity.CRITICAL,
                            service=service_name,
                            evidence={'username': username, 'endpoint': endpoint},
                            remediation="Remove all default credentials and enforce strong passwords"
                        ))
                        
                except Exception:
                    pass
        
        return findings
    
    async def _check_authorization(self, service_name: str, config: Dict) -> List[SecurityFinding]:
        """Check authorization mechanisms"""
        
        findings = []
        base_url = config.get('url', '')
        
        # Test for common authorization issues
        sensitive_endpoints = [
            '/admin',
            '/api/admin',
            '/api/users',
            '/api/config',
            '/metrics',
            '/health/detailed'
        ]
        
        for endpoint in sensitive_endpoints:
            try:
                # Test without authentication
                response = requests.get(
                    f"{base_url}{endpoint}",
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    findings.append(SecurityFinding(
                        category="Authorization",
                        title="Unauthenticated access to sensitive endpoint",
                        description=f"Endpoint {endpoint} accessible without authentication",
                        severity=Severity.HIGH,
                        service=service_name,
                        evidence={'endpoint': endpoint, 'status_code': response.status_code},
                        remediation="Implement proper authentication and authorization checks"
                    ))
                    
            except Exception:
                pass
        
        # Check for IDOR vulnerabilities
        idor_patterns = [
            '/api/users/1',
            '/api/accounts/1',
            '/api/orders/1'
        ]
        
        for pattern in idor_patterns:
            try:
                # Test sequential IDs
                responses = []
                for i in range(1, 4):
                    endpoint = pattern.replace('/1', f'/{i}')
                    response = requests.get(
                        f"{base_url}{endpoint}",
                        timeout=5,
                        verify=False
                    )
                    responses.append((i, response.status_code))
                
                # If all return same status (especially 200), might be IDOR
                if all(r[1] == 200 for r in responses):
                    findings.append(SecurityFinding(
                        category="Authorization",
                        title="Potential IDOR vulnerability",
                        description=f"Sequential IDs accessible at {pattern}",
                        severity=Severity.HIGH,
                        service=service_name,
                        evidence={'pattern': pattern, 'responses': responses},
                        remediation="Implement proper authorization checks and use UUIDs instead of sequential IDs"
                    ))
                    
            except Exception:
                pass
        
        return findings
    
    async def _check_input_validation(self, service_name: str, config: Dict) -> List[SecurityFinding]:
        """Check input validation"""
        
        findings = []
        base_url = config.get('url', '')
        
        # Test for injection vulnerabilities
        injection_payloads = [
            ("SQL Injection", "' OR '1'='1"),
            ("NoSQL Injection", '{"$ne": null}'),
            ("Command Injection", "; ls -la"),
            ("XSS", "<script>alert('xss')</script>"),
            ("XXE", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
            ("Path Traversal", "../../../etc/passwd"),
            ("LDAP Injection", "*)(uid=*))(|(uid=*"),
        ]
        
        # Common endpoints to test
        test_endpoints = [
            '/api/search',
            '/api/users',
            '/api/data',
            '/search'
        ]
        
        for endpoint in test_endpoints:
            for vuln_type, payload in injection_payloads:
                try:
                    # Test GET parameters
                    response = requests.get(
                        f"{base_url}{endpoint}",
                        params={'q': payload, 'search': payload, 'query': payload},
                        timeout=5,
                        verify=False
                    )
                    
                    # Check for signs of successful injection
                    if self._check_injection_success(vuln_type, response):
                        findings.append(SecurityFinding(
                            category="Input Validation",
                            title=f"Potential {vuln_type}",
                            description=f"Endpoint {endpoint} may be vulnerable to {vuln_type}",
                            severity=Severity.CRITICAL,
                            service=service_name,
                            evidence={
                                'endpoint': endpoint,
                                'payload': payload,
                                'response_snippet': response.text[:200]
                            },
                            remediation=f"Implement proper input validation and parameterized queries"
                        ))
                    
                    # Test POST body
                    response = requests.post(
                        f"{base_url}{endpoint}",
                        json={'input': payload, 'data': payload},
                        timeout=5,
                        verify=False
                    )
                    
                    if self._check_injection_success(vuln_type, response):
                        findings.append(SecurityFinding(
                            category="Input Validation",
                            title=f"Potential {vuln_type} in POST body",
                            description=f"Endpoint {endpoint} POST body may be vulnerable to {vuln_type}",
                            severity=Severity.CRITICAL,
                            service=service_name,
                            evidence={
                                'endpoint': endpoint,
                                'method': 'POST',
                                'payload': payload
                            },
                            remediation=f"Implement proper input validation for POST data"
                        ))
                        
                except Exception as e:
                    logger.debug(f"Input validation test error: {e}")
        
        return findings
    
    def _check_injection_success(self, vuln_type: str, response: requests.Response) -> bool:
        """Check if injection was successful based on response"""
        
        if vuln_type == "SQL Injection":
            error_indicators = [
                'sql syntax',
                'mysql_fetch',
                'ORA-01756',
                'PostgreSQL',
                'valid MySQL result',
                'mssql_query()',
                'PostgreSQL query failed',
                'valid PostgreSQL result',
                '[Microsoft][ODBC SQL Server Driver]'
            ]
            return any(indicator.lower() in response.text.lower() for indicator in error_indicators)
        
        elif vuln_type == "Command Injection":
            return any(indicator in response.text for indicator in ['root:', 'bin:', '/etc/passwd'])
        
        elif vuln_type == "XSS":
            return '<script>alert' in response.text
        
        elif vuln_type == "XXE":
            return 'root:' in response.text or 'file:' in response.text
        
        elif vuln_type == "Path Traversal":
            return 'root:' in response.text or 'bin:' in response.text
        
        return False
    
    async def _check_rate_limiting(self, service_name: str, config: Dict) -> List[SecurityFinding]:
        """Check rate limiting implementation"""
        
        findings = []
        base_url = config.get('url', '')
        
        # Test endpoints that should have rate limiting
        test_endpoints = [
            '/api/login',
            '/api/auth',
            '/api/password-reset',
            '/api/data'
        ]
        
        for endpoint in test_endpoints:
            try:
                # Send rapid requests
                start_time = time.time()
                success_count = 0
                total_requests = 50
                
                for i in range(total_requests):
                    response = requests.post(
                        f"{base_url}{endpoint}",
                        json={'test': i},
                        timeout=1,
                        verify=False
                    )
                    
                    if response.status_code != 429:  # 429 = Too Many Requests
                        success_count += 1
                
                elapsed_time = time.time() - start_time
                requests_per_second = total_requests / elapsed_time
                
                # If all requests succeeded, no rate limiting
                if success_count == total_requests:
                    findings.append(SecurityFinding(
                        category="Rate Limiting",
                        title="No rate limiting detected",
                        description=f"Endpoint {endpoint} has no rate limiting ({requests_per_second:.1f} req/s allowed)",
                        severity=Severity.HIGH,
                        service=service_name,
                        evidence={
                            'endpoint': endpoint,
                            'requests_sent': total_requests,
                            'requests_succeeded': success_count,
                            'requests_per_second': requests_per_second
                        },
                        remediation="Implement rate limiting to prevent abuse and DDoS attacks"
                    ))
                elif success_count > 20:
                    findings.append(SecurityFinding(
                        category="Rate Limiting",
                        title="Weak rate limiting",
                        description=f"Endpoint {endpoint} has weak rate limiting ({success_count}/{total_requests} requests allowed)",
                        severity=Severity.MEDIUM,
                        service=service_name,
                        evidence={
                            'endpoint': endpoint,
                            'requests_allowed': success_count,
                            'total_requests': total_requests
                        },
                        remediation="Strengthen rate limiting thresholds"
                    ))
                    
            except Exception as e:
                logger.debug(f"Rate limiting test error: {e}")
        
        return findings
    
    async def _check_configuration(self, service_name: str, config: Dict) -> List[SecurityFinding]:
        """Check service configuration"""
        
        findings = []
        base_url = config.get('url', '')
        
        # Check for exposed configuration endpoints
        config_endpoints = [
            '/.env',
            '/config.json',
            '/config.yaml',
            '/application.properties',
            '/.git/config',
            '/wp-config.php',
            '/web.config',
            '/package.json',
            '/composer.json'
        ]
        
        for endpoint in config_endpoints:
            try:
                response = requests.get(
                    f"{base_url}{endpoint}",
                    timeout=5,
                    verify=False
                )
                
                if response.status_code == 200:
                    # Check for sensitive data
                    sensitive_patterns = [
                        r'(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]+)',
                        r'(api[_-]?key|apikey)\s*[=:]\s*["\']?([^"\'\s]+)',
                        r'(secret|token)\s*[=:]\s*["\']?([^"\'\s]+)',
                        r'(aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["\']?([^"\'\s]+)',
                        r'(database[_-]?url|db[_-]?connection)\s*[=:]\s*["\']?([^"\'\s]+)'
                    ]
                    
                    content = response.text
                    exposed_secrets = []
                    
                    for pattern in sensitive_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            exposed_secrets.append(match.group(1))
                    
                    severity = Severity.CRITICAL if exposed_secrets else Severity.HIGH
                    
                    findings.append(SecurityFinding(
                        category="Configuration",
                        title="Exposed configuration file",
                        description=f"Configuration file accessible at {endpoint}",
                        severity=severity,
                        service=service_name,
                        evidence={
                            'endpoint': endpoint,
                            'file_size': len(content),
                            'exposed_secrets': exposed_secrets[:3]  # Limit to first 3
                        },
                        remediation="Remove configuration files from web root and implement proper access controls"
                    ))
                    
            except Exception:
                pass
        
        # Check security headers
        try:
            response = requests.get(base_url, timeout=5, verify=False)
            headers = response.headers
            
            # Required security headers
            required_headers = {
                'Strict-Transport-Security': 'HSTS not configured',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-XSS-Protection': 'XSS protection header missing',
                'Content-Security-Policy': 'CSP not configured'
            }
            
            for header, issue in required_headers.items():
                if header not in headers:
                    findings.append(SecurityFinding(
                        category="Configuration",
                        title=issue,
                        description=f"Security header {header} is not set",
                        severity=Severity.MEDIUM,
                        service=service_name,
                        evidence={'missing_header': header},
                        remediation=f"Add {header} header to all responses"
                    ))
            
            # Check for dangerous headers
            dangerous_headers = {
                'Server': 'Server header exposes version information',
                'X-Powered-By': 'X-Powered-By header exposes technology stack',
                'X-AspNet-Version': 'ASP.NET version exposed'
            }
            
            for header, issue in dangerous_headers.items():
                if header in headers:
                    findings.append(SecurityFinding(
                        category="Configuration",
                        title=issue,
                        description=f"Header {header} reveals: {headers[header]}",
                        severity=Severity.LOW,
                        service=service_name,
                        evidence={'header': header, 'value': headers[header]},
                        remediation=f"Remove or obfuscate {header} header"
                    ))
                    
        except Exception as e:
            logger.debug(f"Header check error: {e}")
        
        return findings
    
    async def check_dependencies(self) -> List[SecurityFinding]:
        """Check for vulnerable dependencies"""
        
        findings = []
        
        # Check Python dependencies
        requirements_files = [
            'requirements.txt',
            'Pipfile.lock',
            'poetry.lock'
        ]
        
        for req_file in requirements_files:
            if os.path.exists(req_file):
                try:
                    # Run safety check
                    result = subprocess.run(
                        ['safety', 'check', '--file', req_file, '--json'],
                        capture_output=True,
                        text=True
                    )
                    
                    if result.returncode != 0:
                        vulnerabilities = json.loads(result.stdout)
                        
                        for vuln in vulnerabilities:
                            findings.append(SecurityFinding(
                                category="Dependencies",
                                title=f"Vulnerable dependency: {vuln['package']}",
                                description=vuln['description'],
                                severity=Severity.HIGH,
                                evidence={
                                    'package': vuln['package'],
                                    'installed_version': vuln['installed_version'],
                                    'vulnerable_versions': vuln['vulnerable_versions']
                                },
                                cve=vuln.get('cve'),
                                cvss_score=vuln.get('cvss'),
                                remediation=f"Update {vuln['package']} to {vuln.get('safe_version', 'latest safe version')}"
                            ))
                            
                except Exception as e:
                    logger.error(f"Dependency check error: {e}")
        
        # Check for package.json (Node.js)
        if os.path.exists('package.json'):
            try:
                result = subprocess.run(
                    ['npm', 'audit', '--json'],
                    capture_output=True,
                    text=True
                )
                
                audit_data = json.loads(result.stdout)
                
                for advisory_id, advisory in audit_data.get('advisories', {}).items():
                    findings.append(SecurityFinding(
                        category="Dependencies",
                        title=f"Vulnerable npm package: {advisory['module_name']}",
                        description=advisory['overview'],
                        severity=self._npm_to_severity(advisory['severity']),
                        evidence={
                            'package': advisory['module_name'],
                            'vulnerable_versions': advisory['vulnerable_versions'],
                            'patched_versions': advisory['patched_versions']
                        },
                        cve=advisory.get('cves', [None])[0],
                        remediation=advisory['recommendation']
                    ))
                    
            except Exception as e:
                logger.error(f"NPM audit error: {e}")
        
        return findings
    
    def _npm_to_severity(self, npm_severity: str) -> Severity:
        """Convert NPM severity to our severity scale"""
        mapping = {
            'critical': Severity.CRITICAL,
            'high': Severity.HIGH,
            'moderate': Severity.MEDIUM,
            'low': Severity.LOW,
            'info': Severity.INFO
        }
        return mapping.get(npm_severity.lower(), Severity.MEDIUM)
    
    async def scan_network(self) -> List[SecurityFinding]:
        """Scan network for exposed services"""
        
        findings = []
        
        try:
            nm = nmap.PortScanner()
            
            # Scan common ports
            logger.info("Scanning network for exposed services...")
            nm.scan(hosts='127.0.0.1', arguments='-p 1-65535 -sS -sV -O')
            
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        service = nm[host][proto][port]
                        
                        # Check for dangerous exposed services
                        dangerous_services = {
                            22: "SSH",
                            23: "Telnet",
                            3389: "RDP",
                            5432: "PostgreSQL",
                            3306: "MySQL",
                            6379: "Redis",
                            27017: "MongoDB",
                            9200: "Elasticsearch",
                            5984: "CouchDB"
                        }
                        
                        if port in dangerous_services and service['state'] == 'open':
                            findings.append(SecurityFinding(
                                category="Network",
                                title=f"Exposed {dangerous_services[port]} service",
                                description=f"{dangerous_services[port]} is accessible on port {port}",
                                severity=Severity.HIGH,
                                evidence={
                                    'port': port,
                                    'service': service['name'],
                                    'version': service.get('version', 'unknown')
                                },
                                remediation=f"Restrict access to {dangerous_services[port]} using firewall rules"
                            ))
                            
        except Exception as e:
            logger.error(f"Network scan error: {e}")
            logger.info("Install nmap for network scanning: apt-get install nmap")
        
        return findings
    
    async def run_full_audit(self) -> AuditReport:
        """Run complete security audit"""
        
        logger.info("Starting comprehensive security audit...")
        
        # Audit all services
        for service_name in self.config['services']:
            await self.audit_service(service_name)
        
        # Additional checks
        dep_findings = await self.check_dependencies()
        self.findings.extend(dep_findings)
        
        network_findings = await self.scan_network()
        self.findings.extend(network_findings)
        
        # Generate report
        report = self._generate_report()
        
        return report
    
    def _generate_report(self) -> AuditReport:
        """Generate audit report"""
        
        # Count findings by severity
        severity_counts = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            Severity.INFO.value: 0
        }
        
        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
        
        # Generate executive summary
        critical_count = severity_counts[Severity.CRITICAL.value]
        high_count = severity_counts[Severity.HIGH.value]
        
        if critical_count > 0:
            summary = f"⚠️  CRITICAL: {critical_count} critical vulnerabilities found requiring immediate attention!"
        elif high_count > 0:
            summary = f"⚠️  {high_count} high-severity issues found that should be addressed soon."
        else:
            summary = "✅ No critical or high-severity issues found. Good security posture!"
        
        # Check compliance
        compliance_status = {}
        for framework in self.config['compliance']['frameworks']:
            compliance_status[framework] = self._check_compliance(framework)
        
        report = AuditReport(
            audit_id=f"audit_{int(time.time())}",
            timestamp=datetime.utcnow(),
            duration=time.time() - self.start_time,
            services_audited=list(self.services_checked),
            total_findings=len(self.findings),
            findings_by_severity=severity_counts,
            findings=self.findings,
            compliance_status=compliance_status,
            executive_summary=summary
        )
        
        return report
    
    def _check_compliance(self, framework: str) -> bool:
        """Check compliance with specific framework"""
        
        # Simplified compliance check
        if framework == "SOC2":
            # SOC2 requires no critical vulnerabilities and proper logging
            return all(f.severity != Severity.CRITICAL for f in self.findings)
        
        elif framework == "GDPR":
            # GDPR requires encryption and access controls
            encryption_issues = [f for f in self.findings if 'encryption' in f.title.lower()]
            auth_issues = [f for f in self.findings if 'authentication' in f.category.lower()]
            return len(encryption_issues) == 0 and len(auth_issues) == 0
        
        return True
    
    def print_report(self, report: AuditReport, format: str = "table"):
        """Print audit report"""
        
        if format == "table":
            self._print_table_report(report)
        elif format == "json":
            print(json.dumps(report.__dict__, default=str, indent=2))
        elif format == "markdown":
            self._print_markdown_report(report)
    
    def _print_table_report(self, report: AuditReport):
        """Print report in table format"""
        
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}Security Audit Report")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        print(f"\nAudit ID: {report.audit_id}")
        print(f"Timestamp: {report.timestamp}")
        print(f"Duration: {report.duration:.2f} seconds")
        print(f"Services Audited: {', '.join(report.services_audited)}")
        
        print(f"\n{Fore.YELLOW}Executive Summary:{Style.RESET_ALL}")
        print(report.executive_summary)
        
        print(f"\n{Fore.YELLOW}Findings Summary:{Style.RESET_ALL}")
        
        # Summary table
        summary_data = []
        for severity, count in report.findings_by_severity.items():
            color = {
                'critical': Fore.RED,
                'high': Fore.RED,
                'medium': Fore.YELLOW,
                'low': Fore.BLUE,
                'info': Fore.GREEN
            }.get(severity, '')
            
            summary_data.append([
                f"{color}{severity.upper()}{Style.RESET_ALL}",
                str(count)
            ])
        
        print(tabulate(summary_data, headers=['Severity', 'Count'], tablefmt='grid'))
        
        # Compliance status
        print(f"\n{Fore.YELLOW}Compliance Status:{Style.RESET_ALL}")
        compliance_data = []
        for framework, compliant in report.compliance_status.items():
            status = f"{Fore.GREEN}✓ Compliant{Style.RESET_ALL}" if compliant else f"{Fore.RED}✗ Non-compliant{Style.RESET_ALL}"
            compliance_data.append([framework, status])
        
        print(tabulate(compliance_data, headers=['Framework', 'Status'], tablefmt='grid'))
        
        # Detailed findings
        print(f"\n{Fore.YELLOW}Detailed Findings:{Style.RESET_ALL}")
        
        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            severity_findings = [f for f in report.findings if f.severity == severity]
            
            if severity_findings:
                color = {
                    Severity.CRITICAL: Fore.RED,
                    Severity.HIGH: Fore.RED,
                    Severity.MEDIUM: Fore.YELLOW,
                    Severity.LOW: Fore.BLUE,
                    Severity.INFO: Fore.GREEN
                }.get(severity, '')
                
                print(f"\n{color}{severity.value.upper()} ({len(severity_findings)}){Style.RESET_ALL}")
                print("-" * 80)
                
                for finding in severity_findings:
                    print(f"\n📌 {finding.title}")
                    if finding.service:
                        print(f"   Service: {finding.service}")
                    print(f"   Category: {finding.category}")
                    print(f"   Description: {finding.description}")
                    
                    if finding.evidence:
                        print(f"   Evidence: {json.dumps(finding.evidence, indent=6)}")
                    
                    if finding.cve:
                        print(f"   CVE: {finding.cve}")
                    
                    if finding.cvss_score:
                        print(f"   CVSS Score: {finding.cvss_score}")
                    
                    if finding.remediation:
                        print(f"   {Fore.GREEN}Remediation: {finding.remediation}{Style.RESET_ALL}")

def main():
    """Main entry point"""
    
    parser = argparse.ArgumentParser(description='MCP Security Audit Tool')
    parser.add_argument('--service', help='Audit specific service')
    parser.add_argument('--full', action='store_true', help='Run full audit')
    parser.add_argument('--compliance', choices=['SOC2', 'HIPAA', 'GDPR', 'PCI_DSS', 'ISO_27001'],
                       help='Check specific compliance framework')
    parser.add_argument('--output-format', choices=['table', 'json', 'markdown'],
                       default='table', help='Output format')
    parser.add_argument('--output-file', help='Save report to file')
    parser.add_argument('--config', default='configs/audit_config.yaml',
                       help='Audit configuration file')
    
    args = parser.parse_args()
    
    # Initialize auditor
    auditor = SecurityAuditor(args.config)
    
    # Run audit
    if args.full:
        report = asyncio.run(auditor.run_full_audit())
    elif args.service:
        findings = asyncio.run(auditor.audit_service(args.service))
        report = auditor._generate_report()
    else:
        parser.print_help()
        return
    
    # Output report
    if args.output_file:
        with open(args.output_file, 'w') as f:
            if args.output_format == 'json':
                json.dump(report.__dict__, f, default=str, indent=2)
            else:
                # Redirect stdout to file
                import contextlib
                with contextlib.redirect_stdout(f):
                    auditor.print_report(report, args.output_format)
        print(f"Report saved to {args.output_file}")
    else:
        auditor.print_report(report, args.output_format)
    
    # Exit with appropriate code
    if report.findings_by_severity.get(Severity.CRITICAL.value, 0) > 0:
        sys.exit(2)  # Critical findings
    elif report.findings_by_severity.get(Severity.HIGH.value, 0) > 0:
        sys.exit(1)  # High findings
    else:
        sys.exit(0)  # Success

if __name__ == '__main__':
    main()
