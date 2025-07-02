#!/usr/bin/env python3
"""
E-Gov Guardian Security Scanner
Production-grade security scanner for web applications and source code
Author: E-Gov Guardian Team
Version: 2.0.0
"""

import os
import sys
import json
import yaml
import logging
import argparse
import urllib3
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from .zap_client import ZAPClient
from .vulnerability_detector import VulnerabilityDetector
from .report_generator import ReportGenerator
from .builtin_scanner import BuiltinAPIScanner
from .ai_advisor import AIFixAdvisor

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityScanner:
    """Production-grade security scanner for comprehensive vulnerability assessment"""
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self._setup_logging()
        self.logger = logging.getLogger(__name__)
        
        # Initialize components based on configuration
        self.zap_enabled = self.config.get('zap', {}).get('enabled', False)
        
        if self.zap_enabled:
            self.zap_client = ZAPClient(
                host=self.config['zap']['host'],
                port=self.config['zap']['port'],
                api_key=self.config['zap'].get('api_key')
            )
        else:
            self.zap_client = None
            
        # Always initialize built-in scanner and vulnerability detector
        self.builtin_scanner = BuiltinAPIScanner()
        self.vuln_detector = VulnerabilityDetector()
        self.report_generator = ReportGenerator()
        
        # Initialize AI advisor if API key is available (always try to initialize)
        self.ai_enabled = self.config.get('ai_analysis', {}).get('enabled', False)
        
        # Try to get OpenAI API key from environment variable first, then config file
        import os
        openai_api_key = (
            os.getenv('OPENAI_API_KEY') or 
            os.getenv('OPENAI_API_KEY_EGOV') or
            self.config.get('ai_analysis', {}).get('openai_api_key')
        )
        
        if openai_api_key and openai_api_key != "YOUR_OPENAI_API_KEY_HERE":
            try:
                self.ai_advisor = AIFixAdvisor(
                    api_key=openai_api_key,
                    model=self.config.get('ai_analysis', {}).get('model', 'gpt-4o-mini'),
                    max_tokens=self.config.get('ai_analysis', {}).get('max_tokens', 150),
                    temperature=self.config.get('ai_analysis', {}).get('temperature', 0.1)
                )
                api_source = "environment variable" if os.getenv('OPENAI_API_KEY') or os.getenv('OPENAI_API_KEY_EGOV') else "config file"
                self.logger.info(f"🧠 AI advisor initialized successfully (API key from {api_source})")
            except Exception as e:
                self.logger.warning(f"Failed to initialize AI advisor: {str(e)}")
                self.ai_advisor = None
        else:
            self.ai_advisor = None
            self.logger.info("No OpenAI API key found - AI analysis disabled")
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.error(f"Configuration file not found: {config_path}")
            # Use default configuration
            return self._get_default_config()
        except yaml.YAMLError as e:
            self.logger.error(f"Error parsing configuration file: {e}")
            sys.exit(1)
    
    def _get_default_config(self):
        """Return default configuration if config file is missing"""
        return {
            'zap': {'enabled': False, 'host': '127.0.0.1', 'port': 8080, 'api_key': None},
            'alternative_scanners': {'enabled': True, 'use_builtin_checks': True},
            'scanner': {'max_scan_time': 1800, 'max_depth': 5, 'thread_count': 10},
            'vulnerabilities': {
                'sql_injection': {'enabled': True, 'severity_threshold': 'Medium'},
                'xss': {'enabled': True, 'severity_threshold': 'Medium'},
                'insecure_headers': {'enabled': True},
                'insecure_cookies': {'enabled': True},
                'port_scan': {'enabled': True, 'common_ports': [80, 443, 22, 21, 25, 53, 110, 993, 995, 8080, 8443]},
                'malware_check': {'enabled': True}
            },
            'reporting': {'output_format': 'json', 'detailed_report': True}
        }
    
    def _setup_logging(self):
        """Setup logging configuration"""
        log_level = logging.INFO
        if self.config.get('debug', False):
            log_level = logging.DEBUG
            
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler()  # Console-only logging for in-memory operation
            ]
        )
    
    def scan_url(self, target_url: str, deep_scan: bool = False) -> Dict[str, Any]:
        """Perform comprehensive security scan on a URL"""
        self.logger.info(f"Starting security assessment for: {target_url}")
        
        scan_results = {
            'target': target_url,
            'scan_type': 'web_application',
            'timestamp': datetime.now().isoformat(),
            'scanner_version': '2.0.0',
            'scan_config': {
                'zap_enabled': self.zap_enabled,
                'deep_scan': deep_scan,
                'max_depth': self.config['scanner']['max_depth']
            },
            'results': {}
        }
        
        try:
            # Validate URL first
            if not self._validate_url(target_url):
                raise ValueError(f"Invalid URL format: {target_url}")
            
            self.logger.info("Phase 1: Reconnaissance and Discovery")
            
            # 1. ZAP comprehensive scan (if enabled and available)
            if self.zap_enabled and self.zap_client:
                if self.zap_client.is_zap_running():
                    self.logger.info("Running OWASP ZAP professional scan...")
                    scan_config = self.config['scanner'].copy()
                    if deep_scan:
                        scan_config['max_depth'] = 10
                        scan_config['timeout'] = 3600  # 1 hour for deep scan
                    
                    zap_results = self.zap_client.scan_url(target_url, scan_config)
                    scan_results['results']['zap_scan'] = zap_results
                else:
                    self.logger.warning("ZAP enabled but not accessible. Continuing with built-in scanner.")
            
            # 2. Built-in comprehensive vulnerability scan
            self.logger.info("Phase 2: Active Vulnerability Assessment")
            if self.config.get('alternative_scanners', {}).get('enabled', True):
                scan_config = self.config['scanner'].copy()
                if deep_scan:
                    scan_config['max_depth'] = 8
                    
                builtin_results = self.builtin_scanner.scan_url(target_url, scan_config)
                scan_results['results']['vulnerability_scan'] = builtin_results
            
            # 3. Security configuration analysis
            self.logger.info("Phase 3: Security Configuration Analysis")
            
            # Security headers assessment
            if self.config['vulnerabilities']['insecure_headers']['enabled']:
                headers_result = self.vuln_detector.check_insecure_headers(target_url)
                scan_results['results']['security_headers'] = headers_result
            
            # Cookie security analysis
            if self.config['vulnerabilities']['insecure_cookies']['enabled']:
                cookies_result = self.vuln_detector.check_insecure_cookies(target_url)
                scan_results['results']['cookie_security'] = cookies_result
            
            # SSL/TLS security assessment
            from urllib.parse import urlparse
            parsed_url = urlparse(target_url)
            if parsed_url.scheme == 'https':
                self.logger.info("Analyzing SSL/TLS configuration...")
                ssl_result = self.vuln_detector.check_ssl_configuration(parsed_url.hostname)
                scan_results['results']['ssl_configuration'] = ssl_result
            
            # 4. Infrastructure assessment
            if self.config['vulnerabilities']['port_scan']['enabled']:
                self.logger.info("Phase 4: Infrastructure Assessment")
                try:
                    port_result = self.vuln_detector.scan_open_ports(
                        parsed_url.hostname, 
                        self.config['vulnerabilities']['port_scan']['common_ports']
                    )
                    scan_results['results']['infrastructure'] = port_result
                except Exception as e:
                    self.logger.warning(f"Port scan failed: {str(e)}")
                    scan_results['results']['infrastructure'] = {'error': 'Port scan requires elevated privileges'}
            
            # 5. AI-powered vulnerability analysis (if enabled)
            if self.ai_enabled and self.ai_advisor:
                self.logger.info("Phase 5: AI-Powered Vulnerability Analysis")
                scan_results = self.ai_advisor.analyze_vulnerabilities(scan_results)
                scan_results['ai_analysis_enabled'] = True
            else:
                scan_results['ai_analysis_enabled'] = False
            
            # 6. Generate comprehensive analysis
            self.logger.info("Phase 6: Final Analysis and Risk Assessment")
            scan_results['summary'] = self._generate_comprehensive_summary(scan_results['results'])
            scan_results['risk_rating'] = self._calculate_risk_rating(scan_results['summary'])
            scan_results['recommendations'] = self._generate_recommendations(scan_results['results'])
            
            scan_results['status'] = 'completed'
            scan_results['scan_duration'] = self._calculate_duration(scan_results['timestamp'])
            
        except Exception as e:
            self.logger.error(f"Security scan failed: {str(e)}")
            scan_results['status'] = 'failed'
            scan_results['error'] = str(e)
            scan_results['scan_duration'] = self._calculate_duration(scan_results['timestamp'])
        
        return scan_results
    
    def scan_source_code(self, source_path: str) -> Dict[str, Any]:
        """Perform comprehensive security scan on source code"""
        self.logger.info(f"Starting source code security assessment: {source_path}")
        
        scan_results = {
            'target': source_path,
            'scan_type': 'source_code_analysis',
            'timestamp': datetime.now().isoformat(),
            'scanner_version': '2.0.0',
            'results': {}
        }
        
        try:
            if not os.path.exists(source_path):
                raise ValueError(f"Source path does not exist: {source_path}")
            
            # 1. Dependency vulnerability analysis
            self.logger.info("Analyzing dependencies for known vulnerabilities...")
            libs_result = self.vuln_detector.check_outdated_libraries(source_path)
            scan_results['results']['dependency_analysis'] = libs_result
            
            # 2. Static code analysis for security patterns
            self.logger.info("Performing static code security analysis...")
            pattern_results = self._comprehensive_code_analysis(source_path)
            scan_results['results']['static_analysis'] = pattern_results
            
            # 3. Malware and suspicious file detection
            if self.config['vulnerabilities']['malware_check']['enabled']:
                self.logger.info("Scanning for malicious files and patterns...")
                malware_results = self._comprehensive_malware_scan(source_path)
                scan_results['results']['malware_analysis'] = malware_results
            
            # 4. Configuration file security analysis
            self.logger.info("Analyzing configuration files...")
            config_results = self._analyze_config_files(source_path)
            scan_results['results']['configuration_analysis'] = config_results
            
            scan_results['summary'] = self._generate_comprehensive_summary(scan_results['results'])
            scan_results['risk_rating'] = self._calculate_risk_rating(scan_results['summary'])
            scan_results['recommendations'] = self._generate_recommendations(scan_results['results'])
            scan_results['status'] = 'completed'
            
        except Exception as e:
            self.logger.error(f"Source code analysis failed: {str(e)}")
            scan_results['status'] = 'failed'
            scan_results['error'] = str(e)
        
        return scan_results
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format and accessibility"""
        from urllib.parse import urlparse
        import requests
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False
                
            # Quick connectivity test
            response = requests.head(url, timeout=10, allow_redirects=True)
            return True
            
        except Exception:
            return False
    
    def _comprehensive_code_analysis(self, source_path: str) -> Dict[str, Any]:
        """Enhanced static code analysis with comprehensive security patterns"""
        
        security_patterns = {
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'SELECT.*\+.*(?:request|input|user)',
                r'WHERE.*\+.*(?:request|input|user)',
                r'cursor\.execute\s*\([^)]*%[^)]*\)',
                r'query\s*=.*\+.*(?:request|input|user)'
            ],
            'xss': [
                r'innerHTML\s*=.*(?:request|input|user)',
                r'document\.write\s*\(.*(?:request|input|user)',
                r'eval\s*\(.*(?:request|input|user)',
                r'dangerouslySetInnerHTML.*(?:request|input|user)',
                r'v-html.*(?:request|input|user)'
            ],
            'command_injection': [
                r'exec\s*\(.*(?:request|input|user)',
                r'system\s*\(.*(?:request|input|user)',
                r'shell_exec\s*\(.*(?:request|input|user)',
                r'subprocess\..*(?:request|input|user)',
                r'os\.system.*(?:request|input|user)'
            ],
            'hardcoded_secrets': [
                r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{8,}["\']',
                r'(?:api_key|apikey|api-key)\s*=\s*["\'][^"\']{16,}["\']',
                r'(?:secret|secret_key)\s*=\s*["\'][^"\']{16,}["\']',
                r'(?:token|access_token)\s*=\s*["\'][^"\']{20,}["\']',
                r'(?:private_key|privatekey)\s*=\s*["\'][^"\']{50,}["\']'
            ],
            'file_inclusion': [
                r'include\s*\(.*(?:request|input|user)',
                r'require\s*\(.*(?:request|input|user)',
                r'file_get_contents\s*\(.*(?:request|input|user)',
                r'readfile\s*\(.*(?:request|input|user)'
            ],
            'insecure_crypto': [
                r'md5\s*\(',
                r'sha1\s*\(',
                r'DES\s*\(',
                r'RC4\s*\(',
                r'ECB\s*mode'
            ]
        }
        
        findings = {
            'sql_injection': [],
            'xss_vulnerabilities': [],
            'command_injection': [],
            'hardcoded_secrets': [],
            'file_inclusion': [],
            'insecure_crypto': [],
            'total_critical': 0,
            'total_high': 0,
            'total_medium': 0,
            'files_analyzed': 0
        }
        
        import re
        
        code_extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', '.cs', '.rb', '.go', '.cpp', '.c']
        
        for root, dirs, files in os.walk(source_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.vscode', 'vendor']]
            
            for file in files:
                if any(file.endswith(ext) for ext in code_extensions):
                    file_path = os.path.join(root, file)
                    findings['files_analyzed'] += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for vuln_type, patterns in security_patterns.items():
                                for pattern in patterns:
                                    matches = re.finditer(pattern, content, re.IGNORECASE)
                                    for match in matches:
                                        line_num = content[:match.start()].count('\n') + 1
                                        
                                        severity = self._determine_severity(vuln_type, match.group())
                                        
                                        finding = {
                                            'file': os.path.relpath(file_path, source_path),
                                            'line': line_num,
                                            'pattern': pattern,
                                            'match': match.group()[:100] + "..." if len(match.group()) > 100 else match.group(),
                                            'severity': severity,
                                            'description': self._get_vulnerability_description(vuln_type)
                                        }
                                        
                                        findings[vuln_type].append(finding)
                                        
                                        # Count by severity
                                        if severity == 'Critical':
                                            findings['total_critical'] += 1
                                        elif severity == 'High':
                                            findings['total_high'] += 1
                                        else:
                                            findings['total_medium'] += 1
                                        
                    except Exception as e:
                        self.logger.warning(f"Could not analyze file {file_path}: {str(e)}")
        
        findings['total_issues'] = findings['total_critical'] + findings['total_high'] + findings['total_medium']
        
        return findings
    
    def _comprehensive_malware_scan(self, source_path: str) -> Dict[str, Any]:
        """Enhanced malware detection with multiple indicators"""
        malware_results = {
            'suspicious_files': [],
            'suspicious_patterns': [],
            'total_files_scanned': 0,
            'risk_level': 'Low'
        }
        
        suspicious_extensions = ['.exe', '.dll', '.bat', '.cmd', '.scr', '.pif', '.com', '.vbs', '.ps1']
        suspicious_patterns = [
            b'CreateRemoteThread',
            b'VirtualAlloc',
            b'WriteProcessMemory',
            b'GetProcAddress',
            b'LoadLibrary',
            b'WinExec',
            b'ShellExecute',
            b'encrypt',
            b'decrypt',
            b'ransom',
            b'bitcoin',
            b'cryptocurrency',
            b'payload',
            b'backdoor',
            b'rootkit'
        ]
        
        for root, dirs, files in os.walk(source_path):
            for file in files:
                file_path = os.path.join(root, file)
                malware_results['total_files_scanned'] += 1
                
                # Check file extension
                _, ext = os.path.splitext(file)
                if ext.lower() in suspicious_extensions:
                    malware_check = self.vuln_detector.basic_malware_check(file_path)
                    if malware_check.get('suspicious_indicators'):
                        malware_results['suspicious_files'].append(malware_check)
                        malware_results['risk_level'] = 'High'
                
                # Check file content for suspicious patterns
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read(1024 * 1024)  # Read first 1MB
                        
                        for pattern in suspicious_patterns:
                            if pattern in content.lower():
                                malware_results['suspicious_patterns'].append({
                                    'file': os.path.relpath(file_path, source_path),
                                    'pattern': pattern.decode(),
                                    'risk': 'Medium'
                                })
                                
                except Exception:
                    continue  # Skip files that can't be read
        
        return malware_results
    
    def _analyze_config_files(self, source_path: str) -> Dict[str, Any]:
        """Analyze configuration files for security issues"""
        config_results = {
            'insecure_configurations': [],
            'exposed_secrets': [],
            'total_config_files': 0
        }
        
        config_files = ['.env', 'config.yaml', 'config.json', 'settings.py', 'web.config', 'application.properties']
        
        for root, dirs, files in os.walk(source_path):
            for file in files:
                if any(file.endswith(cf) or file == cf for cf in config_files):
                    file_path = os.path.join(root, file)
                    config_results['total_config_files'] += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            # Check for exposed secrets
                            secret_patterns = [
                                r'(?i)password\s*[:=]\s*["\']?[^"\'\s]{8,}',
                                r'(?i)api[_-]?key\s*[:=]\s*["\']?[^"\'\s]{16,}',
                                r'(?i)secret\s*[:=]\s*["\']?[^"\'\s]{16,}',
                                r'(?i)token\s*[:=]\s*["\']?[^"\'\s]{20,}'
                            ]
                            
                            for pattern in secret_patterns:
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    config_results['exposed_secrets'].append({
                                        'file': os.path.relpath(file_path, source_path),
                                        'line': content[:match.start()].count('\n') + 1,
                                        'type': 'Exposed Secret',
                                        'severity': 'High'
                                    })
                            
                            # Check for insecure configurations
                            if 'debug=true' in content.lower() or 'debug: true' in content.lower():
                                config_results['insecure_configurations'].append({
                                    'file': os.path.relpath(file_path, source_path),
                                    'issue': 'Debug mode enabled',
                                    'severity': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.warning(f"Could not analyze config file {file_path}: {str(e)}")
        
        return config_results
    
    def _determine_severity(self, vuln_type: str, match_content: str) -> str:
        """Determine severity based on vulnerability type and context"""
        critical_types = ['sql_injection', 'command_injection']
        high_types = ['xss_vulnerabilities', 'file_inclusion', 'hardcoded_secrets']
        
        if vuln_type in critical_types:
            return 'Critical'
        elif vuln_type in high_types:
            return 'High'
        else:
            return 'Medium'
    
    def _get_vulnerability_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'sql_injection': 'SQL injection vulnerability allows attackers to manipulate database queries',
            'xss': 'Cross-site scripting vulnerability allows injection of malicious scripts',
            'command_injection': 'Command injection allows execution of arbitrary system commands',
            'hardcoded_secrets': 'Hardcoded credentials pose security risk if source code is exposed',
            'file_inclusion': 'File inclusion vulnerability allows unauthorized file access',
            'insecure_crypto': 'Use of weak cryptographic algorithms compromises data security'
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected')
    
    def _generate_comprehensive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive summary with detailed metrics"""
        summary = {
            'total_vulnerabilities': 0,
            'critical_issues': 0,
            'high_risk_issues': 0,
            'medium_risk_issues': 0,
            'low_risk_issues': 0,
            'categories': {},
            'compliance_score': 0,
            'security_posture': 'Unknown'
        }
        
        # Count vulnerabilities from all sources
        for source, data in results.items():
            if source == 'zap_scan' and 'vulnerabilities' in data:
                zap_vulns = data['vulnerabilities'].get('all_alerts', [])
                for alert in zap_vulns:
                    risk = alert.get('risk', '').lower()
                    summary['total_vulnerabilities'] += 1
                    
                    if risk == 'high':
                        summary['high_risk_issues'] += 1
                    elif risk == 'medium':
                        summary['medium_risk_issues'] += 1
                    else:
                        summary['low_risk_issues'] += 1
            
            elif source == 'vulnerability_scan' and 'vulnerabilities' in data:
                for vuln_type, vuln_list in data['vulnerabilities'].items():
                    if isinstance(vuln_list, list):
                        for vuln in vuln_list:
                            risk = vuln.get('risk', '').lower()
                            summary['total_vulnerabilities'] += 1
                            
                            if risk == 'high':
                                summary['high_risk_issues'] += 1
                            elif risk == 'medium':
                                summary['medium_risk_issues'] += 1
                            else:
                                summary['low_risk_issues'] += 1
            
            elif source == 'static_analysis':
                summary['critical_issues'] += data.get('total_critical', 0)
                summary['high_risk_issues'] += data.get('total_high', 0)
                summary['medium_risk_issues'] += data.get('total_medium', 0)
                summary['total_vulnerabilities'] += data.get('total_issues', 0)
        
        # Add infrastructure and configuration issues
        for category in ['security_headers', 'cookie_security', 'ssl_configuration', 'infrastructure']:
            if category in results:
                issues = results[category].get('total_missing', 0) or results[category].get('total_issues', 0)
                summary['medium_risk_issues'] += issues
                summary['total_vulnerabilities'] += issues
                summary['categories'][category] = issues
        
        # Calculate compliance score (0-100)
        max_score = 100
        deductions = (summary['critical_issues'] * 25) + (summary['high_risk_issues'] * 10) + (summary['medium_risk_issues'] * 5) + (summary['low_risk_issues'] * 2)
        summary['compliance_score'] = max(0, max_score - deductions)
        
        # Determine security posture
        if summary['compliance_score'] >= 90:
            summary['security_posture'] = 'Excellent'
        elif summary['compliance_score'] >= 75:
            summary['security_posture'] = 'Good'
        elif summary['compliance_score'] >= 50:
            summary['security_posture'] = 'Fair'
        else:
            summary['security_posture'] = 'Poor'
        
        return summary
    
    def _calculate_risk_rating(self, summary: Dict[str, Any]) -> str:
        """Calculate overall risk rating"""
        if summary['critical_issues'] > 0:
            return 'CRITICAL'
        elif summary['high_risk_issues'] > 5:
            return 'HIGH'
        elif summary['high_risk_issues'] > 0 or summary['medium_risk_issues'] > 10:
            return 'MEDIUM'
        elif summary['medium_risk_issues'] > 0:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        
        # Check for common issues and provide recommendations
        if 'security_headers' in results and results['security_headers'].get('total_missing', 0) > 0:
            recommendations.append("Implement missing security headers (CSP, HSTS, X-Frame-Options, etc.)")
        
        if 'ssl_configuration' in results and results['ssl_configuration'].get('total_issues', 0) > 0:
            recommendations.append("Update SSL/TLS configuration to use secure protocols and strong ciphers")
        
        if 'static_analysis' in results:
            static = results['static_analysis']
            if static.get('total_critical', 0) > 0:
                recommendations.append("Address critical code vulnerabilities (SQL injection, command injection)")
            if len(static.get('hardcoded_secrets', [])) > 0:
                recommendations.append("Remove hardcoded secrets and use secure configuration management")
        
        if 'vulnerability_scan' in results:
            vuln_scan = results['vulnerability_scan']
            if vuln_scan.get('vulnerabilities', {}).get('sql_injection'):
                recommendations.append("Implement parameterized queries to prevent SQL injection")
            if vuln_scan.get('vulnerabilities', {}).get('xss'):
                recommendations.append("Implement proper input validation and output encoding")
        
        if 'infrastructure' in results and len(results['infrastructure'].get('high_risk_ports', [])) > 0:
            recommendations.append("Close unnecessary open ports and secure exposed services")
        
        # Add general recommendations
        recommendations.extend([
            "Conduct regular security assessments and penetration testing",
            "Implement Web Application Firewall (WAF) for additional protection",
            "Establish security monitoring and incident response procedures",
            "Train development team on secure coding practices"
        ])
        
        return recommendations
    
    def _calculate_duration(self, start_time: str) -> str:
        """Calculate scan duration"""
        start = datetime.fromisoformat(start_time)
        end = datetime.now()
        duration = end - start
        return str(duration).split('.')[0]  # Remove microseconds
    
    def generate_report(self, scan_results: Dict[str, Any], output_path: str = None) -> str:
        """Generate comprehensive security report"""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_type = scan_results.get('scan_type', 'security')
            output_format = self.config['reporting']['output_format']
            output_path = f"egov_security_report_{scan_type}_{timestamp}.{output_format}"
        
        return self.report_generator.generate(
            scan_results, 
            output_path, 
            self.config['reporting']
        )

def main():
    """Production CLI entry point"""
    parser = argparse.ArgumentParser(
        description="E-Gov Guardian Security Scanner - Production Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target https://example.com --type url
  %(prog)s --target https://example.com --type url --deep
  %(prog)s --target /path/to/source --type source
  %(prog)s --target https://example.com --output security_report.html
        """
    )
    
    parser.add_argument("--target", "-t", required=True, 
                       help="Target URL or source code path for security assessment")
    parser.add_argument("--type", "-T", choices=["url", "source"], default="url", 
                       help="Assessment type: url (web application) or source (source code)")
    parser.add_argument("--config", "-c", default="config.yaml", 
                       help="Configuration file path (default: config.yaml)")
    parser.add_argument("--output", "-o", 
                       help="Output report file path (auto-generated if not specified)")
    parser.add_argument("--deep", action="store_true", 
                       help="Perform deep scan with extended coverage (longer duration)")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose logging output")
    parser.add_argument("--no-zap", action="store_true", 
                       help="Disable ZAP integration (use built-in scanner only)")
    parser.add_argument("--format", choices=["json", "html", "csv"], default="json",
                       help="Report output format (default: json)")
    
    args = parser.parse_args()
    
    try:
        # Initialize scanner
        scanner = SecurityScanner(args.config)
        
        if args.verbose:
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Override ZAP setting if --no-zap flag is used
        if args.no_zap:
            scanner.zap_enabled = False
            scanner.zap_client = None
        
        # Override output format if specified
        scanner.config['reporting']['output_format'] = args.format
        
        print(f"\n🛡️ E-Gov Guardian Security Scanner v2.0")
        print(f"{'='*60}")
        print(f"Target: {args.target}")
        print(f"Assessment Type: {args.type.upper()}")
        print(f"Deep Scan: {'Yes' if args.deep else 'No'}")
        print(f"{'='*60}")
        
        # Perform security assessment
        if args.type == "url":
            results = scanner.scan_url(args.target, deep_scan=args.deep)
        else:
            results = scanner.scan_source_code(args.target)
        
        # Generate comprehensive report
        report_path = scanner.generate_report(results, args.output)
        
        # Display results summary
        print(f"\n📊 SECURITY ASSESSMENT RESULTS")
        print(f"{'='*40}")
        print(f"Status: {results.get('status', 'unknown').upper()}")
        
        if 'summary' in results:
            summary = results['summary']
            print(f"Risk Rating: {results.get('risk_rating', 'UNKNOWN')}")
            print(f"Compliance Score: {summary.get('compliance_score', 0)}/100")
            print(f"Security Posture: {summary.get('security_posture', 'Unknown')}")
            print(f"\nVulnerability Breakdown:")
            print(f"  🔴 Critical: {summary.get('critical_issues', 0)}")
            print(f"  🟠 High: {summary.get('high_risk_issues', 0)}")
            print(f"  🟡 Medium: {summary.get('medium_risk_issues', 0)}")
            print(f"  🟢 Low: {summary.get('low_risk_issues', 0)}")
            print(f"  📊 Total: {summary.get('total_vulnerabilities', 0)}")
        
        if 'scan_duration' in results:
            print(f"\nScan Duration: {results['scan_duration']}")
        
        print(f"\n📄 Detailed Report: {report_path}")
        
        if results.get('status') == 'failed':
            print(f"\n❌ Assessment failed: {results.get('error', 'Unknown error')}")
            sys.exit(1)
        elif results.get('risk_rating') in ['CRITICAL', 'HIGH']:
            print(f"\n⚠️  Critical security issues detected - immediate action required")
            sys.exit(2)
        
    except KeyboardInterrupt:
        print("\n⏹️ Assessment interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 