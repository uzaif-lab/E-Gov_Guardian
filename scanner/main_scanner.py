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
from uuid import uuid4
import time

from .zap_client import ZAPClient
from .vulnerability_detector import VulnerabilityDetector
from .report_generator import ReportGenerator
from .builtin_scanner import BuiltinAPIScanner
from .ai_advisor import AIFixAdvisor
from .advanced_tests import AdvancedSecurityTests

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
        self.advanced_tests = AdvancedSecurityTests()
        
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
    
    def scan_url(self, target_url: str, deep_scan: bool = False, selected_tests: Dict[str, bool] = None) -> Dict[str, Any]:
        """Perform comprehensive security scan on a URL with selective test execution"""
        self.logger.info(f"Starting security assessment for: {target_url}")
        
        # Generate a scan ID
        scan_id = str(uuid4())
        self._update_scan_progress(scan_id, 0)
        
        # If no tests selected, enable all tests
        if selected_tests is None or not any(selected_tests.values()):
            selected_tests = {
                'sql_injection': True,
                'xss': True,
                'csrf': True,
                'headers': True,
                'cors': True,
                'open_redirect': True,
                'host_header': True,
                'api_fuzzing': True,
                'subresource_integrity': True,
                'graphql': True
            }
        
        scan_results = {
            'target': target_url,
            'scan_type': 'web_application',
            'timestamp': datetime.now().isoformat(),
            'scanner_version': '2.0.0',
            'scan_config': {
                'zap_enabled': self.zap_enabled,
                'deep_scan': deep_scan,
                'max_depth': self.config['scanner']['max_depth'],
                'selected_tests': selected_tests
            },
            'results': {},
            'scan_id': scan_id
        }
        
        try:
            # Validate URL first
            if not self._validate_url(target_url):
                raise ValueError(f"Invalid URL format: {target_url}")
            
            # Phase 1: Initial Setup and Configuration (0-10%)
            self.logger.info("Phase 1: Reconnaissance and Discovery")
            self._update_scan_progress(scan_id, 10)
            
            # Phase 2: ZAP Scan if enabled (10-30%)
            if self.zap_enabled and self.zap_client:
                if self.zap_client.is_zap_running():
                    self.logger.info("Running OWASP ZAP professional scan...")
                    scan_config = self.config['scanner'].copy()
                    if deep_scan:
                        scan_config['max_depth'] = 10
                        scan_config['timeout'] = 3600  # 1 hour for deep scan
                    
                    zap_results = self.zap_client.scan_url(target_url, scan_config)
                    scan_results['results']['zap_scan'] = zap_results
                    self._update_scan_progress(scan_id, 30)
                else:
                    self.logger.warning("ZAP enabled but not accessible. Continuing with built-in scanner.")
            
            # Phase 3: Built-in Vulnerability Scan (30-50%)
            self.logger.info("Phase 2: Active Vulnerability Assessment")
            if self.config.get('alternative_scanners', {}).get('enabled', True):
                scan_config = self.config['scanner'].copy()
                if deep_scan:
                    scan_config['max_depth'] = 8
                    
                builtin_results = self.builtin_scanner.scan_url(target_url, scan_config, selected_tests)
                scan_results['results']['vulnerability_scan'] = builtin_results
                self._update_scan_progress(scan_id, 50)
            
            # Phase 4: Security Headers and Cookie Analysis (50-70%)
            self.logger.info("Phase 3: Security Configuration Analysis")
            
            # Security headers assessment (if selected)
            if selected_tests.get('headers', False) and self.config['vulnerabilities']['insecure_headers']['enabled']:
                self.logger.info("Running security headers tests...")
                headers_result = self.vuln_detector.check_insecure_headers(target_url)
                scan_results['results']['security_headers'] = headers_result
            
            # Cookie security analysis
            if self.config['vulnerabilities']['insecure_cookies']['enabled']:
                cookies_result = self.vuln_detector.check_insecure_cookies(target_url)
                scan_results['results']['cookie_security'] = cookies_result
            
            self._update_scan_progress(scan_id, 70)
            
            # Phase 5: Advanced Security Tests (70-90%)
            self.logger.info("Phase 3.5: Advanced Security Tests")
            advanced_results = {'vulnerabilities': []}
            
            total_tests = sum(1 for test in selected_tests.values() if test)
            completed_tests = 0
            
            # CORS Policy Testing
            if selected_tests.get('cors', False):
                self.logger.info("Running CORS policy tests...")
                cors_vulns = self.advanced_tests.test_cors_policy(target_url)
                advanced_results['vulnerabilities'].extend(cors_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            # CSRF Protection Testing
            if selected_tests.get('csrf', False):
                self.logger.info("Running CSRF protection tests...")
                csrf_vulns = self.advanced_tests.test_csrf_protection(target_url)
                advanced_results['vulnerabilities'].extend(csrf_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            # Open Redirect Testing
            if selected_tests.get('open_redirect', False):
                self.logger.info("Running open redirect tests...")
                redirect_vulns = self.advanced_tests.test_open_redirects(target_url)
                advanced_results['vulnerabilities'].extend(redirect_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            # Host Header Injection Testing
            if selected_tests.get('host_header', False):
                self.logger.info("Running host header injection tests...")
                host_header_vulns = self.advanced_tests.test_host_header_injection(target_url)
                advanced_results['vulnerabilities'].extend(host_header_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            # API Endpoint Fuzzing
            if selected_tests.get('api_fuzzing', False):
                self.logger.info("Running API endpoint fuzzing...")
                api_vulns = self.advanced_tests.test_api_endpoint_fuzzing(target_url)
                advanced_results['vulnerabilities'].extend(api_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            # Subresource Integrity Testing
            if selected_tests.get('subresource_integrity', False):
                self.logger.info("Running subresource integrity tests...")
                sri_vulns = self.advanced_tests.test_subresource_integrity(target_url)
                advanced_results['vulnerabilities'].extend(sri_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            # GraphQL Security Testing
            if selected_tests.get('graphql', False):
                self.logger.info("Running GraphQL security tests...")
                graphql_vulns = self.advanced_tests.test_graphql_security(target_url)
                advanced_results['vulnerabilities'].extend(graphql_vulns)
                completed_tests += 1
                self._update_scan_progress(scan_id, 70 + int((completed_tests / total_tests) * 20))
            
            scan_results['results']['advanced_tests'] = advanced_results
            
            # Phase 6: Final Analysis and Report Generation (90-100%)
            # Calculate risk rating
            risk_rating = self._calculate_risk_rating(scan_results)
            scan_results['risk_rating'] = risk_rating
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(scan_results)
            scan_results['compliance_score'] = compliance_score
            
            # Generate recommendations
            recommendations = self._generate_recommendations(scan_results)
            scan_results['recommendations'] = recommendations
            
            # Add AI analysis if enabled
            if self.ai_enabled and self.ai_advisor:
                self.logger.info("🧠 AI analysis enabled for this scan")
                try:
                    # Get AI recommendations for each vulnerability
                    for vuln in advanced_results['vulnerabilities']:
                        try:
                            ai_rec = self.ai_advisor._get_vulnerability_recommendation(
                                vuln_type=vuln['type'],
                                vulnerability=vuln
                            )
                            if ai_rec:
                                vuln['ai_recommendation'] = ai_rec
                        except Exception as e:
                            self.logger.warning(f"Failed to get AI recommendation for vulnerability: {str(e)}")
                    
                    # Get overall AI analysis
                    ai_analysis = self.ai_advisor.analyze_vulnerabilities(scan_results)
                    scan_results['ai_recommendations'] = ai_analysis.get('recommendations', [])
                    scan_results['ai_summary'] = ai_analysis.get('summary', '')
                    scan_results['ai_analysis_enabled'] = True
                    scan_results['ai_analysis_status'] = ai_analysis.get('ai_analysis_status', {})
                    
                    self.logger.info("✅ AI analysis completed successfully")
                except Exception as e:
                    self.logger.error(f"AI analysis failed: {str(e)}")
                    scan_results['ai_analysis_enabled'] = False
                    scan_results['ai_error'] = str(e)
            else:
                scan_results['ai_analysis_enabled'] = False
                if not self.ai_enabled:
                    self.logger.info("AI analysis not enabled in configuration")
                elif not self.ai_advisor:
                    self.logger.info("AI advisor not initialized (missing API key or initialization failed)")
            
            self._update_scan_progress(scan_id, 100)
            self.logger.info(f"Scanner.scan_url() completed for {target_url}")
            
            return scan_results
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            scan_results['error'] = str(e)
            scan_results['status'] = 'failed'
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
            scan_results['risk_rating'] = self._calculate_risk_rating(scan_results['results'])
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
        
        # Add advanced security test results
        if 'advanced_tests' in results:
            advanced_vulns = results['advanced_tests'].get('vulnerabilities', [])
            for vuln in advanced_vulns:
                severity = vuln.get('severity', '').lower()
                summary['total_vulnerabilities'] += 1
                
                if severity == 'critical':
                    summary['critical_issues'] += 1
                elif severity == 'high':
                    summary['high_risk_issues'] += 1
                elif severity == 'medium':
                    summary['medium_risk_issues'] += 1
                else:
                    summary['low_risk_issues'] += 1
        
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
    
    def _calculate_risk_rating(self, results: Dict[str, Any]) -> str:
        """Calculate overall risk rating based on vulnerability findings"""
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        # Get all vulnerabilities
        all_vulnerabilities = []
        
        # From ZAP scan
        if 'zap_scan' in results.get('results', {}):
            zap_vulns = results['results']['zap_scan'].get('vulnerabilities', {})
            if 'all_alerts' in zap_vulns:
                all_vulnerabilities.extend(zap_vulns['all_alerts'])
        
        # From built-in vulnerability scan
        if 'vulnerability_scan' in results.get('results', {}):
            vuln_scan = results['results']['vulnerability_scan']
            if 'vulnerabilities' in vuln_scan:
                for vuln_list in vuln_scan['vulnerabilities'].values():
                    if isinstance(vuln_list, list):
                        all_vulnerabilities.extend(vuln_list)
        
        # From security headers
        if 'security_headers' in results.get('results', {}):
            headers = results['results']['security_headers']
            if 'missing_headers' in headers:
                all_vulnerabilities.extend(headers['missing_headers'])
        
        # From advanced security tests
        if 'advanced_tests' in results.get('results', {}):
            advanced = results['results']['advanced_tests']
            if 'vulnerabilities' in advanced:
                all_vulnerabilities.extend(advanced['vulnerabilities'])
        
        # Count vulnerabilities by severity
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', vuln.get('risk', 'MEDIUM')).upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate weighted score
        weighted_score = (
            severity_counts['HIGH'] * 10 +    # High severity issues count 10x
            severity_counts['MEDIUM'] * 5 +   # Medium severity issues count 5x
            severity_counts['LOW'] * 1        # Low severity issues count 1x
        )
        
        # Log the calculation
        self.logger.info(f"Risk calculation: {severity_counts['HIGH']} High, {severity_counts['MEDIUM']} Medium, {severity_counts['LOW']} Low")
        self.logger.info(f"Weighted score: {weighted_score}")
        
        # Determine risk rating based on weighted score
        if weighted_score == 0:
            return "Low"
        elif weighted_score <= 10:
            return "Medium"
        elif weighted_score <= 30:
            return "High"
        else:
            return "Critical"
    
    def _calculate_compliance_score(self, results: Dict[str, Any]) -> int:
        """Calculate compliance score based on security findings"""
        base_score = 100
        deductions = 0
        
        # Get all vulnerabilities
        all_vulnerabilities = []
        
        # From ZAP scan
        if 'zap_scan' in results.get('results', {}):
            zap_vulns = results['results']['zap_scan'].get('vulnerabilities', {})
            if 'all_alerts' in zap_vulns:
                all_vulnerabilities.extend(zap_vulns['all_alerts'])
        
        # From built-in vulnerability scan
        if 'vulnerability_scan' in results.get('results', {}):
            vuln_scan = results['results']['vulnerability_scan']
            if 'vulnerabilities' in vuln_scan:
                for vuln_list in vuln_scan['vulnerabilities'].values():
                    if isinstance(vuln_list, list):
                        all_vulnerabilities.extend(vuln_list)
        
        # From security headers
        if 'security_headers' in results.get('results', {}):
            headers = results['results']['security_headers']
            if 'missing_headers' in headers:
                all_vulnerabilities.extend(headers['missing_headers'])
        
        # From advanced security tests
        if 'advanced_tests' in results.get('results', {}):
            advanced = results['results']['advanced_tests']
            if 'vulnerabilities' in advanced:
                all_vulnerabilities.extend(advanced['vulnerabilities'])
        
        # Calculate deductions based on severity
        for vuln in all_vulnerabilities:
            severity = vuln.get('severity', vuln.get('risk', 'MEDIUM')).upper()
            if severity == 'HIGH' or severity == 'CRITICAL':
                deductions += 15  # -15 points for each high/critical vulnerability
            elif severity == 'MEDIUM':
                deductions += 10  # -10 points for each medium vulnerability
            elif severity == 'LOW':
                deductions += 5   # -5 points for each low vulnerability
        
        # Ensure score doesn't go below 0
        final_score = max(0, base_score - deductions)
        
        # Log the calculation
        self.logger.info(f"Compliance score calculation: Base {base_score} - Deductions {deductions} = Final {final_score}")
        
        return final_score
    
    def _update_scan_progress(self, scan_id: str, progress: int):
        """Update scan progress in global storage"""
        from web_app import save_scan_status
        save_scan_status({
            scan_id: {
                'status': 'completed' if progress >= 100 else 'scanning',
                'progress': progress,
                'timestamp': time.time()
            }
        })
        self.logger.info(f"Updated scan progress: {progress}%")
    
    def get_scan_progress(self, scan_id: str) -> int:
        """Get current scan progress percentage"""
        return getattr(self, '_scan_progress', {}).get(scan_id, 0)
    
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
        
        # Add advanced security test recommendations
        if 'advanced_tests' in results:
            advanced_vulns = results['advanced_tests'].get('vulnerabilities', [])
            vuln_types = set(vuln.get('type', '') for vuln in advanced_vulns)
            
            if 'Permissive CORS Policy' in vuln_types or 'CORS Credentials Exposure' in vuln_types:
                recommendations.append("Configure CORS policy to restrict origins and disable credentials with wildcard")
            if 'Missing CSRF Protection' in vuln_types or 'Missing SameSite Cookie Attribute' in vuln_types:
                recommendations.append("Implement CSRF protection tokens and configure SameSite cookie attributes")
            if 'Open Redirect' in vuln_types:
                recommendations.append("Validate all redirect URLs against a whitelist of allowed destinations")
            if 'Host Header Injection' in vuln_types or 'Password Reset Poisoning' in vuln_types:
                recommendations.append("Validate Host header and use absolute URLs in password reset emails")
            if 'API Information Disclosure' in vuln_types or 'Exposed API Documentation' in vuln_types:
                recommendations.append("Secure API endpoints and restrict access to API documentation")
            if 'Missing Subresource Integrity' in vuln_types:
                recommendations.append("Add integrity attributes to all external scripts and stylesheets")
            if 'GraphQL Introspection Enabled' in vuln_types or 'GraphQL Query Depth Not Limited' in vuln_types:
                recommendations.append("Disable GraphQL introspection and implement query depth limiting")
        
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