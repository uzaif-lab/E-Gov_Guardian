"""
Built-in API-based Security Scanner
Alternative to ZAP for vulnerability detection without local installation
"""

import re
import requests
import time
import logging
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import json

class BuiltinAPIScanner:
    """API-based security scanner without ZAP dependency"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'E-Gov-Guardian-Scanner/1.0'
        })
        
    def scan_url(self, target_url: str, scan_config: Dict[str, Any], selected_tests: Dict[str, bool] = None) -> Dict[str, Any]:
        """Perform comprehensive API-based security scan with selective test execution"""
        results = {
            'target_url': target_url,
            'scan_start_time': time.time(),
            'vulnerabilities': {},
            'scan_status': 'started'
        }
        
        # If no tests selected, enable all core tests
        if selected_tests is None:
            selected_tests = {
                'sql_injection': True,
                'xss': True,
                'headers': True
            }
        
        try:
            self.logger.info(f"Starting built-in API scan for: {target_url}")
            
            # 1. Basic URL crawling and discovery (always needed for active tests)
            if selected_tests.get('sql_injection', False) or selected_tests.get('xss', False):
                discovered_urls = self._crawl_website(target_url, scan_config.get('max_depth', 3))
            else:
                discovered_urls = [target_url]  # Just the main URL for other tests
            
            # 2. SQL Injection testing (if selected)
            if selected_tests.get('sql_injection', False):
                self.logger.info("Running SQL injection tests...")
                sql_vulns = self._test_sql_injection(discovered_urls)
                results['vulnerabilities']['sql_injection'] = sql_vulns
            
            # 3. XSS testing (if selected)
            if selected_tests.get('xss', False):
                self.logger.info("Running XSS tests...")
                xss_vulns = self._test_xss(discovered_urls)
                results['vulnerabilities']['xss'] = xss_vulns
            
            # 4. Directory traversal testing (always run as core security test)
            traversal_vulns = self._test_directory_traversal(discovered_urls)
            results['vulnerabilities']['directory_traversal'] = traversal_vulns
            
            # 5. Command injection testing (always run as core security test)
            cmd_vulns = self._test_command_injection(discovered_urls)
            results['vulnerabilities']['command_injection'] = cmd_vulns
            
            # 6. HTTP method testing (always run as core security test)
            method_vulns = self._test_http_methods(target_url)
            results['vulnerabilities']['http_methods'] = method_vulns
            
            # 7. Information disclosure (always run as core security test)
            info_disclosure = self._test_information_disclosure(target_url)
            results['vulnerabilities']['information_disclosure'] = info_disclosure
            
            results['scan_status'] = 'completed'
            
        except Exception as e:
            self.logger.error(f"Built-in scan error: {str(e)}")
            results['scan_status'] = 'error'
            results['error'] = str(e)
            
        results['scan_end_time'] = time.time()
        results['scan_duration'] = results['scan_end_time'] - results['scan_start_time']
        
        return results
    
    def _crawl_website(self, base_url: str, max_depth: int = 3) -> List[str]:
        """Crawl website to discover URLs and forms"""
        discovered_urls = set([base_url])
        urls_to_crawl = [base_url]
        crawled_urls = set()
        
        depth = 0
        while urls_to_crawl and depth < max_depth:
            current_url = urls_to_crawl.pop(0)
            if current_url in crawled_urls:
                continue
                
            try:
                response = self.session.get(current_url, timeout=10, verify=False)
                crawled_urls.add(current_url)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    
                    # Find links
                    for link in soup.find_all('a', href=True):
                        url = urljoin(current_url, link['href'])
                        parsed = urlparse(url)
                        
                        # Only include URLs from same domain
                        if parsed.netloc == urlparse(base_url).netloc:
                            discovered_urls.add(url)
                            if url not in crawled_urls and len(urls_to_crawl) < 50:
                                urls_to_crawl.append(url)
                
            except Exception as e:
                self.logger.warning(f"Error crawling {current_url}: {str(e)}")
                
            depth += 1
            
        return list(discovered_urls)[:20]  # Limit to 20 URLs for testing
    
    def _test_sql_injection(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        # Common SQL injection payloads
        sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND 1=1--",
            "' AND 1=2--"
        ]
        
        # SQL error patterns
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL.*Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"SqlException",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*"
        ]
        
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                
                for param_name in query_params.keys():
                    for payload in sql_payloads:
                        try:
                            # Test GET parameter
                            test_params = query_params.copy()
                            test_params[param_name] = [payload]
                            
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                            response = self.session.get(test_url, params=test_params, timeout=10)
                            
                            # Check for SQL errors in response
                            for pattern in error_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerabilities.append({
                                        'url': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'type': 'SQL Injection',
                                        'risk': 'High',
                                        'evidence': f'SQL error pattern detected: {pattern}'
                                    })
                                    break
                                    
                        except Exception as e:
                            self.logger.debug(f"SQL injection test error: {str(e)}")
        
        return vulnerabilities
    
    def _test_xss(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>"
        ]
        
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                
                for param_name in query_params.keys():
                    for payload in xss_payloads:
                        try:
                            test_params = query_params.copy()
                            test_params[param_name] = [payload]
                            
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                            response = self.session.get(test_url, params=test_params, timeout=10)
                            
                            # Check if payload is reflected in response
                            if payload in response.text:
                                vulnerabilities.append({
                                    'url': url,
                                    'parameter': param_name,
                                    'payload': payload,
                                    'type': 'Cross-Site Scripting (XSS)',
                                    'risk': 'Medium',
                                    'evidence': 'Payload reflected in response'
                                })
                                
                        except Exception as e:
                            self.logger.debug(f"XSS test error: {str(e)}")
        
        return vulnerabilities
    
    def _test_directory_traversal(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        # Directory traversal payloads
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../windows/win.ini",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd"
        ]
        
        # Sensitive file patterns
        sensitive_patterns = [
            r"root:.*:0:0:",
            r"\[drivers\]",
            r"\[fonts\]",
            r"# Copyright.*Microsoft Corp"
        ]
        
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                
                for param_name in query_params.keys():
                    for payload in traversal_payloads:
                        try:
                            test_params = query_params.copy()
                            test_params[param_name] = [payload]
                            
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                            response = self.session.get(test_url, params=test_params, timeout=10)
                            
                            # Check for sensitive file content
                            for pattern in sensitive_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerabilities.append({
                                        'url': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'type': 'Directory Traversal',
                                        'risk': 'High',
                                        'evidence': f'Sensitive file content detected'
                                    })
                                    break
                                    
                        except Exception as e:
                            self.logger.debug(f"Directory traversal test error: {str(e)}")
        
        return vulnerabilities
    
    def _test_command_injection(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Test for command injection vulnerabilities"""
        vulnerabilities = []
        
        # Command injection payloads
        cmd_payloads = [
            "; ls -la",
            "| dir",
            "&& whoami",
            "; cat /etc/passwd",
            "| type C:\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        # Command output patterns
        cmd_patterns = [
            r"total \d+",
            r"Directory of",
            r"root:.*:0:0:",
            r"WINDOWS\\system32"
        ]
        
        for url in urls:
            parsed_url = urlparse(url)
            if parsed_url.query:
                query_params = parse_qs(parsed_url.query)
                
                for param_name in query_params.keys():
                    for payload in cmd_payloads:
                        try:
                            test_params = query_params.copy()
                            test_params[param_name] = [payload]
                            
                            test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                            response = self.session.get(test_url, params=test_params, timeout=10)
                            
                            # Check for command output
                            for pattern in cmd_patterns:
                                if re.search(pattern, response.text, re.IGNORECASE):
                                    vulnerabilities.append({
                                        'url': url,
                                        'parameter': param_name,
                                        'payload': payload,
                                        'type': 'Command Injection',
                                        'risk': 'High',
                                        'evidence': f'Command output detected'
                                    })
                                    break
                                    
                        except Exception as e:
                            self.logger.debug(f"Command injection test error: {str(e)}")
        
        return vulnerabilities
    
    def _test_http_methods(self, url: str) -> List[Dict[str, Any]]:
        """Test for dangerous HTTP methods"""
        vulnerabilities = []
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS', 'CONNECT']
        
        for method in dangerous_methods:
            try:
                response = self.session.request(method, url, timeout=10)
                
                if response.status_code not in [405, 501]:  # Method not allowed/not implemented
                    vulnerabilities.append({
                        'url': url,
                        'method': method,
                        'type': 'Dangerous HTTP Method',
                        'risk': 'Medium',
                        'evidence': f'HTTP {method} method allowed (Status: {response.status_code})'
                    })
                    
            except Exception as e:
                self.logger.debug(f"HTTP method test error: {str(e)}")
        
        return vulnerabilities
    
    def _test_information_disclosure(self, url: str) -> List[Dict[str, Any]]:
        """Test for information disclosure"""
        vulnerabilities = []
        
        # Common sensitive paths
        sensitive_paths = [
            "/robots.txt",
            "/.git/config",
            "/.env",
            "/config.php",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
            "/admin",
            "/backup",
            "/test"
        ]
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                response = self.session.get(test_url, timeout=10)
                
                if response.status_code == 200:
                    # Check for sensitive content
                    sensitive_content = [
                        "User-agent:",
                        "[core]",
                        "DB_PASSWORD",
                        "phpinfo()",
                        "Server Version:",
                        "admin panel",
                        "backup"
                    ]
                    
                    for content in sensitive_content:
                        if content.lower() in response.text.lower():
                            vulnerabilities.append({
                                'url': test_url,
                                'type': 'Information Disclosure',
                                'risk': 'Low',
                                'evidence': f'Sensitive file accessible: {path}'
                            })
                            break
                            
            except Exception as e:
                self.logger.debug(f"Information disclosure test error: {str(e)}")
        
        return vulnerabilities 