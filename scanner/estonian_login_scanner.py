"""
Estonian e-ID Login Page Security Scanner
Specialized security scanner for Estonian e-ID, Smart-ID, and Mobile-ID authentication pages
"""

import re
import requests
import ssl
import socket
import time
import logging
import json
import os
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin, parse_qs
from bs4 import BeautifulSoup
import hashlib
import subprocess
from datetime import datetime

class EstonianLoginScanner:
    """Specialized security scanner for Estonian e-ID authentication pages"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'E-Gov-Guardian-Estonian-Login-Scanner/1.0'
        })
        # Disable SSL warnings for testing
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Initialize AI advisor if API key is available
        self.ai_enabled = False
        self.ai_advisor = None
        
        # Try to get OpenAI API key from environment variable
        openai_api_key = (
            os.getenv('OPENAI_API_KEY') or 
            os.getenv('OPENAI_API_KEY_EGOV')
        )
        
        if openai_api_key:
            try:
                from scanner.ai_advisor import AIFixAdvisor
                self.ai_advisor = AIFixAdvisor(api_key=openai_api_key)
                self.ai_enabled = True
                self.logger.info("🧠 AI advisor initialized successfully")
            except Exception as e:
                self.logger.warning(f"Failed to initialize AI advisor: {str(e)}")
                
    def _enable_ai_analysis(self):
        """Enable AI analysis if not already enabled"""
        if not self.ai_enabled:
            openai_api_key = (
                os.getenv('OPENAI_API_KEY') or 
                os.getenv('OPENAI_API_KEY_EGOV')
            )
            if openai_api_key:
                try:
                    from scanner.ai_advisor import AIFixAdvisor
                    self.ai_advisor = AIFixAdvisor(
                        api_key=openai_api_key,
                        model="gpt-3.5-turbo",  # Use the same model as main scanner
                        max_tokens=1000,        # Match main scanner's token limit
                        temperature=0.1         # Match main scanner's temperature
                    )
                    self.ai_enabled = True
                    self.logger.info("🧠 AI advisor initialized successfully")
                except Exception as e:
                    self.logger.warning(f"Failed to initialize AI advisor: {str(e)}")
                    self.ai_enabled = False
                    self.ai_advisor = None
                    
    def scan_estonian_login_page(self, target_url: str, ai_analysis: bool = False, scan_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Perform comprehensive Estonian e-ID login page security scan"""
        if scan_config is None:
            scan_config = {}
            
        # Override AI analysis based on parameter
        if ai_analysis:
            self._enable_ai_analysis()
            
        results = {
            'target_url': target_url,
            'scan_type': 'estonian_login_page',
            'scan_start_time': time.time(),
            'vulnerabilities': [],
            'scan_status': 'started',
            'estonian_specific_findings': {},
            'ai_analysis_enabled': self.ai_enabled and ai_analysis,
            'authentication_methods_found': []
        }
        
        self.logger.info(f"Starting Estonian e-ID login page scan for: {target_url}")
        
        try:
            # Detect Estonian authentication methods
            auth_methods = self._detect_authentication_methods(target_url)
            results['authentication_methods_found'] = auth_methods
            
            # Run security checks
            all_findings = []
            
            # 1. HTTPS & TLS Security
            self.logger.info("Checking HTTPS & TLS Security...")
            tls_findings = self._check_https_tls_security(target_url)
            all_findings.extend(tls_findings)
            
            # 2. Security Headers
            self.logger.info("Checking Security Headers...")
            header_findings = self._check_security_headers(target_url)
            all_findings.extend(header_findings)
            
            # 3. Cookie Security
            self.logger.info("Checking Cookie Security...")
            cookie_findings = self._check_cookie_security(target_url)
            all_findings.extend(cookie_findings)
            
            # 4. Input/Form Security
            self.logger.info("Checking Input/Form Security...")
            form_findings = self._check_input_form_security(target_url)
            all_findings.extend(form_findings)
            
            # 5. Open Redirect Detection
            self.logger.info("Checking for Open Redirects...")
            redirect_findings = self._check_open_redirects(target_url)
            all_findings.extend(redirect_findings)
            
            # 6. Error Leak Detection
            self.logger.info("Checking for Error Information Leaks...")
            error_findings = self._check_error_leaks(target_url)
            all_findings.extend(error_findings)
            
            # 7. Outdated JavaScript Libraries
            self.logger.info("Checking for Outdated JavaScript Libraries...")
            js_findings = self._check_outdated_js_libraries(target_url)
            all_findings.extend(js_findings)
            
            # 8. CORS Misconfiguration
            self.logger.info("Checking CORS Configuration...")
            cors_findings = self._check_cors_misconfiguration(target_url)
            all_findings.extend(cors_findings)
            
            # 9. Frame Busting / Clickjacking
            self.logger.info("Checking for Clickjacking Protection...")
            clickjacking_findings = self._check_clickjacking_protection(target_url)
            all_findings.extend(clickjacking_findings)
            
            # 10. Privacy Risks
            self.logger.info("Checking for Privacy Risks...")
            privacy_findings = self._check_privacy_risks(target_url)
            all_findings.extend(privacy_findings)
            
            # Estonian e-ID specific checks
            self.logger.info("Performing Estonian e-ID specific security checks...")
            estonian_findings = self._check_estonian_specific_security(target_url)
            results['estonian_specific_findings'] = estonian_findings
            all_findings.extend(estonian_findings.get('vulnerabilities', []))
            
            # Process findings with AI
            if self.ai_enabled and self.ai_advisor and ai_analysis:
                self.logger.info("🧠 Running AI analysis on Estonian scan results...")
                try:
                    # Group findings by authentication method and vulnerability type
                    processed_findings = []
                    for finding in all_findings:
                        # Enhance finding with authentication context
                        finding['authentication_context'] = self._get_auth_context(finding, auth_methods)
                        finding['scan_type'] = 'estonian_login'
                        
                        # Get detailed AI recommendation
                        ai_rec = self.ai_advisor._get_vulnerability_recommendation(
                            vuln_type=finding['type'],
                            vulnerability={
                                **finding,
                                'auth_methods': auth_methods,
                                'compliance_requirements': [
                                    'eIDAS Regulation',
                                    'Estonian Electronic Identification and Trust Services Act',
                                    'GDPR',
                                    'Estonian Personal Data Protection Act',
                                    'Web Authentication (WebAuthn) Standard'
                                ],
                                'security_standards': [
                                    'ETSI TS 119 403-3',  # Trust Service Provider Conformity Assessment
                                    'ETSI EN 319 401',    # Security Requirements for Trust Service Providers
                                    'eIDAS Implementing Acts'
                                ]
                            }
                        )
                        if ai_rec:
                            finding['ai_recommendation'] = ai_rec
                        processed_findings.append(finding)
                    
                    results['vulnerabilities'] = processed_findings
                    
                    # Get method-specific recommendations
                    for method in auth_methods:
                        method_findings = [f for f in processed_findings 
                                        if method in f.get('authentication_context', {}).get('affected_methods', [])]
                        
                        method_recs = self._get_method_specific_recommendations(method, method_findings)
                        results[f'{method.lower()}_recommendations'] = method_recs
                    
                    # Get overall security assessment
                    results['ai_security_assessment'] = self._get_security_assessment(processed_findings, auth_methods)
                    
                    self.logger.info("✅ AI analysis completed successfully")
                    
                except Exception as e:
                    self.logger.error(f"Error in AI analysis: {str(e)}")
                    # Continue with non-AI results
                    results['vulnerabilities'] = all_findings
                    results['ai_analysis_error'] = str(e)
            else:
                results['vulnerabilities'] = all_findings
            
            # Add scan duration
            results['scan_duration'] = time.time() - results['scan_start_time']
            results['scan_status'] = 'completed'
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during Estonian login page scan: {str(e)}")
            results['scan_status'] = 'error'
            results['error'] = str(e)
            return results
        
    def _detect_authentication_methods(self, url: str) -> List[str]:
        """Detect which Estonian authentication methods are present"""
        methods = []
        try:
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text.lower()
            
            # ID-card detection
            if any(x in content for x in ['id-kaart', 'id card', 'eid', 'id.ee', 'auth.riik.ee']):
                methods.append('e-ID')
                
            # Mobile-ID detection
            if any(x in content for x in ['mobiil-id', 'mobile-id', 'mid.sk.ee']):
                methods.append('Mobile-ID')
                
            # Smart-ID detection
            if any(x in content for x in ['smart-id', 'sid.sk.ee']):
                methods.append('Smart-ID')
                
        except Exception as e:
            self.logger.warning(f"Error detecting authentication methods: {str(e)}")
            
        return methods
        
    def _get_auth_context(self, finding: Dict[str, Any], auth_methods: List[str]) -> Dict[str, Any]:
        """Get authentication-specific security context"""
        context = {
            'affected_methods': [],
            'impact_level': 'Unknown',
            'authentication_flow': 'Unknown'
        }
        
        vuln_type = finding.get('type', '').lower()
        
        # Determine affected authentication methods
        if 'e-ID' in auth_methods:
            if any(x in vuln_type for x in ['tls', 'https', 'certificate']):
                context['affected_methods'].append('e-ID')
                context['impact_level'] = 'Critical'
                context['authentication_flow'] = 'Certificate-based Authentication'
                
        if 'Mobile-ID' in auth_methods:
            if any(x in vuln_type for x in ['redirect', 'cors', 'origin']):
                context['affected_methods'].append('Mobile-ID')
                context['impact_level'] = 'High'
                context['authentication_flow'] = 'Mobile PKI Authentication'
                
        if 'Smart-ID' in auth_methods:
            if any(x in vuln_type for x in ['api', 'endpoint', 'request']):
                context['affected_methods'].append('Smart-ID')
                context['impact_level'] = 'High'
                context['authentication_flow'] = 'Smart-ID Authentication'
                
        # If no specific method is affected, consider it affecting all methods
        if not context['affected_methods']:
            context['affected_methods'] = auth_methods
            context['impact_level'] = 'Medium'
            context['authentication_flow'] = 'General Authentication Flow'
            
        return context
        
    def _get_method_specific_recommendations(self, method: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get security recommendations specific to each authentication method"""
        method_findings = [f for f in findings if method in f.get('authentication_context', {}).get('affected_methods', [])]
        
        recommendations = {
            'critical_issues': [],
            'security_improvements': [],
            'compliance_requirements': [],
            'best_practices': []
        }
        
        if method == 'e-ID':
            recommendations['best_practices'].extend([
                'Implement strict certificate validation',
                'Use secure OCSP for certificate status checking',
                'Implement proper certificate pinning',
                'Monitor certificate expiration'
            ])
            
        elif method == 'Mobile-ID':
            recommendations['best_practices'].extend([
                'Implement proper session management',
                'Use secure communication channels',
                'Validate mobile number format',
                'Implement proper timeout handling'
            ])
            
        elif method == 'Smart-ID':
            recommendations['best_practices'].extend([
                'Implement proper API authentication',
                'Use secure random challenge generation',
                'Validate response signatures',
                'Implement proper error handling'
            ])
            
        # Add findings-based recommendations
        for finding in method_findings:
            if finding.get('severity', '').upper() == 'HIGH':
                recommendations['critical_issues'].append(finding)
            
            # Add compliance requirements based on findings
            if 'compliance' in finding.get('ai_recommendation', '').lower():
                recommendations['compliance_requirements'].append(finding)
                
        return recommendations
        
    def _get_security_assessment(self, findings: List[Dict[str, Any]], auth_methods: List[str]) -> Dict[str, Any]:
        """Generate overall security assessment"""
        assessment = {
            'overall_security_rating': 'Unknown',
            'critical_findings': [],
            'authentication_security': {},
            'compliance_status': {},
            'recommendations': []
        }
        
        # Count severity levels
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in findings:
            severity = finding.get('severity', 'MEDIUM').upper()
            severity_counts[severity] += 1
            
            if severity == 'HIGH':
                assessment['critical_findings'].append({
                    'type': finding['type'],
                    'description': finding.get('description', ''),
                    'recommendation': finding.get('ai_recommendation', '')
                })
        
        # Calculate overall security rating
        if severity_counts['HIGH'] > 2:
            assessment['overall_security_rating'] = 'Critical'
        elif severity_counts['HIGH'] > 0:
            assessment['overall_security_rating'] = 'Poor'
        elif severity_counts['MEDIUM'] > 3:
            assessment['overall_security_rating'] = 'Fair'
        elif severity_counts['MEDIUM'] > 0:
            assessment['overall_security_rating'] = 'Good'
        else:
            assessment['overall_security_rating'] = 'Excellent'
        
        # Assess each authentication method
        for method in auth_methods:
            method_findings = [f for f in findings if method in f.get('authentication_context', {}).get('affected_methods', [])]
            method_severity = max([f.get('severity', 'LOW') for f in method_findings], default='LOW')
            
            assessment['authentication_security'][method] = {
                'security_rating': self._get_method_security_rating(method_severity),
                'findings_count': len(method_findings),
                'critical_issues': len([f for f in method_findings if f.get('severity') == 'HIGH']),
                'recommendations': [f.get('ai_recommendation', '') for f in method_findings if f.get('ai_recommendation')]
            }
        
        # Add compliance assessment
        assessment['compliance_status'] = {
            'eIDAS_compliant': self._check_eidas_compliance(findings),
            'GDPR_compliant': self._check_gdpr_compliance(findings),
            'Estonian_trust_services_compliant': self._check_trust_services_compliance(findings)
        }
        
        return assessment
        
    def _get_method_security_rating(self, severity: str) -> str:
        """Convert severity to security rating"""
        ratings = {
            'HIGH': 'Poor',
            'MEDIUM': 'Fair',
            'LOW': 'Good',
            'INFO': 'Excellent'
        }
        return ratings.get(severity.upper(), 'Unknown')
        
    def _check_eidas_compliance(self, findings: List[Dict[str, Any]]) -> bool:
        """Check if findings indicate eIDAS compliance issues"""
        critical_issues = ['tls', 'certificate', 'encryption', 'privacy']
        return not any(
            issue in finding.get('type', '').lower() 
            for finding in findings 
            for issue in critical_issues
        )
        
    def _check_gdpr_compliance(self, findings: List[Dict[str, Any]]) -> bool:
        """Check if findings indicate GDPR compliance issues"""
        gdpr_issues = ['privacy', 'data leak', 'personal data', 'consent']
        return not any(
            issue in finding.get('type', '').lower() 
            for finding in findings 
            for issue in gdpr_issues
        )
        
    def _check_trust_services_compliance(self, findings: List[Dict[str, Any]]) -> bool:
        """Check if findings indicate Estonian Trust Services compliance issues"""
        trust_issues = ['signature', 'certificate', 'timestamp', 'validation']
        return not any(
            issue in finding.get('type', '').lower() 
            for finding in findings 
            for issue in trust_issues
        )
    
    def _check_https_tls_security(self, url: str) -> List[Dict[str, Any]]:
        """Check HTTPS & TLS Security configuration"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        # Check if HTTPS is used
        if parsed_url.scheme != 'https':
            vulnerabilities.append({
                'type': 'Insecure Protocol',
                'severity': 'HIGH',
                'description': 'Login page is not using HTTPS protocol',
                'location': url,
                'evidence': f'URL uses {parsed_url.scheme} instead of HTTPS',
                'recommendation': 'Implement HTTPS with strong TLS configuration',
                'estonian_context': 'Estonian e-ID authentication requires secure HTTPS connections'
            })
            return vulnerabilities  # Can't check TLS if not HTTPS
        
        try:
            # Check TLS configuration
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get TLS version
                    tls_version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check for weak TLS versions
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'severity': 'MEDIUM',
                            'description': f'Server supports weak TLS version: {tls_version}',
                            'location': url,
                            'evidence': f'TLS version: {tls_version}',
                            'recommendation': 'Use TLS 1.2 or higher',
                            'estonian_context': 'e-ID authentication should use modern TLS versions'
                        })
                    
                    # Check for weak ciphers
                    if cipher and 'RC4' in cipher[0] or 'DES' in cipher[0]:
                        vulnerabilities.append({
                            'type': 'Weak Cipher',
                            'severity': 'HIGH',
                            'description': f'Server uses weak cipher: {cipher[0]}',
                            'location': url,
                            'evidence': f'Cipher: {cipher[0]}',
                            'recommendation': 'Use strong cipher suites (AES-GCM, ChaCha20)',
                            'estonian_context': 'Strong encryption is critical for e-ID security'
                        })
                        
        except Exception as e:
            vulnerabilities.append({
                'type': 'TLS Configuration Error',
                'severity': 'MEDIUM',
                'description': f'Unable to verify TLS configuration: {str(e)}',
                'location': url,
                'evidence': str(e),
                'recommendation': 'Verify TLS configuration manually',
                'estonian_context': 'TLS configuration verification failed'
            })
        
        # Check for mixed content
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                # Look for HTTP resources in HTTPS page
                http_resources = re.findall(r'http://[^"\s]+', response.text, re.IGNORECASE)
                if http_resources:
                    vulnerabilities.append({
                        'type': 'Mixed Content',
                        'severity': 'MEDIUM',
                        'description': 'HTTPS page loads resources over insecure HTTP',
                        'location': url,
                        'evidence': f'Found {len(http_resources)} HTTP resources',
                        'recommendation': 'Load all resources over HTTPS',
                        'estonian_context': 'Mixed content can compromise e-ID authentication security'
                    })
        except Exception as e:
            self.logger.warning(f"Error checking mixed content: {str(e)}")
        
        return vulnerabilities
    
    def _check_security_headers(self, url: str) -> List[Dict[str, Any]]:
        """Check for missing or weak security headers"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Required security headers for login pages
            required_headers = {
                'Strict-Transport-Security': {
                    'description': 'HSTS header missing - allows downgrade attacks',
                    'recommendation': 'Add Strict-Transport-Security header with max-age and includeSubDomains',
                    'severity': 'HIGH'
                },
                'Content-Security-Policy': {
                    'description': 'CSP header missing - vulnerable to XSS attacks',
                    'recommendation': 'Implement strict Content Security Policy',
                    'severity': 'HIGH'
                },
                'X-Frame-Options': {
                    'description': 'X-Frame-Options missing - vulnerable to clickjacking',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN',
                    'severity': 'MEDIUM'
                },
                'X-Content-Type-Options': {
                    'description': 'X-Content-Type-Options missing - vulnerable to MIME sniffing',
                    'recommendation': 'Add X-Content-Type-Options: nosniff',
                    'severity': 'MEDIUM'
                },
                'Referrer-Policy': {
                    'description': 'Referrer-Policy missing - may leak sensitive information',
                    'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin',
                    'severity': 'LOW'
                }
            }
            
            for header_name, header_info in required_headers.items():
                if header_name not in headers:
                    vulnerabilities.append({
                        'type': f'Missing Security Header: {header_name}',
                        'severity': header_info['severity'],
                        'description': header_info['description'],
                        'location': url,
                        'evidence': f'Header {header_name} not found',
                        'recommendation': header_info['recommendation'],
                        'estonian_context': f'{header_name} is crucial for e-ID login page security'
                    })
            
            # Check for weak CSP if present
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                    vulnerabilities.append({
                        'type': 'Weak Content Security Policy',
                        'severity': 'MEDIUM',
                        'description': 'CSP allows unsafe-inline or unsafe-eval',
                        'location': url,
                        'evidence': f'CSP: {csp}',
                        'recommendation': 'Remove unsafe-inline and unsafe-eval from CSP',
                        'estonian_context': 'Strict CSP is essential for e-ID authentication security'
                    })
            
            # Check for weak HSTS if present
            if 'Strict-Transport-Security' in headers:
                hsts = headers['Strict-Transport-Security']
                if 'max-age' not in hsts or 'includeSubDomains' not in hsts:
                    vulnerabilities.append({
                        'type': 'Weak HSTS Configuration',
                        'severity': 'MEDIUM',
                        'description': 'HSTS header lacks max-age or includeSubDomains',
                        'location': url,
                        'evidence': f'HSTS: {hsts}',
                        'recommendation': 'Use HSTS with max-age and includeSubDomains',
                        'estonian_context': 'Strong HSTS prevents downgrade attacks on e-ID authentication'
                    })
                    
        except Exception as e:
            vulnerabilities.append({
                'type': 'Security Headers Check Error',
                'severity': 'LOW',
                'description': f'Unable to check security headers: {str(e)}',
                'location': url,
                'evidence': str(e),
                'recommendation': 'Verify security headers manually',
                'estonian_context': 'Security headers verification failed'
            })
        
        return vulnerabilities
    
    def _check_cookie_security(self, url: str) -> List[Dict[str, Any]]:
        """Check cookie security configuration"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            
            # Check cookies set by the server
            for cookie in response.cookies:
                issues = []
                
                # Check for Secure flag
                if not cookie.secure:
                    issues.append('Missing Secure flag')
                
                # Check for HttpOnly flag
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')
                
                # Check for SameSite attribute
                samesite = cookie.get_nonstandard_attr('SameSite')
                if not samesite:
                    issues.append('Missing SameSite attribute')
                elif samesite.lower() not in ['strict', 'lax']:
                    issues.append(f'Weak SameSite value: {samesite}')
                
                if issues:
                    vulnerabilities.append({
                        'type': 'Insecure Cookie Configuration',
                        'severity': 'MEDIUM',
                        'description': f'Cookie "{cookie.name}" has security issues',
                        'location': url,
                        'evidence': ', '.join(issues),
                        'recommendation': 'Set Secure, HttpOnly, and SameSite=Strict for sensitive cookies',
                        'estonian_context': 'Secure cookies are critical for e-ID session management'
                    })
                    
        except Exception as e:
            self.logger.warning(f"Error checking cookies: {str(e)}")
        
        return vulnerabilities
    
    def _check_input_form_security(self, url: str) -> List[Dict[str, Any]]:
        """Check input/form security for login pages"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Check for forms
                forms = soup.find_all('form')
                for form in forms:
                    # Check for password fields without autocomplete=off
                    password_fields = form.find_all('input', {'type': 'password'})
                    for field in password_fields:
                        autocomplete = field.get('autocomplete', '')
                        if autocomplete.lower() != 'off':
                            vulnerabilities.append({
                                'type': 'Insecure Password Field',
                                'severity': 'MEDIUM',
                                'description': 'Password field allows autocomplete',
                                'location': url,
                                'evidence': f'Password field lacks autocomplete="off"',
                                'recommendation': 'Add autocomplete="off" to sensitive input fields',
                                'estonian_context': 'e-ID PIN fields should not be cached by browsers'
                            })
                    
                    # Check for forms without CSRF protection
                    csrf_tokens = form.find_all('input', {'name': re.compile(r'csrf|token|_token', re.I)})
                    if not csrf_tokens and form.get('method', '').lower() == 'post':
                        vulnerabilities.append({
                            'type': 'Missing CSRF Protection',
                            'severity': 'HIGH',
                            'description': 'Form lacks CSRF protection tokens',
                            'location': url,
                            'evidence': 'No CSRF token found in form',
                            'recommendation': 'Implement CSRF tokens for all forms',
                            'estonian_context': 'CSRF protection is essential for e-ID authentication forms'
                        })
                
                # Check for sensitive data in HTML comments
                comments = soup.find_all(string=lambda text: isinstance(text, str) and text.strip().startswith('<!--'))
                for comment in comments:
                    if re.search(r'(password|token|key|secret|api)', comment, re.I):
                        vulnerabilities.append({
                            'type': 'Sensitive Data in Comments',
                            'severity': 'MEDIUM',
                            'description': 'HTML comments contain sensitive information',
                            'location': url,
                            'evidence': 'Sensitive keywords found in HTML comments',
                            'recommendation': 'Remove sensitive information from HTML comments',
                            'estonian_context': 'e-ID pages should not expose sensitive data in source'
                        })
                        
        except Exception as e:
            self.logger.warning(f"Error checking form security: {str(e)}")
        
        return vulnerabilities
    
    def _check_open_redirects(self, url: str) -> List[Dict[str, Any]]:
        """Check for open redirect vulnerabilities"""
        vulnerabilities = []
        
        # Common redirect parameters
        redirect_params = ['redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'continue']
        
        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            for param in redirect_params:
                if param in query_params:
                    # Test with external domain
                    test_url = f"{url}&{param}=http://evil.example.com"
                    response = self.session.get(test_url, timeout=10, verify=False, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.example.com' in location:
                            vulnerabilities.append({
                                'type': 'Open Redirect',
                                'severity': 'MEDIUM',
                                'description': f'Open redirect via {param} parameter',
                                'location': url,
                                'evidence': f'Redirects to external domain: {location}',
                                'recommendation': 'Validate redirect URLs against whitelist',
                                'estonian_context': 'Open redirects can facilitate phishing attacks on e-ID users'
                            })
                            
        except Exception as e:
            self.logger.warning(f"Error checking open redirects: {str(e)}")
        
        return vulnerabilities
    
    def _check_error_leaks(self, url: str) -> List[Dict[str, Any]]:
        """Check for error information disclosure"""
        vulnerabilities = []
        
        # Test various error conditions
        error_tests = [
            ('404', '/nonexistent-page-12345'),
            ('500', '?error=true'),
            ('sql', "?id=1'"),
            ('debug', '?debug=1')
        ]
        
        try:
            base_url = url.rstrip('/')
            
            for test_name, test_path in error_tests:
                test_url = base_url + test_path
                response = self.session.get(test_url, timeout=10, verify=False)
                
                # Look for verbose error messages
                error_patterns = [
                    r'stack trace',
                    r'apache/\d+\.\d+',
                    r'nginx/\d+\.\d+',
                    r'php.*error',
                    r'mysql.*error',
                    r'java\.lang\.',
                    r'microsoft.*ole.*db',
                    r'\.net framework',
                    r'internal server error.*debug'
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': 'Verbose Error Messages',
                            'severity': 'LOW',
                            'description': f'Server reveals verbose error information ({test_name})',
                            'location': test_url,
                            'evidence': f'Error pattern detected: {pattern}',
                            'recommendation': 'Configure custom error pages, disable debug mode',
                            'estonian_context': 'Error messages should not reveal system information to attackers'
                        })
                        break
                        
        except Exception as e:
            self.logger.warning(f"Error checking error leaks: {str(e)}")
        
        return vulnerabilities
    
    def _check_outdated_js_libraries(self, url: str) -> List[Dict[str, Any]]:
        """Check for outdated JavaScript libraries"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                # Common vulnerable library patterns
                library_patterns = {
                    r'jquery[/-](\d+\.\d+\.\d+)': {
                        'name': 'jQuery',
                        'vulnerable_versions': ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0', '1.7.0', '1.8.0', '1.9.0', '2.0.0', '2.1.0', '2.2.0', '3.0.0']
                    },
                    r'angular[/-](\d+\.\d+\.\d+)': {
                        'name': 'AngularJS',
                        'vulnerable_versions': ['1.0.0', '1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0', '1.6.0']
                    },
                    r'bootstrap[/-](\d+\.\d+\.\d+)': {
                        'name': 'Bootstrap',
                        'vulnerable_versions': ['2.0.0', '2.1.0', '2.2.0', '2.3.0', '3.0.0', '3.1.0', '3.2.0', '3.3.0']
                    }
                }
                
                for pattern, library_info in library_patterns.items():
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    for version in matches:
                        if any(version.startswith(vuln_ver.split('.')[0] + '.' + vuln_ver.split('.')[1]) 
                               for vuln_ver in library_info['vulnerable_versions']):
                            vulnerabilities.append({
                                'type': 'Outdated JavaScript Library',
                                'severity': 'MEDIUM',
                                'description': f'Outdated {library_info["name"]} library detected',
                                'location': url,
                                'evidence': f'{library_info["name"]} version {version}',
                                'recommendation': f'Update {library_info["name"]} to latest stable version',
                                'estonian_context': f'Outdated libraries can compromise e-ID authentication security'
                            })
                            
        except Exception as e:
            self.logger.warning(f"Error checking JS libraries: {str(e)}")
        
        return vulnerabilities
    
    def _check_cors_misconfiguration(self, url: str) -> List[Dict[str, Any]]:
        """Check for CORS misconfigurations"""
        vulnerabilities = []
        
        try:
            # Test CORS with various origins
            test_origins = [
                'http://evil.com',
                'https://evil.com',
                'null',
                '*'
            ]
            
            for origin in test_origins:
                headers = {'Origin': origin}
                response = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                
                if cors_header == '*':
                    vulnerabilities.append({
                        'type': 'Permissive CORS Policy',
                        'severity': 'MEDIUM',
                        'description': 'Server allows requests from any origin (*)',
                        'location': url,
                        'evidence': 'Access-Control-Allow-Origin: *',
                        'recommendation': 'Restrict CORS to specific trusted origins',
                        'estonian_context': 'Permissive CORS can allow unauthorized access to e-ID endpoints'
                    })
                elif cors_header == origin and origin in ['http://evil.com', 'https://evil.com']:
                    vulnerabilities.append({
                        'type': 'CORS Reflects Arbitrary Origins',
                        'severity': 'HIGH',
                        'description': 'Server reflects arbitrary origins in CORS headers',
                        'location': url,
                        'evidence': f'Access-Control-Allow-Origin: {cors_header}',
                        'recommendation': 'Implement strict origin validation',
                        'estonian_context': 'Unrestricted CORS can compromise e-ID authentication'
                    })
                    
        except Exception as e:
            self.logger.warning(f"Error checking CORS: {str(e)}")
        
        return vulnerabilities
    
    def _check_clickjacking_protection(self, url: str) -> List[Dict[str, Any]]:
        """Check for clickjacking protection"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Check X-Frame-Options
            x_frame_options = headers.get('X-Frame-Options', '').upper()
            
            # Check CSP frame-ancestors
            csp = headers.get('Content-Security-Policy', '')
            frame_ancestors = 'frame-ancestors' in csp
            
            if not x_frame_options and not frame_ancestors:
                vulnerabilities.append({
                    'type': 'Missing Clickjacking Protection',
                    'severity': 'MEDIUM',
                    'description': 'Page can be embedded in frames (no X-Frame-Options or CSP frame-ancestors)',
                    'location': url,
                    'evidence': 'No clickjacking protection headers found',
                    'recommendation': 'Add X-Frame-Options: DENY or CSP frame-ancestors directive',
                    'estonian_context': 'e-ID login pages must prevent iframe embedding to avoid UI redressing attacks'
                })
            elif x_frame_options == 'ALLOWALL':
                vulnerabilities.append({
                    'type': 'Weak Clickjacking Protection',
                    'severity': 'MEDIUM',
                    'description': 'X-Frame-Options allows all origins to embed the page',
                    'location': url,
                    'evidence': 'X-Frame-Options: ALLOWALL',
                    'recommendation': 'Use X-Frame-Options: DENY or SAMEORIGIN',
                    'estonian_context': 'e-ID pages should deny all framing to prevent attacks'
                })
                
        except Exception as e:
            self.logger.warning(f"Error checking clickjacking protection: {str(e)}")
        
        return vulnerabilities
    
    def _check_privacy_risks(self, url: str) -> List[Dict[str, Any]]:
        """Check for privacy risks and information disclosure"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text
                
                # Check for exposed email addresses
                emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
                if emails:
                    vulnerabilities.append({
                        'type': 'Exposed Email Addresses',
                        'severity': 'LOW',
                        'description': f'Found {len(emails)} email addresses in page source',
                        'location': url,
                        'evidence': f'Email addresses: {", ".join(emails[:3])}...',
                        'recommendation': 'Remove or obfuscate email addresses from public pages',
                        'estonian_context': 'Exposed emails can be targets for phishing attacks on e-ID users'
                    })
                
                # Check for sensitive comments
                comments = re.findall(r'<!--.*?-->', content, re.DOTALL)
                sensitive_patterns = [
                    r'(password|pin|secret|key|token)',
                    r'(test|debug|dev|admin)',
                    r'(todo|fixme|hack|temp)'
                ]
                
                for comment in comments:
                    for pattern in sensitive_patterns:
                        if re.search(pattern, comment, re.IGNORECASE):
                            vulnerabilities.append({
                                'type': 'Sensitive Information in Comments',
                                'severity': 'LOW',
                                'description': 'HTML comments contain sensitive information',
                                'location': url,
                                'evidence': 'Sensitive keywords found in comments',
                                'recommendation': 'Remove sensitive information from HTML comments',
                                'estonian_context': 'e-ID pages should not expose internal information'
                            })
                            break
                
                # Check for exposed system paths
                path_patterns = [
                    r'[A-Za-z]:\\[\w\\]+',  # Windows paths
                    r'/etc/[\w/]+',         # Unix config paths
                    r'/var/[\w/]+',         # Unix var paths
                    r'/usr/[\w/]+',         # Unix usr paths
                ]
                
                for pattern in path_patterns:
                    if re.search(pattern, content):
                        vulnerabilities.append({
                            'type': 'Exposed System Paths',
                            'severity': 'LOW',
                            'description': 'System file paths exposed in page source',
                            'location': url,
                            'evidence': 'System paths found in HTML',
                            'recommendation': 'Remove system paths from public content',
                            'estonian_context': 'System information should not be visible to attackers'
                        })
                        break
                        
        except Exception as e:
            self.logger.warning(f"Error checking privacy risks: {str(e)}")
        
        return vulnerabilities
    
    def _check_estonian_specific_security(self, url: str) -> Dict[str, Any]:
        """Perform Estonian e-ID specific security checks"""
        findings = {
            'vulnerabilities': [],
            'estonian_authentication_methods': [],
            'certificate_handling': {},
            'session_management': {}
        }
        
        try:
            response = self.session.get(url, timeout=10, verify=False)
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for Estonian authentication methods
                auth_methods = {
                    'id-card': ['id-card', 'idcard', 'id card', 'kaart'],
                    'mobile-id': ['mobile-id', 'mobileid', 'mobile id', 'mobiil-id'],
                    'smart-id': ['smart-id', 'smartid', 'smart id']
                }
                
                for method, keywords in auth_methods.items():
                    if any(keyword in content for keyword in keywords):
                        findings['estonian_authentication_methods'].append(method)
                
                # Check for proper certificate validation indicators
                cert_indicators = [
                    'certificate', 'sert', 'x509', 'pki', 'ocsp', 'crl'
                ]
                
                if any(indicator in content for indicator in cert_indicators):
                    findings['certificate_handling']['present'] = True
                else:
                    findings['vulnerabilities'].append({
                        'type': 'Missing Certificate Validation References',
                        'severity': 'MEDIUM',
                        'description': 'No certificate validation indicators found',
                        'location': url,
                        'evidence': 'No certificate-related terms in page content',
                        'recommendation': 'Ensure proper certificate validation is implemented',
                        'estonian_context': 'e-ID authentication must validate certificates properly'
                    })
                
                # Check for session management indicators
                session_indicators = [
                    'session', 'logout', 'seanss', 'väljalogimine'
                ]
                
                if any(indicator in content for indicator in session_indicators):
                    findings['session_management']['present'] = True
                
                # Check for Estonian language support
                estonian_words = [
                    'sisselogimine', 'autentimine', 'tuvastamine', 'eesti'
                ]
                
                if any(word in content for word in estonian_words):
                    findings['estonian_language_support'] = True
                
                # Check for proper PIN handling warnings
                pin_warnings = [
                    'pin', 'parool', 'kood', 'salakood'
                ]
                
                if any(warning in content for warning in pin_warnings):
                    findings['pin_handling_present'] = True
                else:
                    findings['vulnerabilities'].append({
                        'type': 'Missing PIN Security Information',
                        'severity': 'LOW',
                        'description': 'No PIN security information found on login page',
                        'location': url,
                        'evidence': 'No PIN-related security guidance visible',
                        'recommendation': 'Add user guidance about PIN security',
                        'estonian_context': 'e-ID login pages should educate users about PIN security'
                    })
                    
        except Exception as e:
            findings['vulnerabilities'].append({
                'type': 'Estonian Specific Check Error',
                'severity': 'LOW',
                'description': f'Error during Estonian-specific checks: {str(e)}',
                'location': url,
                'evidence': str(e),
                'recommendation': 'Verify Estonian e-ID implementation manually',
                'estonian_context': 'Unable to verify Estonian e-ID specific security features'
            })
        
        return findings

    def _get_estonian_context(self, vuln_type: str) -> str:
        """Get Estonian-specific security context for vulnerability types"""
        contexts = {
            'Insecure Protocol': 'Estonian e-ID authentication requires secure HTTPS connections with strong TLS configuration to protect sensitive personal data and comply with eIDAS regulation.',
            'Weak TLS Version': 'Estonian authentication services require TLS 1.2 or higher with strong cipher suites to maintain trust service provider status.',
            'Missing Security Headers': 'Estonian e-ID authentication pages must implement strict security headers to prevent attacks and protect user identity data.',
            'Cookie Security': 'Session cookies in Estonian authentication must be secure and comply with both eIDAS and GDPR requirements.',
            'Form Security': 'Input validation is critical for Estonian e-ID forms to prevent injection attacks and maintain service trust status.',
            'Open Redirect': 'Authentication redirects must be strictly controlled to prevent phishing attacks targeting Estonian e-ID users.',
            'Error Leaks': 'Error messages must not expose sensitive information about Estonian identity verification processes.',
            'Outdated Libraries': 'Authentication components must be up-to-date to maintain compliance with Estonian trust service requirements.',
            'CORS Misconfiguration': 'Cross-origin resource sharing must be strictly controlled for Estonian identity verification endpoints.',
            'Clickjacking Protection': 'Frame protection is essential to prevent attacks on Estonian authentication dialogs.',
            'Privacy Risks': 'Estonian e-ID services must maintain strict privacy controls in compliance with GDPR and local regulations.'
        }
        return contexts.get(vuln_type, 'Must comply with Estonian Electronic Identification and Trust Services requirements.')