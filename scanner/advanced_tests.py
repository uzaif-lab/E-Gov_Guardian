#!/usr/bin/env python3
"""
Advanced Security Test Modules for E-Gov Guardian
Implements CORS, CSRF, Open Redirects, Host Header Injection, and API Fuzzing
"""

import requests
import re
import json
import time
from urllib.parse import urlparse, urljoin, parse_qs
from typing import Dict, List, Any
import logging

class AdvancedSecurityTests:
    """Advanced security test implementations"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.logger = logging.getLogger(__name__)
    
    def test_graphql_security(self, target_url: str) -> List[Dict[str, Any]]:
        """Test GraphQL endpoints for security issues"""
        vulnerabilities = []
        
        # Common GraphQL paths
        graphql_paths = ['/graphql', '/graphiql', '/api/graphql', '/v1/graphql', '/query']
        
        try:
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for path in graphql_paths:
                graphql_url = urljoin(base_url, path)
                
                # Test for introspection
                introspection_query = {
                    "query": "query IntrospectionQuery { __schema { queryType { name } } }"
                }
                
                try:
                    response = self.session.post(
                        graphql_url,
                        json=introspection_query,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if 'data' in data and '__schema' in str(data):
                                vulnerabilities.append({
                                    'type': 'GraphQL Introspection Enabled',
                                    'severity': 'Medium',
                                    'location': graphql_url,
                                    'description': 'GraphQL introspection is enabled in production',
                                    'evidence': 'Successfully executed introspection query',
                                    'recommendation': 'Disable GraphQL introspection in production'
                                })
                        except json.JSONDecodeError:
                            pass
                    
                    # Test for query depth limit
                    simple_query = {
                        "query": "query { user { friends { name } } }"
                    }
                    
                    response = self.session.post(
                        graphql_url,
                        json=simple_query,
                        headers={'Content-Type': 'application/json'},
                        timeout=30
                    )
                    
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'GraphQL Query Depth Not Limited',
                            'severity': 'High',
                            'location': graphql_url,
                            'description': 'GraphQL allows nested queries (DoS risk)',
                            'evidence': 'Nested query executed successfully',
                            'recommendation': 'Implement query depth limiting and complexity analysis'
                        })
                        
                except requests.RequestException:
                    continue
                    
        except Exception as e:
            self.logger.warning(f"GraphQL security test error: {str(e)}")
            
        return vulnerabilities
    
    def test_cors_policy(self, target_url: str) -> List[Dict[str, Any]]:
        """Test CORS policy configuration"""
        vulnerabilities = []
        
        # Test origins to check
        test_origins = [
            'https://evil.com',
            'http://attacker.example.com',
            'null',
            '*'
        ]
        
        try:
            for origin in test_origins:
                headers = {
                    'Origin': origin,
                    'Access-Control-Request-Method': 'POST',
                    'Access-Control-Request-Headers': 'X-Requested-With'
                }
                
                response = self.session.options(target_url, headers=headers)
                
                # Check for permissive CORS
                if 'Access-Control-Allow-Origin' in response.headers:
                    allowed_origin = response.headers['Access-Control-Allow-Origin']
                    
                    if allowed_origin == '*' or allowed_origin == origin:
                        vulnerabilities.append({
                            'type': 'Permissive CORS Policy',
                            'severity': 'Medium',
                            'location': target_url,
                            'description': f'CORS allows origin: {allowed_origin}',
                            'evidence': f'Access-Control-Allow-Origin: {allowed_origin}',
                            'recommendation': 'Restrict CORS to specific trusted origins'
                        })
                
                # Check for credentials exposure
                if response.headers.get('Access-Control-Allow-Credentials') == 'true':
                    if allowed_origin == '*':
                        vulnerabilities.append({
                            'type': 'CORS Credentials Exposure',
                            'severity': 'High',
                            'location': target_url,
                            'description': 'CORS allows credentials with wildcard origin',
                            'evidence': 'Access-Control-Allow-Credentials: true with Origin: *',
                            'recommendation': 'Never use wildcard origin with credentials'
                        })
                        
        except Exception as e:
            self.logger.warning(f"CORS test error: {str(e)}")
            
        return vulnerabilities
    
    def test_csrf_protection(self, target_url: str) -> List[Dict[str, Any]]:
        """Test for CSRF protection mechanisms"""
        vulnerabilities = []
        
        try:
            # Get the page first
            response = self.session.get(target_url)
            
            if response.status_code == 200:
                content = response.text.lower()
                
                # Check for CSRF tokens in forms
                forms_without_csrf = []
                if '<form' in content:
                    # Look for forms without CSRF protection
                    forms = re.findall(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
                    
                    for form in forms:
                        if 'method="post"' in form or 'method=post' in form:
                            # Check for CSRF token patterns
                            csrf_patterns = [
                                r'csrf[_-]?token',
                                r'_token',
                                r'authenticity[_-]?token',
                                r'anti[_-]?forgery[_-]?token'
                            ]
                            
                            has_csrf = any(re.search(pattern, form, re.IGNORECASE) for pattern in csrf_patterns)
                            
                            if not has_csrf:
                                forms_without_csrf.append(form[:100] + '...')
                
                if forms_without_csrf:
                    vulnerabilities.append({
                        'type': 'Missing CSRF Protection',
                        'severity': 'Medium',
                        'location': target_url,
                        'description': f'Found {len(forms_without_csrf)} forms without CSRF tokens',
                        'evidence': f'Forms: {forms_without_csrf[:2]}',
                        'recommendation': 'Implement CSRF tokens in all state-changing forms'
                    })
                
                # Check for SameSite cookie attribute
                cookies = response.cookies
                for cookie in cookies:
                    if not hasattr(cookie, 'same_site') or not cookie.same_site:
                        vulnerabilities.append({
                            'type': 'Missing SameSite Cookie Attribute',
                            'severity': 'Low',
                            'location': target_url,
                            'description': f'Cookie {cookie.name} lacks SameSite attribute',
                            'evidence': f'Cookie: {cookie.name}',
                            'recommendation': 'Set SameSite=Strict or SameSite=Lax for all cookies'
                        })
                        
        except Exception as e:
            self.logger.warning(f"CSRF test error: {str(e)}")
            
        return vulnerabilities
    
    def test_open_redirects(self, target_url: str) -> List[Dict[str, Any]]:
        """Test for open redirect vulnerabilities"""
        vulnerabilities = []
        
        # Common redirect parameters
        redirect_params = [
            'redirect', 'url', 'next', 'return', 'returnUrl', 'goto', 'destination',
            'continue', 'successUrl', 'failureUrl', 'callback', 'target'
        ]
        
        # Malicious URLs to test
        test_urls = [
            'https://evil.com',
            'http://attacker.example.com',
            '//evil.com',
            'javascript:alert(1)'
        ]
        
        try:
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
            
            for param in redirect_params:
                for test_url in test_urls:
                    test_target = f"{base_url}?{param}={test_url}"
                    
                    response = self.session.get(test_target, allow_redirects=False)
                    
                    # Check for redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        
                        # Check if redirect goes to our test URL
                        if test_url in location or location.startswith('//'):
                            vulnerabilities.append({
                                'type': 'Open Redirect',
                                'severity': 'Medium',
                                'location': test_target,
                                'description': f'Open redirect via {param} parameter',
                                'evidence': f'Location: {location}',
                                'recommendation': 'Validate redirect URLs against whitelist'
                            })
                            
        except Exception as e:
            self.logger.warning(f"Open redirect test error: {str(e)}")
            
        return vulnerabilities
    
    def test_host_header_injection(self, target_url: str) -> List[Dict[str, Any]]:
        """Test for Host header injection vulnerabilities"""
        vulnerabilities = []
        
        # Malicious host headers to test
        malicious_hosts = [
            'evil.com',
            'attacker.example.com',
            'localhost:1337',
            '127.0.0.1:8080'
        ]
        
        try:
            original_response = self.session.get(target_url)
            
            for malicious_host in malicious_hosts:
                headers = {'Host': malicious_host}
                response = self.session.get(target_url, headers=headers)
                
                # Check if malicious host appears in response
                if malicious_host in response.text:
                    vulnerabilities.append({
                        'type': 'Host Header Injection',
                        'severity': 'Medium',
                        'location': target_url,
                        'description': f'Host header injection with {malicious_host}',
                        'evidence': f'Malicious host reflected in response',
                        'recommendation': 'Validate Host header against whitelist'
                    })
                
                # Check for password reset poisoning
                if any(keyword in response.text.lower() for keyword in ['reset', 'password', 'email']):
                    vulnerabilities.append({
                        'type': 'Password Reset Poisoning',
                        'severity': 'High',
                        'location': target_url,
                        'description': f'Potential password reset poisoning via Host header',
                        'evidence': f'Host: {malicious_host} on password reset page',
                        'recommendation': 'Use absolute URLs in password reset emails'
                    })
                    
        except Exception as e:
            self.logger.warning(f"Host header injection test error: {str(e)}")
            
        return vulnerabilities
    
    def test_api_endpoint_fuzzing(self, target_url: str) -> List[Dict[str, Any]]:
        """Test API endpoints for common vulnerabilities"""
        vulnerabilities = []
        
        # Common API paths
        api_paths = [
            '/api/v1/', '/api/v2/', '/api/', '/rest/', '/graphql',
            '/api/users', '/api/admin', '/api/config', '/api/health',
            '/swagger.json', '/openapi.json', '/api-docs'
        ]
        
        # HTTP methods to test
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
        
        try:
            parsed_url = urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            for path in api_paths:
                full_url = urljoin(base_url, path)
                
                for method in methods:
                    try:
                        response = self.session.request(method, full_url, timeout=5)
                        
                        # Check for exposed API documentation
                        if response.status_code == 200:
                            content_type = response.headers.get('content-type', '').lower()
                            
                            if 'json' in content_type:
                                # Check for sensitive information exposure
                                content = response.text.lower()
                                sensitive_patterns = [
                                    'password', 'secret', 'token', 'key', 'credential',
                                    'admin', 'root', 'private', 'internal'
                                ]
                                
                                for pattern in sensitive_patterns:
                                    if pattern in content:
                                        vulnerabilities.append({
                                            'type': 'API Information Disclosure',
                                            'severity': 'Medium',
                                            'location': full_url,
                                            'description': f'API endpoint exposes sensitive information',
                                            'evidence': f'Method: {method}, Pattern: {pattern}',
                                            'recommendation': 'Remove sensitive data from API responses'
                                        })
                                        break
                            
                            # Check for Swagger/OpenAPI documentation
                            if any(keyword in response.text.lower() for keyword in ['swagger', 'openapi', 'api-docs']):
                                vulnerabilities.append({
                                    'type': 'Exposed API Documentation',
                                    'severity': 'Low',
                                    'location': full_url,
                                    'description': 'API documentation is publicly accessible',
                                    'evidence': f'Documentation found at {full_url}',
                                    'recommendation': 'Restrict access to API documentation'
                                })
                        
                        # Check for method not allowed responses
                        elif response.status_code == 405:
                            allowed_methods = response.headers.get('Allow', '')
                            if 'DELETE' in allowed_methods or 'PUT' in allowed_methods:
                                vulnerabilities.append({
                                    'type': 'Dangerous HTTP Methods Allowed',
                                    'severity': 'Medium',
                                    'location': full_url,
                                    'description': f'Dangerous HTTP methods allowed: {allowed_methods}',
                                    'evidence': f'Allow header: {allowed_methods}',
                                    'recommendation': 'Restrict HTTP methods to only necessary ones'
                                })
                                
                    except requests.RequestException:
                        continue
                        
        except Exception as e:
            self.logger.warning(f"API fuzzing test error: {str(e)}")
            
        return vulnerabilities
    
    def test_subresource_integrity(self, target_url: str) -> List[Dict[str, Any]]:
        """Test for Subresource Integrity implementation"""
        vulnerabilities = []
        
        try:
            response = self.session.get(target_url)
            
            if response.status_code == 200:
                content = response.text
                
                # Find script and link tags
                script_tags = re.findall(r'<script[^>]*src=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
                link_tags = re.findall(r'<link[^>]*href=["\']([^"\']*)["\'][^>]*>', content, re.IGNORECASE)
                
                external_scripts = [src for src in script_tags if src.startswith('http') and urlparse(src).netloc != urlparse(target_url).netloc]
                external_links = [href for href in link_tags if href.startswith('http') and urlparse(href).netloc != urlparse(target_url).netloc]
                
                # Check for SRI attributes
                for script_src in external_scripts:
                    script_pattern = rf'<script[^>]*src=["\']([^"\']*)["\'][^>]*>'
                    script_match = re.search(script_pattern, content, re.IGNORECASE)
                    
                    if script_match and 'integrity=' not in script_match.group():
                        vulnerabilities.append({
                            'type': 'Missing Subresource Integrity',
                            'severity': 'Medium',
                            'location': target_url,
                            'description': f'External script lacks SRI protection: {script_src}',
                            'evidence': f'Script source: {script_src}',
                            'recommendation': 'Add integrity attributes to external scripts and stylesheets'
                        })
                
                for link_href in external_links:
                    link_pattern = rf'<link[^>]*href=["\']([^"\']*)["\'][^>]*>'
                    link_match = re.search(link_pattern, content, re.IGNORECASE)
                    
                    if link_match and 'integrity=' not in link_match.group():
                        if 'stylesheet' in link_match.group().lower():
                            vulnerabilities.append({
                                'type': 'Missing Subresource Integrity',
                                'severity': 'Medium',
                                'location': target_url,
                                'description': f'External stylesheet lacks SRI protection: {link_href}',
                                'evidence': f'Stylesheet href: {link_href}',
                                'recommendation': 'Add integrity attributes to external stylesheets'
                            })
                            
        except Exception as e:
            self.logger.warning(f"Subresource integrity test error: {str(e)}")
            
        return vulnerabilities 