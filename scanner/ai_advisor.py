"""
AI Fix Advisor - OpenAI Integration for Security Recommendations
Provides intelligent fix recommendations for detected vulnerabilities
"""

import logging
import time
from typing import Dict, List, Any, Optional
from openai import OpenAI

class AIFixAdvisor:
    """AI-powered vulnerability fix advisor using OpenAI GPT-3.5-turbo"""
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", max_tokens: int = 150, temperature: float = 0.1):
        self.logger = logging.getLogger(__name__)
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        
    def analyze_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process scan results and add AI recommendations"""
        if not self._is_api_available():
            self.logger.warning("OpenAI API not available, skipping AI analysis")
            # Add AI analysis status to scan results
            scan_results['ai_analysis_status'] = {
                'attempted': True,
                'successful': False,
                'error': 'OpenAI API not available',
                'recommendations_count': 0
            }
            return scan_results
            
        self.logger.info("🧠 Starting AI analysis for vulnerability recommendations...")
        
        total_processed = 0
        total_failures = 0
        
        # Process different types of vulnerabilities
        if 'results' in scan_results:
            results = scan_results['results']
            
            # Process built-in scanner vulnerabilities
            if 'vulnerability_scan' in results:
                vuln_scan = results['vulnerability_scan']
                if 'vulnerabilities' in vuln_scan:
                    for vuln_type, vulns in vuln_scan['vulnerabilities'].items():
                        if isinstance(vulns, list) and vulns:
                            self.logger.info(f"🔍 Processing {len(vulns)} {vuln_type} vulnerabilities")
                            for vuln in vulns:
                                recommendation = self._get_vulnerability_recommendation(vuln_type, vuln)
                                if recommendation:
                                    vuln['ai_recommendation'] = recommendation
                                    total_processed += 1
                                else:
                                    total_failures += 1
            
            # Process security headers issues
            if 'security_headers' in results:
                headers_result = results['security_headers']
                if 'missing_headers' in headers_result:
                    header_count = len(headers_result['missing_headers'])
                    self.logger.info(f"🔍 Processing {header_count} security header issues")
                    for header_issue in headers_result['missing_headers']:
                        recommendation = self._get_header_recommendation(header_issue)
                        if recommendation:
                            header_issue['ai_recommendation'] = recommendation
                            total_processed += 1
                        else:
                            total_failures += 1
            
            # Process cookie security issues
            if 'cookie_security' in results:
                cookie_result = results['cookie_security']
                if 'insecure_cookies' in cookie_result:
                    cookie_count = len(cookie_result['insecure_cookies'])
                    self.logger.info(f"🔍 Processing {cookie_count} cookie security issues")
                    for cookie_issue in cookie_result['insecure_cookies']:
                        recommendation = self._get_cookie_recommendation(cookie_issue)
                        if recommendation:
                            cookie_issue['ai_recommendation'] = recommendation
                            total_processed += 1
                        else:
                            total_failures += 1
        
        # Add AI analysis status to scan results
        if total_processed > 0:
            self.logger.info(f"✅ AI analysis completed - {total_processed} recommendations generated")
            status_msg = f"✅ Successfully generated {total_processed} AI recommendations"
        else:
            self.logger.warning(f"⚠️ AI analysis failed - {total_failures} failures encountered")
            status_msg = f"⚠️ AI analysis failed - likely due to API quota or connectivity issues"
        
        scan_results['ai_analysis_status'] = {
            'attempted': True,
            'successful': total_processed > 0,
            'recommendations_count': total_processed,
            'failures_count': total_failures,
            'status_message': status_msg
        }
        
        return scan_results
    
    def _get_vulnerability_recommendation(self, vuln_type: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Get AI recommendation for a specific vulnerability"""
        try:
            prompt = self._create_vulnerability_prompt(vuln_type, vulnerability)
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Provide concise, actionable fix recommendations in 1-2 lines. Focus on exact code examples."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            recommendation = response.choices[0].message.content.strip()
            time.sleep(0.1)  # Rate limiting
            return recommendation
            
        except Exception as e:
            self.logger.warning(f"Failed to get AI recommendation for {vuln_type}: {str(e)}")
            return None
    
    def _get_header_recommendation(self, header_issue: Dict[str, Any]) -> Optional[str]:
        """Get AI recommendation for security header issues"""
        try:
            header_name = header_issue.get('header', 'Unknown')
            prompt = f"How to fix missing security header '{header_name}'? Provide exact header value and brief explanation in 1-2 lines."
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a web security expert. Provide exact HTTP header values and brief explanations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            recommendation = response.choices[0].message.content.strip()
            time.sleep(0.1)  # Rate limiting
            return recommendation
            
        except Exception as e:
            self.logger.warning(f"Failed to get header recommendation: {str(e)}")
            return None
    
    def _get_cookie_recommendation(self, cookie_issue: Dict[str, Any]) -> Optional[str]:
        """Get AI recommendation for cookie security issues"""
        try:
            cookie_name = cookie_issue.get('name', 'cookie')
            issues = cookie_issue.get('issues', [])
            prompt = f"Cookie '{cookie_name}' has issues: {', '.join(issues)}. How to fix? Provide exact cookie attribute in 1-2 lines."
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a web security expert. Provide exact cookie attributes and brief explanations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            recommendation = response.choices[0].message.content.strip()
            time.sleep(0.1)  # Rate limiting
            return recommendation
            
        except Exception as e:
            self.logger.warning(f"Failed to get cookie recommendation: {str(e)}")
            return None
    
    def _create_vulnerability_prompt(self, vuln_type: str, vulnerability: Dict[str, Any]) -> str:
        """Create a specific prompt for the vulnerability type"""
        base_info = f"Vulnerability: {vuln_type}\n"
        
        if 'url' in vulnerability:
            base_info += f"URL: {vulnerability['url']}\n"
        if 'parameter' in vulnerability:
            base_info += f"Parameter: {vulnerability['parameter']}\n"
        if 'payload' in vulnerability:
            base_info += f"Payload: {vulnerability['payload']}\n"
        if 'evidence' in vulnerability:
            base_info += f"Evidence: {vulnerability['evidence']}\n"
        
        vulnerability_prompts = {
            'sql_injection': f"{base_info}\nHow to fix this SQL injection? Provide exact parameterized query example in 1-2 lines.",
            'xss': f"{base_info}\nHow to prevent this XSS? Provide exact input sanitization code in 1-2 lines.",
            'directory_traversal': f"{base_info}\nHow to prevent directory traversal? Provide exact path validation code in 1-2 lines.",
            'command_injection': f"{base_info}\nHow to prevent command injection? Provide exact input validation code in 1-2 lines.",
            'http_methods': f"{base_info}\nHow to disable dangerous HTTP methods? Provide exact server configuration in 1-2 lines.",
            'information_disclosure': f"{base_info}\nHow to prevent this information disclosure? Provide exact fix in 1-2 lines."
        }
        
        return vulnerability_prompts.get(vuln_type, f"{base_info}\nHow to fix this vulnerability? Provide exact solution in 1-2 lines.")
    
    def _is_api_available(self) -> bool:
        """Check if OpenAI API is available"""
        try:
            # Simple test call
            self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1
            )
            return True
        except Exception as e:
            self.logger.error(f"OpenAI API unavailable: {str(e)}")
            return False 