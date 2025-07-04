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
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo", max_tokens: int = 1000, temperature: float = 0.1):
        self.logger = logging.getLogger(__name__)
        self.client = OpenAI(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        
    def analyze_vulnerabilities(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Process scan results and provide AI-powered recommendations"""
        try:
            vulnerabilities = scan_results.get('vulnerabilities', [])
            scan_type = scan_results.get('scan_type', 'general')
            
            # Process each vulnerability
            for vuln in vulnerabilities:
                recommendation = self._get_vulnerability_recommendation(
                    vuln_type=vuln['type'],
                    vulnerability=vuln
                )
                if recommendation:
                    vuln['ai_recommendation'] = recommendation
            
            # Generate overall analysis
            analysis = {
                'recommendations': [],
                'summary': '',
                'ai_analysis_status': {
                    'processed_vulnerabilities': len(vulnerabilities),
                    'recommendations_generated': len([v for v in vulnerabilities if 'ai_recommendation' in v]),
                    'scan_type': scan_type
                }
            }
            
            # Get overall recommendations
            if vulnerabilities:
                analysis['recommendations'] = self._get_overall_recommendations(scan_results)
                analysis['summary'] = self._generate_executive_summary(scan_results)
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in AI analysis: {str(e)}")
            return {
                'error': str(e),
                'recommendations': [],
                'summary': 'AI analysis failed'
            }
    
    def _get_vulnerability_recommendation(self, vuln_type: str, vulnerability: Dict[str, Any]) -> Optional[str]:
        """Get detailed recommendation for a specific vulnerability"""
        try:
            # Prepare vulnerability context
            scan_type = vulnerability.get('scan_type', 'general')
            auth_methods = vulnerability.get('auth_methods', [])
            auth_context = vulnerability.get('authentication_context', {})
            
            # Build prompt based on scan type
            if scan_type == 'estonian_login':
                prompt = self._build_estonian_prompt(vulnerability, auth_methods, auth_context)
            else:
                prompt = self._build_general_prompt(vulnerability)
            
            # Get AI recommendation
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in authentication systems and Estonian e-ID services. Provide detailed, actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            self.logger.error(f"Error getting recommendation: {str(e)}")
            return None
    
    def _build_estonian_prompt(self, vulnerability: Dict[str, Any], auth_methods: List[str], auth_context: Dict[str, Any]) -> str:
        """Build detailed prompt for Estonian authentication vulnerabilities"""
        vuln_type = vulnerability.get('type', '')
        description = vulnerability.get('description', '')
        severity = vulnerability.get('severity', 'MEDIUM')
        affected_methods = auth_context.get('affected_methods', [])
        impact_level = auth_context.get('impact_level', 'Unknown')
        auth_flow = auth_context.get('authentication_flow', 'Unknown')
        
        prompt = f"""Analyze this Estonian authentication security issue and provide detailed recommendations:

VULNERABILITY DETAILS:
- Type: {vuln_type}
- Description: {description}
- Severity: {severity}
- Impact Level: {impact_level}
- Authentication Flow: {auth_flow}
- Affected Methods: {', '.join(affected_methods)}
- Available Auth Methods: {', '.join(auth_methods)}

Please provide a comprehensive security recommendation including:

1. DETAILED ISSUE ANALYSIS:
- Explain the security implications specific to Estonian e-ID authentication
- Describe how this affects each impacted authentication method
- Outline potential attack scenarios

2. TECHNICAL SOLUTION:
- Step-by-step fix instructions with code examples where relevant
- Configuration changes needed
- Security headers or parameters to implement
- Validation and verification steps

3. AUTHENTICATION-SPECIFIC MEASURES:
- e-ID specific security controls
- Mobile-ID specific configurations
- Smart-ID specific requirements
- Cross-method security considerations

4. COMPLIANCE REQUIREMENTS:
- eIDAS regulation requirements
- Estonian Trust Services compliance
- GDPR considerations
- Technical standards to follow

5. BEST PRACTICES:
- Industry standard security controls
- Estonian authentication best practices
- Monitoring and logging recommendations
- Security testing procedures

Format the response with clear sections and actionable steps."""
        
        return prompt
    
    def _build_general_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """Build prompt for general vulnerabilities"""
        base_info = f"Vulnerability Type: {vulnerability.get('type', '')}\n"
        
        # Add all available vulnerability information
        for key, value in vulnerability.items():
            if key not in ['ai_recommendation', 'type'] and value:
                base_info += f"{key.replace('_', ' ').title()}: {value}\n"
        
        return base_info
    
    def _get_overall_recommendations(self, scan_results: Dict[str, Any]) -> List[str]:
        """Generate overall recommendations based on all findings"""
        try:
            scan_type = scan_results.get('scan_type', 'general')
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            if scan_type == 'estonian_login':
                auth_methods = scan_results.get('authentication_methods_found', [])
                
                # Build comprehensive prompt for Estonian authentication
                prompt = f"""Analyze these security findings for an Estonian authentication system:

SCAN CONTEXT:
- Authentication Methods: {', '.join(auth_methods)}
- Total Vulnerabilities: {len(vulnerabilities)}
- High Severity Issues: {len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])}

Provide comprehensive recommendations covering:

1. OVERALL SECURITY ASSESSMENT:
- System-wide security posture
- Critical areas needing immediate attention
- Authentication flow security

2. METHOD-SPECIFIC RECOMMENDATIONS:
- e-ID security improvements
- Mobile-ID security enhancements
- Smart-ID security measures
- Cross-method security controls

3. COMPLIANCE AND STANDARDS:
- eIDAS compliance measures
- Estonian Trust Services requirements
- GDPR compliance steps
- Technical standards implementation

4. SECURITY HARDENING:
- Infrastructure security
- API security
- Client-side security
- Monitoring and incident response

Please provide detailed, actionable recommendations with specific steps and examples."""
                
            else:
                # ... existing general prompt ...
                pass
            
            # Get AI recommendations
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in authentication systems and Estonian e-ID services. Provide detailed, actionable security recommendations."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            # Parse and format recommendations
            recommendations = response.choices[0].message.content.strip().split('\n\n')
            return [rec.strip() for rec in recommendations if rec.strip()]
            
        except Exception as e:
            self.logger.error(f"Error generating overall recommendations: {str(e)}")
            return []
    
    def _generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate an executive summary of the security assessment"""
        try:
            scan_type = scan_results.get('scan_type', 'general')
            vulnerabilities = scan_results.get('vulnerabilities', [])
            
            if scan_type == 'estonian_login':
                auth_methods = scan_results.get('authentication_methods_found', [])
                high_severity = len([v for v in vulnerabilities if v.get('severity') == 'HIGH'])
                medium_severity = len([v for v in vulnerabilities if v.get('severity') == 'MEDIUM'])
                
                prompt = f"""Generate an executive summary for an Estonian authentication security assessment:

SCAN OVERVIEW:
- Authentication Methods: {', '.join(auth_methods)}
- Total Issues: {len(vulnerabilities)}
- High Severity: {high_severity}
- Medium Severity: {medium_severity}

Create a concise executive summary that covers:
1. Overall security posture
2. Critical findings and their impact
3. Authentication system security
4. Compliance status
5. Key recommendations

Focus on business impact and risk levels. Be specific about Estonian e-ID implications."""
                
            else:
                # ... existing general prompt ...
                pass
            
            # Get AI summary
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert specializing in authentication systems and Estonian e-ID services. Provide clear, business-focused security assessments."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=500,
                temperature=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            self.logger.error(f"Error generating executive summary: {str(e)}")
            return "Failed to generate executive summary" 