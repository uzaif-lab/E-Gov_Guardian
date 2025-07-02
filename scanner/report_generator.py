"""
Report Generator for Security Scan Results
"""

import json
import csv
import html
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

class ReportGenerator:
    """Generate formatted reports from scan results"""
    
    def __init__(self):
        pass
    
    def generate(self, scan_results: Dict[str, Any], output_path: str, config: Dict[str, Any]) -> str:
        """Generate report in specified format"""
        format_type = config.get('output_format', 'json').lower()
        
        if format_type == 'html':
            return self._generate_html_report(scan_results, output_path, config)
        elif format_type == 'csv':
            return self._generate_csv_report(scan_results, output_path, config)
        else:
            return self._generate_json_report(scan_results, output_path, config)
    
    def _generate_json_report(self, results: Dict[str, Any], output_path: str, config: Dict[str, Any]) -> str:
        """Generate JSON report"""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        return output_path
    
    def _generate_html_report(self, results: Dict[str, Any], output_path: str, config: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html_content = self._create_html_template(results, config)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return output_path
    
    def _generate_csv_report(self, results: Dict[str, Any], output_path: str, config: Dict[str, Any]) -> str:
        """Generate CSV report"""
        vulnerabilities = []
        
        # Extract vulnerabilities from different sources
        if 'results' in results:
            scan_results = results['results']
            
            # ZAP vulnerabilities
            if 'zap_scan' in scan_results and 'vulnerabilities' in scan_results['zap_scan']:
                zap_vulns = scan_results['zap_scan']['vulnerabilities']
                if 'all_alerts' in zap_vulns:
                    for alert in zap_vulns['all_alerts']:
                        vulnerabilities.append({
                            'Type': 'ZAP Alert',
                            'Name': alert.get('alert', 'Unknown'),
                            'Risk': alert.get('risk', 'Unknown'),
                            'Confidence': alert.get('confidence', 'Unknown'),
                            'URL': alert.get('url', ''),
                            'Description': alert.get('desc', '')[:100] + '...' if len(alert.get('desc', '')) > 100 else alert.get('desc', '')
                        })
            
            # Security headers
            if 'security_headers' in scan_results:
                for header in scan_results['security_headers'].get('missing_headers', []):
                    vulnerabilities.append({
                        'Type': 'Missing Security Header',
                        'Name': header['header'],
                        'Risk': header['severity'],
                        'Confidence': 'High',
                        'URL': results.get('target', ''),
                        'Description': header['description']
                    })
        
        # Write CSV
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            if vulnerabilities:
                fieldnames = vulnerabilities[0].keys()
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(vulnerabilities)
        
        return output_path
    
    def _create_html_template(self, results: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Create HTML report template"""
        
        # Get summary info
        summary = results.get('summary', {})
        target = results.get('target', 'Unknown')
        scan_type = results.get('scan_type', 'Unknown')
        timestamp = results.get('timestamp', datetime.now().isoformat())
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>E-Gov Guardian Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; border-left: 4px solid #007bff; }}
        .high-risk {{ border-left-color: #dc3545; }}
        .medium-risk {{ border-left-color: #ffc107; }}
        .low-risk {{ border-left-color: #28a745; }}
        .vulnerability-section {{ margin-bottom: 30px; }}
        .vulnerability-item {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; margin-bottom: 10px; overflow: hidden; }}
        .vulnerability-header {{ padding: 15px; background: #f8f9fa; cursor: pointer; display: flex; justify-content: between; align-items: center; }}
        .vulnerability-content {{ padding: 15px; display: none; }}
        .risk-high {{ background: #f8d7da; }}
        .risk-medium {{ background: #fff3cd; }}
        .risk-low {{ background: #d4edda; }}
        .toggle {{ font-size: 18px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; }}
    </style>
    <script>
        function toggleVulnerability(id) {{
            var content = document.getElementById(id);
            var toggle = document.getElementById(id + '_toggle');
            if (content.style.display === 'none' || content.style.display === '') {{
                content.style.display = 'block';
                toggle.innerHTML = '−';
            }} else {{
                content.style.display = 'none';
                toggle.innerHTML = '+';
            }}
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ E-Gov Guardian Security Report</h1>
            <p><strong>Target:</strong> {html.escape(target)}</p>
            <p><strong>Scan Type:</strong> {html.escape(scan_type.title())}</p>
            <p><strong>Generated:</strong> {timestamp}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card high-risk">
                <h3>High Risk</h3>
                <div style="font-size: 24px; font-weight: bold;">{summary.get('high_risk_issues', 0)}</div>
            </div>
            <div class="summary-card medium-risk">
                <h3>Medium Risk</h3>
                <div style="font-size: 24px; font-weight: bold;">{summary.get('medium_risk_issues', 0)}</div>
            </div>
            <div class="summary-card low-risk">
                <h3>Low Risk</h3>
                <div style="font-size: 24px; font-weight: bold;">{summary.get('low_risk_issues', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Total Issues</h3>
                <div style="font-size: 24px; font-weight: bold;">{summary.get('total_vulnerabilities', 0)}</div>
            </div>
        </div>
"""
        
        # Add vulnerability sections
        if 'results' in results:
            scan_results = results['results']
            
            # ZAP Results
            if 'zap_scan' in scan_results:
                html += self._generate_zap_section(scan_results['zap_scan'])
            
            # Security Headers
            if 'security_headers' in scan_results:
                html += self._generate_headers_section(scan_results['security_headers'])
            
            # Cookie Security
            if 'cookie_security' in scan_results:
                html += self._generate_cookies_section(scan_results['cookie_security'])
            
            # SSL Issues
            if 'ssl_configuration' in scan_results:
                html += self._generate_ssl_section(scan_results['ssl_configuration'])
            
            # Port Scan
            if 'port_scan' in scan_results:
                html += self._generate_ports_section(scan_results['port_scan'])
            
            # Code Patterns
            if 'code_patterns' in scan_results:
                html += self._generate_code_section(scan_results['code_patterns'])
        
        html += """
        </div>
    </body>
    </html>
    """
        
        return html
    
    def _generate_zap_section(self, zap_results: Dict[str, Any]) -> str:
        """Generate ZAP scan results section"""
        html = '<div class="vulnerability-section"><h2>🕷️ ZAP Security Scan Results</h2>'
        
        vulnerabilities = zap_results.get('vulnerabilities', {})
        all_alerts = vulnerabilities.get('all_alerts', [])
        
        if all_alerts:
            for i, alert in enumerate(all_alerts):
                risk_class = f"risk-{alert.get('risk', 'low').lower()}"
                html += f'''
                <div class="vulnerability-item">
                    <div class="vulnerability-header {risk_class}" onclick="toggleVulnerability('zap_{i}')">
                        <div>
                            <strong>{html.escape(alert.get('alert', 'Unknown'))}</strong>
                            <span style="margin-left: 10px; padding: 4px 8px; background: white; border-radius: 4px; font-size: 12px;">
                                {alert.get('risk', 'Unknown')} Risk
                            </span>
                        </div>
                        <span class="toggle" id="zap_{i}_toggle">+</span>
                    </div>
                    <div class="vulnerability-content" id="zap_{i}">
                        <p><strong>URL:</strong> {html.escape(alert.get('url', 'N/A'))}</p>
                        <p><strong>Description:</strong> {html.escape(alert.get('desc', 'No description available'))}</p>
                        <p><strong>Solution:</strong> {html.escape(alert.get('solution', 'No solution provided'))}</p>
                        <p><strong>Confidence:</strong> {alert.get('confidence', 'Unknown')}</p>
                    </div>
                </div>
                '''
        else:
            html += '<p>No ZAP vulnerabilities found.</p>'
        
        html += '</div>'
        return html
    
    def _generate_headers_section(self, headers_results: Dict[str, Any]) -> str:
        """Generate security headers section"""
        html = '<div class="vulnerability-section"><h2>🔒 Security Headers Analysis</h2>'
        
        missing_headers = headers_results.get('missing_headers', [])
        
        if missing_headers:
            for i, header in enumerate(missing_headers):
                html += f'''
                <div class="vulnerability-item">
                    <div class="vulnerability-header risk-medium" onclick="toggleVulnerability('header_{i}')">
                        <div>
                            <strong>Missing Header: {html.escape(header['header'])}</strong>
                            <span style="margin-left: 10px; padding: 4px 8px; background: white; border-radius: 4px; font-size: 12px;">
                                {header['severity']} Risk
                            </span>
                        </div>
                        <span class="toggle" id="header_{i}_toggle">+</span>
                    </div>
                    <div class="vulnerability-content" id="header_{i}">
                        <p><strong>Description:</strong> {html.escape(header['description'])}</p>
                        <p><strong>Impact:</strong> This missing header could allow various client-side attacks.</p>
                    </div>
                </div>
                '''
        else:
            html += '<p>✅ All important security headers are present.</p>'
        
        html += '</div>'
        return html
    
    def _generate_cookies_section(self, cookies_results: Dict[str, Any]) -> str:
        """Generate cookie security section"""
        html = '<div class="vulnerability-section"><h2>🍪 Cookie Security Analysis</h2>'
        
        insecure_cookies = cookies_results.get('insecure_cookies', [])
        
        if insecure_cookies:
            for i, cookie in enumerate(insecure_cookies):
                html += f'''
                <div class="vulnerability-item">
                    <div class="vulnerability-header risk-medium" onclick="toggleVulnerability('cookie_{i}')">
                        <div>
                            <strong>Insecure Cookie: {html.escape(cookie['name'])}</strong>
                            <span style="margin-left: 10px; padding: 4px 8px; background: white; border-radius: 4px; font-size: 12px;">
                                {cookie['severity']} Risk
                            </span>
                        </div>
                        <span class="toggle" id="cookie_{i}_toggle">+</span>
                    </div>
                    <div class="vulnerability-content" id="cookie_{i}">
                        <p><strong>Domain:</strong> {html.escape(str(cookie['domain']))}</p>
                        <p><strong>Issues:</strong> {', '.join(cookie['issues'])}</p>
                        <p><strong>Recommendation:</strong> Configure proper cookie security flags.</p>
                    </div>
                </div>
                '''
        else:
            html += '<p>✅ No insecure cookies detected.</p>'
        
        html += '</div>'
        return html
    
    def _generate_ssl_section(self, ssl_results: Dict[str, Any]) -> str:
        """Generate SSL configuration section"""
        html = '<div class="vulnerability-section"><h2>🔐 SSL/TLS Configuration</h2>'
        
        ssl_issues = ssl_results.get('ssl_issues', [])
        
        if ssl_issues:
            for i, issue in enumerate(ssl_issues):
                risk_class = f"risk-{issue['severity'].lower()}"
                html += f'''
                <div class="vulnerability-item">
                    <div class="vulnerability-header {risk_class}">
                        <div>
                            <strong>SSL Issue</strong>
                            <span style="margin-left: 10px; padding: 4px 8px; background: white; border-radius: 4px; font-size: 12px;">
                                {issue['severity']} Risk
                            </span>
                        </div>
                    </div>
                    <div class="vulnerability-content" style="display: block;">
                        <p>{html.escape(issue['issue'])}</p>
                    </div>
                </div>
                '''
        else:
            html += '<p>✅ SSL/TLS configuration appears secure.</p>'
        
        html += '</div>'
        return html
    
    def _generate_ports_section(self, ports_results: Dict[str, Any]) -> str:
        """Generate open ports section"""
        html = '<div class="vulnerability-section"><h2>🌐 Open Ports Analysis</h2>'
        
        open_ports = ports_results.get('open_ports', [])
        
        if open_ports:
            html += '<table><thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Risk Level</th></tr></thead><tbody>'
            for port in open_ports:
                risk_class = f"risk-{port['risk_level'].lower()}"
                html += f'''
                <tr class="{risk_class}">
                    <td>{port['port']}</td>
                    <td>{html.escape(port['service'])}</td>
                    <td>{html.escape(port['version'])}</td>
                    <td>{port['risk_level']}</td>
                </tr>
                '''
            html += '</tbody></table>'
        else:
            html += '<p>No open ports detected in scan range.</p>'
        
        html += '</div>'
        return html
    
    def _generate_code_section(self, code_results: Dict[str, Any]) -> str:
        """Generate code analysis section"""
        html = '<div class="vulnerability-section"><h2>💻 Code Security Analysis</h2>'
        
        total_issues = code_results.get('total_issues', 0)
        
        if total_issues > 0:
            # SQL Injection patterns
            sql_issues = code_results.get('sql_injection', [])
            if sql_issues:
                html += '<h3>SQL Injection Patterns</h3>'
                for issue in sql_issues:
                    html += f'<p>📄 <strong>{html.escape(issue["file"])}:{issue["line"]}</strong> - {html.escape(issue["match"][:50])}...</p>'
            
            # XSS patterns
            xss_issues = code_results.get('xss_vulnerabilities', [])
            if xss_issues:
                html += '<h3>XSS Vulnerability Patterns</h3>'
                for issue in xss_issues:
                    html += f'<p>📄 <strong>{html.escape(issue["file"])}:{issue["line"]}</strong> - {html.escape(issue["match"][:50])}...</p>'
            
            # Hardcoded secrets
            secret_issues = code_results.get('hardcoded_secrets', [])
            if secret_issues:
                html += '<h3>Hardcoded Secrets</h3>'
                for issue in secret_issues:
                    html += f'<p>📄 <strong>{html.escape(issue["file"])}:{issue["line"]}</strong> - Potential hardcoded secret detected</p>'
        else:
            html += '<p>✅ No obvious code security issues detected.</p>'
        
        html += '</div>'
        return html 