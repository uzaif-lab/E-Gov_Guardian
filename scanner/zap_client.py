"""
ZAP API Client for security scanning
"""

import time
import json
import logging
from typing import Dict, List, Optional, Any
from zapv2 import ZAPv2
import requests
from urllib.parse import urlparse

class ZAPClient:
    """OWASP ZAP API Client for automated security scanning"""
    
    def __init__(self, host: str = "127.0.0.1", port: int = 8080, api_key: Optional[str] = None):
        self.host = host
        self.port = port
        self.api_key = api_key
        self.zap = ZAPv2(proxies={'http': f'http://{host}:{port}', 'https': f'http://{host}:{port}'})
        
        if api_key:
            self.zap.core.set_option_api_key(api_key)
            
        self.logger = logging.getLogger(__name__)
        
    def is_zap_running(self) -> bool:
        """Check if ZAP is running and accessible"""
        try:
            response = requests.get(f"http://{self.host}:{self.port}", timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
    
    def start_spider_scan(self, target_url: str, max_depth: int = 5) -> str:
        """Start spider scan to discover URLs"""
        self.logger.info(f"Starting spider scan for: {target_url}")
        
        # Add target to context
        context_id = self.zap.context.new_context("auto-scan-context")
        self.zap.context.include_in_context("auto-scan-context", f"{target_url}.*")
        
        # Start spider
        scan_id = self.zap.spider.scan(target_url, maxchildren=max_depth)
        return scan_id
    
    def wait_for_spider(self, scan_id: str, timeout: int = 300) -> bool:
        """Wait for spider scan to complete"""
        start_time = time.time()
        
        while int(self.zap.spider.status(scan_id)) < 100:
            if time.time() - start_time > timeout:
                self.logger.warning("Spider scan timeout")
                return False
            time.sleep(2)
            
        self.logger.info("Spider scan completed")
        return True
    
    def start_active_scan(self, target_url: str) -> str:
        """Start active security scan"""
        self.logger.info(f"Starting active scan for: {target_url}")
        scan_id = self.zap.ascan.scan(target_url)
        return scan_id
    
    def wait_for_active_scan(self, scan_id: str, timeout: int = 1800) -> bool:
        """Wait for active scan to complete"""
        start_time = time.time()
        
        while int(self.zap.ascan.status(scan_id)) < 100:
            if time.time() - start_time > timeout:
                self.logger.warning("Active scan timeout")
                return False
            
            progress = self.zap.ascan.status(scan_id)
            self.logger.info(f"Active scan progress: {progress}%")
            time.sleep(10)
            
        self.logger.info("Active scan completed")
        return True
    
    def get_alerts(self, risk_level: str = "Medium") -> List[Dict[str, Any]]:
        """Get security alerts from ZAP"""
        alerts = self.zap.core.alerts()
        
        # Filter by risk level if specified
        if risk_level:
            risk_levels = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
            min_risk = risk_levels.get(risk_level, 2)
            alerts = [alert for alert in alerts if int(alert.get('risk', 0)) >= min_risk]
            
        return alerts
    
    def get_vulnerabilities_by_type(self, vuln_type: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities filtered by type"""
        all_alerts = self.get_alerts()
        
        # Common vulnerability mappings
        vuln_mappings = {
            'sql_injection': ['SQL Injection', 'SQL', 'Injection'],
            'xss': ['Cross Site Scripting', 'XSS', 'Script'],
            'csrf': ['Cross Site Request', 'CSRF'],
            'directory_traversal': ['Path Traversal', 'Directory'],
            'weak_authentication': ['Authentication', 'Weak Password']
        }
        
        if vuln_type not in vuln_mappings:
            return []
            
        keywords = vuln_mappings[vuln_type]
        filtered_alerts = []
        
        for alert in all_alerts:
            alert_name = alert.get('alert', '').lower()
            if any(keyword.lower() in alert_name for keyword in keywords):
                filtered_alerts.append(alert)
                
        return filtered_alerts
    
    def scan_url(self, target_url: str, scan_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform complete security scan on URL"""
        results = {
            'target_url': target_url,
            'scan_start_time': time.time(),
            'spider_results': {},
            'vulnerabilities': {},
            'scan_status': 'started'
        }
        
        try:
            # Start spider scan
            spider_id = self.start_spider_scan(target_url, scan_config.get('max_depth', 5))
            spider_success = self.wait_for_spider(spider_id, scan_config.get('timeout', 300))
            
            results['spider_results'] = {
                'success': spider_success,
                'urls_found': len(self.zap.core.urls())
            }
            
            if spider_success:
                # Start active scan
                active_scan_id = self.start_active_scan(target_url)
                scan_success = self.wait_for_active_scan(active_scan_id, scan_config.get('timeout', 1800))
                
                if scan_success:
                    # Get vulnerability results
                    results['vulnerabilities'] = {
                        'sql_injection': self.get_vulnerabilities_by_type('sql_injection'),
                        'xss': self.get_vulnerabilities_by_type('xss'),
                        'csrf': self.get_vulnerabilities_by_type('csrf'),
                        'all_alerts': self.get_alerts(scan_config.get('severity_threshold', 'Medium'))
                    }
                    results['scan_status'] = 'completed'
                else:
                    results['scan_status'] = 'timeout'
            else:
                results['scan_status'] = 'spider_failed'
                
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
            results['scan_status'] = 'error'
            results['error'] = str(e)
            
        results['scan_end_time'] = time.time()
        results['scan_duration'] = results['scan_end_time'] - results['scan_start_time']
        
        return results
    
    def generate_report(self, format_type: str = "json") -> str:
        """Generate scan report in specified format"""
        if format_type.lower() == "html":
            return self.zap.core.htmlreport()
        elif format_type.lower() == "xml":
            return self.zap.core.xmlreport()
        else:
            # JSON format
            alerts = self.get_alerts()
            return json.dumps(alerts, indent=2) 