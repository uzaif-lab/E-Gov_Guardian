#!/usr/bin/env python3
"""
E-Gov Guardian Web Interface
A web-based security scanner with PDF report generation
"""

import threading
import uuid
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, session, g
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, URL

# Core modules
from scanner.main_scanner import SecurityScanner
from scanner.estonian_login_scanner import EstonianLoginScanner

# Simple i18n helper
from scanner.i18n import translate

app = Flask(__name__)
app.secret_key = 'egov-guardian-security-scanner-in-memory-2024'

# ---------------------------------------------------------------------------
# Internationalisation helpers
# ---------------------------------------------------------------------------


@app.before_request
def _set_request_language():
    """Determine the current language for the request (defaults to *en*)."""
    lang = session.get('lang', 'en')
    if lang not in ('en', 'et'):
        lang = 'en'
    g.lang = lang


@app.context_processor
def _inject_translation_helpers():
    """Expose translator *t* and *current_lang* in all Jinja templates."""
    return {
        't': lambda key: translate(key, g.get('lang', 'en')),
        'current_lang': g.get('lang', 'en'),
    }


# Simple route to switch UI language
@app.route('/set-language/<lang_code>')
def set_language(lang_code: str):
    if lang_code not in ('en', 'et'):
        lang_code = 'en'
    session['lang'] = lang_code
    # Redirect back to referrer or homepage
    referrer = request.referrer or url_for('index')
    return redirect(referrer)

# In-memory operation - no file storage

def load_scan_status():
    """Load scan status from in-memory global storage"""
    return scan_status

def save_scan_status(status_dict):
    """Save scan status to in-memory global storage"""
    global scan_status
    scan_status.update(status_dict)

def load_scan_results():
    """Load scan results from in-memory global storage"""
    return scan_results

def save_scan_results(results_dict):
    """Save scan results to in-memory global storage"""
    global scan_results
    scan_results.update(results_dict)
    cleanup_old_scans()

def cleanup_old_scans():
    """Clean up scan data older than 2 hours to prevent memory buildup"""
    current_time = time.time()
    cutoff_time = current_time - (2 * 60 * 60)  # 2 hours ago
    
    # Clean up old scan statuses
    global scan_status, scan_results
    scan_status = {k: v for k, v in scan_status.items() 
                   if v.get('timestamp', current_time) > cutoff_time}
    
    # Clean up old scan results
    scan_results = {k: v for k, v in scan_results.items() 
                    if v.get('scan_info', {}).get('timestamp_numeric', current_time) > cutoff_time}

def transform_scanner_results(scanner_output):
    """Transform scanner output to match web template format"""
    # Extract vulnerabilities from scanner results
    vulnerabilities = []
    ai_analysis_attempted = scanner_output.get('ai_analysis_enabled', False)
    ai_recommendations_found = 0
    
    # Get vulnerabilities from different scan sources
    if 'results' in scanner_output:
        results = scanner_output['results']
        
        # From ZAP scan
        if 'zap_scan' in results and 'vulnerabilities' in results['zap_scan']:
            zap_vulns = results['zap_scan']['vulnerabilities']
            if 'all_alerts' in zap_vulns:
                for alert in zap_vulns['all_alerts']:
                    vulnerabilities.append({
                        'type': alert.get('alert', 'Unknown Alert'),
                        'severity': alert.get('risk', 'Medium').upper(),
                        'description': alert.get('desc', 'No description available'),
                        'location': alert.get('url', ''),
                        'details': alert.get('solution', 'No solution provided'),
                        'remediation': alert.get('solution', 'No remediation provided')
                    })
        
        # From built-in vulnerability scan
        if 'vulnerability_scan' in results and 'vulnerabilities' in results['vulnerability_scan']:
            builtin_vulns = results['vulnerability_scan']['vulnerabilities']
            for vuln_type, vuln_list in builtin_vulns.items():
                if isinstance(vuln_list, list):
                    for vuln in vuln_list:
                        # Check for AI recommendation
                        ai_recommendation = vuln.get('ai_recommendation', '')
                        if ai_recommendation:
                            ai_recommendations_found += 1
                        
                        remediation = ai_recommendation if ai_recommendation else f'Fix {vuln_type} vulnerability'
                        
                        vulnerabilities.append({
                            'type': vuln_type.replace('_', ' ').title(),
                            'severity': vuln.get('risk', 'MEDIUM').upper(),
                            'description': vuln.get('description', f'{vuln_type} vulnerability detected'),
                            'location': vuln.get('url', ''),
                            'details': vuln.get('payload', ''),
                            'remediation': remediation,
                            'ai_powered': bool(ai_recommendation)
                        })
        
        # From security headers
        if 'security_headers' in results and 'missing_headers' in results['security_headers']:
            for header in results['security_headers']['missing_headers']:
                # Check for AI recommendation
                ai_recommendation = header.get('ai_recommendation', '')
                if ai_recommendation:
                    ai_recommendations_found += 1
                    
                remediation = ai_recommendation if ai_recommendation else 'Add the missing security header'
                
                vulnerabilities.append({
                    'type': f'Missing Security Header: {header.get("header", "Unknown")}',
                    'severity': header.get('severity', 'MEDIUM').upper(),
                    'description': header.get('description', 'Missing security header'),
                    'location': scanner_output.get('target', ''),
                    'details': f'Header: {header.get("header", "Unknown")}',
                    'remediation': remediation,
                    'ai_powered': bool(ai_recommendation)
                })
        
        # From cookie security
        if 'cookie_security' in results and 'insecure_cookies' in results['cookie_security']:
            for cookie in results['cookie_security']['insecure_cookies']:
                # Check for AI recommendation
                ai_recommendation = cookie.get('ai_recommendation', '')
                if ai_recommendation:
                    ai_recommendations_found += 1
                    
                remediation = ai_recommendation if ai_recommendation else 'Set secure cookie flags (Secure, HttpOnly, SameSite)'
                
                vulnerabilities.append({
                    'type': 'Insecure Cookie Configuration',
                    'severity': cookie.get('severity', 'MEDIUM').upper(),
                    'description': cookie.get('issue', 'Cookie security issue'),
                    'location': scanner_output.get('target', ''),
                    'details': f'Cookie: {cookie.get("name", "Unknown")}',
                    'remediation': remediation,
                    'ai_powered': bool(ai_recommendation)
                })
        
        # From advanced security tests
        if 'advanced_tests' in results and 'vulnerabilities' in results['advanced_tests']:
            for vuln in results['advanced_tests']['vulnerabilities']:
                # Check for AI recommendation (if AI analysis was performed on these)
                ai_recommendation = vuln.get('ai_recommendation', '')
                if ai_recommendation:
                    ai_recommendations_found += 1
                    
                remediation = ai_recommendation if ai_recommendation else vuln.get('recommendation', 'Address the security issue')
                
                vulnerabilities.append({
                    'type': vuln.get('type', 'Security Issue'),
                    'severity': vuln.get('severity', 'MEDIUM').upper(),
                    'description': vuln.get('description', 'Security vulnerability detected'),
                    'location': vuln.get('location', scanner_output.get('target', '')),
                    'details': vuln.get('evidence', 'See vulnerability details'),
                    'remediation': remediation,
                    'ai_powered': bool(ai_recommendation)
                })

    # Get summary data
    summary = scanner_output.get('summary', {})
    
    # Determine AI analysis status message
    ai_status_message = ""
    if ai_analysis_attempted:
        if ai_recommendations_found > 0:
            ai_status_message = f"✅ AI analysis completed - {ai_recommendations_found} AI-powered recommendations generated"
        else:
            ai_status_message = "⚠️ AI analysis attempted but failed (likely due to OpenAI API quota limits or connectivity issues)"
    else:
        ai_status_message = "ℹ️ AI analysis not requested for this scan"
    
    # Calculate severity counts
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'MEDIUM').upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Transform to template format
    web_format = {
        'target': scanner_output.get('target', ''),
        'risk_rating': scanner_output.get('risk_rating', 'Unknown').title(),
        'compliance_score': scanner_output.get('compliance_score', 0),
        'executive_summary': {
            'total_vulnerabilities': len(vulnerabilities),
            'high_risk_issues': severity_counts['HIGH'],
            'medium_risk_issues': severity_counts['MEDIUM'],
            'low_risk_issues': severity_counts['LOW'],
            'recommendations': scanner_output.get('recommendations', [])[:5]  # Limit to top 5
        },
        'vulnerabilities': vulnerabilities,
        'scan_info': {
            'timestamp': scanner_output.get('timestamp', ''),
            'scanner_version': scanner_output.get('scanner_version', '2.0.0'),
            'duration': scanner_output.get('scan_duration', '0'),
            'scan_type': scanner_output.get('scan_type', 'web_application'),
            'total_checks': len(vulnerabilities) + 10,  # Estimate
            'ai_analysis_attempted': ai_analysis_attempted,
            'ai_recommendations_count': ai_recommendations_found,
            'ai_status_message': ai_status_message
        }
    }
    
    return web_format

# In-memory global storage
scan_status = {}
scan_results = {}

class ScanForm(FlaskForm):
    """Form for URL scanning with test selection"""
    target_url = StringField('Target URL', validators=[DataRequired(), URL()], 
                            render_kw={"placeholder": "https://example.com"})
    deep_scan = BooleanField('Deep Scan (More thorough but slower)')
    ai_analysis = BooleanField('🧠 AI Fix Advisor (Get AI-powered fix recommendations)')
    scan_type = SelectField('Scan Type', choices=[('url', 'Web Application')])
    
    # Core Vulnerability Tests
    test_sql_injection = BooleanField('SQL Injection Detection')
    test_xss = BooleanField('Cross-Site Scripting (XSS)')
    test_csrf = BooleanField('CSRF Detection')
    test_headers = BooleanField('Missing Security Headers')
    test_cors = BooleanField('CORS Policy Testing')
    
    # Advanced & API Tests
    test_open_redirect = BooleanField('Open Redirects')
    test_host_header = BooleanField('Host Header Injection')
    test_api_fuzzing = BooleanField('API Endpoint Fuzzing')
    test_subresource_integrity = BooleanField('Subresource Integrity')
    test_graphql = BooleanField('GraphQL Security')
    
    submit = SubmitField('Start Security Scan')

class EstonianScanForm(FlaskForm):
    """Form for Estonian e-ID login page scanning"""
    estonian_url = StringField('Estonian Login Page URL', validators=[DataRequired(), URL()], 
                             render_kw={"placeholder": "https://login.eesti.ee/"})
    estonian_ai_analysis = BooleanField('🧠 AI Fix Advisor (Get AI-powered recommendations for e-ID security)')
    
    submit_estonian = SubmitField('Start Estonian e-ID Security Scan')

def generate_pdf_report_in_memory(json_data, lang: str = 'en'):
    """Generate PDF report from JSON data in memory using ReportLab"""
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from io import BytesIO
    
    # Translation helper
    from scanner.i18n import translate as _t

    # Create in-memory buffer
    buffer = BytesIO()
    
    # Create PDF document in memory
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    story = []
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    heading_style = ParagraphStyle(
        'CustomHeading',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=20
    )
    
    subheading_style = ParagraphStyle(
        'CustomSubHeading',
        parent=styles['Heading2'],
        fontSize=14,
        spaceAfter=10
    )
    
    normal_style = ParagraphStyle(
        'CustomNormal',
        parent=styles['Normal'],
        fontSize=10,
        leading=14,
        spaceAfter=8
    )
    
    cell_style = ParagraphStyle(
        'CellStyle',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        wordWrap='CJK',
        alignment=0
    )
    
    # Title
    story.append(Paragraph(_t("security_report_title", lang), heading_style))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    summary = json_data.get('executive_summary', {})
    story.append(Paragraph(_t("executive_summary", lang), subheading_style))
    
    summary_text = f"""
    {_t('target_url', lang)}: {json_data.get('target', 'N/A')}
    {_t('risk_rating', lang)}: {json_data.get('risk_rating', 'N/A')}
    {_t('compliance_score', lang)}: {json_data.get('compliance_score', 'N/A')}/100
    {_t('total_issues', lang)}: {len(json_data.get('vulnerabilities', []))}
    """
    story.append(Paragraph(summary_text, normal_style))
    story.append(Spacer(1, 20))
    
    # Vulnerabilities by Severity
    vulnerabilities = json_data.get('vulnerabilities', [])
    if vulnerabilities:
        story.append(Paragraph(_t("detailed_vulnerability_analysis", lang), heading_style))
        
        # Group by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        severity_data = [[_t('severity', lang), 'Count']]
        for severity, count in severity_counts.items():
            if count > 0:
                severity_data.append([severity, str(count)])
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkred),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(severity_table)
        story.append(Spacer(1, 20))
        
        # Detailed Vulnerabilities
        story.append(Paragraph(_t("detailed_vulnerability_analysis", lang), heading_style))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            vuln_title = f"{i}. {vuln.get('type', 'Unknown Vulnerability')}"
            story.append(Paragraph(vuln_title, subheading_style))
            
            # Format each field with proper styling
            vuln_details = []
            
            # Add severity with background color
            severity = vuln.get('severity', 'N/A')
            severity_color = {
                'HIGH': colors.red,
                'MEDIUM': colors.orange,
                'LOW': colors.green
            }.get(severity.upper(), colors.white)
            
            # Create table data with proper formatting
            table_data = [
                [_t('severity', lang), Paragraph(severity, cell_style)],
                [_t('location', lang), Paragraph(vuln.get('location', 'N/A'), cell_style)],
                [_t('description', lang), Paragraph(vuln.get('description', 'N/A'), cell_style)],
                [_t('technical_details', lang), Paragraph(vuln.get('details', 'N/A'), cell_style)],
                [_t('remediation', lang), Paragraph(vuln.get('remediation', 'N/A'), cell_style)]
            ]
            
            # Add AI recommendation if available
            if vuln.get('ai_powered') and vuln.get('remediation'):
                ai_rec = vuln.get('remediation', '')
                # Clean and wrap AI recommendation text for PDF
                ai_label = _t('ai_recommendation', lang)
                # Limit AI recommendation to 250 chars for better PDF formatting
                if len(ai_rec) > 250:
                    ai_rec = ai_rec[:250] + '...'
                # Create a Paragraph object for better text wrapping
                ai_text = Paragraph(ai_rec, normal_style)
                table_data.append([ai_label, ai_text])
            
            # Create and style the table
            table = Table(table_data, colWidths=[120, 380])
            table.setStyle(TableStyle([
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            story.append(table)
            story.append(Spacer(1, 12))  # Add space between vulnerabilities
    
    # Recommendations
    recommendations = summary.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Security Recommendations", heading_style))
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", normal_style))
            story.append(Spacer(1, 6))
    
    # Build PDF in memory
    doc.build(story)
    
    # Return buffer positioned at start
    buffer.seek(0)
    return buffer

def run_scan_async(scan_id, target_url, deep_scan, ai_analysis=False, selected_tests=None):
    """Run security scan asynchronously with selective test execution"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        current_timestamp = time.time()
        
        scan_status[scan_id] = {
            'status': 'running', 
            'progress': 0, 
            'timestamp': current_timestamp
        }
        save_scan_status(scan_status)
        logger.info(f"Starting scan for {target_url} (AI Analysis: {ai_analysis})")
        logger.info(f"Selected tests: {selected_tests}")
        
        # Initialize scanner with AI analysis setting
        scanner = SecurityScanner()
        
        # Enable AI analysis if requested
        if ai_analysis:
            if scanner.ai_advisor:
                scanner.ai_enabled = True
                logger.info("🧠 AI analysis enabled for this scan")
            else:
                logger.warning("🚫 AI analysis requested but AI advisor not available (check OpenAI API key)")
                scanner.ai_enabled = False
        else:
            scanner.ai_enabled = False
            logger.info("ℹ️  AI analysis not requested by user")
        
        # Run scan
        scan_status[scan_id]['progress'] = 25
        scan_status[scan_id]['status'] = 'scanning'
        save_scan_status(scan_status)
        
        logger.info(f"Calling scanner.scan_url() for {target_url}")
        
        # Use threading with timeout (cross-platform solution)
        import queue
        
        result_queue = queue.Queue()
        error_queue = queue.Queue()
        
        def run_scan():
            try:
                result = scanner.scan_url(target_url, deep_scan=deep_scan, selected_tests=selected_tests)
                result_queue.put(result)
            except Exception as e:
                error_queue.put(e)
        
        scan_thread = threading.Thread(target=run_scan)
        scan_thread.daemon = True
        scan_thread.start()
        
        # Wait for scan to complete with timeout
        scan_thread.join(timeout=300)  # 5 minutes timeout
        
        if scan_thread.is_alive():
            # Scan is still running, it timed out
            raise TimeoutError("Security scan timed out after 5 minutes - target may be unresponsive")
        
        # Check if there was an error
        if not error_queue.empty():
            raise error_queue.get()
        
        # Get the result
        if not result_queue.empty():
            result = result_queue.get()
            logger.info(f"Scanner.scan_url() completed for {target_url}")
        else:
            raise Exception("Scan completed but no result was returned")
        
        scan_status[scan_id]['progress'] = 75
        save_scan_status(scan_status)
        
        # Transform scanner results to match template format
        web_results = transform_scanner_results(result)
        
        # Add timestamp for cleanup
        if 'scan_info' not in web_results:
            web_results['scan_info'] = {}
        web_results['scan_info']['timestamp_numeric'] = current_timestamp
        
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['status'] = 'completed'
        save_scan_status(scan_status)
        scan_results[scan_id] = web_results
        save_scan_results(scan_results)
        
        logger.info(f"Scan completed successfully for {target_url}")
        logger.info(f"Results saved for scan_id: {scan_id}")
        logger.info(f"Transformed result keys: {list(web_results.keys()) if isinstance(web_results, dict) else 'Not a dict'}")
        
    except Exception as e:
        logger.error(f"Scan failed for {target_url}: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        scan_status[scan_id] = {
            'status': 'error', 
            'error': str(e),
            'timestamp': time.time()
        }
        save_scan_status(scan_status)

def run_estonian_scan_async(scan_id: str, target_url: str, ai_analysis: bool = False):
    """Run Estonian e-ID login page security scan asynchronously"""
    import logging
    logger = logging.getLogger(__name__)
    current_timestamp = time.time()
    
    try:
        logger.info(f"Starting Estonian e-ID scan for {target_url} (AI Analysis: {ai_analysis})")
        
        # Update status
        scan_status = load_scan_status()
        scan_status[scan_id]['status'] = 'running'
        scan_status[scan_id]['progress'] = 10
        save_scan_status(scan_status)
        
        # Initialize Estonian scanner
        estonian_scanner = EstonianLoginScanner()
        
        scan_status[scan_id]['progress'] = 25
        save_scan_status(scan_status)
        
        # Run Estonian scan with AI analysis flag
        result = estonian_scanner.scan_estonian_login_page(target_url, ai_analysis=ai_analysis)
        
        scan_status[scan_id]['progress'] = 75
        save_scan_status(scan_status)
        
        # Transform results for web interface
        web_results = transform_estonian_scanner_results(result, ai_analysis)
        
        # Add timestamp for cleanup
        if 'scan_info' not in web_results:
            web_results['scan_info'] = {}
        web_results['scan_info']['timestamp_numeric'] = current_timestamp
        web_results['scan_info']['scan_type'] = 'estonian_login'
        
        scan_status[scan_id]['progress'] = 100
        scan_status[scan_id]['status'] = 'completed'
        save_scan_status(scan_status)
        scan_results = load_scan_results()
        scan_results[scan_id] = web_results
        save_scan_results(scan_results)
        
        logger.info(f"Estonian scan completed successfully for {target_url}")
        
    except Exception as e:
        logger.error(f"Estonian scan failed for {target_url}: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        scan_status = load_scan_status()
        scan_status[scan_id] = {
            'status': 'error', 
            'error': str(e),
            'timestamp': time.time()
        }
        save_scan_status(scan_status)

def transform_estonian_scanner_results(scanner_output: dict, ai_analysis: bool = False) -> dict:
    """Transform Estonian scanner output to match web template format"""
    vulnerabilities = scanner_output.get('vulnerabilities', [])
    ai_analysis_attempted = scanner_output.get('ai_analysis_enabled', False)
    ai_recommendations_found = 0
    
    # Process vulnerabilities and count AI recommendations
    processed_vulnerabilities = []
    for vuln in vulnerabilities:
        # Check for AI recommendation
        ai_recommendation = vuln.get('ai_recommendation', '')
        if ai_recommendation:
            ai_recommendations_found += 1
            
        # Get authentication context
        auth_context = vuln.get('authentication_context', {})
        affected_methods = auth_context.get('affected_methods', [])
        auth_flow = auth_context.get('authentication_flow', '')
        
        # Build detailed description
        detailed_description = vuln.get('description', 'Security vulnerability detected')
        if affected_methods:
            detailed_description += f"\nAffected Authentication Methods: {', '.join(affected_methods)}"
        if auth_flow:
            detailed_description += f"\nAuthentication Flow: {auth_flow}"
            
        processed_vuln = {
            'type': vuln.get('type', 'Security Issue'),
            'severity': vuln.get('severity', 'MEDIUM').upper(),
            'description': detailed_description,
            'location': vuln.get('location', ''),
            'details': vuln.get('evidence', 'See vulnerability details'),
            'remediation': ai_recommendation if ai_recommendation else vuln.get('recommendation', 'Address the security issue'),
            'ai_powered': bool(ai_recommendation),
            'auth_context': auth_context  # Include full auth context for UI
        }
        processed_vulnerabilities.append(processed_vuln)
    
    # Calculate severity counts
    severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for vuln in processed_vulnerabilities:
        severity = vuln.get('severity', 'MEDIUM')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Get method-specific recommendations
    method_recommendations = {}
    for method in scanner_output.get('authentication_methods_found', []):
        method_key = f'{method.lower()}_recommendations'
        if method_key in scanner_output:
            method_recommendations[method] = scanner_output[method_key]
    
    # Calculate risk rating based on vulnerabilities
    total_vulns = len(processed_vulnerabilities)
    high_vulns = severity_counts['HIGH']
    medium_vulns = severity_counts['MEDIUM']
    
    if high_vulns > 3:
        risk_rating = 'Critical'
    elif high_vulns > 0 or medium_vulns > 5:
        risk_rating = 'High'
    elif medium_vulns > 2 or total_vulns > 5:
        risk_rating = 'Medium'
    elif total_vulns > 0:
        risk_rating = 'Low'
    else:
        risk_rating = 'Minimal'
    
    # Calculate compliance score (higher is better)
    max_possible_score = 100
    deduction_per_high = 15
    deduction_per_medium = 8
    deduction_per_low = 3
    
    compliance_score = max_possible_score - (
        high_vulns * deduction_per_high +
        medium_vulns * deduction_per_medium +
        severity_counts['LOW'] * deduction_per_low
    )
    compliance_score = max(0, min(100, compliance_score))
    
    # Determine AI analysis status message
    ai_status_message = ""
    if ai_analysis_attempted:
        if ai_recommendations_found > 0:
            ai_status_message = f"✅ AI analysis completed - {ai_recommendations_found} AI-powered recommendations generated"
        else:
            ai_status_message = "⚠️ AI analysis attempted but failed (likely due to OpenAI API quota limits or connectivity issues)"
    else:
        ai_status_message = "ℹ️ AI analysis not requested for this scan"
    
    # Get AI recommendations and security assessment
    recommendations = []
    if scanner_output.get('ai_security_assessment'):
        assessment = scanner_output['ai_security_assessment']
        recommendations.extend(assessment.get('recommendations', []))
        
        # Add method-specific recommendations
        for method, recs in method_recommendations.items():
            if recs.get('recommendations'):
                recommendations.extend([f"[{method}] {rec}" for rec in recs['recommendations'][:2]])
    
    if not recommendations:
        # Fallback to basic recommendations
        if high_vulns > 0:
            recommendations.append("Immediately address all HIGH severity vulnerabilities")
        if medium_vulns > 0:
            recommendations.append("Review and fix MEDIUM severity issues to improve security posture")
        if 'HTTPS' in str(vulnerabilities):
            recommendations.append("Ensure all Estonian e-ID authentication uses strong HTTPS/TLS")
        if 'Header' in str(vulnerabilities):
            recommendations.append("Implement comprehensive security headers for e-ID protection")
        recommendations.append("Regular security assessments recommended for e-ID authentication systems")
    
    # Format for web template
    web_format = {
        'target': scanner_output.get('target_url', ''),
        'risk_rating': risk_rating,
        'compliance_score': compliance_score,
        'executive_summary': {
            'total_vulnerabilities': total_vulns,
            'high_risk_issues': high_vulns,
            'medium_risk_issues': medium_vulns,
            'low_risk_issues': severity_counts['LOW'],
            'recommendations': recommendations[:5],  # Limit to top 5
            'ai_status': ai_status_message,
            'ai_recommendations_count': ai_recommendations_found,
            'authentication_methods': scanner_output.get('authentication_methods_found', [])
        },
        'vulnerabilities': processed_vulnerabilities,
        'scan_info': {
            'timestamp': scanner_output.get('scan_start_time', time.time()),
            'scanner_version': '2.0.0-Estonian',
            'scan_duration': scanner_output.get('scan_duration', 0),
            'scan_type': 'Estonian e-ID Login Page Security Scan'
        },
        'estonian_specific_findings': scanner_output.get('estonian_specific_findings', {}),
        'ai_analysis_enabled': ai_analysis_attempted,
        'ai_recommendations_found': ai_recommendations_found,
        'method_specific_recommendations': method_recommendations
    }
    
    # Add AI security assessment if available
    if scanner_output.get('ai_security_assessment'):
        web_format['ai_security_assessment'] = scanner_output['ai_security_assessment']
    
    return web_format

@app.route('/')
def index():
    """Main page with scan form"""
    form = ScanForm()
    estonian_form = EstonianScanForm()
    return render_template('index.html', form=form, estonian_form=estonian_form)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    form = ScanForm()
    if form.validate_on_submit():
        target_url = form.target_url.data
        deep_scan = form.deep_scan.data
        ai_analysis = form.ai_analysis.data
        
        # Get selected tests
        selected_tests = {
            'sql_injection': form.test_sql_injection.data,
            'xss': form.test_xss.data,
            'csrf': form.test_csrf.data,
            'headers': form.test_headers.data,
            'cors': form.test_cors.data,
            'open_redirect': form.test_open_redirect.data,
            'host_header': form.test_host_header.data,
            'api_fuzzing': form.test_api_fuzzing.data,
            'subresource_integrity': form.test_subresource_integrity.data,
            'graphql': form.test_graphql.data
        }
        
        # If no tests selected, enable all tests
        if not any(selected_tests.values()):
            selected_tests = {key: True for key in selected_tests}
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        save_scan_status({
            scan_id: {
                'status': 'starting',
                'progress': 0,
                'timestamp': time.time()
            }
        })
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=run_scan_async,
            args=(scan_id, target_url, deep_scan, ai_analysis, selected_tests)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Redirect to scan progress page
        return redirect(url_for('scan_progress', scan_id=scan_id))
    
    # If form validation failed
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'Error in {field}: {error}', 'error')
    return redirect(url_for('index'))

@app.route('/estonian-scan', methods=['POST'])
def start_estonian_scan():
    """Start a new Estonian e-ID login page security scan"""
    estonian_form = EstonianScanForm()
    if estonian_form.validate_on_submit():
        target_url = estonian_form.estonian_url.data
        ai_analysis = estonian_form.estonian_ai_analysis.data
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Initialize scan status
        save_scan_status({
            scan_id: {
                'status': 'starting',
                'progress': 0,
                'timestamp': time.time(),
                'scan_type': 'estonian_login'
            }
        })
        
        # Start Estonian scan in background thread
        scan_thread = threading.Thread(
            target=run_estonian_scan_async,
            args=(scan_id, target_url, ai_analysis)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Redirect to scan progress page
        return redirect(url_for('scan_progress', scan_id=scan_id))
    
    # If form validation failed
    for field, errors in estonian_form.errors.items():
        for error in errors:
            flash(f'Error in {field}: {error}', 'error')
    return redirect(url_for('index'))

@app.route('/scan/<scan_id>')
def scan_progress(scan_id):
    """Show scan progress page"""
    return render_template('progress.html', scan_id=scan_id)

@app.route('/api/scan-status/<scan_id>')
def get_scan_status(scan_id):
    """API endpoint for scan status"""
    scan_status = load_scan_status()
    status = scan_status.get(scan_id, {'status': 'not_found'})
    
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Status API called for {scan_id}: {status}")
    return jsonify(status)

@app.route('/results/<scan_id>')
def scan_results_page(scan_id):
    """Display scan results"""
    # Get scan results from storage
    results = load_scan_results().get(scan_id)
    if not results:
        flash('Scan results not found', 'error')
        return redirect(url_for('index'))
    
    # Log for debugging
    app.logger.info(f"Results page requested for scan_id: {scan_id}")
    app.logger.info(f"Available scan results: {list(load_scan_results().keys())}")
    app.logger.info(f"Returning results page for scan_id: {scan_id}")
    
    # Transform results for template if needed
    if not isinstance(results, dict) or 'risk_rating' not in results:
        results = transform_scanner_results(results)
        # Update stored results with transformed version
        save_scan_results({scan_id: results})
    
    return render_template('results.html', results=results, scan_id=scan_id)

@app.route('/download/<scan_id>')
def download_report(scan_id):
    """Download PDF report - generated in memory"""
    scan_results = load_scan_results()
    
    if scan_id not in scan_results:
        flash('Scan results not found.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Generate PDF in memory
        results = scan_results[scan_id]
        lang = session.get('lang', 'en')
        pdf_buffer = generate_pdf_report_in_memory(results, lang)
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_filename = f"security_report_{timestamp}.pdf"
        
        # Return PDF directly from memory - no file storage
        return send_file(
            pdf_buffer,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        flash(f'Error generating PDF: {str(e)}', 'error')
        return redirect(url_for('scan_results_page', scan_id=scan_id))

@app.route('/api/scan-results/<scan_id>')
def get_scan_results_api(scan_id):
    """API endpoint for scan results"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"API Results requested for scan_id: {scan_id}")
    
    scan_results = load_scan_results()
    logger.info(f"Available results in API: {list(scan_results.keys())}")
    
    if scan_id not in scan_results:
        logger.error(f"API: Results not found for {scan_id}")
        return jsonify({'error': 'Results not found'}), 404
    
    logger.info(f"API: Returning results for {scan_id}")
    return jsonify(scan_results[scan_id])

if __name__ == '__main__':
    print("🚀 Starting E-Gov Guardian Web Interface...")
    print("📊 Access the scanner at: http://localhost:5000")
    print("🔒 Ready to perform security assessments!")
    app.run(debug=True, host='0.0.0.0', port=5000) 