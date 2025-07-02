#!/usr/bin/env python3
"""
E-Gov Guardian Web Interface
A web-based security scanner with PDF report generation
"""

import threading
import uuid
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, BooleanField, SubmitField
from wtforms.validators import DataRequired, URL

# Import our scanner
from scanner.main_scanner import SecurityScanner

app = Flask(__name__)
app.secret_key = 'egov-guardian-security-scanner-in-memory-2024'

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
    
    # Transform to template format
    web_format = {
        'target': scanner_output.get('target', ''),
        'executive_summary': {
            'risk_rating': scanner_output.get('risk_rating', 'UNKNOWN'),
            'compliance_score': summary.get('compliance_score', 0),
            'total_vulnerabilities': summary.get('total_vulnerabilities', len(vulnerabilities)),
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
    """Form for URL scanning"""
    target_url = StringField('Target URL', validators=[DataRequired(), URL()], 
                            render_kw={"placeholder": "https://example.com"})
    deep_scan = BooleanField('Deep Scan (More thorough but slower)')
    ai_analysis = BooleanField('🧠 AI Fix Advisor (Get AI-powered fix recommendations)')
    scan_type = SelectField('Scan Type', choices=[('url', 'Web Application')])
    submit = SubmitField('Start Security Scan')

def generate_pdf_report_in_memory(json_data):
    """Generate PDF report from JSON data in memory using ReportLab"""
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from io import BytesIO
    
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
        spaceAfter=12,
        textColor=colors.darkred
    )
    
    # Title
    story.append(Paragraph("E-Gov Guardian Security Assessment Report", title_style))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    summary = json_data.get('executive_summary', {})
    story.append(Paragraph("Executive Summary", heading_style))
    
    summary_data = [
        ['Target', json_data.get('target', 'N/A')],
        ['Scan Date', json_data.get('scan_info', {}).get('timestamp', 'N/A')],
        ['Risk Rating', summary.get('risk_rating', 'N/A')],
        ['Compliance Score', f"{summary.get('compliance_score', 0)}/100"],
        ['Total Vulnerabilities', str(summary.get('total_vulnerabilities', 0))],
        ['Scan Duration', f"{json_data.get('scan_info', {}).get('duration', 'N/A')} seconds"]
    ]
    
    # Add AI analysis status if applicable
    scan_info = json_data.get('scan_info', {})
    if scan_info.get('ai_analysis_attempted'):
        ai_status = f"{scan_info.get('ai_recommendations_count', 0)} AI recommendations"
        if scan_info.get('ai_recommendations_count', 0) == 0:
            ai_status += " (Failed - API quota/connectivity issue)"
        summary_data.append(['AI Analysis', ai_status])
    
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 14),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Vulnerabilities by Severity
    vulnerabilities = json_data.get('vulnerabilities', [])
    if vulnerabilities:
        story.append(Paragraph("Vulnerabilities Found", heading_style))
        
        # Group by severity
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'INFO').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        severity_data = [['Severity', 'Count']]
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
        story.append(Paragraph("Detailed Vulnerability Analysis", heading_style))
        
        for i, vuln in enumerate(vulnerabilities[:10], 1):  # Limit to first 10 for PDF
            vuln_title = f"{i}. {vuln.get('type', 'Unknown Vulnerability')}"
            story.append(Paragraph(vuln_title, styles['Heading3']))
            
            vuln_details = [
                ['Severity', vuln.get('severity', 'N/A')],
                ['Location', vuln.get('location', 'N/A')],
                ['Description', vuln.get('description', 'N/A')[:200] + '...' if len(vuln.get('description', '')) > 200 else vuln.get('description', 'N/A')]
            ]
            
            # Add AI recommendation if available
            if vuln.get('ai_powered') and vuln.get('remediation'):
                ai_rec = vuln.get('remediation', '')
                ai_label = "🧠 AI Fix Advisor"
                vuln_details.append([ai_label, ai_rec[:300] + '...' if len(ai_rec) > 300 else ai_rec])
            elif vuln.get('remediation'):
                vuln_details.append(['Remediation', vuln.get('remediation', 'N/A')[:200] + '...' if len(vuln.get('remediation', '')) > 200 else vuln.get('remediation', 'N/A')])
            
            vuln_table = Table(vuln_details, colWidths=[1.5*inch, 4*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'TOP')
            ]))
            
            story.append(vuln_table)
            story.append(Spacer(1, 12))
    
    # Recommendations
    recommendations = summary.get('recommendations', [])
    if recommendations:
        story.append(Paragraph("Security Recommendations", heading_style))
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            story.append(Spacer(1, 6))
    
    # Build PDF in memory
    doc.build(story)
    
    # Return buffer positioned at start
    buffer.seek(0)
    return buffer

def run_scan_async(scan_id, target_url, deep_scan, ai_analysis=False):
    """Run security scan asynchronously"""
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
                result = scanner.scan_url(target_url, deep_scan=deep_scan)
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

@app.route('/')
def index():
    """Main page with scan form"""
    form = ScanForm()
    return render_template('index.html', form=form)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Start a new security scan"""
    form = ScanForm()
    
    if form.validate_on_submit():
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Get form data
        target_url = form.target_url.data
        deep_scan = form.deep_scan.data
        ai_analysis = form.ai_analysis.data
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan_async,
            args=(scan_id, target_url, deep_scan, ai_analysis)
        )
        thread.daemon = True
        thread.start()
        
        return redirect(url_for('scan_progress', scan_id=scan_id))
    
    return render_template('index.html', form=form)

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
    """Show scan results page"""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(f"Results page requested for scan_id: {scan_id}")
    
    scan_results = load_scan_results()
    logger.info(f"Available scan results: {list(scan_results.keys())}")
    
    if scan_id not in scan_results:
        logger.error(f"Scan results not found for {scan_id}")
        flash('Scan results not found or scan still in progress.', 'error')
        return redirect(url_for('index'))
    
    results = scan_results[scan_id]
    logger.info(f"Returning results page for scan_id: {scan_id}")
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
        pdf_buffer = generate_pdf_report_in_memory(results)
        
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