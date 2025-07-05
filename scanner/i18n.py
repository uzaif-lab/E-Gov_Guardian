"""Simple i18n helper for English ↔ Estonian UI strings.

Usage::
    from scanner.i18n import translate
    translate(key, lang='et')

If a key or language is missing, the English fallback is returned so the
application never breaks.
"""
from typing import Dict

# Minimal set of UI strings.  Extend as needed.
_TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "site_title": {
        "en": "E-Gov Guardian Security Portal",
        "et": "E-Gov Guardiani Turvakaitseportaal",
    },
    "site_tagline": {
        "en": "Comprehensive security scanning for government web applications and Estonian e-ID authentication",
        "et": "Põhjalik turvakontroll valitsuse veebirakendustele ja Eesti e-ID autentimisele",
    },
    "meta_description": {
        "en": "E-Gov Guardian offers AI-powered security scanning for government websites and Estonian e-ID authentication, delivering instant vulnerability insights and PDF reports.",
        "et": "E-Gov Guardian pakub AI-põhist turvakontrolli valitsuse veebisaitidele ja Eesti e-ID autentimisele, pakkudes kiireid haavatavuse ülevaateid ja PDF aruandeid.",
    },
    "web_scanner_title": {
        "en": "Web Application Security Scanner",
        "et": "Veebirakenduste Turvakanner",
    },
    "web_scanner_desc": {
        "en": "Comprehensive vulnerability detection for web applications",
        "et": "Veebirakenduste haavatavuste terviklik tuvastamine",
    },
    "estonian_scanner_title": {
        "en": "Estonian e-ID Login Scanner",
        "et": "Eesti e-ID sisselogimise Turvakanner",
    },
    "estonian_scanner_desc": {
        "en": "Specialized security assessment for Estonian e-ID, Smart-ID, and Mobile-ID authentication",
        "et": "Spetsialiseeritud turvahindamine Eesti e-ID, Smart-ID ja Mobiil-ID autentimisele",
    },
    "target_url_label": {
        "en": "Target URL",
        "et": "Siht-URL",
    },
    "deep_scan_label": {
        "en": "Deep Scan",
        "et": "Põhjalik skaneerimine",
    },
    "ai_fix_advisor": {
        "en": "🧠 AI Fix Advisor",
        "et": "🧠 AI Paranduste Nõustaja",
    },
    "scan_type_label": {
        "en": "Scan Type",
        "et": "Skaneerimise tüüp",
    },
    "submit_scan": {
        "en": "Start Security Scan",
        "et": "Alusta turvaskaneerimist",
    },
    "security_scan_in_progress": {
        "en": "Security Scan in Progress",
        "et": "Turvakontroll käsil",
    },
    "analysis_tagline": {
        "en": "Analyzing target for security vulnerabilities...",
        "et": "Analüüsime sihtmärki turvahaavatavuste suhtes...",
    },
    "cancel_scan": {
        "en": "Cancel Scan",
        "et": "Tühista skaneerimine",
    },
    "scan_results_header": {
        "en": "Security Assessment Results",
        "et": "Turvahindamise tulemused",
    },
    "download_report": {
        "en": "Download PDF Report",
        "et": "Laadi alla PDF aruanne",
    },
    "developer": {
        "en": "Developer",
        "et": "Arendaja",
    },

    # Index page extras
    "vulnerability_detection": {"en": "Vulnerability Detection", "et": "Haavatavuste tuvastamine"},
    "advanced_testing": {"en": "Advanced Testing", "et": "Täpsemad testid"},
    "security_tests": {"en": "Security Tests", "et": "Turvatestid"},
    "core_tests": {"en": "Core Tests", "et": "Põhitestid"},
    "advanced_tests": {"en": "Advanced", "et": "Täiustatud"},
    "sql_injection": {"en": "SQL Injection", "et": "SQL süstimine"},
    "xss": {"en": "Cross-Site Scripting", "et": "XSS ründed"},
    "csrf": {"en": "CSRF Detection", "et": "CSRF tuvastus"},
    "security_headers": {"en": "Security Headers", "et": "Turbe päised"},
    "cors_policy": {"en": "CORS Policy", "et": "CORS poliitika"},
    "open_redirects": {"en": "Open Redirects", "et": "Avatud ümbersuunamised"},
    "host_header_injection": {"en": "Host Header Injection", "et": "Host-pealkirja süstimine"},
    "api_fuzzing": {"en": "API Fuzzing", "et": "API vuditamine"},
    "subresource_integrity": {"en": "Subresource Integrity", "et": "Alamressursi terviklus"},
    "graphql_security": {"en": "GraphQL Security", "et": "GraphQL turvalisus"},

    "pdf_reports": {"en": "PDF Reports", "et": "PDF aruanded"},
    "real_time_scanning": {"en": "Real-time Scanning", "et": "Reaalajas skaneerimine"},
    "ai_powered_analysis": {"en": "AI-Powered Analysis", "et": "AI-põhine analüüs"},
    "government_security": {"en": "Government Security", "et": "Valitsuse turvalisus"},

    "security_disclaimer": {"en": "Security Disclaimer", "et": "Turvadiskleimer"},

    # Progress page
    "phase_discovery": {"en": "Discovery", "et": "Avastamine"},
    "phase_vulnerability_testing": {"en": "Vulnerability Testing", "et": "Haavatavuste testimine"},
    "phase_report_generation": {"en": "Report Generation", "et": "Aruande koostamine"},
    "whats_happening": {"en": "What's happening?", "et": "Mis toimub?"},

    # Results page
    "high_risk": {"en": "High Risk", "et": "Kõrge risk"},
    "medium_risk": {"en": "Medium Risk", "et": "Keskmine risk"},
    "low_risk": {"en": "Low Risk", "et": "Madal risk"},
    "total_issues": {"en": "Total Issues", "et": "Kokku probleeme"},
    "vulnerability_breakdown": {"en": "Vulnerability Breakdown", "et": "Haavatavuste jaotus"},
    "key_recommendations": {"en": "Key Recommendations", "et": "Põhisoovitused"},
    "risk_rating_label": {"en": "Risk Rating", "et": "Riskihinnang"},
    "compliance_score_label": {"en": "Compliance Score", "et": "Vastavuse skoor"},
    "scan_duration_label": {"en": "Scan Duration", "et": "Skaneerimise kestus"},

    # Results page
    "auth_method_security_analysis": {"en": "Authentication Method Security Analysis", "et": "Autentimismeetodi turbeanalüüs"},
    "security_rating_label": {"en": "Security Rating", "et": "Turbehinne"},
    "recommendations_label": {"en": "Recommendations", "et": "Soovitused"},
    "compliance_issues_label": {"en": "Compliance Issues", "et": "Vastavuse probleemid"},

    # Progress item list
    "progress_item_crawl": {"en": "Crawling website structure and discovering endpoints", "et": "Veebisaidi struktuuri indekseerimine ja lõpp-punktide avastamine"},
    "progress_item_vuln_tests": {"en": "Testing for common vulnerabilities (SQL Injection, XSS, etc.)", "et": "Levinud haavatavuste testimine (SQL süstimine, XSS jne)"},
    "progress_item_headers": {"en": "Analyzing security headers and configurations", "et": "Turbe päiste ja konfiguratsioonide analüüs"},
    "progress_item_known_issues": {"en": "Checking for known security issues", "et": "Tuntud turvaprobleemide kontroll"},

    # PDF / Report labels
    "security_report_title": {"en": "E-Gov Guardian Security Report", "et": "E-Gov Guardiani turvaraport"},
    "executive_summary": {"en": "Executive Summary", "et": "Juhtkonna kokkuvõte"},
    "detailed_vulnerability_analysis": {"en": "Detailed Vulnerability Analysis", "et": "Põhjalik haavatavuste analüüs"},
    "target_url": {"en": "Target URL", "et": "Siht-URL"},
    "risk_rating": {"en": "Risk Rating", "et": "Riskihinnang"},
    "compliance_score": {"en": "Compliance Score", "et": "Vastavuse skoor"},
    "total_issues": {"en": "Total Issues", "et": "Probleemide koguarv"},
    "severity": {"en": "Severity", "et": "Tõsidus"},
    "location": {"en": "Location", "et": "Asukoht"},
    "description": {"en": "Description", "et": "Kirjeldus"},
    "technical_details": {"en": "Technical Details", "et": "Tehnilised üksikasjad"},
    "remediation": {"en": "Remediation", "et": "Parandus"},
    "ai_recommendation": {"en": "AI Recommendation", "et": "AI soovitus"},
}


def translate(key: str, lang: str = "en") -> str:
    """Return the translated string for *key* in *lang*.

    Falls back to English if the language or the key translation is missing.
    """
    entry = _TRANSLATIONS.get(key, {})
    return entry.get(lang) or entry.get("en") or key 