#!/usr/bin/env python3
"""
Privacy Compliance Checker
Scans codebases and data flows to identify potential GDPR/CCPA violations
"""

import os
import re
import ast
import json
import argparse
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
from datetime import datetime

@dataclass
class ComplianceIssue:
    """Represents a privacy compliance issue"""
    severity: str  # 'critical', 'high', 'medium', 'low'
    category: str  # 'data_collection', 'consent', 'retention', 'transfer', 'security'
    regulation: str  # 'GDPR', 'CCPA', 'BOTH'
    file_path: str
    line_number: int
    issue_type: str
    description: str
    code_snippet: str
    suggestion: str
    article_reference: Optional[str] = None

class PrivacyComplianceChecker:
    def __init__(self, config_path: Optional[str] = None):
        self.issues: List[ComplianceIssue] = []
        self.sensitive_data_patterns = self._load_sensitive_patterns()
        self.compliance_rules = self._load_compliance_rules()
        self.config = self._load_config(config_path) if config_path else self._default_config()
        
    def _default_config(self) -> Dict:
        """Default configuration for the checker"""
        return {
            "regulations": ["GDPR", "CCPA"],
            "file_extensions": [".py", ".js", ".java", ".php", ".rb", ".go", ".cs"],
            "exclude_dirs": ["node_modules", ".git", "__pycache__", "venv", ".env"],
            "severity_threshold": "low",
            "output_format": "json"
        }
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Config file {config_path} not found, using defaults")
            return self._default_config()
    
    def _load_sensitive_patterns(self) -> Dict[str, List[str]]:
        """Define patterns for sensitive data detection"""
        return {
            "email": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'email\s*[=:]\s*["\'][^"\']+["\']',
                r'\.email\b',
                r'user\.email',
                r'customer\.email'
            ],
            "phone": [
                r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
                r'phone\s*[=:]\s*["\'][^"\']+["\']',
                r'\.phone\b',
                r'phoneNumber',
                r'mobile'
            ],
            "ssn": [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'\b\d{9}\b',
                r'ssn\s*[=:]\s*["\'][^"\']+["\']',
                r'social_security',
                r'socialSecurityNumber'
            ],
            "credit_card": [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',  # Visa
                r'\b5[1-5][0-9]{14}\b',  # MasterCard
                r'\b3[47][0-9]{13}\b',  # American Express
                r'credit_card',
                r'creditCard',
                r'cardNumber'
            ],
            "ip_address": [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'ip_address',
                r'ipAddress',
                r'client_ip'
            ],
            "personal_id": [
                r'user_id',
                r'customer_id',
                r'person_id',
                r'individual_id',
                r'\.id\b',
                r'passport',
                r'license'
            ]
        }
    
    def _load_compliance_rules(self) -> Dict[str, List[Dict]]:
        """Define compliance rules for GDPR and CCPA"""
        return {
            "data_collection": [
                {
                    "pattern": r'(collect|gather|obtain|acquire).*(?:personal|user|customer|individual).*data',
                    "severity": "high",
                    "regulation": "BOTH",
                    "description": "Data collection without explicit consent mechanism",
                    "suggestion": "Implement explicit consent collection before gathering personal data",
                    "gdpr_article": "Article 6 (Lawful basis for processing)"
                }
            ],
            "consent": [
                {
                    "pattern": r'(cookie|tracking|analytics)(?!.*consent)',
                    "severity": "critical",
                    "regulation": "GDPR",
                    "description": "Cookie/tracking implementation without consent mechanism",
                    "suggestion": "Implement cookie consent banner and opt-in mechanism",
                    "gdpr_article": "Article 7 (Conditions for consent)"
                },
                {
                    "pattern": r'(newsletter|marketing|promotional).*email(?!.*consent|.*opt)',
                    "severity": "high",
                    "regulation": "BOTH",
                    "description": "Marketing email without explicit opt-in",
                    "suggestion": "Implement double opt-in for marketing communications",
                    "gdpr_article": "Article 7 (Conditions for consent)"
                }
            ],
            "data_retention": [
                {
                    "pattern": r'(delete|remove|purge).*(?:user|customer|personal).*data',
                    "severity": "medium",
                    "regulation": "BOTH",
                    "description": "Data deletion mechanism found - verify retention periods",
                    "suggestion": "Ensure data retention periods comply with legal requirements",
                    "gdpr_article": "Article 17 (Right to erasure)"
                },
                {
                    "pattern": r'(permanent|forever|indefinite).*(?:store|keep|retain)',
                    "severity": "critical",
                    "regulation": "BOTH",
                    "description": "Indefinite data retention detected",
                    "suggestion": "Implement data retention policies with defined time limits",
                    "gdpr_article": "Article 5 (Principles of processing)"
                }
            ],
            "data_transfer": [
                {
                    "pattern": r'(transfer|send|export).*data.*(?:third.party|external|outside)',
                    "severity": "high",
                    "regulation": "BOTH",
                    "description": "Data transfer to third parties detected",
                    "suggestion": "Ensure proper safeguards and agreements for data transfers",
                    "gdpr_article": "Chapter V (Transfers to third countries)"
                }
            ],
            "user_rights": [
                {
                    "pattern": r'(access|download|export).*(?:personal|user).*data',
                    "severity": "low",
                    "regulation": "BOTH",
                    "description": "Data access functionality found - verify completeness",
                    "suggestion": "Ensure users can access all their personal data",
                    "gdpr_article": "Article 15 (Right of access)"
                }
            ]
        }
    
    def scan_directory(self, directory_path: str) -> None:
        """Scan entire directory for compliance issues"""
        directory = Path(directory_path)
        
        if not directory.exists():
            raise FileNotFoundError(f"Directory {directory_path} does not exist")
        
        for file_path in self._get_files_to_scan(directory):
            try:
                self.scan_file(str(file_path))
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
    
    def _get_files_to_scan(self, directory: Path) -> List[Path]:
        """Get list of files to scan based on configuration"""
        files = []
        
        for root, dirs, filenames in os.walk(directory):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.config["exclude_dirs"]]
            
            for filename in filenames:
                file_path = Path(root) / filename
                if any(filename.endswith(ext) for ext in self.config["file_extensions"]):
                    files.append(file_path)
        
        return files
    
    def scan_file(self, file_path: str) -> None:
        """Scan a single file for compliance issues"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Check for sensitive data patterns
            self._check_sensitive_data(file_path, content, lines)
            
            # Check compliance rules
            self._check_compliance_rules(file_path, content, lines)
            
            # Language-specific checks
            if file_path.endswith('.py'):
                self._check_python_specific(file_path, content, lines)
            elif file_path.endswith('.js'):
                self._check_javascript_specific(file_path, content, lines)
            elif file_path.endswith('.java'):
                self._check_java_specific(file_path, content, lines)
                
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
    def _check_sensitive_data(self, file_path: str, content: str, lines: List[str]) -> None:
        """Check for sensitive data patterns"""
        for data_type, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = ComplianceIssue(
                        severity="medium",
                        category="data_collection",
                        regulation="BOTH",
                        file_path=file_path,
                        line_number=line_num,
                        issue_type=f"sensitive_data_{data_type}",
                        description=f"Potential {data_type} data detected",
                        code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        suggestion=f"Ensure {data_type} data is properly protected and consent is obtained"
                    )
                    self.issues.append(issue)
    
    def _check_compliance_rules(self, file_path: str, content: str, lines: List[str]) -> None:
        """Check against compliance rules"""
        for category, rules in self.compliance_rules.items():
            for rule in rules:
                matches = re.finditer(rule["pattern"], content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = ComplianceIssue(
                        severity=rule["severity"],
                        category=category,
                        regulation=rule["regulation"],
                        file_path=file_path,
                        line_number=line_num,
                        issue_type=category,
                        description=rule["description"],
                        code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        suggestion=rule["suggestion"],
                        article_reference=rule.get("gdpr_article")
                    )
                    self.issues.append(issue)
    
    def _check_python_specific(self, file_path: str, content: str, lines: List[str]) -> None:
        """Python-specific privacy checks"""
        # Check for database operations without proper safeguards
        db_patterns = [
            r'SELECT.*FROM.*users.*WHERE',
            r'INSERT.*INTO.*users',
            r'UPDATE.*users.*SET',
            r'DELETE.*FROM.*users'
        ]
        
        for pattern in db_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                issue = ComplianceIssue(
                    severity="medium",
                    category="security",
                    regulation="BOTH",
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="database_operation",
                    description="Database operation on user data detected",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    suggestion="Ensure proper access controls and audit logging for user data operations"
                )
                self.issues.append(issue)
    
    def _check_javascript_specific(self, file_path: str, content: str, lines: List[str]) -> None:
        """JavaScript-specific privacy checks"""
        # Check for localStorage usage without consent
        patterns = [
            r'localStorage\.setItem',
            r'sessionStorage\.setItem',
            r'document\.cookie\s*='
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                issue = ComplianceIssue(
                    severity="high",
                    category="consent",
                    regulation="GDPR",
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="client_storage",
                    description="Client-side storage without consent check",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    suggestion="Implement consent check before storing data in browser storage",
                    article_reference="Article 7 (Conditions for consent)"
                )
                self.issues.append(issue)
    
    def _check_java_specific(self, file_path: str, content: str, lines: List[str]) -> None:
        """Java-specific privacy checks"""
        # Check for Cookie creation without consent
        cookie_patterns = [
            r'new\s+Cookie\s*\(',
            r'response\.addCookie\s*\(',
            r'HttpServletResponse.*Cookie'
        ]
        
        for pattern in cookie_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                issue = ComplianceIssue(
                    severity="high",
                    category="consent",
                    regulation="GDPR",
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="cookie_creation",
                    description="Cookie creation without consent verification",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    suggestion="Implement consent check before setting cookies",
                    article_reference="Article 7 (Conditions for consent)"
                )
                self.issues.append(issue)
        
        # Check for JDBC operations on user data
        jdbc_patterns = [
            r'PreparedStatement.*INSERT.*users',
            r'PreparedStatement.*UPDATE.*users',
            r'PreparedStatement.*DELETE.*users',
            r'Statement.*executeQuery.*users'
        ]
        
        for pattern in jdbc_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                issue = ComplianceIssue(
                    severity="medium",
                    category="security",
                    regulation="BOTH",
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="database_operation",
                    description="Database operation on user data detected",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    suggestion="Ensure proper access controls and audit logging for user data operations"
                )
                self.issues.append(issue)
        
        # Check for logging sensitive information
        logging_patterns = [
            r'System\.out\.println.*(?:email|phone|ssn|credit|card)',
            r'logger\..*(?:email|phone|ssn|credit|card)',
            r'log\..*(?:email|phone|ssn|credit|card)'
        ]
        
        for pattern in logging_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                issue = ComplianceIssue(
                    severity="high",
                    category="security",
                    regulation="BOTH",
                    file_path=file_path,
                    line_number=line_num,
                    issue_type="sensitive_logging",
                    description="Sensitive information being logged",
                    code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                    suggestion="Remove sensitive data from logs or implement secure logging practices"
                )
                self.issues.append(issue)
    
    def generate_report(self) -> Dict:
        """Generate compliance report"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        regulation_counts = {"GDPR": 0, "CCPA": 0, "BOTH": 0}
        category_counts = {}
        
        for issue in self.issues:
            severity_counts[issue.severity] += 1
            regulation_counts[issue.regulation] += 1
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        
        return {
            "scan_timestamp": datetime.now().isoformat(),
            "total_issues": len(self.issues),
            "severity_breakdown": severity_counts,
            "regulation_breakdown": regulation_counts,
            "category_breakdown": category_counts,
            "issues": [asdict(issue) for issue in self.issues],
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate general recommendations based on found issues"""
        recommendations = []
        
        critical_issues = [i for i in self.issues if i.severity == "critical"]
        if critical_issues:
            recommendations.append("Address critical privacy issues immediately to avoid potential legal violations")
        
        consent_issues = [i for i in self.issues if i.category == "consent"]
        if consent_issues:
            recommendations.append("Implement comprehensive consent management system")
        
        data_retention_issues = [i for i in self.issues if "retention" in i.category]
        if data_retention_issues:
            recommendations.append("Establish clear data retention and deletion policies")
        
        if not recommendations:
            recommendations.append("Continue monitoring for privacy compliance")
        
        return recommendations
    
    def save_report(self, output_path: str, format_type: str = "json") -> None:
        """Save report to file"""
        report = self.generate_report()
        
        if format_type == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        elif format_type == "html":
            self._save_html_report(report, output_path)
        elif format_type == "pdf":
            self._save_pdf_report(report, output_path)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _save_html_report(self, report: Dict, output_path: str) -> None:
        """Save HTML formatted report"""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Privacy Compliance Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
                .issue {{ border: 1px solid #ddd; margin: 10px 0; padding: 10px; border-radius: 3px; }}
                .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
                .stat-box {{ background: #f9f9f9; padding: 15px; border-radius: 5px; flex: 1; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Privacy Compliance Report</h1>
                <p>Generated: {report['scan_timestamp']}</p>
                <p>Total Issues: {report['total_issues']}</p>
            </div>
            
            <div class="summary">
                <div class="stat-box">
                    <h3>Severity Breakdown</h3>
                    <ul>
                        <li class="critical">Critical: {report['severity_breakdown']['critical']}</li>
                        <li class="high">High: {report['severity_breakdown']['high']}</li>
                        <li class="medium">Medium: {report['severity_breakdown']['medium']}</li>
                        <li class="low">Low: {report['severity_breakdown']['low']}</li>
                    </ul>
                </div>
                <div class="stat-box">
                    <h3>Regulation Impact</h3>
                    <ul>
                        <li>GDPR: {report['regulation_breakdown']['GDPR']}</li>
                        <li>CCPA: {report['regulation_breakdown']['CCPA']}</li>
                        <li>Both: {report['regulation_breakdown']['BOTH']}</li>
                    </ul>
                </div>
            </div>
            
            <h2>Issues Found</h2>
        """
        
        for issue in report['issues']:
            severity_class = issue['severity']
            html_content += f"""
            <div class="issue {severity_class}">
                <h4 class="{severity_class}">[{issue['severity'].upper()}] {issue['description']}</h4>
                <p><strong>File:</strong> {issue['file_path']}:{issue['line_number']}</p>
                <p><strong>Category:</strong> {issue['category']}</p>
                <p><strong>Regulation:</strong> {issue['regulation']}</p>
                <p><strong>Code:</strong> <code>{issue['code_snippet']}</code></p>
                <p><strong>Suggestion:</strong> {issue['suggestion']}</p>
                {f"<p><strong>Reference:</strong> {issue['article_reference']}</p>" if issue.get('article_reference') else ""}
            </div>
            """
        
        html_content += """
            <h2>Recommendations</h2>
            <ul>
        """
        
        for rec in report['recommendations']:
            html_content += f"<li>{rec}</li>"
        
        html_content += """
            </ul>
        </body>
        </html>
        """
        
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    def _save_pdf_report(self, report: Dict, output_path: str) -> None:
        """Save PDF formatted report"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
            from datetime import datetime
        except ImportError:
            raise ImportError("PDF generation requires reportlab. Install with: pip install reportlab")
        
        # Create PDF document
        doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=1*inch)
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.darkblue,
            spaceBefore=20,
            spaceAfter=10
        )
        
        subheading_style = ParagraphStyle(
            'CustomSubHeading',
            parent=styles['Heading3'],
            fontSize=12,
            textColor=colors.darkred,
            spaceBefore=10,
            spaceAfter=5
        )
        
        # Title
        story.append(Paragraph("Privacy Compliance Report", title_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        
        summary_data = [
            ['Metric', 'Count'],
            ['Total Issues', str(report['total_issues'])],
            ['Critical Issues', str(report['severity_breakdown']['critical'])],
            ['High Priority', str(report['severity_breakdown']['high'])],
            ['Medium Priority', str(report['severity_breakdown']['medium'])],
            ['Low Priority', str(report['severity_breakdown']['low'])]
        ]
        
        summary_table = Table(summary_data, colWidths=[3*inch, 1.5*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Regulation Impact
        story.append(Paragraph("Regulation Impact", heading_style))
        
        regulation_data = [
            ['Regulation', 'Issues Count'],
            ['GDPR Only', str(report['regulation_breakdown']['GDPR'])],
            ['CCPA Only', str(report['regulation_breakdown']['CCPA'])],
            ['Both GDPR & CCPA', str(report['regulation_breakdown']['BOTH'])]
        ]
        
        regulation_table = Table(regulation_data, colWidths=[3*inch, 1.5*inch])
        regulation_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightblue),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(regulation_table)
        story.append(Spacer(1, 20))
        
        # Category Breakdown
        story.append(Paragraph("Issues by Category", heading_style))
        
        category_data = [['Category', 'Count']]
        for category, count in report['category_breakdown'].items():
            category_data.append([category.replace('_', ' ').title(), str(count)])
        
        category_table = Table(category_data, colWidths=[3*inch, 1.5*inch])
        category_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkgreen),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgreen),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(category_table)
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Key Recommendations", heading_style))
        for i, rec in enumerate(report['recommendations'], 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            story.append(Spacer(1, 6))
        
        story.append(PageBreak())
        
        # Detailed Issues
        story.append(Paragraph("Detailed Issues", heading_style))
        
        severity_colors = {
            'critical': colors.red,
            'high': colors.orange,
            'medium': colors.yellow,
            'low': colors.green
        }
        
        for i, issue in enumerate(report['issues'], 1):
            # Issue header
            severity_color = severity_colors.get(issue['severity'], colors.black)
            issue_title = f"Issue #{i}: [{issue['severity'].upper()}] {issue['description']}"
            
            issue_style = ParagraphStyle(
                'IssueTitle',
                parent=styles['Heading4'],
                fontSize=11,
                textColor=severity_color,
                spaceBefore=15,
                spaceAfter=5
            )
            
            story.append(Paragraph(issue_title, issue_style))
            
            # Issue details table
            issue_data = [
                ['Property', 'Value'],
                ['File', issue['file_path']],
                ['Line Number', str(issue['line_number'])],
                ['Category', issue['category'].replace('_', ' ').title()],
                ['Regulation', issue['regulation']],
                ['Code Snippet', issue['code_snippet'][:100] + '...' if len(issue['code_snippet']) > 100 else issue['code_snippet']],
                ['Suggestion', issue['suggestion'][:150] + '...' if len(issue['suggestion']) > 150 else issue['suggestion']]
            ]
            
            if issue.get('article_reference'):
                issue_data.append(['GDPR Reference', issue['article_reference']])
            
            issue_table = Table(issue_data, colWidths=[1.5*inch, 4*inch])
            issue_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
                ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
                ('BACKGROUND', (0, 1), (-1, -1), colors.white)
            ]))
            
            story.append(issue_table)
            story.append(Spacer(1, 10))
            
            # Add page break every 3 issues to avoid overcrowding
            if i % 3 == 0 and i < len(report['issues']):
                story.append(PageBreak())
        
        # Footer information
        story.append(Spacer(1, 30))
        footer_style = ParagraphStyle(
            'Footer',
            parent=styles['Normal'],
            fontSize=8,
            textColor=colors.grey,
            alignment=TA_CENTER
        )
        
        story.append(Paragraph(f"Report generated on {report['scan_timestamp']}", footer_style))
        story.append(Paragraph("Privacy Compliance Checker v1.0", footer_style))
        
        # Build PDF
        doc.build(story)
        print(f"PDF report saved to: {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Privacy Compliance Checker")
    parser.add_argument("path", help="Path to scan (file or directory)")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("-o", "--output", help="Output report file path")
    parser.add_argument("-f", "--format", choices=["json", "html", "pdf"], default="json", help="Output format")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="low", help="Minimum severity to report")
    
    args = parser.parse_args()
    
    # Initialize checker
    checker = PrivacyComplianceChecker(args.config)
    
    # Scan path
    if os.path.isfile(args.path):
        checker.scan_file(args.path)
    elif os.path.isdir(args.path):
        checker.scan_directory(args.path)
    else:
        print(f"Error: {args.path} is not a valid file or directory")
        return
    
    # Filter by severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_severity = severity_order[args.severity]
    checker.issues = [i for i in checker.issues if severity_order[i.severity] >= min_severity]
    
    # Generate and save report
    if args.output:
        checker.save_report(args.output, args.format)
        print(f"Report saved to {args.output}")
    else:
        report = checker.generate_report()
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()