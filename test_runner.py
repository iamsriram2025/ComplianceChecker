#!/usr/bin/env python3
"""
Standalone Test Runner for Privacy Compliance Checker
Includes the checker code and test cases
"""

import os
import re
import json
import tempfile
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, asdict
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
    def __init__(self):
        self.issues: List[ComplianceIssue] = []
        self.sensitive_data_patterns = self._load_sensitive_patterns()
        self.compliance_rules = self._load_compliance_rules()
        
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
            ]
        }
    
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

def create_sample_java_file():
    """Create a sample Java file with privacy issues"""
    java_code = '''package com.example;

import java.sql.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.UUID;

public class UserService {
    
    // Hardcoded sensitive data patterns
    private static final String TEST_EMAIL = "john.doe@example.com";
    private static final String TEST_PHONE = "555-123-4567";
    private static final String TEST_SSN = "123-45-6789";
    private static final String CREDIT_CARD = "4532-1234-5678-9012";
    
    /**
     * Collect user data without explicit consent mechanism
     */
    public void collectUserData(String email, String phone) {
        // Collecting personal data without consent
        System.out.println("Collecting user data: " + email);
        
        try (Connection conn = getConnection()) {
            String sql = "INSERT INTO users (email, phone, created_date) VALUES (?, ?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);
            stmt.setString(2, phone);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Set tracking cookies without consent
     */
    public void setTrackingCookies(HttpServletResponse response) {
        // Setting tracking cookies without consent check
        Cookie analyticsCookie = new Cookie("analytics_id", UUID.randomUUID().toString());
        analyticsCookie.setMaxAge(365 * 24 * 60 * 60); // 1 year
        response.addCookie(analyticsCookie);
        
        Cookie marketingCookie = new Cookie("marketing_pref", "all");
        marketingCookie.setMaxAge(365 * 24 * 60 * 60);
        response.addCookie(marketingCookie);
    }
    
    /**
     * Newsletter signup without explicit opt-in
     */
    public void subscribeToNewsletter(String email) {
        // Adding user to promotional email list without explicit consent
        System.out.println("Adding to promotional email list: " + email);
        
        try (Connection conn = getConnection()) {
            String sql = "INSERT INTO newsletter_subscribers (email, subscribed_date) VALUES (?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, email);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Store user data permanently without retention policy
     */
    public void storeUserDataPermanently(String userData) {
        // Storing user data forever without retention policy
        System.out.println("Storing user data permanently in archive");
        
        try (Connection conn = getConnection()) {
            String sql = "INSERT INTO permanent_user_data (data, created_date) VALUES (?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, userData);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Transfer data to third party without safeguards
     */
    public void shareDataWithPartners(String email, String personalData) {
        // Transfer user data to external third party
        System.out.println("Transferring user data to external marketing partner");
        sendDataToExternalPartner(email, personalData);
    }
    
    private void sendDataToExternalPartner(String email, String data) {
        // Simulated external data transfer
        System.out.println("Sending data outside our organization");
    }
    
    /**
     * Track user activity including IP address
     */
    public void trackUserActivity(String ipAddress, String userId) {
        System.out.println("Tracking user activity from IP: " + ipAddress);
        
        try (Connection conn = getConnection()) {
            String sql = "INSERT INTO user_tracking (user_id, ip_address, tracking_date) VALUES (?, ?, NOW())";
            PreparedStatement stmt = conn.prepareStatement(sql);
            stmt.setString(1, userId);
            stmt.setString(2, ipAddress);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Process payment with sensitive logging
     */
    public void processPayment(String creditCardNumber, String email) {
        // Logging sensitive payment information
        System.out.println("Processing payment for card: " + creditCardNumber);
        System.out.println("Customer email: " + email);
    }
    
    private Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:mysql://localhost:3306/userdb", "admin", "password");
    }
}
'''
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
        f.write(java_code)
        return f.name

def test_privacy_checker():
    """Test the privacy checker with sample Java code"""
    
    print("🚀 Privacy Compliance Checker Test")
    print("=" * 50)
    
    # Create sample Java file
    print("📝 Creating sample Java file with privacy issues...")
    temp_file = create_sample_java_file()
    
    try:
        # Initialize checker
        checker = PrivacyComplianceChecker()
        
        # Scan the file
        print("🔍 Scanning Java code for privacy compliance issues...")
        checker.scan_file(temp_file)
        
        # Generate report
        report = checker.generate_report()
        
        # Display results
        print(f"\\n📊 Scan Results:")
        print("=" * 30)
        print(f"Total Issues Found: {report['total_issues']}")
        print(f"Critical: {report['severity_breakdown']['critical']}")
        print(f"High: {report['severity_breakdown']['high']}")
        print(f"Medium: {report['severity_breakdown']['medium']}")
        print(f"Low: {report['severity_breakdown']['low']}")
        
        print(f"\\n🏛️ Regulation Impact:")
        print("=" * 25)
        print(f"GDPR: {report['regulation_breakdown']['GDPR']}")
        print(f"CCPA: {report['regulation_breakdown']['CCPA']}")
        print(f"Both: {report['regulation_breakdown']['BOTH']}")
        
        print(f"\\n📋 Issues by Category:")
        print("=" * 25)
        for category, count in report['category_breakdown'].items():
            print(f"{category.replace('_', ' ').title()}: {count}")
        
        print(f"\\n🔍 Detailed Issues (First 10):")
        print("=" * 35)
        for i, issue in enumerate(report['issues'][:10], 1):
            severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}
            icon = severity_icon.get(issue['severity'], "⚪")
            
            print(f"\\n{i}. {icon} [{issue['severity'].upper()}] {issue['description']}")
            print(f"   📁 File: {os.path.basename(issue['file_path'])}:{issue['line_number']}")
            print(f"   💻 Code: {issue['code_snippet']}")
            print(f"   💡 Fix: {issue['suggestion']}")
            if issue.get('article_reference'):
                print(f"   📖 Reference: {issue['article_reference']}")
        
        if len(report['issues']) > 10:
            print(f"\\n... and {len(report['issues']) - 10} more issues")
        
        print(f"\\n💡 Recommendations:")
        print("=" * 20)
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"{i}. {rec}")
        
        # Save detailed report
        report_file = 'privacy_compliance_report.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\\n📄 Detailed report saved to: {report_file}")
        
        print(f"\\n✅ Test completed successfully!")
        print(f"Found {report['total_issues']} privacy compliance issues in the sample code.")
        
    finally:
        # Clean up
        if os.path.exists(temp_file):
            os.unlink(temp_file)

if __name__ == "__main__":
    test_privacy_checker()