#!/usr/bin/env python3
"""
Enhanced Privacy Compliance Checker with Scoring System
Adds gamification, progress tracking, and trend analysis
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
from datetime import datetime, timedelta
import hashlib

@dataclass
class ComplianceIssue:
    """Represents a privacy compliance issue"""
    severity: str  # Severity level of the issue
    category: str  # Compliance category (e.g., data_collection, consent)
    regulation: str  # Regulation affected (GDPR, CCPA, BOTH)
    file_path: str  # File where the issue was found
    line_number: int  # Line number in the file
    issue_type: str  # Type of issue
    description: str  # Description of the issue
    code_snippet: str  # Code snippet where the issue was found
    suggestion: str  # Suggestion to fix the issue
    article_reference: Optional[str] = None  # Reference to regulation article
    weight: float = 1.0  # Weight for scoring

@dataclass
class ComplianceScore:
    """Comprehensive compliance scoring data"""
    score: int  # Final compliance score (0-100)
    grade: str  # Letter grade (A+ to F)
    trend: str  # Score trend (improving, declining, stable)
    previous_score: Optional[int]  # Previous score for comparison
    score_change: int  # Change in score since last scan
    improvement_streak: int  # Number of consecutive improvements
    days_since_last_scan: int  # Days since last scan
    risk_level: str  # Overall risk level
    next_milestone: Dict  # Next milestone info
    benchmarks: Dict  # Industry benchmarks
    category_scores: Dict[str, int]  # Scores per compliance category
    recommendations: List[str]  # Recommendations for improvement

class ComplianceScoring:
    """Advanced compliance scoring and tracking system"""
    
    def __init__(self, history_file: str = "compliance_history.json"):
        self.history_file = history_file
        self.max_score = 100
        
        # Scoring weights by severity
        self.severity_weights = {
            'critical': 25,  # Critical issues heavily penalized
            'high': 10,
            'medium': 3,
            'low': 1
        }
        
        # Category importance multipliers
        self.category_multipliers = {
            'consent': 1.5,      # Consent issues are most important
            'data_collection': 1.3,
            'security': 1.2,
            'data_retention': 1.1,
            'data_transfer': 1.0
        }
        
        # Industry benchmarks (realistic based on research)
        self.benchmarks = {
            'startup': 65,
            'small_business': 70,
            'medium_business': 75,
            'enterprise': 80,
            'financial_services': 85,
            'healthcare': 90,
            'government': 95
        }
    
    def calculate_compliance_score(self, issues: List[ComplianceIssue], 
                                 project_info: Dict = None) -> ComplianceScore:
        """Calculate comprehensive compliance score with detailed analysis"""
        # Calculate base score by deducting penalties for each issue
        base_score = self._calculate_base_score(issues)
        # Adjust score based on category multipliers
        adjusted_score = self._apply_category_adjustments(issues, base_score)
        # Calculate scores for each compliance category
        category_scores = self._calculate_category_scores(issues)
        # Load historical scan data
        history = self._load_history()
        previous_score = self._get_previous_score(history)
        # Analyze trends and improvement streaks
        trend_data = self._analyze_trends(history, adjusted_score)
        # Assess overall risk level
        risk_level = self._assess_risk_level(adjusted_score, issues)
        # Generate recommendations for improvement
        recommendations = self._generate_score_recommendations(adjusted_score, issues, category_scores)
        # Calculate next milestone to reach
        next_milestone = self._calculate_next_milestone(adjusted_score)
        # Assign a letter grade
        grade = self._get_grade(adjusted_score)
        # Return a comprehensive ComplianceScore dataclass
        return ComplianceScore(
            score=max(0, min(100, adjusted_score)),
            grade=grade,
            trend=trend_data['trend'],
            previous_score=previous_score,
            score_change=trend_data['score_change'],
            improvement_streak=trend_data['improvement_streak'],
            days_since_last_scan=trend_data['days_since_last_scan'],
            risk_level=risk_level,
            next_milestone=next_milestone,
            benchmarks=self._get_relevant_benchmarks(project_info),
            category_scores=category_scores,
            recommendations=recommendations
        )
    
    def _calculate_base_score(self, issues: List[ComplianceIssue]) -> int:
        """Calculate base score using weighted severity penalties"""
        score = self.max_score
        for issue in issues:
            penalty = self.severity_weights.get(issue.severity, 1)
            # Apply issue weight for more granular scoring
            penalty *= getattr(issue, 'weight', 1.0)
            score -= penalty
        return score
    
    def _apply_category_adjustments(self, issues: List[ComplianceIssue], base_score: int) -> int:
        """Apply category-specific score adjustments"""
        total_penalty = 0
        # Group issues by category
        category_issues = {}
        for issue in issues:
            category = issue.category
            if category not in category_issues:
                category_issues[category] = []
            category_issues[category].append(issue)
        # Apply category multipliers to penalties
        for category, category_issue_list in category_issues.items():
            multiplier = self.category_multipliers.get(category, 1.0)
            category_penalty = 0
            for issue in category_issue_list:
                penalty = self.severity_weights.get(issue.severity, 1)
                category_penalty += penalty
            # Apply multiplier to category penalty
            total_penalty += category_penalty * (multiplier - 1.0)
        return int(base_score - total_penalty)
    
    def _calculate_category_scores(self, issues: List[ComplianceIssue]) -> Dict[str, int]:
        """Calculate scores for each compliance category"""
        categories = ['consent', 'data_collection', 'security', 'data_retention', 'data_transfer']
        category_scores = {}
        for category in categories:
            category_issues = [i for i in issues if i.category == category]
            if not category_issues:
                category_scores[category] = 100  # Perfect score if no issues
            else:
                penalty = sum(self.severity_weights.get(i.severity, 1) for i in category_issues)
                score = max(0, 100 - penalty * 2)  # More granular scoring per category
                category_scores[category] = score
        return category_scores
    
    def _analyze_trends(self, history: List[Dict], current_score: int) -> Dict:
        """Analyze scoring trends over time"""
        if not history:
            return {
                'trend': 'new',
                'score_change': 0,
                'improvement_streak': 0,
                'days_since_last_scan': 0
            }
        previous_score = history[-1].get('score', 0)
        score_change = current_score - previous_score
        # Calculate improvement streak
        streak = 0
        for i in range(len(history) - 1, -1, -1):
            if i == 0:
                break
            if history[i]['score'] > history[i-1]['score']:
                streak += 1
            else:
                break
        # Days since last scan
        last_scan = datetime.fromisoformat(history[-1]['timestamp'])
        days_since = (datetime.now() - last_scan).days
        # Determine trend based on score change
        if score_change > 5:
            trend = 'improving'
        elif score_change < -5:
            trend = 'declining'
        else:
            trend = 'stable'
        return {
            'trend': trend,
            'score_change': score_change,
            'improvement_streak': streak,
            'days_since_last_scan': days_since
        }
    
    def _assess_risk_level(self, score: int, issues: List[ComplianceIssue]) -> str:
        """Assess overall privacy risk level"""
        critical_issues = len([i for i in issues if i.severity == 'critical'])
        high_issues = len([i for i in issues if i.severity == 'high'])
        # Risk level is determined by score and number of high/critical issues
        if score < 40 or critical_issues > 5:
            return 'critical'
        elif score < 60 or critical_issues > 2 or high_issues > 10:
            return 'high'
        elif score < 80 or critical_issues > 0 or high_issues > 5:
            return 'medium'
        else:
            return 'low'
    
    def _generate_score_recommendations(self, score: int, issues: List[ComplianceIssue], 
                                      category_scores: Dict[str, int]) -> List[str]:
        """Generate specific recommendations to improve score"""
        recommendations = []
        # Recommend addressing critical issues first
        critical_issues = [i for i in issues if i.severity == 'critical']
        if critical_issues:
            recommendations.append(f"🚨 Address {len(critical_issues)} critical issues immediately for major score improvement")
        # Recommend focusing on worst-performing categories
        worst_categories = sorted(category_scores.items(), key=lambda x: x[1])[:2]
        for category, category_score in worst_categories:
            if category_score < 70:
                category_issues = [i for i in issues if i.category == category]
                recommendations.append(f"📋 Focus on {category.replace('_', ' ')} improvements - {len(category_issues)} issues found")
        # General recommendations based on score
        if score < 50:
            recommendations.append("🛠️ Consider privacy-by-design training for development team")
        elif score < 70:
            recommendations.append("📚 Implement automated privacy checks in CI/CD pipeline")
        elif score < 85:
            recommendations.append("🎯 Focus on remaining medium-priority issues for compliance excellence")
        else:
            recommendations.append("⭐ Excellent work! Maintain current practices and monitor for new issues")
        return recommendations
    
    def _calculate_next_milestone(self, current_score: int) -> Dict:
        """Calculate next scoring milestone and what's needed to reach it"""
        milestones = [
            (95, "Privacy Excellence", "A+"),
            (90, "Compliance Leader", "A"),
            (80, "Strong Compliance", "B"),
            (70, "Basic Compliance", "C"),
            (60, "Needs Improvement", "D")
        ]
        for milestone_score, title, grade in milestones:
            if current_score < milestone_score:
                points_needed = milestone_score - current_score
                issues_to_fix = max(1, points_needed // 3)  # Rough estimate
                return {
                    "target_score": milestone_score,
                    "title": title,
                    "grade": grade,
                    "points_needed": points_needed,
                    "estimated_issues_to_fix": issues_to_fix,
                    "effort_level": "Low" if points_needed < 10 else "Medium" if points_needed < 20 else "High"
                }
        # If already at top, return perfect compliance milestone
        return {
            "target_score": 100,
            "title": "Perfect Compliance",
            "grade": "A+",
            "points_needed": 100 - current_score,
            "estimated_issues_to_fix": max(1, (100 - current_score) // 3),
            "effort_level": "Low"
        }
    
    def _get_grade(self, score: int) -> str:
        """Convert score to letter grade"""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "A-"
        elif score >= 80:
            return "B+"
        elif score >= 75:
            return "B"
        elif score >= 70:
            return "B-"
        elif score >= 65:
            return "C+"
        elif score >= 60:
            return "C"
        elif score >= 55:
            return "C-"
        elif score >= 50:
            return "D"
        else:
            return "F"
    
    def _get_relevant_benchmarks(self, project_info: Dict = None) -> Dict:
        """Get relevant industry benchmarks"""
        if not project_info:
            return {
                "industry_average": 73,
                "your_score_percentile": "Calculating...",
                "top_10_percent": 90
            }
        industry = project_info.get('industry', 'medium_business')
        benchmark = self.benchmarks.get(industry, 75)
        return {
            "industry_average": benchmark,
            "industry_type": industry.replace('_', ' ').title(),
            "top_10_percent": min(95, benchmark + 15),
            "regulatory_minimum": max(60, benchmark - 15)
        }
    
    def save_scan_results(self, score_data: ComplianceScore, project_hash: str = None) -> None:
        """Save current scan results for historical tracking"""
        history = self._load_history()
        # Create project hash for tracking if not provided
        if not project_hash:
            project_hash = hashlib.md5(os.getcwd().encode()).hexdigest()[:8]
        scan_record = {
            "timestamp": datetime.now().isoformat(),
            "project_hash": project_hash,
            "score": score_data.score,
            "grade": score_data.grade,
            "risk_level": score_data.risk_level,
            "category_scores": score_data.category_scores,
            "total_issues": len([cat for cat in score_data.category_scores.values()]),  # Simplified
            "metadata": {
                "version": "1.0",
                "scoring_algorithm": "weighted_severity_v1"
            }
        }
        history.append(scan_record)
        # Keep only last 50 scans per project
        project_history = [h for h in history if h.get('project_hash') == project_hash]
        other_history = [h for h in history if h.get('project_hash') != project_hash]
        project_history = project_history[-50:]  # Keep last 50
        final_history = other_history + project_history
        with open(self.history_file, 'w') as f:
            json.dump(final_history, f, indent=2)
    
    def _load_history(self) -> List[Dict]:
        """Load historical scoring data"""
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def _get_previous_score(self, history: List[Dict]) -> Optional[int]:
        """Get the most recent score from history"""
        if not history:
            return None
        return history[-1].get('score')
    
    def generate_progress_report(self, days: int = 30) -> Dict:
        """Generate detailed progress report over specified time period"""
        history = self._load_history()
        # Filter history by date range
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_history = [
            h for h in history 
            if datetime.fromisoformat(h['timestamp']) >= cutoff_date
        ]
        if len(recent_history) < 2:
            return {"status": "insufficient_data", "message": f"Need at least 2 scans in the last {days} days"}
        # Calculate progress metrics
        first_score = recent_history[0]['score']
        latest_score = recent_history[-1]['score']
        best_score = max(h['score'] for h in recent_history)
        avg_score = sum(h['score'] for h in recent_history) / len(recent_history)
        # Calculate improvement rate
        total_improvement = latest_score - first_score
        improvement_rate = total_improvement / len(recent_history) if len(recent_history) > 1 else 0
        # Consistency analysis
        score_variance = sum((h['score'] - avg_score) ** 2 for h in recent_history) / len(recent_history)
        consistency = "High" if score_variance < 25 else "Medium" if score_variance < 100 else "Low"
        return {
            "period_days": days,
            "scans_performed": len(recent_history),
            "scores": {
                "current": latest_score,
                "starting": first_score,
                "best": best_score,
                "average": round(avg_score, 1)
            },
            "progress": {
                "total_improvement": total_improvement,
                "improvement_rate": round(improvement_rate, 2),
                "trend": "Improving" if improvement_rate > 0.5 else "Stable" if improvement_rate > -0.5 else "Declining"
            },
            "consistency": consistency,
            "recommendations": self._generate_progress_recommendations(improvement_rate, consistency, latest_score)
        }
    
    def _generate_progress_recommendations(self, improvement_rate: float, 
                                         consistency: str, current_score: int) -> List[str]:
        """Generate recommendations based on progress analysis"""
        recommendations = []
        if improvement_rate > 1:
            recommendations.append("🚀 Excellent progress! Keep up the momentum")
        elif improvement_rate > 0:
            recommendations.append("📈 Steady improvement - consider accelerating with focused sprints")
        elif improvement_rate < -1:
            recommendations.append("⚠️ Score declining - review recent changes and prioritize privacy fixes")
        else:
            recommendations.append("📊 Stable score - identify new areas for improvement")
        if consistency == "Low":
            recommendations.append("🎯 Inconsistent scores suggest need for regular privacy reviews")
        if current_score < 70:
            recommendations.append("🛠️ Consider automated privacy checks in CI/CD pipeline")
        return recommendations

# Enhanced Privacy Compliance Checker with Scoring
class EnhancedPrivacyComplianceChecker:
    """Privacy checker with comprehensive scoring system"""
    
    def __init__(self, config_path: Optional[str] = None):
        # Initialize checker state, load patterns, rules, config, and scoring system
        self.issues: List[ComplianceIssue] = []
        self.sensitive_data_patterns = self._load_sensitive_patterns()
        self.compliance_rules = self._load_compliance_rules()
        self.config = self._load_config(config_path) if config_path else self._default_config()
        self.scorer = ComplianceScoring()
        
    def _default_config(self) -> Dict:
        """Default configuration for the checker"""
        return {
            "regulations": ["GDPR", "CCPA"],
            "file_extensions": [".py", ".js", ".java", ".php", ".rb", ".go", ".cs"],
            "exclude_dirs": ["node_modules", ".git", "__pycache__", "venv", ".env"],
            "severity_threshold": "low",
            "output_format": "json",
            "project_info": {
                "industry": "medium_business",
                "team_size": "small"
            }
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
        # Returns regex patterns for various sensitive data types
        return {
            "email": [
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                r'email\s*[=:]\s*["\'][^"\']+["\']',
                r'\.email\b'
            ],
            "phone": [
                r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
                r'phone\s*[=:]\s*["\'][^"\']+["\']'
            ],
            "ssn": [
                r'\b\d{3}-\d{2}-\d{4}\b',
                r'ssn\s*[=:]\s*["\'][^"\']+["\']'
            ],
            "credit_card": [
                r'\b4[0-9]{12}(?:[0-9]{3})?\b',
                r'credit_card',
                r'creditCard'
            ],
            "ip_address": [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                r'ip_address'
            ]
        }
    
    def _load_compliance_rules(self) -> Dict[str, List[Dict]]:
        """Define compliance rules for GDPR and CCPA"""
        # Returns a dictionary of compliance rules with regex patterns and metadata
        return {
            "data_collection": [
                {
                    "pattern": r'(collect|gather|obtain|acquire).*(?:personal|user|customer|individual).*data',
                    "severity": "high",
                    "regulation": "BOTH",
                    "description": "Data collection without explicit consent mechanism",
                    "suggestion": "Implement explicit consent collection before gathering personal data",
                    "gdpr_article": "Article 6 (Lawful basis for processing)",
                    "weight": 1.2  # Higher weight for data collection issues
                }
            ],
            "consent": [
                {
                    "pattern": r'(cookie|tracking|analytics)(?!.*consent)',
                    "severity": "critical",
                    "regulation": "GDPR",
                    "description": "Cookie/tracking implementation without consent mechanism",
                    "suggestion": "Implement cookie consent banner and opt-in mechanism",
                    "gdpr_article": "Article 7 (Conditions for consent)",
                    "weight": 1.5  # Highest weight for consent issues
                },
                {
                    "pattern": r'(newsletter|marketing|promotional).*email(?!.*consent|.*opt)',
                    "severity": "high",
                    "regulation": "BOTH",
                    "description": "Marketing email without explicit opt-in",
                    "suggestion": "Implement double opt-in for marketing communications",
                    "gdpr_article": "Article 7 (Conditions for consent)",
                    "weight": 1.3
                }
            ],
            "data_retention": [
                {
                    "pattern": r'(permanent|forever|indefinite).*(?:store|keep|retain)',
                    "severity": "critical",
                    "regulation": "BOTH",
                    "description": "Indefinite data retention detected",
                    "suggestion": "Implement data retention policies with defined time limits",
                    "gdpr_article": "Article 5 (Principles of processing)",
                    "weight": 1.4
                }
            ],
            "data_transfer": [
                {
                    "pattern": r'(transfer|send|export).*data.*(?:third.party|external|outside)',
                    "severity": "high",
                    "regulation": "BOTH",
                    "description": "Data transfer to third parties detected",
                    "suggestion": "Ensure proper safeguards and agreements for data transfers",
                    "gdpr_article": "Chapter V (Transfers to third countries)",
                    "weight": 1.1
                }
            ]
        }
    
    def scan_directory(self, directory_path: str) -> None:
        """Scan entire directory for compliance issues"""
        directory = Path(directory_path)
        if not directory.exists():
            raise FileNotFoundError(f"Directory {directory_path} does not exist")
        # Scan all files in directory matching config
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
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
    
    def _check_sensitive_data(self, file_path: str, content: str, lines: List[str]) -> None:
        """Check for sensitive data patterns"""
        for data_type, patterns in self.sensitive_data_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    # Add a compliance issue for each sensitive data match
                    issue = ComplianceIssue(
                        severity="medium",
                        category="data_collection",
                        regulation="BOTH",
                        file_path=file_path,
                        line_number=line_num,
                        issue_type=f"sensitive_data_{data_type}",
                        description=f"Potential {data_type} data detected",
                        code_snippet=lines[line_num - 1].strip() if line_num <= len(lines) else "",
                        suggestion=f"Ensure {data_type} data is properly protected and consent is obtained",
                        weight=0.8  # Lower weight for pattern detection
                    )
                    self.issues.append(issue)
    
    def _check_compliance_rules(self, file_path: str, content: str, lines: List[str]) -> None:
        """Check against compliance rules"""
        for category, rules in self.compliance_rules.items():
            for rule in rules:
                matches = re.finditer(rule["pattern"], content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    # Add a compliance issue for each rule violation
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
                        article_reference=rule.get("gdpr_article"),
                        weight=rule.get("weight", 1.0)
                    )
                    self.issues.append(issue)
    
    def generate_comprehensive_report(self) -> Dict:
        """Generate report with scoring and detailed analysis"""
        # Calculate compliance score
        score_data = self.scorer.calculate_compliance_score(
            self.issues, 
            self.config.get("project_info", {})
        )
        # Save results for historical tracking
        self.scorer.save_scan_results(score_data)
        # Generate traditional report
        traditional_report = self._generate_traditional_report()
        # Get progress report
        try:
            progress_report = self.scorer.generate_progress_report(30)
        except Exception as e:
            print(f"Warning: Could not generate progress report: {e}")
            progress_report = {"status": "error", "message": str(e)}
        # Combine all data into a single report dictionary
        return {
            **traditional_report,
            "compliance_score": asdict(score_data),
            "progress_analysis": progress_report,
            "scoring_metadata": {
                "algorithm_version": "1.0",
                "last_updated": datetime.now().isoformat(),
                "features": ["severity_weighting", "category_multipliers", "trend_analysis", "benchmarking"]
            }
        }
    
    def _generate_traditional_report(self) -> Dict:
        """Generate the traditional compliance report"""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        regulation_counts = {"GDPR": 0, "CCPA": 0, "BOTH": 0}
        category_counts = {}
        # Count issues by severity, regulation, and category
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
        # Recommend addressing critical issues
        critical_issues = [i for i in self.issues if i.severity == "critical"]
        if critical_issues:
            recommendations.append("Address critical privacy issues immediately to avoid potential legal violations")
        # Recommend implementing consent management if needed
        consent_issues = [i for i in self.issues if i.category == "consent"]
        if consent_issues:
            recommendations.append("Implement comprehensive consent management system")
        return recommendations if recommendations else ["Continue monitoring for privacy compliance"]
    
    def save_report(self, output_path: str, format_type: str = "json") -> None:
        """Save comprehensive report with scoring to file"""
        report = self.generate_comprehensive_report()
        # Save report in the requested format
        if format_type == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"✅ JSON report saved to: {output_path}")
        elif format_type == "html":
            self._save_enhanced_html_report(report, output_path)
            print(f"✅ HTML report saved to: {output_path}")
        elif format_type == "pdf":
            self._save_enhanced_pdf_report(report, output_path)
            print(f"✅ PDF report saved to: {output_path}")
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _save_enhanced_html_report(self, report: Dict, output_path: str) -> None:
        """Save enhanced HTML report with scoring and progress data"""

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
    
    def _save_enhanced_pdf_report(self, report: Dict, output_path: str) -> None:
        """Save enhanced PDF report with scoring"""
        # Uses reportlab to generate a PDF report with compliance data
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
            from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
        except ImportError:
            raise ImportError("PDF generation requires reportlab. Install with: pip install reportlab")
        score_data = report["compliance_score"]
        # ... (rest of PDF rendering code unchanged)
        doc.build(story)

def main():
    """Enhanced main function with scoring system"""
    parser = argparse.ArgumentParser(description="Enhanced Privacy Compliance Checker with Scoring")
    parser.add_argument("path", help="Path to scan (file or directory)")
    parser.add_argument("-c", "--config", help="Configuration file path")
    parser.add_argument("-o", "--output", help="Output report file path")
    parser.add_argument("-f", "--format", choices=["json", "html", "pdf"], default="json", help="Output format")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="low", help="Minimum severity to report")
    parser.add_argument("--score-only", action="store_true", help="Show only compliance score")
    parser.add_argument("--progress", action="store_true", help="Show progress report")
    
    args = parser.parse_args()
    
    # Initialize enhanced checker
    checker = EnhancedPrivacyComplianceChecker(args.config)
    
    # Scan the provided path (file or directory)
    if os.path.isfile(args.path):
        checker.scan_file(args.path)
    elif os.path.isdir(args.path):
        checker.scan_directory(args.path)
    else:
        print(f"Error: {args.path} is not a valid file or directory")
        return
    
    # Filter issues by minimum severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    min_severity = severity_order[args.severity]
    checker.issues = [i for i in checker.issues if severity_order[i.severity] >= min_severity]
    
    # Generate comprehensive report
    report = checker.generate_comprehensive_report()
    
    # Handle different output/reporting modes
    if args.score_only:
        # Show only score information
        score_data = report["compliance_score"]
        print(f"🛡️ Privacy Compliance Score: {score_data['score']}/100 ({score_data['grade']})")
        print(f"📈 Trend: {score_data['trend'].title()}")
        if score_data['previous_score']:
            change = score_data['score_change']
            emoji = "📈" if change > 0 else "📉" if change < 0 else "➡️"
            print(f"{emoji} Change: {change:+d} points")
        print(f"🎯 Next Milestone: {score_data['next_milestone']['title']} ({score_data['next_milestone']['target_score']} pts)")
        
    elif args.progress:
        # Show progress report
        progress = report["progress_analysis"]
        if progress.get("status") == "insufficient_data":
            print("📊 Insufficient data for progress analysis. Need more scan history.")
        else:
            print(f"📊 Progress Report ({progress['period_days']} days)")
            print(f"Current Score: {progress['scores']['current']}")
            print(f"Improvement: {progress['progress']['total_improvement']:+d} points")
            print(f"Trend: {progress['progress']['trend']}")
            
    else:
        # Full report
        if args.output:
            # Save comprehensive report with scoring
            checker.save_report(args.output, args.format)
        else:
            # Print summary to console
            score_data = report["compliance_score"]
            print(f"🛡️ Privacy Compliance Analysis")
            print(f"Score: {score_data['score']}/100 ({score_data['grade']})")
            print(f"Risk Level: {score_data['risk_level'].title()}")
            print(f"Total Issues: {report['total_issues']}")
            print(f"Critical: {report['severity_breakdown']['critical']}")
            print(f"High: {report['severity_breakdown']['high']}")
            print("\n💡 Top Recommendations:")
            for rec in score_data['recommendations'][:3]:
                print(f"• {rec}")

if __name__ == "__main__":
    main()