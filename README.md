# Privacy Compliance Checker 🛡️

A comprehensive, free, and open-source tool for scanning codebases to automatically identify potential GDPR and CCPA privacy violations before they become legal issues.

## 🚀 Quick Start

```bash
# Install dependencies
pip install reportlab

# Download the script
wget https://example.com/privacy_checker.py

# Scan a file
python privacy_checker.py MyService.java -o report.pdf -f pdf

# Scan entire project
python privacy_checker.py /path/to/project -o compliance_report.html -f html
```

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Basic Usage](#-basic-usage)
- [Advanced Usage](#-advanced-usage)
- [Report Formats](#-report-formats)
- [Configuration](#-configuration)
- [Understanding Reports](#-understanding-reports)
- [Supported Languages](#-supported-languages)
- [Compliance Rules](#-compliance-rules)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 **Comprehensive Detection**
- **Sensitive Data Patterns**: Emails, phone numbers, SSNs, credit cards, IP addresses
- **Cookie & Tracking**: Unauthorized cookies, analytics, localStorage usage
- **Data Collection**: Missing consent mechanisms, unauthorized data gathering
- **Data Retention**: Indefinite storage, missing deletion policies
- **Third-Party Transfers**: External data sharing without safeguards
- **User Rights**: Missing access, deletion, and portability features

### 📊 **Professional Reporting**
- **PDF Reports**: Executive-ready compliance reports
- **HTML Reports**: Interactive web-based reports
- **JSON Reports**: Machine-readable data for CI/CD integration
- **Color-coded Severity**: Critical, High, Medium, Low priority issues

### 🏛️ **Regulation Compliance**
- **GDPR (General Data Protection Regulation)** - EU privacy law
- **CCPA (California Consumer Privacy Act)** - California privacy law
- **Article References**: Direct links to specific GDPR articles
- **Actionable Suggestions**: Specific fixes for each violation

### 💻 **Multi-Language Support**
- **Python**: Database operations, data processing
- **JavaScript**: localStorage, cookies, client-side tracking
- **Java**: Servlets, JDBC operations, cookie management
- **Extensible**: Easy to add support for additional languages

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Step 1: Download the Script
```bash
# Download privacy_checker.py to your project directory
curl -O https://example.com/privacy_checker.py
```

### Step 2: Install Dependencies
```bash
# Required for PDF generation
pip install reportlab
```

### Step 3: Verify Installation
```bash
python privacy_checker.py --help
```

## 📖 Basic Usage

### Scan a Single File
```bash
# Generate JSON report (default)
python privacy_checker.py MyService.java

# Generate HTML report
python privacy_checker.py MyService.java -o report.html -f html

# Generate PDF report
python privacy_checker.py MyService.java -o report.pdf -f pdf
```

### Scan a Directory
```bash
# Scan entire project
python privacy_checker.py /path/to/project -o compliance_report.pdf -f pdf

# Scan with output to specific file
python privacy_checker.py ./src -o privacy_audit.html -f html
```

### Filter by Severity
```bash
# Only show critical issues
python privacy_checker.py project/ --severity critical

# Show critical and high priority issues
python privacy_checker.py project/ --severity high

# Show all issues (default)
python privacy_checker.py project/ --severity low
```

## 🔧 Advanced Usage

### Command Line Options
```bash
python privacy_checker.py [PATH] [OPTIONS]
```

| Option | Description | Example |
|--------|-------------|---------|
| `PATH` | File or directory to scan | `./src` |
| `-o, --output` | Output file path | `-o report.pdf` |
| `-f, --format` | Output format (json/html/pdf) | `-f pdf` |
| `-c, --config` | Configuration file path | `-c config.json` |
| `--severity` | Minimum severity level | `--severity high` |
| `-h, --help` | Show help message | `-h` |

### Using Configuration Files
Create a `config.json` file to customize scanning behavior:

```json
{
  "regulations": ["GDPR", "CCPA"],
  "file_extensions": [".py", ".js", ".java", ".php", ".rb", ".go", ".cs"],
  "exclude_dirs": ["node_modules", ".git", "__pycache__", "venv", ".env"],
  "severity_threshold": "medium",
  "output_format": "pdf"
}
```

```bash
python privacy_checker.py project/ -c config.json -o custom_report.pdf
```

### CI/CD Integration
```yaml
# .github/workflows/privacy-check.yml
name: Privacy Compliance Check
on: [push, pull_request]

jobs:
  privacy-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.9'
    - name: Install dependencies
      run: pip install reportlab
    - name: Run privacy compliance check
      run: python privacy_checker.py src/ -o privacy-report.pdf -f pdf --severity high
    - name: Upload report
      uses: actions/upload-artifact@v2
      with:
        name: privacy-compliance-report
        path: privacy-report.pdf
```

## 📄 Report Formats

### 📊 PDF Reports
Professional, executive-ready reports with:
- Executive summary with issue counts
- Color-coded severity indicators
- Detailed findings with code snippets
- GDPR article references
- Actionable recommendations

**Best for**: Compliance audits, executive reviews, legal documentation

### 🌐 HTML Reports
Interactive web-based reports with:
- Responsive design
- Clickable navigation
- Syntax highlighting
- Filterable results

**Best for**: Developer reviews, team collaboration, detailed analysis

### 📁 JSON Reports
Machine-readable data with:
- Structured issue data
- Severity breakdowns
- Regulation mapping
- Programmatic integration

**Best for**: CI/CD pipelines, automated processing, custom tools

## ⚙️ Configuration

### Default Configuration
```json
{
  "regulations": ["GDPR", "CCPA"],
  "file_extensions": [".py", ".js", ".java", ".php", ".rb", ".go", ".cs"],
  "exclude_dirs": ["node_modules", ".git", "__pycache__", "venv", ".env"],
  "severity_threshold": "low",
  "output_format": "json"
}
```

### Customizing File Types
```json
{
  "file_extensions": [".py", ".js", ".java", ".tsx", ".php"],
  "exclude_dirs": ["build", "dist", "coverage", "logs"]
}
```

### Regulation-Specific Scanning
```json
{
  "regulations": ["GDPR"],  // Only GDPR compliance
  "severity_threshold": "high"
}
```

## 📊 Understanding Reports

### Severity Levels

| Level | Icon | Description | Action Required |
|-------|------|-------------|-----------------|
| **Critical** | 🔴 | Immediate legal violation risk | Fix immediately |
| **High** | 🟠 | Significant compliance risk | Fix within days |
| **Medium** | 🟡 | Moderate compliance concern | Fix within weeks |
| **Low** | 🟢 | Best practice improvement | Fix when convenient |

### Issue Categories

#### 🗃️ Data Collection
Issues related to gathering personal data without proper consent.
- Missing consent mechanisms
- Unauthorized data collection
- Insufficient legal basis

#### ✅ Consent
Problems with obtaining and managing user consent.
- Cookie consent missing
- Marketing email opt-in missing
- Tracking without permission

#### 🔒 Security
Security-related privacy concerns.
- Sensitive data in logs
- Insecure data handling
- Missing access controls

#### 📅 Data Retention
Issues with data storage and deletion policies.
- Indefinite data retention
- Missing deletion mechanisms
- Unclear retention periods

#### 📤 Data Transfer
Problems with sharing data with third parties.
- Unauthorized external transfers
- Missing data processing agreements
- Inadequate safeguards

### Sample Report Structure
```
Executive Summary
├── Total Issues: 15
├── Critical: 2
├── High: 5
├── Medium: 6
└── Low: 2

Regulation Impact
├── GDPR: 8 issues
├── CCPA: 3 issues
└── Both: 4 issues

Detailed Issues
├── Issue #1: Cookie tracking without consent
│   ├── File: UserService.java:45
│   ├── Severity: Critical
│   ├── Regulation: GDPR
│   ├── Code: Cookie trackingCookie = new Cookie(...)
│   ├── Suggestion: Implement consent check
│   └── Reference: Article 7 (Conditions for consent)
└── ...
```

## 💻 Supported Languages

### 🐍 Python
- Database operations (SQLAlchemy, Django ORM, raw SQL)
- Personal data processing
- API endpoints handling user data

### 🟨 JavaScript/TypeScript
- localStorage and sessionStorage usage
- Cookie management
- Client-side tracking
- React/Vue component data handling

### ☕ Java
- Servlet cookie management
- JDBC operations on user data
- Spring Boot controllers
- Logging sensitive information

### 🔧 Adding New Languages
To add support for a new language, extend the checker:

```python
def _check_new_language_specific(self, file_path: str, content: str, lines: List[str]) -> None:
    """New language-specific privacy checks"""
    patterns = [
        r'language_specific_pattern',
        r'another_pattern'
    ]
    
    for pattern in patterns:
        # Implementation here
        pass
```

## 📋 Compliance Rules

### GDPR Rules Detected

#### Article 6 - Lawful Basis for Processing
- ✅ Consent verification before data collection
- ✅ Legitimate interest assessments
- ✅ Legal basis documentation

#### Article 7 - Conditions for Consent
- ✅ Cookie consent mechanisms
- ✅ Marketing email opt-in
- ✅ Clear consent requests

#### Article 13/14 - Information to be Provided
- ✅ Privacy policy links
- ✅ Data usage transparency
- ✅ Contact information

#### Article 15 - Right of Access
- ✅ Data download functionality
- ✅ Complete data access
- ✅ User data portability

#### Article 17 - Right to Erasure
- ✅ Account deletion mechanisms
- ✅ Data retention policies
- ✅ Automated deletion processes

#### Chapter V - International Transfers
- ✅ Third-party data sharing safeguards
- ✅ Adequacy decisions compliance
- ✅ Standard contractual clauses

### CCPA Rules Detected

#### Right to Know
- ✅ Data collection disclosure
- ✅ Category identification
- ✅ Source transparency

#### Right to Delete
- ✅ Deletion request mechanisms
- ✅ Data removal verification
- ✅ Third-party deletion coordination

#### Right to Opt-Out
- ✅ Sale opt-out mechanisms
- ✅ "Do Not Sell" links
- ✅ Third-party sharing controls

## 🔍 Common Issues & Solutions

### Critical Issues

#### 🔴 Cookie Tracking Without Consent
**Problem**: Setting cookies for analytics/marketing without user consent.

**Detection Pattern**:
```java
Cookie trackingCookie = new Cookie("analytics_id", userId);
response.addCookie(trackingCookie);
```

**Solution**:
```java
if (userHasConsented()) {
    Cookie trackingCookie = new Cookie("analytics_id", userId);
    response.addCookie(trackingCookie);
}
```

#### 🔴 Indefinite Data Retention
**Problem**: Storing user data "permanently" or "forever".

**Detection Pattern**:
```python
# Store user data permanently
user_archive.store_forever(user_data)
```

**Solution**:
```python
# Store with retention policy
user_archive.store_with_retention(user_data, retention_days=365)
```

### High Priority Issues

#### 🟠 Marketing Without Opt-in
**Problem**: Adding users to marketing lists without explicit consent.

**Detection Pattern**:
```javascript
addToNewsletterList(email); // No consent check
```

**Solution**:
```javascript
if (user.hasOptedInToMarketing()) {
    addToNewsletterList(email);
}
```

#### 🟠 Third-Party Data Sharing
**Problem**: Sending user data to external services without safeguards.

**Detection Pattern**:
```python
external_analytics.send_user_data(user_info)
```

**Solution**:
```python
if (user.hasConsentedToAnalytics() && hasDataProcessingAgreement()):
    external_analytics.send_anonymized_data(anonymize(user_info))
```

## 🚨 Troubleshooting

### Common Errors

#### ImportError: No module named 'reportlab'
**Solution**:
```bash
pip install reportlab
```

#### Permission denied writing report
**Solution**:
```bash
# Check write permissions
chmod 755 /path/to/output/directory

# Or specify different output location
python privacy_checker.py project/ -o ~/reports/privacy.pdf -f pdf
```

#### Large projects causing memory issues
**Solution**:
```bash
# Use severity filtering
python privacy_checker.py project/ --severity high -o report.pdf -f pdf

# Scan directories in chunks
python privacy_checker.py src/main -o main_report.pdf -f pdf
python privacy_checker.py src/test -o test_report.pdf -f pdf
```

#### No issues found in known problematic code
**Check**:
1. File extensions are supported
2. Directory isn't in exclude list
3. Severity threshold isn't too high
4. Patterns match your code style

### Getting Help

1. **Check the documentation** - Most questions are answered here
2. **Run with verbose output** - Add `-v` flag for detailed logging
3. **Test with sample code** - Use the provided test files
4. **Check file permissions** - Ensure read access to source files
5. **Verify dependencies** - Ensure all required packages are installed

## 🔄 Automation & Integration

### Pre-commit Hooks
```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: privacy-check
        name: Privacy Compliance Check
        entry: python privacy_checker.py
        language: system
        args: ['src/', '--severity', 'high']
        pass_filenames: false
```

### Docker Integration
```dockerfile
FROM python:3.9-slim
RUN pip install reportlab
COPY privacy_checker.py /usr/local/bin/
ENTRYPOINT ["python", "/usr/local/bin/privacy_checker.py"]
```

```bash
# Build and run
docker build -t privacy-checker .
docker run -v $(pwd):/workspace privacy-checker /workspace/src -o /workspace/report.pdf -f pdf
```

### IDE Integration

#### VS Code Task
```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Privacy Compliance Check",
            "type": "shell",
            "command": "python",
            "args": ["privacy_checker.py", "${workspaceFolder}", "-o", "privacy_report.html", "-f", "html"],
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always",
                "panel": "new"
            }
        }
    ]
}
```

## 🤝 Contributing

We welcome contributions! Here's how to help:

### Development Setup
```bash
# Clone the repository
git clone https://github.com/youruser/privacy-compliance-checker.git
cd privacy-compliance-checker

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

### Adding New Patterns
1. **Identify the pattern** in real code
2. **Add to appropriate category** in `_load_compliance_rules()`
3. **Test with sample code** 
4. **Update documentation**

### Adding Language Support
1. **Create language-specific method** `_check_language_specific()`
2. **Add file extension** to default config
3. **Add test cases**
4. **Update documentation**

### Submitting Changes
1. **Fork the repository**
2. **Create feature branch** (`git checkout -b feature/new-language`)
3. **Make changes with tests**
4. **Update documentation**
5. **Submit pull request**

## 📚 Additional Resources

### Privacy Law Resources
- [GDPR Full Text](https://gdpr.eu/tag/gdpr/) - Complete GDPR regulation
- [CCPA Guide](https://www.caprivacy.org/) - California privacy law details
- [Privacy by Design](https://www.ipc.on.ca/privacy-by-design/) - Privacy principles

### Development Resources
- [Python Regular Expressions](https://docs.python.org/3/library/re.html)
- [ReportLab Documentation](https://www.reportlab.com/docs/reportlab-userguide.pdf)
- [OWASP Privacy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Privacy_Engineering_Cheat_Sheet.html)

### Sample Test Files
Download test files to verify the tool works correctly:
- [Java Test File](https://example.com/test_java.java)
- [Python Test File](https://example.com/test_python.py)
- [JavaScript Test File](https://example.com/test_js.js)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Privacy Compliance Checker

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🙏 Acknowledgments

- **Privacy advocates** who push for better data protection
- **Open source community** for tools and libraries
- **Legal experts** who provide compliance guidance
- **Developers** who care about user privacy

---

## ⭐ Support the Project

If this tool helps your organization achieve privacy compliance:
- ⭐ **Star the repository** to show support
- 🐛 **Report issues** to help improve the tool
- 💡 **Suggest features** for new compliance checks
- 🤝 **Contribute code** to expand language support
- 📖 **Share the tool** with other developers

**Together, we can make privacy compliance accessible to everyone!**

---

*Privacy Compliance Checker - Making GDPR and CCPA compliance accessible to all developers* 🛡️
