🔐 Secure Scan – Python AppSec Scanner
A lightweight Application Security (AppSec) scanner that analyzes log files and detects common security vulnerabilities such as exposed credentials, SQL injection attempts, and XSS payloads.

🚀 Features
* 🔍 Scans log files for security risks
* ⚠️ Detects:
    * Password exposure
    * Tokens / secrets
    * SQL Injection patterns
    * Cross-Site Scripting (XSS)
* 📊 Severity classification (HIGH / MEDIUM / LOW)
* 📄 Generates:
    * Text report
    * JSON report
* 🧠 CLI support using argparse

📁 Project Structure
secure-scan/
├── README.md
├── requirements.txt
├── src/
│   └── scanner.py
├── data/
│   └── sample_log.txt
├── reports/

⚙️ Installation
Clone the repository:
git clone https://github.com/davidionclark8594-svg/secure-scan.git
cd secure-scan
Create virtual environment (optional but recommended):
python -m venv venv
source venv/bin/activate
Install dependencies:
pip install -r requirements.txt

▶️ Usage
Run the scanner:
python src/scanner.py --path data

📊 Example Output
Line 2 | HIGH   | password | WARN Failed password attempt user=bob
Line 3 | MEDIUM | sql      | ERROR SQL injection attempt detected
Line 5 | HIGH   | token    | WARN Admin token exposed

📄 Reports Generated
After running the scanner:
* reports/scan_report.txt
* reports/scan_report.json

🧠 Future Improvements
* Recursive directory scanning
* File type filtering
* Integration with CI/CD pipelines
* AI-based vulnerability classification

👨‍💻 Author
Davidion ClarkAspiring Application Security Engineer | DevSecOps | AI + Security

⚠️ Disclaimer
This tool is for educational purposes only and is not intended for production security auditing.

