# SecureSight AI 🔐
### AI-Assisted Web Security Assessment Platform

SecureSight AI is a Python-based web security assessment platform designed to analyze websites for common security weaknesses and provide actionable security recommendations.

The project aims to simplify website security assessments by checking HTTPS configurations, SSL/TLS settings, HTTP security headers, and cookie security attributes, with security analysis aligned with the OWASP Top 10.

> 🚧 **Project Status: Under Development**

## 🎯 Objectives

- Assess website security configurations through automated scanning.
- Identify missing or misconfigured HTTP security headers.
- Analyze HTTPS and SSL/TLS configurations.
- Evaluate cookie security attributes.
- Classify identified security issues based on their severity.
- Provide recommendations to improve website security.

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| FastAPI | Backend API development |
| Requests | HTTP requests and website analysis |
| Pydantic | Data validation |
| Uvicorn | ASGI server |

## 🔍 Planned Features

- **HTTPS Analysis:** Check whether websites use secure HTTPS connections.
- **SSL/TLS Assessment:** Examine SSL/TLS configuration.
- **Security Header Analysis:** Check headers such as CSP, HSTS, X-Frame-Options and X-Content-Type-Options.
- **Cookie Security Checks:** Analyze Secure, HttpOnly and SameSite attributes.
- **Vulnerability Classification:** Categorize security findings based on severity.
- **Remediation Recommendations:** Suggest possible fixes for identified security weaknesses.
- **OWASP Alignment:** Organize security findings with reference to relevant OWASP security guidelines.


*Note: The structure may change as development progresses.*

## ⚙️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <YOUR_REPOSITORY_URL>
cd SecureSight-AI
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Backend

```bash
uvicorn backend.main:app --reload
```

### 5. Access API Documentation

Open the following URL in your browser:

```text
http://127.0.0.1:8000/docs
```

*Startup commands may be updated depending on the final project structure.*

## 🧪 Testing

Automated testing using Pytest is planned to validate scanning functionality and API behavior.

```bash
pytest -v
```

## 🛡️ Security & Ethical Use

SecureSight AI is intended for authorized security assessments and educational purposes. Only scan websites that you own or have explicit permission to assess.

## 🚀 Future Improvements

- AI-assisted analysis of security findings.
- Enhanced vulnerability prioritization.
- Detailed security assessment reports.
- Improved frontend dashboard and visualization.
- Expanded OWASP security coverage.

## 👨‍💻 Developer

**Vijay Mathew A**

Integrated M.Tech – Software Engineering  
VIT Chennai

[GitHub](https://github.com/Vijay-Mathew-7318-A) | [LinkedIn](https://www.linkedin.com/in/vijaymathewa07/)

---

⭐ SecureSight AI is an ongoing project focused on making web security assessment more accessible and understandable.
