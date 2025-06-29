## Vulnerability Summary
A critical Stored Cross-Site Scripting (XSS) vulnerability was discovered in the Registred Patients file of CodeAstro Simple Hospital Management System in Python.
Attackers can inject malicious JavaScript via the patname field (POST parameter), which gets persistently stored in the database and executed whenever the profile page is viewed.

## Key Details

| Property             | Value                                                                 |
|----------------------|------------------------------------------------------------------------|
| **Affected Vendor**  | CodeAstro                                                              |
| **Vulnerable File**  | `patient.html`                                                     |
| **Attack Vector**    | `First Name` parameter via POST request                                   |
| **Vulnerability Type** | Stored Cross-Site Scripting (XSS)                                   |
| **Version Affected** | v1.0                                                                   |
| **Official Website** | [Simple Python Hospital Management System](https://codeastro.com/simple-hospital-management-system-in-python-with-source-code/) |

## Proof of Concept (PoC)

### Step 1: Navigate to the Python Simple Hospital Management System Patient's Section

Navigate to the Registred Patients Section:

```
(http://localhost:8000/patient.html)
```

![image](https://github.com/user-attachments/assets/715a63ec-7b16-4d8d-a566-71c34539e6b5)

### Step 2: Inject XSS Payload in Name Field
Navigate To The Add Patient Inside The Patient.html Page:
![image](https://github.com/user-attachments/assets/b55a10b8-bad9-4016-917f-47f12224cd9e)

Paste the following payload in the "First Name" input field and click Save Info After Filling Other Information:

```html
<script>alert(1)</script>
```
![image](https://github.com/user-attachments/assets/1a8b37bc-59d0-495e-afb9-12745be10e84)


### Step 3: Trigger the Payload

Reload the profile page.  
You’ll see a JavaScript `alert(1)` triggered — confirming the stored XSS vulnerability.

Also, refreshing the page again will show the alert repeatedly. and if anyone open Patient.html Popup will also occur:
![image](https://github.com/user-attachments/assets/4d5ecc27-75b8-4f6c-a588-d4ba518db9e6)
![image](https://github.com/user-attachments/assets/fc8a7649-d0a6-49e4-9d40-daba9ef72d49)

## Potential Impact

- **Session Hijacking** – Steal user/admin session cookies via `document.cookie`.
- **Phishing** – Inject fake forms to harvest credentials.
- **Defacement** – Alter webpage content, defame the brand.
- **Data Exfiltration** – Steal sensitive data through background requests.
- **Malware Propagation** – Redirect users to malicious domains.
- **Privilege Escalation** – Gain access to higher-privilege accounts by exploiting stored scripts.

---

## Mitigation Strategies

### Input Sanitization

Sanitize all user inputs on the server side using:

```php
htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```

### Output Encoding

Encode output before rendering dynamic content:

```php
echo htmlentities($user_input, ENT_QUOTES, 'UTF-8');
```

### Content Security Policy (CSP)

Implement a strong CSP header to prevent inline script execution:

```
Content-Security-Policy: default-src 'self'; script-src 'self';
```

### Use Modern Frameworks

Use frameworks like Laravel, Symfony, or CodeIgniter, which offer built-in XSS protection.

### Security Testing

Perform regular penetration testing using tools such as:

- OWASP ZAP
- Burp Suite

---

## References and Resources

- [OWASP XSS Prevention Cheat Sheet](https://owasp.org/www-community/xss-prevention)
- [Content Security Policy (CSP) Guide - MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [PHP htmlspecialchars()](https://www.php.net/manual/en/function.htmlspecialchars.php)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices/)

---

**Author:** Subhash Paudel  
**Date:** 2025-06-29  
**Severity:** High

