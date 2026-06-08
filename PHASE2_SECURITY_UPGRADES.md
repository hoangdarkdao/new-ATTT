# Phase 2: Security Upgrades Implementation Guide

This guide shows how to fix all the intentional vulnerabilities from Phase 1.

---

## 🔧 Upgrade Implementations

### 1. SQL Injection Prevention - Use Parameterized Queries

**VULNERABLE (Current):**
```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
cursor.execute(query)
```

**SECURE (Fixed):**
```python
query = "SELECT * FROM users WHERE username = %s AND password = %s"
cursor.execute(query, (username, password))
```

**All query examples:**
```python
# Instead of f-strings, use %s placeholders
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
cursor.execute("SELECT * FROM users WHERE username LIKE %s", (f"%{query}%",))
cursor.execute("INSERT INTO posts VALUES (%s, %s, %s, %s)", (title, content, user_id, datetime.now()))
```

---

### 2. Password Hashing - Use bcrypt

**Installation:**
```bash
pip install bcrypt
```

**VULNERABLE (Current):**
```python
@app.route('/api/register', methods=['POST'])
def register():
    # ... 
    # Password stored as plain text
    query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, email, password))
```

**SECURE (Fixed):**
```python
import bcrypt

@app.route('/api/register', methods=['POST'])
def register():
    # Hash password with bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    query = "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)"
    cursor.execute(query, (username, email, hashed_password))
    conn.commit()

@app.route('/api/login', methods=['POST'])
def login():
    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    
    if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'success': True, 'user_id': user['id']})
    return jsonify({'error': 'Invalid credentials'}), 401
```

---

### 3. Input Validation & Sanitization

**Installation:**
```bash
pip install email-validator
pip install bleach
```

**VULNERABLE (Current):**
```python
# No validation, direct use of user input
bio = data.get('bio')
cursor.execute("UPDATE users SET bio = %s WHERE id = %s", (bio, user_id))
```

**SECURE (Fixed):**
```python
from email_validator import validate_email, EmailNotValidError
import bleach

@app.route('/api/users/<int:user_id>/update', methods=['POST'])
def update_profile(user_id):
    data = request.json
    bio = data.get('bio', '').strip()
    
    # Validate length
    if len(bio) > 500:
        return jsonify({'error': 'Bio too long (max 500 chars)'}), 400
    
    # Sanitize HTML/XSS
    safe_bio = bleach.clean(bio, tags=[], strip=True)
    
    cursor.execute("UPDATE users SET bio = %s WHERE id = %s", (safe_bio, user_id))
    conn.commit()
    return jsonify({'success': True})
```

---

### 4. XSS Protection - HTML Escaping

**Installation:**
```bash
pip install markupsafe
```

**Backend Fix:**
```python
from markupsafe import escape

# When returning data, escape HTML
@app.route('/api/posts', methods=['GET'])
def get_posts():
    # ... fetch posts ...
    for post in posts:
        post['content'] = escape(post['content'])
    return jsonify({'posts': posts})

# Or use Flask's auto-escaping in Jinja2 templates
```

**Frontend Fix (React):**
```javascript
// React automatically escapes by default
// But be careful with dangerouslySetInnerHTML:

// UNSAFE:
<div dangerouslySetInnerHTML={{__html: post.content}} />

// SAFE (default):
<div>{post.content}</div>  // React escapes this automatically
```

---

### 5. JWT Authentication - Replace Simple Auth

**Installation:**
```bash
pip install PyJWT
```

**VULNERABLE (Current):**
```python
# Only user_id sent to frontend
return jsonify({
    'success': True,
    'user_id': user['id'],
    'username': user['username']
})
```

**SECURE (Fixed):**
```python
import jwt
import os
from datetime import datetime, timedelta

SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key-change-in-production')

@app.route('/api/login', methods=['POST'])
def login():
    # ... authentication ...
    
    # Create JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'username': user['username'],
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')
    
    return jsonify({'success': True, 'token': token})

# Middleware to verify JWT
def verify_token(request):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except:
        return None

@app.route('/api/posts', methods=['POST'])
def create_post():
    auth = verify_token(request)
    if not auth:
        return jsonify({'error': 'Unauthorized'}), 401
    
    # ... create post ...
```

---

### 6. CSRF Protection - Add CSRF Tokens

**Installation:**
```bash
pip install Flask-WTF
```

**VULNERABLE (Current):**
```python
# No CSRF protection
@app.route('/api/posts', methods=['POST'])
def create_post():
    data = request.json
    # Direct action without token verification
```

**SECURE (Fixed):**
```python
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# Get CSRF token (before forms)
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

# Verify on POST requests
@app.route('/api/posts', methods=['POST'])
@csrf.protect
def create_post():
    # CSRF token is automatically verified
    data = request.json
    # ... safe to create post ...
```

**Frontend (React):**
```javascript
// Get token before making requests
const response = await axios.get('http://localhost:5000/api/csrf-token');
const csrfToken = response.data.csrf_token;

// Add to all POST/PUT/DELETE requests
axios.post('http://localhost:5000/api/posts', postData, {
  headers: {
    'X-CSRFToken': csrfToken
  }
});
```

---

### 7. Rate Limiting - Prevent Brute Force

**Installation:**
```bash
pip install Flask-Limiter
```

**VULNERABLE (Current):**
```python
# Unlimited login attempts
@app.route('/api/login', methods=['POST'])
def login():
    # ... no rate limiting ...
```

**SECURE (Fixed):**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Strict limit on login
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    # ... login logic ...
    # After 5 failed attempts per minute, returns 429 Too Many Requests
```

---

### 8. HTTPS - Use SSL/TLS

**Development with Self-Signed Certificate:**
```bash
# Generate self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

**Run Flask with HTTPS:**
```python
if __name__ == '__main__':
    app.run(
        ssl_context=('cert.pem', 'key.pem'),
        host='0.0.0.0',
        port=5000,
        debug=True
    )
```

**Production:** Use nginx/Apache with Let's Encrypt certificates

---

### 9. Security Headers

**VULNERABLE (Current):**
```python
# No security headers
app = Flask(__name__)
```

**SECURE (Fixed):**
```python
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
    return response
```

---

### 10. Secure Cookies

**VULNERABLE (Current):**
```python
# Frontend stores sensitive data in localStorage
localStorage.setItem('user_id', user.user_id)
```

**SECURE (Fixed):**
```python
# Use secure, httpOnly cookies
@app.route('/api/login', methods=['POST'])
def login():
    # ... authentication ...
    response = jsonify({'success': True})
    response.set_cookie(
        'auth_token',
        token,
        max_age=86400,  # 24 hours
        secure=True,    # HTTPS only
        httponly=True,  # Not accessible from JavaScript
        samesite='Strict'
    )
    return response
```

---

## 📋 Upgrade Checklist

- [ ] Replace all SQL queries with parameterized queries
- [ ] Implement bcrypt password hashing
- [ ] Add input validation and sanitization
- [ ] Enable XSS protection (HTML escaping)
- [ ] Implement JWT authentication
- [ ] Add CSRF protection tokens
- [ ] Enable rate limiting
- [ ] Setup HTTPS/SSL
- [ ] Add security headers
- [ ] Use secure cookies
- [ ] Add error handling without info disclosure
- [ ] Implement proper logging
- [ ] Add database access control
- [ ] Enable audit logging
- [ ] Setup WAF (Web Application Firewall)

---

## 🧪 Verification Tests After Upgrade

```python
# Test 1: SQL Injection Prevention
def test_sql_injection():
    response = login_request(username="admin' --", password="anything")
    assert response.status_code == 401, "SQL Injection failed to prevent"

# Test 2: Password Hashing
def test_password_hashing():
    db = get_connection()
    cursor = db.cursor()
    cursor.execute("SELECT password FROM users WHERE username = %s", ("testuser",))
    password = cursor.fetchone()[0]
    assert not password.startswith("test123"), "Password not hashed!"

# Test 3: XSS Prevention
def test_xss_prevention():
    comment = "<script>alert('XSS')</script>"
    response = add_comment(comment)
    assert response.text.find("<script>") == -1, "XSS not prevented!"

# Test 4: Rate Limiting
def test_rate_limiting():
    for i in range(10):
        response = login_request("admin", "wrong")
    assert response.status_code == 429, "Rate limiting not working!"
```

---

## 📚 Security Best Practices Reference

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CWE/CVSS Scoring](https://nvd.nist.gov/vuln/detail/CVE-2024-1234)
- [Flask Security Best Practices](https://flask.palletsprojects.com/en/2.3.x/)

---

**Happy Secure Coding! 🔒**
