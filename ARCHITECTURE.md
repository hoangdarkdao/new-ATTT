# Simple Blog - Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER BROWSER                              │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         │ HTTP/CORS
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
    ┌────────┐     ┌──────────┐    ┌──────────┐
    │ LOGIN  │     │   BLOG   │    │ PROFILE  │
    │ PAGE   │     │  POSTS   │    │  &BIO    │
    │ (React)│     │ (React)  │    │ (React)  │
    └────────┘     └──────────┘    └──────────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                         │ REST API
                         │ (Port 5000)
        ┌────────────────▼────────────────┐
        │                                  │
        │    FLASK BACKEND (Python)        │
        │                                  │
        │  ├─ /api/login                   │
        │  ├─ /api/register                │
        │  ├─ /api/users/<id>              │
        │  ├─ /api/posts                   │
        │  ├─ /api/comments                │
        │  └─ /api/search                  │
        │                                  │
        └────────────────┬────────────────┘
                         │
                         │ TCP/IP
                         │ (Port 3306)
        ┌────────────────▼────────────────┐
        │                                  │
        │     MYSQL DATABASE               │
        │                                  │
        │  ├─ users table                  │
        │  ├─ posts table                  │
        │  └─ comments table               │
        │                                  │
        └──────────────────────────────────┘
```

---

## Data Flow - User Login

```
1. USER enters credentials in React Login Form
   │
2. React sends POST request to /api/login
   │ Body: {username: "admin", password: "admin123"}
   │
3. Flask receives request
   │ VULNERABLE: Builds SQL query with string concatenation
   │ Query: SELECT * FROM users WHERE username = 'admin' AND password = 'admin123'
   │
4. Query executes on MySQL
   │ Returns user record
   │
5. Flask returns response to React
   │ Response: {success: true, user_id: 1, username: "admin"}
   │
6. React stores user data in localStorage
   │ localStorage.user_id = "1"
   │
7. User now logged in and can create posts/comments
```

---

## Data Flow - Creating a Comment

```
1. LOGGED-IN USER types comment and clicks "Post"
   │
2. React sends POST to /api/comments
   │ Body: {
   │   content: "<script>alert('XSS')</script>",
   │   post_id: 1,
   │   user_id: 1
   │ }
   │
3. Flask receives request
   │ VULNERABLE: No HTML escaping
   │ Directly inserts into database
   │
4. Comment stored in MySQL
   │ INSERT INTO comments (content, ...) 
   │ VALUES ("<script>alert('XSS')</script>", ...)
   │
5. Other users view post
   │ Flask fetches comment from DB
   │ VULNERABLE: Returns raw HTML
   │
6. React renders comment
   │ VULNERABLE: If using dangerouslySetInnerHTML
   │ <script> tag executes in all visitors' browsers
   │
7. Attacker can:
   │ ├─ Steal session cookies
   │ ├─ Redirect to phishing site
   │ ├─ Steal credentials
   │ └─ Modify page content
```

---

## Data Flow - Search Users

```
1. USER types search query in search box
   │ Search: " OR '1'='1
   │
2. React sends GET to /api/search?q=" OR '1'='1
   │
3. Flask receives request
   │ VULNERABLE: Direct string interpolation
   │ Query: SELECT id, username FROM users 
   │        WHERE username LIKE '%' OR '1'='1%'
   │
4. The '1'='1 makes condition always true
   │ Returns ALL users from database
   │
5. React displays all users as search results
   │ Attacker now knows:
   │ ├─ All usernames
   │ ├─ All user IDs
   │ └─ Can enumerate entire user list
```

---

## Vulnerability Impact Matrix

| Feature | Vulnerability | Attack | Impact |
|---------|----------------|--------|--------|
| **Login** | SQL Injection | `admin' --` | Bypass authentication |
| **Login** | No hashing | DB breach | All passwords exposed |
| **Search** | SQL Injection | `' OR '1'='1` | Data enumeration |
| **Comments** | XSS | `<script>` | Session hijacking |
| **Profile** | XSS | `<img onerror>` | Malware injection |
| **Session** | No CSRF | POST manipulation | Unauthorized actions |
| **Login** | No rate limit | Brute force | Account compromise |
| **HTTP** | No encryption | Network sniffing | Credential theft |

---

## Component Interaction

```
┌─────────────────────────────────────────────────────────┐
│                    REACT FRONTEND                        │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌──────────┐      │
│  │ Login  │  │Register│  │  Blog  │  │ Profile  │      │
│  │        │  │        │  │        │  │          │      │
│  │ - Form │  │ - Form │  │ - Posts│  │ - View   │      │
│  │ - Auth │  │ - Creds│  │ - Cmts │  │ - Edit   │      │
│  └────────┘  └────────┘  └────────┘  └──────────┘      │
│       │           │            │           │             │
│       └───────────┼────────────┼───────────┘             │
│                   │            │                         │
│         ┌─────────▼────────────▼────────┐               │
│         │   Axios HTTP Client           │               │
│         │   - Requests to backend       │               │
│         │   - localStorage (insecure)   │               │
│         └─────────┬────────────────────┘               │
└─────────────────────────────────────────────────────────┘
                    │
         HTTP (unencrypted)
                    │
        ┌───────────▼───────────┐
        │  FLASK BACKEND        │
        │  ┌──────────────────┐ │
        │  │ Routes/Views     │ │
        │  │ - No validation  │ │
        │  │ - No escaping    │ │
        │  │ - Raw SQL        │ │
        │  └────────┬─────────┘ │
        │           │           │
        │  ┌────────▼─────────┐ │
        │  │ Database Queries │ │
        │  │ - SQL Injection  │ │
        │  │ - No hashing     │ │
        │  └────────┬─────────┘ │
        └───────────┼───────────┘
                    │
                    │ TCP 3306
                    │
        ┌───────────▼───────────┐
        │  MYSQL DATABASE       │
        │  - users              │
        │  - posts              │
        │  - comments           │
        └───────────────────────┘
```

---

## File Structure with Details

```
d:\ATTT2\
│
├── README.md                          # Complete documentation
├── QUICKSTART.md                      # Quick setup guide
├── SECURITY_TESTING_GUIDE.md          # How to test vulnerabilities
├── PHASE2_SECURITY_UPGRADES.md        # How to fix issues
├── .gitignore                         # Git ignore rules
├── setup.bat                          # Windows auto-setup
├── setup.sh                           # Linux/macOS auto-setup
│
├── backend/
│   ├── app.py                         # Main Flask application
│   │   ├── Routes:
│   │   │  ├─ /api/login (SQL Injection)
│   │   │  ├─ /api/register (No hashing)
│   │   │  ├─ /api/users/<id> (Privilege escalation)
│   │   │  ├─ /api/posts (XSS)
│   │   │  ├─ /api/comments (XSS)
│   │   │  └─ /api/search (SQL Injection)
│   │   └── Vulnerabilities: 10+
│   │
│   ├── requirements.txt                # Python dependencies
│   │   ├─ Flask==2.3.0
│   │   ├─ mysql-connector-python==8.0.33
│   │   └─ python-dotenv==1.0.0
│   │
│   └── .env                           # Database credentials
│       ├─ DB_HOST=localhost
│       ├─ DB_USER=root
│       ├─ DB_PASSWORD=
│       └─ DB_NAME=blog_db
│
├── frontend/
│   ├── package.json                   # NPM dependencies
│   │   ├─ react==18.2.0
│   │   └─ axios==1.4.0
│   │
│   ├── public/
│   │   └── index.html                 # HTML template
│   │
│   └── src/
│       ├── App.js                     # Main component
│       ├── App.css                    # Styling
│       ├── index.js                   # React entry
│       │
│       └── components/
│           ├── Login.js               # Login form (tests SQL injection)
│           ├── Register.js            # Registration (no validation)
│           ├── Blog.js                # Posts & comments (XSS prone)
│           └── Profile.js             # User profile (XSS prone)
│
└── database/
    └── schema.sql                     # MySQL schema
        ├── CREATE users table
        ├── CREATE posts table
        ├── CREATE comments table
        └── Sample data (admin/user1)
```

---

## Port Configuration

| Service | Port | URL | Status |
|---------|------|-----|--------|
| **Frontend (React)** | 3000 | `http://localhost:3000` | 🔴 Vulnerable |
| **Backend (Flask)** | 5000 | `http://localhost:5000` | 🔴 Vulnerable |
| **MySQL Database** | 3306 | `localhost:3306` | 🔴 No auth |

---

## API Endpoints Summary

```
Authentication:
  POST /api/login           - Login user (SQL Injection)
  POST /api/register        - Register user (No validation)

User Management:
  GET  /api/users/<id>      - Get profile (Privilege escalation)
  POST /api/users/<id>/update - Update profile (XSS)

Blog:
  GET  /api/posts           - List posts (XSS in comments)
  POST /api/posts           - Create post (No auth check)

Comments:
  POST /api/comments        - Add comment (Stored XSS)

Search:
  GET  /api/search?q=query  - Search users (SQL Injection)
```

---

## Vulnerability Scorecard

```
Phase 1 (Current):
├─ SQL Injection                 ████████████████████ 100%
├─ XSS (Cross-Site Scripting)    ████████████████████ 100%
├─ No Password Hashing           ████████████████████ 100%
├─ No HTTPS Encryption           ████████████████████ 100%
├─ No Rate Limiting              ████████████████████ 100%
├─ No Input Validation           ████████████████████ 100%
├─ No CSRF Protection            ████████████████████ 100%
├─ Weak Session Management       ████████████████████ 100%
├─ No Security Headers           ████████████████████ 100%
└─ Information Disclosure        ████████████████████ 100%

Phase 2 (After Upgrades):
├─ SQL Injection                 ░░░░░░░░░░░░░░░░░░░░  0%
├─ XSS                           ░░░░░░░░░░░░░░░░░░░░  0%
├─ No Password Hashing           ░░░░░░░░░░░░░░░░░░░░  0%
├─ No HTTPS Encryption           ░░░░░░░░░░░░░░░░░░░░  0%
├─ No Rate Limiting              ░░░░░░░░░░░░░░░░░░░░  0%
├─ No Input Validation           ░░░░░░░░░░░░░░░░░░░░  0%
├─ No CSRF Protection            ░░░░░░░░░░░░░░░░░░░░  0%
├─ Weak Session Management       ░░░░░░░░░░░░░░░░░░░░  0%
├─ No Security Headers           ░░░░░░░░░░░░░░░░░░░░  0%
└─ Information Disclosure        ░░░░░░░░░░░░░░░░░░░░  0%
```

---

**Next: Follow QUICKSTART.md to set up and SECURITY_TESTING_GUIDE.md to test vulnerabilities!**
