# Simple Blog - Security Testing Environment

A deliberately vulnerable web application for learning and testing authentication security mechanisms.

## ⚠️ WARNING: Security Features are INTENTIONALLY DISABLED

This application is designed with **intentional security vulnerabilities** for educational and testing purposes:

- ❌ No password hashing (plain text storage)
- ❌ SQL Injection vulnerabilities
- ❌ No input validation
- ❌ No XSS protection  
- ❌ No CSRF protection
- ❌ No rate limiting
- ❌ Weak authentication

**DO NOT USE IN PRODUCTION!**

---

## 📋 Architecture

```
Simple Blog
├── Backend (Python Flask)
│   ├── app.py - Main Flask application
│   ├── requirements.txt - Python dependencies
│   └── .env - Environment configuration
├── Frontend (React)
│   ├── src/
│   │   ├── App.js - Main app component
│   │   ├── components/
│   │   │   ├── Login.js - Login form
│   │   │   ├── Register.js - Registration form
│   │   │   ├── Blog.js - Blog posts and comments
│   │   │   └── Profile.js - User profile
│   ├── public/index.html - HTML template
│   └── package.json - NPM dependencies
└── Database
    └── schema.sql - MySQL schema
```

---

## 🔧 Prerequisites

- **MySQL** (version 8.0+)
- **Python** (version 3.8+)
- **Node.js** (version 14+) with npm
- **Git** (optional)

---

## 🚀 Installation & Setup

### 1. Database Setup

Open MySQL client and execute the schema:

```bash
mysql -u root -p < database/schema.sql
```

Or run directly in MySQL:

```sql
-- Copy all content from database/schema.sql and paste in MySQL
```

**Sample Credentials:**
- Username: `admin` | Password: `admin123`
- Username: `user1` | Password: `password123`

---

### 2. Backend Setup

Navigate to backend directory:

```bash
cd backend
```

**Create virtual environment:**

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# macOS/Linux
python3 -m venv venv
# có thể cấp quyền tạm = 
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
source venv/bin/activate
```

**Install dependencies:**

```bash
pip install -r requirements.txt
```

**Configure environment:**

Edit `.env` file with your MySQL credentials:

```env
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_password
DB_NAME=blog_db
FLASK_ENV=development
```

**Run Flask server:**

```bash
python app.py
```

Server runs on: `http://localhost:5000`

---

### 3. Frontend Setup

In a new terminal, navigate to frontend directory:

```bash
cd frontend
```

**Install dependencies:**

```bash
npm install
```

**Start development server:**

```bash
npm start
```

Application opens at: `http://localhost:3000`

---

## 📱 Features

### Authentication
- **Login** - Simple user login (vulnerable to SQL injection)
- **Register** - New user registration (no password hashing)

### User Profile
- View user information
- Edit bio (no input sanitization)

### Blog Posts
- Create posts (only when logged in)
- View all posts with comments
- Add comments to posts

### Search
- Search users by username
- Full-text search (vulnerable to SQL injection)

---

## 🎯 Testing Scenarios

### SQL Injection Testing

**Login Form:**
```
Username: admin' --
Password: anything
```

**Search Box:**
```
Search: ' OR '1'='1
```

### XSS Testing

**Comment/Bio:**
```
<script>alert('XSS Vulnerability')</script>
```

### Authentication Bypass
- Try modifying user_id in API calls
- Inspect network requests for exposed credentials
- Try CSRF attacks

---

## 📊 API Endpoints

### Authentication
- `POST /api/login` - User login
- `POST /api/register` - User registration

### User Profile
- `GET /api/users/<id>` - Get user profile
- `POST /api/users/<id>/update` - Update profile

### Posts
- `GET /api/posts` - Get all posts with comments
- `POST /api/posts` - Create new post

### Search
- `GET /api/search?q=query` - Search users

### Comments
- `POST /api/comments` - Add comment to post

---

## 🔐 Security Issues to Explore

1. **SQL Injection** - In login, search, and registration
2. **No Password Hashing** - Passwords stored as plain text
3. **No Input Validation** - Direct user input to database
4. **No XSS Protection** - HTML/JS in comments not sanitized
5. **No Authentication Headers** - No JWT or session tokens
6. **No CSRF Protection** - No token verification
7. **No Rate Limiting** - Unlimited login attempts
8. **Information Disclosure** - Detailed error messages
9. **Weak Session Management** - Only user_id stored locally
10. **No HTTPS** - Credentials sent over plain HTTP

---

## 📈 Upgrade Plan (Phase 2)

After testing vulnerabilities, you can upgrade to secure versions:

1. **Add password hashing** (bcrypt)
2. **Implement JWT tokens**
3. **Input sanitization & validation**
4. **Parameterized queries**
5. **XSS prevention** (HTML escaping)
6. **CSRF protection tokens**
7. **Rate limiting**
8. **HTTPS/SSL**
9. **Better error handling**
10. **Database access control**

---

## 🐛 Troubleshooting

**MySQL Connection Error:**
```
Check DB_HOST, DB_USER, DB_PASSWORD in .env
Ensure MySQL is running
```

**CORS Error:**
```
Already enabled in Flask backend
Check if backend runs on port 5000
```

**React Won't Start:**
```
Delete node_modules folder
npm install
npm start
```

**Port Already in Use:**
```
Flask: Change port in app.py: app.run(port=5001)
React: npm start (will ask to use different port)
```

---

## 📝 Project Structure

```
d:\ATTT2\
├── backend/
│   ├── app.py
│   ├── requirements.txt
│   └── .env
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── package-lock.json
├── database/
│   └── schema.sql
└── README.md
```

---

## 🎓 Learning Resources

- OWASP Top 10 Vulnerabilities
- SQL Injection Prevention
- XSS Protection Best Practices
- Secure Authentication Implementation
- CSRF Protection Methods

---

## 📞 Next Steps

1. ✅ Set up database
2. ✅ Run Flask backend
3. ✅ Run React frontend
4. 🧪 Test authentication vulnerabilities
5. 🔒 Implement security fixes (Phase 2)
6. 📊 Compare vulnerable vs secured versions

---

Happy (Secure) Testing! 🚀
