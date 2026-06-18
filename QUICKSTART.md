# Quick Start Guide

## Windows Setup (PowerShell)

### 1. Create Virtual Environment (Backend)

```powershell
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure Database

- Open MySQL Workbench or command line
- Run: `mysql -u root -p < ..\database\schema.sql`
- Update `backend/.env` with your MySQL credentials

### 3. Start Backend

```powershell
python app.py
# Backend runs on http://localhost:5000
```

### 4. Start Frontend (in new PowerShell)

```powershell
cd frontend
npm install
npm start
# Frontend runs on http://localhost:3000
```

---

## Quick Test Logins

**Admin Account:**
- Username: `admin`
- Password: `admin123`

**Test Account:**
- Username: `user1`
- Password: `password123`

---

## Common Issues & Fixes

| Issue | Solution |
|-------|----------|
| MySQL connection error | Check DB credentials in `backend/.env` |
| CORS error | Ensure Flask backend is running on port 5000 |
| npm install fails | Delete `node_modules`, run `npm install` again |
| Port 3000/5000 in use | Use different ports in Flask app.py and npm start |

---

## Testing Vulnerabilities

### SQL Injection Test (Login)
- Username: `admin' --`
- Password: anything

### SQL Injection Test (Search)
- Search box: `' OR '1'='1`

### XSS Test (Comments)
- `<script>alert('XSS')</script>`

---

**Full documentation in README.md**
