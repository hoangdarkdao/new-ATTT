@echo off
REM Setup script for Windows

echo.
echo 🚀 Starting Blog Setup...
echo.

REM Backend setup
echo 📦 Setting up Backend...
cd backend
python -m venv venv
call venv\Scripts\activate.bat
pip install -r requirements.txt
cd ..

REM Frontend setup  
echo.
echo ⚛️ Setting up Frontend...
cd frontend
call npm install
cd ..

echo.
echo ✅ Setup Complete!
echo.
echo To start the application:
echo 1. Backend: cd backend ^&^& .\venv\Scripts\activate.bat ^&^& python app.py
echo 2. Frontend: cd frontend ^&^& npm start
echo.
echo Make sure to:
echo - Setup MySQL and run database/schema.sql
echo - Update backend/.env with your database credentials
echo.
pause
