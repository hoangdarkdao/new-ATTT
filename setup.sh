#!/bin/bash
# Setup script for Linux/macOS

echo "🚀 Starting Blog Setup..."

# Backend setup
echo "📦 Setting up Backend..."
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..

# Frontend setup
echo "⚛️ Setting up Frontend..."
cd frontend
npm install
cd ..

echo ""
echo "✅ Setup Complete!"
echo ""
echo "To start the application:"
echo "1. Backend: cd backend && source venv/bin/activate && python app.py"
echo "2. Frontend: cd frontend && npm start"
echo ""
echo "Make sure to:"
echo "- Setup MySQL and run database/schema.sql"
echo "- Update backend/.env with your database credentials"
