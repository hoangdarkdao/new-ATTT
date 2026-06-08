from flask import Flask, request, jsonify
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)
CORS(app)

# Database configuration
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'blog_db')
}

def get_db_connection():
    try:
        conn = mysql.connector.connect(**db_config)
        return conn
    except Error as e:
        print(f"Database error: {e}")
        return None

# ============= Authentication Routes =============

# Simple login - INTENTIONALLY VULNERABLE (SQL Injection possible)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # VULNERABLE: Direct query - SQL Injection risk
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        cursor.execute(query)
        user = cursor.fetchone()
        
        if user:
            return jsonify({
                'success': True,
                'user_id': user['id'],
                'username': user['username'],
                'email': user['email']
            }), 200
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# Register user - INTENTIONALLY VULNERABLE (No input validation)
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # VULNERABLE: No password hashing, no input validation
        query = "INSERT INTO users (username, email, password, created_at) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (username, email, password, datetime.now()))
        conn.commit()
        
        return jsonify({'success': True, 'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    finally:
        cursor.close()
        conn.close()

# ============= User Profile Routes =============

@app.route('/api/users/<int:user_id>', methods=['GET'])
def get_user_profile(user_id):
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("SELECT id, username, email, bio, created_at FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        
        if user:
            return jsonify(user), 200
        else:
            return jsonify({'error': 'User not found'}), 404
    finally:
        cursor.close()
        conn.close()

@app.route('/api/users/<int:user_id>/update', methods=['POST'])
def update_profile(user_id):
    data = request.json
    bio = data.get('bio')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET bio = %s WHERE id = %s", (bio, user_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Profile updated'}), 200
    finally:
        cursor.close()
        conn.close()

# ============= Search Routes =============

@app.route('/api/search', methods=['GET'])
def search():
    query = request.args.get('q', '')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        # VULNERABLE: Direct string interpolation - SQL Injection risk
        search_query = f"SELECT id, username FROM users WHERE username LIKE '%{query}%'"
        cursor.execute(search_query)
        results = cursor.fetchall()
        
        return jsonify({'results': results}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

# ============= Blog/Comments Routes =============

@app.route('/api/posts', methods=['GET'])
def get_posts():
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor(dictionary=True)
    
    try:
        cursor.execute("""
            SELECT p.id, p.title, p.content, p.user_id, u.username, p.created_at 
            FROM posts p 
            JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        """)
        posts = cursor.fetchall()
        
        # Get comments for each post
        for post in posts:
            cursor.execute("""
                SELECT c.id, c.content, c.user_id, u.username, c.created_at 
                FROM comments c 
                JOIN users u ON c.user_id = u.id 
                WHERE c.post_id = %s 
                ORDER BY c.created_at
            """, (post['id'],))
            post['comments'] = cursor.fetchall()
        
        return jsonify({'posts': posts}), 200
    finally:
        cursor.close()
        conn.close()

@app.route('/api/posts', methods=['POST'])
def create_post():
    data = request.json
    title = data.get('title')
    content = data.get('content')
    user_id = data.get('user_id')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO posts (title, content, user_id, created_at) VALUES (%s, %s, %s, %s)",
            (title, content, user_id, datetime.now())
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Post created'}), 201
    finally:
        cursor.close()
        conn.close()

@app.route('/api/comments', methods=['POST'])
def add_comment():
    data = request.json
    content = data.get('content')
    post_id = data.get('post_id')
    user_id = data.get('user_id')
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # VULNERABLE: No XSS protection - HTML not escaped
        cursor.execute(
            "INSERT INTO comments (content, post_id, user_id, created_at) VALUES (%s, %s, %s, %s)",
            (content, post_id, user_id, datetime.now())
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Comment added'}), 201
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
