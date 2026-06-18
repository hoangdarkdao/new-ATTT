from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import bcrypt
import bleach
from markupsafe import escape
import jwt
import logging
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from email_validator import validate_email, EmailNotValidError
from werkzeug.exceptions import HTTPException
from logging.handlers import RotatingFileHandler

load_dotenv()
SECRET_KEY = os.getenv('SECRET_KEY', 'tccvip_prod')
app = Flask(__name__)
# Configure CORS to allow credentials from the frontend origin(s)
FRONTEND_ORIGINS = os.getenv('FRONTEND_ORIGINS', 'https://localhost:3001').split(',')
if os.getenv('USE_HTTPS', 'False').lower() in ('0', 'false', 'no'):
    FRONTEND_ORIGINS = [origin.replace('https://', 'http://') for origin in FRONTEND_ORIGINS]
# print(f"Configured CORS origins: {FRONTEND_ORIGINS}")
CORS(app, supports_credentials=True, resources={r"/api/*": {"origins": FRONTEND_ORIGINS}})
app.config['SECRET_KEY'] = SECRET_KEY
app.config['WTF_CSRF_SSL_STRICT'] = False

# Logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
# Console handler
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(formatter)
logger.addHandler(ch)
# Rotating file handler
log_dir = os.path.dirname(__file__)
log_path = os.path.join(log_dir, 'app.log')
fh = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=5, encoding='utf-8')
fh.setLevel(logging.INFO)
fh.setFormatter(formatter)
logger.addHandler(fh)

# CSRF protection (for cookie-based flows)
csrf = CSRFProtect()
csrf.init_app(app)

# Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)


@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    logging.exception('Unhandled exception')
    return jsonify({'error': 'Internal server error'}), 500

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
# Middleware to verify JWT
def verify_token(request):
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    # if not token:
    #     token = request.cookies.get('auth_token', '')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
    except:
        return None
    
# Simple login - INTENTIONALLY VULNERABLE (SQL Injection possible)
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.json or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    # Basic validation
    if not username or not password:
        return jsonify({'error': 'Invalid credentials'}), 401

    conn = get_db_connection()
    if not conn:
        logging.error('Database connection failed')
        return jsonify({'error': 'Internal server error'}), 500

    cursor = conn.cursor(dictionary=True)

    try:
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        user = cursor.fetchone()

        if user:
            stored_password = user.get('password')
            # Ensure bytes for bcrypt
            if isinstance(stored_password, str):
                stored_password = stored_password.encode('utf-8')

            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                # Create JWT token
                token = jwt.encode({
                    'user_id': user['id'],
                    'username': user['username'],
                    'exp': datetime.utcnow() + timedelta(hours=24)
                }, SECRET_KEY, algorithm='HS256')

                # Respond with token and set secure cookie when possible
                response = make_response(jsonify({'success': True, 'token': token}), 200)
                use_https = os.getenv('USE_HTTPS', 'False').lower() in ('1', 'true', 'yes')
                response.set_cookie(
                    'auth_token',
                    token,
                    max_age=86400,
                    secure=use_https,
                    httponly=True,
                    samesite='Strict'
                )
                return response

        return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        logging.exception('Error during login')
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/change-password', methods=['POST'])
def change_password():
    auth = verify_token(request)
    if not auth:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json or {}
    new_password = data.get('password')
    if not new_password or len(new_password) < 6:
        return jsonify({'error': 'Invalid new password'}), 400

    user_id = auth.get('user_id')

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500

    cursor = conn.cursor()
    try:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Password changed successfully'}), 200
    except Exception as e:
        logging.exception('Error during password change')
        return jsonify({'error': 'Unable to change password'}), 500
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
        # Basic input validation
        if not username or not email or not password:
            return jsonify({'error': 'Missing required fields'}), 400

        if len(username) > 150 or len(password) < 6:
            return jsonify({'error': 'Invalid input values'}), 400

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            return jsonify({'error': 'Invalid email address'}), 400

        # Hash password with bcrypt and store as string
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        query = "INSERT INTO users (username, email, password, created_at) VALUES (%s, %s, %s, %s)"
        cursor.execute(query, (username, email, hashed_password, datetime.utcnow()))
        conn.commit()

        return jsonify({'success': True, 'message': 'User registered successfully'}), 201
    except Exception as e:
        logging.exception('Error during registration')
        return jsonify({'error': 'Unable to register user'}), 400
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
    bio = data.get('bio', '').strip()
    
    # Validate length
    if len(bio) > 500:
        return jsonify({'error': 'Bio too long (max 500 chars)'}), 400
    
    # Sanitize HTML/XSS
    safe_bio = bleach.clean(bio, tags=[], strip=True)
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute("UPDATE users SET bio = %s WHERE id = %s", (safe_bio, user_id))
        conn.commit()
        return jsonify({'success': True, 'message': 'Profile updated'}), 200
    finally:
        cursor.close()
        conn.close()


# CSRF token endpoint for frontends that use cookie-based auth
@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    print(f"Generated CSRF token: {token}")
    return jsonify({'csrf_token': token}), 200

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
        # search_query = f"SELECT id, username FROM users WHERE username LIKE '%{query}%'"
        # FIXED: Using parameterized query to prevent SQL Injection
        search_query = "SELECT id, username FROM users WHERE username LIKE %s"
        cursor.execute(search_query, (f'%{query}%',))
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
            for comment in post['comments']:
                comment['content'] = escape(comment['content'])
            post['content'] = escape(post['content'])  # Escape content to prevent XSS
        
        return jsonify({'posts': posts}), 200
    finally:
        cursor.close()
        conn.close()

@app.route('/api/posts', methods=['POST'])
def create_post():
    auth = verify_token(request)
    if not auth:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = auth.get('user_id')
    data = request.json
    title = data.get('title')
    content = data.get('content')
    safe_content = bleach.clean(content, tags=[], strip=True)  # Sanitize post content
    safe_title = bleach.clean(title, tags=[], strip=True)  # Sanitize post title
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            "INSERT INTO posts (title, content, user_id, created_at) VALUES (%s, %s, %s, %s)",
            (safe_title, safe_content, user_id, datetime.utcnow())
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Post created'}), 201
    finally:
        cursor.close()
        conn.close()

@app.route('/api/comments', methods=['POST'])
def add_comment():
    auth = verify_token(request)
    if not auth:
        return jsonify({'error': 'Unauthorized'}), 401
    
    user_id = auth.get('user_id')
    data = request.json
    content = data.get('content')
    post_id = data.get('post_id')
    safe_content = bleach.clean(content, tags=[], strip=True)  # Sanitize comment content
    
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Database connection failed'}), 500
    
    cursor = conn.cursor()
    
    try:
        # FIXED: XSS protection - HTML escaped
        cursor.execute(
            "INSERT INTO comments (content, post_id, user_id, created_at) VALUES (%s, %s, %s, %s)",
            (safe_content, post_id, user_id, datetime.utcnow())
        )
        conn.commit()
        return jsonify({'success': True, 'message': 'Comment added'}), 201
    finally:
        cursor.close()
        conn.close()

if __name__ == '__main__':
    port = int(os.getenv('BACKEND_PORT', 5000))
    app.run(
        ssl_context=('cert.pem', 'key.pem') if os.getenv('USE_HTTPS', 'False').lower() in ('1', 'true', 'yes') else None,
        host='0.0.0.0',
        debug=True, port=port)
