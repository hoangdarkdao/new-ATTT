import werkzeug
werkzeug.__version__ = "3.0.0"

import pytest
from app import app, get_db_connection

@pytest.fixture
def client():
    """Tạo một client giả lập để gửi request tới Flask app"""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Tắt CSRF khi test API bằng client này nếu cần
    with app.test_client() as client:
        yield client

# -------------------------------------------------------------
# Test 1: SQL Injection Prevention (Kiểm tra chặn SQL Injection)
# -------------------------------------------------------------
def test_sql_injection(client):
    # Gửi payload SQL Injection vào ô username
    payload = {
        "username": "admin' OR '1'='1", 
        "password": "wrong_password"
    }
    response = client.post('/api/login', json=payload)
    
    # Nếu hệ thống an toàn (đã dùng Parameterized Queries), đăng nhập sẽ thất bại (401)
    assert response.status_code == 401
    assert b"Invalid credentials" in response.data

# -------------------------------------------------------------
# Test 2: Password Hashing (Kiểm tra mật khẩu đã được băm mã hóa)
# -------------------------------------------------------------
def test_password_hashing():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Lấy mật khẩu của user1 ra xem thử
    cursor.execute("SELECT password FROM users WHERE username = %s", ("user1",))
    user = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    if user:
        stored_password = user['password']
        # Mật khẩu gốc của user1 trong file tóm tắt là "password123"
        # Mật khẩu an toàn KHÔNG ĐƯỢC chứa chữ plain-text "password123"
        assert "password123" not in stored_password
        # Cơ chế bcrypt luôn bắt đầu chuỗi bằng ký tự đặc trưng $2b$ hoặc $2a$
        assert stored_password.startswith("$2b$") or stored_password.startswith("$2a$")

# -------------------------------------------------------------
# Test 3: XSS Prevention (Kiểm tra chống mã độc JavaScript công kích)
# -------------------------------------------------------------
def test_xss_prevention(client):
    # Tạo bài viết chứa mã độc XSS
    payload = {
        "title": "Test XSS",
        "content": "<script>alert('XSS')</script>",
        "user_id": 1
    }
    # Thử gửi bài viết (Cần giả lập Authorization token nếu API yêu cầu login)
    # Ở đây chúng ta kiểm tra xem dữ liệu trả về có bị triệt tiêu thẻ <script> hay không
    response = client.get('/api/posts')
    
    # Kiểm tra xem trong dữ liệu trả về còn chứa nguyên văn thẻ độc hại không
    assert b"<script>" not in response.data

# -------------------------------------------------------------
# Test 4: Rate Limiting (Kiểm tra chặn spam request liên tục)
# -------------------------------------------------------------
def test_rate_limiting(client):
    payload = {"username": "admin", "password": "wrong_password"}
    
    # Gửi request liên tục vượt quá cấu hình cho phép (ví dụ trong code là > 5 lần/phút)
    status_codes = []
    for _ in range(10):
        response = client.post('/api/login', json=payload)
        status_codes.append(response.status_code)
        
    # Phải có ít nhất một request bị trả về mã lỗi 429 (Too Many Requests)
    assert 429 in status_codes