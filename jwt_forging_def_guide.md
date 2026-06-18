# Tài Liệu Mô Tả Bản Sửa Đổi Khắc Phục Lỗ Hổng JWT Forging

Tài liệu này ghi nhận các thay đổi được thực hiện trong file `app.py` nhằm loại bỏ rủi ro bị tấn công giả mạo token định danh (JWT Forging/Tampering) và nâng cao mức độ bảo mật chung của hệ thống API Auth.

---

## Các vấn đề bảo mật đã được xác định trước đó
1. **Khóa bí mật (SECRET_KEY) yếu & lộ định danh mặc định**: Hệ thống sử dụng một chuỗi fallback tĩnh (`'tccvip_prod'`) khi không tìm thấy biến môi trường. Chuỗi này rất ngắn, dễ bị tấn công Brute-force/Dictionary attack ngoại tuyến để tìm ra chữ ký số.
2. **Thiếu các Claim xác thực tiêu chuẩn**: JWT được sinh ra chỉ chứa `user_id`, `username` và `exp`. Việc thiếu thông tin xác thực nguồn gốc (`iss`), đối tượng sử dụng (`aud`) và mã định danh Token độc nhất (`jti`) tạo cơ hội cho kẻ tấn công thực hiện kỹ thuật Replay Attack hoặc sử dụng Token của môi trường này gán sang môi trường khác.

---

## Chi tiết các cải tiến mã nguồn

### 1. Cơ chế sinh `SECRET_KEY` an toàn dự phòng
* **Thay đổi**: Loại bỏ chuỗi tĩnh `'tccvip_prod'`. Sử dụng module `secrets` được tối ưu cho mật mã học của Python để tự động tạo chuỗi Hex ngẫu nhiên cường độ cao (32 bytes) nếu tệp `.env` chưa thiết lập khóa.
* **Mục đích**: Chống lại việc giả mạo token do lộ hoặc bẻ khóa thành công `SECRET_KEY`.

### 2. Bổ sung các Registered Claims vào JWT Payload
Tại API đăng nhập (`/api/login`), các trường sau đã được thêm vào cấu trúc Token:
* `iss` (Issuer): Chỉ định rõ định danh của Service phát hành Token (`tccvip_backend`).
* `aud` (Audience): Chỉ định rõ Client được phép sử dụng Token này (`tccvip_frontend`).
* `iat` (Issued At) & `nbf` (Not Before): Ghi nhận mốc thời gian tạo ra và thời gian bắt đầu có hiệu lực của Token.
* `jti` (JWT ID): Một chuỗi UUID ngẫu nhiên duy nhất cho mỗi phiên mã hóa.

### 3. Nghiêm ngặt hóa hàm kiểm tra và giải mã (`verify_token`)
Hàm giải mã `jwt.decode` được bổ sung cấu hình xác thực chặt chẽ:
```python
payload = jwt.decode(
    token, 
    SECRET_KEY, 
    algorithms=['HS256'],
    audience=JWT_AUDIENCE,
    issuer=JWT_ISSUER
)