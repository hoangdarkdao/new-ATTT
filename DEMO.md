
1. csrf demo
- config use full http thay vì https
- cấu hình bật # @csrf.exempt trong app.py route change-password
- cd /demo/csrf && python -m http.server 4000
- chạy fe và be
- mở trình duyệt localhost:3001 của fe và thực hiện đăng nhập
- click vào link localhost:4000
- đăng nhập lại

2. mitm demo(https)
## 🛠️ Bước 1: Cấu hình phía Frontend

Bạn cần chỉnh sửa file biến môi trường (ví dụ: `.env`, `.env.local` hoặc file `config.js`) của dự án Frontend để trỏ API URL về cổng của MITM Proxy thay vì Backend thật.

* **Cấu hình cũ (Gọi trực tiếp):** `https://127.0.0.1:5001` (hoặc `localhost:5001`)
* **Cấu hình mới (Qua Proxy):** `https://127.0.0.1:8080`

### 🔹 Trên Windows (Command Prompt / PowerShell)

```cmd
mitmweb --mode reverse:https://127.0.0.1:5001 -p 8080 --ssl-insecure

```
hiện tại đang lưu cert trên local machine, demo cần xóa đi và check.


