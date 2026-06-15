Dưới đây là toàn bộ nội dung mã nguồn Markdown để bạn có thể copy trực tiếp và dán vào file `.md` của mình nhé:

```markdown
# Hướng dẫn Setup và Chạy Hệ thống MITM Test (Reverse Proxy)

Tài liệu này hướng dẫn cách cấu hình và khởi động bộ công cụ `mitmproxy` ở chế độ Reverse Proxy để bắt và theo dõi gói tin (API) luân chuyển giữa Frontend và Backend ở môi trường Local (Windows/Linux).

---

## 🧭 Luồng đi của dữ liệu (Data Flow)

Khi cấu hình thành công, dữ liệu sẽ không đi thẳng từ Frontend sang Backend nữa mà sẽ đi xuyên qua trạm trung chuyển MITM:

```text
[ Frontend ] (127.0.0.1:3001)
     │
     ▼ (Gửi API đến cổng Proxy)
[ MITM Proxy ] (127.0.0.1:8081) ──► [ Giao diện Web UI ] (127.0.0.1:8121)
     │
     ▼ (Sửa Host Header & Chuyển tiếp)
[ Backend Flask ] (127.0.0.1:5000)

```

---

## 🛠️ Bước 1: Cấu hình phía Frontend

Bạn cần chỉnh sửa file biến môi trường (ví dụ: `.env`, `.env.local` hoặc file `config.js`) của dự án Frontend để trỏ API URL về cổng của MITM Proxy thay vì Backend thật.

* **Cấu hình cũ (Gọi trực tiếp):** `http://127.0.0.1:5000` (hoặc `localhost:5000`)
* **Cấu hình mới (Qua Proxy):** `http://127.0.0.1:8080`

> ⚠️ **Lưu ý:** Sau khi sửa xong file cấu hình, bắt buộc phải **khởi động lại Frontend** (`npm run dev` hoặc `npm start`) để nhận cổng mới.

---

## 🚀 Bước 2: Lệnh khởi động MITM Proxy

Tùy thuộc vào Hệ điều hành bạn đang sử dụng, hãy mở Terminal/CMD lên và chạy lệnh tương ứng:

### 🔹 Trên Windows (Command Prompt / PowerShell)

```cmd
mitmweb --mode reverse:http://127.0.0.1:5000 -p 8080

```

### 🔹 Trên Linux / Ubuntu / Git Bash

```bash
mitmweb --mode reverse:[http://127.0.0.1:5000](http://127.0.0.1:5000) -p 8081 --set modify_headers='~q & :Host:127.0.0.1:5000'

```

---

## 📊 Bước 3: Kiểm tra và Theo dõi gói tin

1. Khởi động **Backend Flask** chạy tại port `5000`.
2. Khởi động **Frontend** chạy tại port `3001`.
3. Chạy lệnh **MITM Proxy** ở Bước 2. Hệ thống sẽ tự động mở một tab trình duyệt mới tại địa chỉ: **`http://127.0.0.1:8121`**
4. Vào trang Frontend, nhấn `Ctrl + F5` để xóa cache, sau đó thực hiện tương tác (ví dụ: Gọi danh sách `/api/posts`).
5. Quay lại giao diện Web UI cổng `8121` để xem toàn bộ Request/Response dạng trực quan.

---

## 💡 Mẹo xử lý sự cố nhanh (Troubleshooting)

* **Lỗi 404 Not Found khi gọi qua 8080:** Kiểm tra xem bạn có gõ thiếu đoạn `--set modify_headers` ở lệnh khởi động không. Thiếu đoạn này Backend Flask sẽ từ chối nhận gói tin do sai Host Header.
* **Lỗi CORS:** Hãy chắc chắn Backend Flask đã được cài và cấu hình thư viện `flask-cors` mở cho tất cả các cổng (`CORS(app)`).
* **Không bắt được gói tin nào (Trống trơn):** Đổi toàn bộ chữ `localhost` trong code Frontend thành IP số `127.0.0.1` để ép trình duyệt không bỏ qua proxy.

```

```