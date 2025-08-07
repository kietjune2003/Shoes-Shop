
# 🛒 E-Commerce Shoes Shop (Spring Boot Project)

Đây là hệ thống **bán giày trực tuyến** được xây dựng bằng Spring Boot, hỗ trợ:
- Quản lý người dùng (admin + user)
- Quản lý sản phẩm, giỏ hàng, đơn hàng
- Thanh toán: **Tiền mặt (COD)** hoặc **VNPAY**
- Gửi OTP xác thực email khi đăng ký
- Giao diện admin quản lý bằng REST API

---

## 🔧 Công nghệ sử dụng

| Thành phần         | Mô tả |
|--------------------|------|
| ☕ Spring Boot      | Backend API chính |
| 🔒 Spring Security | Xác thực, phân quyền |
| 🐬 MySQL           | Hệ quản trị cơ sở dữ liệu |
| 📦 JPA + Hibernate | ORM và mapping dữ liệu |
| ✉️ JavaMailSender  | Gửi email OTP xác thực |
| ☁️ Cloudinary      | Lưu trữ ảnh sản phẩm |
| 💰 VNPAY           | Cổng thanh toán trực tuyến |
| 🔐 JWT             | Xác thực và quản lý phiên |
| 📄 Thymeleaf       | Gửi email template đẹp |

---

## 🚀 Tính năng nổi bật

### 👤 Người dùng
- Đăng ký + OTP email
- Đăng nhập (JWT)
- Cập nhật mật khẩu
- Quản lý giỏ hàng
- Thanh toán đơn hàng

### 🛍️ Quản lý Admin
- CRUD sản phẩm
- Danh sách người dùng
- Thống kê doanh thu
- Quản lý đơn hàng, voucher

### 💳 Tích hợp thanh toán VNPAY
- Tự động redirect người dùng sang giao diện VNPAY
- Xác thực chữ ký `SecureHash` trả về
- Cập nhật trạng thái đơn hàng sau thanh toán

---

## ⚙️ Cấu hình hệ thống

Cấu hình nằm trong `application.yml`. Một số biến quan trọng:

```yaml
vn-pay:
  secretKey: <SECRET>
  vnp_TmnCode: <MERCHANT_CODE>
  vnp_PayUrl: https://sandbox.vnpayment.vn/paymentv2/vpcpay.html
  vnp_ReturnUrl: /api/v1/vnpay/payment
  vnp_ApiUrl: https://sandbox.vnpayment.vn/merchant_webapi/api/transaction

cloudinary:
  cloud-name: <CLOUD>
  api-key: <API_KEY>
  api-secret: <SECRET>

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/e_commerce_shoes
    username: root
    password:
```

---

## ▶️ Hướng dẫn chạy dự án

### 1. Clone project

```bash
git clone https://github.com/<your-username>/ecommerce-shoes-shop.git
cd ecommerce-shoes-shop
```

### 2. Tạo database

```sql
CREATE DATABASE e_commerce_shoes;
```

### 3. Cấu hình `application.yml`

- Thêm thông tin MySQL, Cloudinary, VNPAY, email
- Cấu hình Gmail App Password (nếu gửi email)

### 4. Chạy Spring Boot app

```bash
./mvnw spring-boot:run
# hoặc chạy từ IDE (IntelliJ, Eclipse, VS Code)
```

---

## 📌 Một số API quan trọng

| Phương thức | Endpoint | Mô tả |
|------------|----------|------|
| POST | `/api/v1/auth/register` | Đăng ký + gửi OTP |
| POST | `/api/v1/auth/login` | Đăng nhập (JWT + refresh cookie) |
| GET  | `/api/v1/cart` | Lấy giỏ hàng người dùng |
| POST | `/api/v1/cart/edit` | Chỉnh sửa giỏ hàng |
| POST | `/api/v1/cart/checkout` | Đặt hàng |
| GET  | `/api/v1/vnpay/payment` | Callback từ VNPAY |

> 📌 Các API khác như quản lý sản phẩm, đơn hàng... nằm trong `/api/v1/admin/**`

---

## 💡 Ghi chú thêm

- ✅ Giới hạn đăng nhập 2 thiết bị (JWT control)
- ✅ Bảo mật JWT bằng `User-Agent`
- ✅ Kiểm tra tồn kho trước khi đặt hàng
- ✅ VNPAY sandbox test: https://sandbox.vnpayment.vn/devguide/

---

## 📬 Liên hệ phát triển

**Đỗ Tuấn Kiệt**  
📧 Email: k.code.2003@gmail.com 
🌐 Dự án học thuật Spring Boot kết hợp thực tế bán hàng  
📦 Repository: `ecommerce-shoes-shop`

---

## ⭐ License

This project is for educational purposes only and not for commercial distribution.
