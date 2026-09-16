# SikeMod DEX Dumper

Web tool bóc DEX từ APK + memory dump, deploy Render.

## Deploy Render

1. Push 6 file lên GitHub repo
2. dashboard.render.com → New → Web Service → Connect repo
3. Render tự build từ render.yaml
4. Mở URL → dùng

## Tính năng

- Bóc classes*.dex từ APK
- Quét DEX ẩn trong assets/ (magic dex\n)
- Nhận diện 9 loại shell: 360, Tencent, Bangcle, IJiami, Alibaba, Naga, Baidu, Virbox, DexProtector
- Thử XOR single-byte + AES-ECB với key trích từ APK
- Quét DEX trong memory dump (từ frida, /proc/pid/mem, GameGuardian)
- Tải từng file .dex về

## Giới hạn

- DEX bị shell pack mạnh (360/Tencent/Bangcle) → chỉ giải mã runtime
  → phải dump động bằng frida-dexdump rồi upload memory dump
- Render free: 512MB RAM, timeout 100s → APK >200MB có thể fail