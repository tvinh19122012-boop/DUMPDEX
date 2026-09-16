# SikeMod DEX Dumper PRO

Web tool dump DEX từ APK + memory dump.

## Tính năng
- Bóc classes*.dex từ APK
- Quét DEX ẩn trong assets/res/raw/lib
- Nhận diện 10 shell pack (360, Tencent, Bangcle, IJiami, Alibaba, Naga, Baidu, Virbox, DexProtector, Tencent Game)
- Giải mã XOR single-byte + AES-ECB với key trích từ APK
- Dump DEX từ memory dump (frida, /proc/pid/mem, GameGuardian)
- Unpack full APK thành ZIP
- Phân tích DEX header + strings
- Tải tất cả DEX 1 click
- Hỗ trợ upload XAPK/APKS

## Deploy Render
1. Push code lên GitHub
2. Render → New Web Service → Docker → main → Free
3. Deploy → mở URL