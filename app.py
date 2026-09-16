import os, re, struct, zipfile, hashlib, json
from io import BytesIO

# ============ SHELL SIGNATURES ============
SHELL_SIGNATURES = {
    "360 (Qihoo)": {
        "files": ["libjiagu.so", "libjiagu_art.so", "libjiagu_x86.so",
                  "libjiagu_x86_64.so", "libjiagu_a64.so"],
        "assets": ["libjiagu.so", "libjiagu_art.so"],
        "strings": [b"libjiagu", b"qihoo", b"360.CrashHandler", b"com.qihoo.util"],
        "type": "dynamic",
        "note": "360 Jiagu — DEX mã hóa trong libjiagu.so, giải mã runtime qua JNI_OnLoad"
    },
    "Tencent Legu": {
        "files": ["libshella.so", "libshellx.so", "libtosprotection.so",
                  "libtosprotection.armeabi.so"],
        "assets": ["0OO00l111l1l", "o0oooOO0ooOo.dat", "tosversion"],
        "strings": [b"legu", b"tencent", b"shellApplication", b"com.tencent.StubShell"],
        "type": "dynamic",
        "note": "Tencent Legu — DEX trong assets mã hóa, stub shell load runtime"
    },
    "Bangcle (SecNeo)": {
        "files": ["libsecexe.so", "libsecmain.so", "libDexHelper.so", "libSecShell.so"],
        "assets": ["classes.dex.dat", "mfc.dat", "bangcle"],
        "strings": [b"bangcle", b"secneo", b"SecShell", b"com.secneo"],
        "type": "dynamic",
        "note": "Bangcle — DEX mã hóa trong assets/classes.dex.dat"
    },
    "IJiami (Jiami)": {
        "files": ["libexec.so", "libexecmain.so", "libjiagu.so", "libijiami.so"],
        "assets": ["ijiami.ajm", "ijiami.dat"],
        "strings": [b"ijiami", b"jiami", b"com.ijiami"],
        "type": "dynamic",
        "note": "IJiami — DEX trong assets/ijiami.ajm"
    },
    "Alibaba (Ali)": {
        "files": ["libmobisec.so", "libsgmain.so", "libsgsecuritybody.so"],
        "assets": ["ali.dat", "mobisec"],
        "strings": [b"mobisec", b"alibaba", b"com.ali.mobisecenhance"],
        "type": "dynamic",
        "note": "Alibaba — DEX mã hóa, giải mã runtime"
    },
    "Naga (Yidun)": {
        "files": ["libchaosvmp.so", "libddog.so", "libfdog.so", "libnsecure.so"],
        "assets": ["naga.dat"],
        "strings": [b"naga", b"yidun", b"libchaosvmp"],
        "type": "dynamic",
        "note": "Naga — VM-based protection"
    },
    "Baidu": {
        "files": ["libbaiduprotect.so"],
        "assets": ["baiduprotect"],
        "strings": [b"baiduprotect", b"com.baidu.protect"],
        "type": "dynamic",
        "note": "Baidu Protect"
    },
    "KiwiVM / Virbox": {
        "files": ["libvirbox.so", "libvbox.so"],
        "assets": ["virbox"],
        "strings": [b"virbox", b"kiwivm"],
        "type": "dynamic",
        "note": "Virbox VM"
    },
    "DexProtector": {
        "files": ["libdexprotector.so", "libdp.so"],
        "assets": ["dexprotector"],
        "strings": [b"dexprotector", b"licensing"],
        "type": "dynamic",
        "note": "DexProtector"
    },
}

DEX_MAGIC = b"dex\n"

# ============ UTILS ============

def is_valid_dex(data: bytes) -> bool:
    if len(data) < 112: return False
    if data[:4] != DEX_MAGIC: return False
    # version: 035, 037, 038, 039
    if data[4:7] not in (b"035", b"037", b"038", b"039"):
        return False
    try:
        file_size = struct.unpack("<I", data[32:36])[0]
        header_size = struct.unpack("<I", data[36:40])[0]
        if file_size < 112 or file_size > len(data) + 16: return False
        if header_size != 0x70: return False
        endian = struct.unpack("<I", data[40:44])[0]
        if endian != 0x12345678: return False
        return True
    except Exception:
        return False

def dex_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()

def detect_shell(zip_names, apk_bytes) -> dict:
    """Phát hiện shell pack dựa trên file names + strings trong APK"""
    detected = []
    names_lower = [n.lower() for n in zip_names]

    for shell_name, sig in SHELL_SIGNATURES.items():
        score = 0
        hits = []
        for f in sig.get("files", []):
            if any(f.lower() in n for n in names_lower):
                score += 3; hits.append(f)
        for a in sig.get("assets", []):
            if any(a.lower() in n for n in names_lower):
                score += 2; hits.append(a)
        for s in sig.get("strings", []):
            if s.lower() in apk_bytes.lower():
                score += 1; hits.append(s.decode('utf-8', 'ignore'))
        if score >= 2:
            detected.append({
                "name": shell_name,
                "score": score,
                "hits": list(set(hits))[:8],
                "type": sig["type"],
                "note": sig["note"],
            })

    detected.sort(key=lambda x: -x["score"])
    return detected

def scan_dex_in_buffer(data: bytes, min_size: int = 112):
    """Quét tìm tất cả DEX trong buffer (magic dex\n)"""
    results = []
    pos = 0
    while True:
        idx = data.find(DEX_MAGIC, pos)
        if idx == -1: break
        # đọc file_size từ header
        if idx + 36 <= len(data):
            file_size = struct.unpack("<I", data[idx+32:idx+36])[0]
            if 112 <= file_size <= len(data) - idx:
                chunk = data[idx:idx+file_size]
                if is_valid_dex(chunk):
                    results.append((idx, chunk))
                    pos = idx + file_size
                    continue
        pos = idx + 4
    return results

# ============ GIẢI MÃ CƠ BẢN ============

def try_xor_decrypt(data: bytes, max_key_len: int = 8):
    """Thử XOR với key 1 byte phổ biến (0x00-0xFF)"""
    candidates = []
    for k in range(1, 256):
        # chỉ test byte đầu để tìm magic dex
        if data[0] ^ k == ord('d') and len(data) > 4:
            if data[1] ^ k == ord('e') and data[2] ^ k == ord('x'):
                dec = bytes(b ^ k for b in data)
                if is_valid_dex(dec):
                    candidates.append(("xor_single_%02x" % k, dec))
    return candidates

def try_aes_ecb_decrypt(data: bytes, keys: list):
    """Thử AES-ECB với danh sách key (bytes)"""
    try:
        from Crypto.Cipher import AES
    except ImportError:
        return []
    candidates = []
    for key in keys:
        if len(key) not in (16, 24, 32): continue
        try:
            cipher = AES.new(key, AES.MODE_ECB)
            dec = cipher.decrypt(data[:len(data)//16*16])
            # tìm magic dex
            if DEX_MAGIC in dec[:4096]:
                idx = dec.find(DEX_MAGIC)
                chunk = dec[idx:]
                if is_valid_dex(chunk):
                    candidates.append((f"aes_ecb_{key.hex()[:8]}", chunk))
        except Exception:
            continue
    return candidates

def extract_keys_from_apk(z: zipfile.ZipFile):
    """Cố gắng trích key hardcoded từ assets/ và lib/"""
    keys = []
    patterns = [
        rb'[A-Za-z0-9+/]{16,32}={0,2}',  # base64-like
        rb'[\x20-\x7e]{16}',              # 16 ascii chars
        rb'[\x20-\x7e]{24}',
        rb'[\x20-\x7e]{32}',
    ]
    for name in z.namelist():
        if name.endswith("/"): continue
        if not (name.startswith("assets/") or name.startswith("lib/") or name.endswith(".dex")):
            continue
        try:
            data = z.read(name)
        except Exception:
            continue
        for pat in patterns:
            for m in re.finditer(pat, data):
                keys.append(m.group())
        if len(keys) > 500: break  # giới hạn
    # dedup
    seen = set(); uniq = []
    for k in keys:
        if k not in seen:
            seen.add(k); uniq.append(k)
    return uniq[:200]

# ============ PROCESS APK ============

def process_apk(apk_path: str, jobdir: str) -> dict:
    found = []
    fallback = ""
    logs = []

    if not zipfile.is_zipfile(apk_path):
        return {"status": "error", "output": "Không phải ZIP/APK hợp lệ",
                "files": [], "fallback": ""}

    with open(apk_path, "rb") as fp:
        apk_bytes = fp.read()

    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()

        # 1. Phát hiện shell
        shells = detect_shell(names, apk_bytes)
        if shells:
            logs.append(f"[!] Phát hiện shell: {', '.join(s['name'] for s in shells)}")

        # 2. Bóc classes*.dex chuẩn
        for name in names:
            base = os.path.basename(name)
            if base.startswith("classes") and base.endswith(".dex"):
                data = z.read(name)
                if is_valid_dex(data):
                    out = base
                    with open(os.path.join(jobdir, out), "wb") as o:
                        o.write(data)
                    found.append({"name": out, "size": len(data), "shell": None})
                else:
                    # DEX bị hỏng/mã hóa
                    logs.append(f"[!] {name} không phải DEX hợp lệ (có thể bị mã hóa)")

        # 3. Quét DEX ẩn trong assets/ và toàn bộ APK
        for name in names:
            if name.endswith("/"): continue
            if name.startswith("classes") and name.endswith(".dex"): continue
            if not (name.startswith("assets/") or name.startswith("res/raw/")):
                continue
            try:
                data = z.read(name)
            except Exception:
                continue
            hits = scan_dex_in_buffer(data)
            for idx, dex_data in hits:
                out = f"embedded_{os.path.basename(name)}_{idx:08x}.dex"
                with open(os.path.join(jobdir, out), "wb") as o:
                    o.write(dex_data)
                found.append({"name": out, "size": len(dex_data), "shell": None})

        # 4. Thử giải mã assets đáng ngờ (XOR / AES)
        suspect_exts = (".dat", ".ajm", ".bin", ".so", ".dex", "")
        suspect_assets = []
        for name in names:
            if name.startswith("assets/"):
                b = os.path.basename(name).lower()
                if any(b.endswith(e) for e in suspect_exts if e) or b in (
                    "0oo00l111l1l", "o0oooOO0ooOo.dat", "tosversion",
                    "ijiami.ajm", "ijiami.dat", "ali.dat", "naga.dat",
                    "mfc.dat", "bangcle", "baiduprotect"
                ):
                    suspect_assets.append(name)

        # Lấy key candidates
        keys = extract_keys_from_apk(z)

        for name in suspect_assets:
            try:
                data = z.read(name)
            except Exception:
                continue
            if len(data) < 200 or len(data) > 100 * 1024 * 1024:
                continue
            # thử XOR
            for tag, dec in try_xor_decrypt(data[:2000000]):
                out = f"decrypted_{tag}_{os.path.basename(name)}.dex"
                with open(os.path.join(jobdir, out), "wb") as o:
                    o.write(dec)
                found.append({"name": out, "size": len(dec), "shell": None})
                logs.append(f"[+] XOR decrypt OK: {name} -> {out}")
            # thử AES
            for tag, dec in try_aes_ecb_decrypt(data[:2000000], keys):
                out = f"decrypted_{tag}_{os.path.basename(name)}.dex"
                with open(os.path.join(jobdir, out), "wb") as o:
                    o.write(dec)
                found.append({"name": out, "size": len(dec), "shell": None})
                logs.append(f"[+] AES decrypt OK: {name} -> {out}")

    # 5. Fallback nếu không có DEX hợp lệ
    if not found and shells:
        fallback = (
            "APK bị shell pack. DEX gốc mã hóa trong native lib/assets, "
            "chỉ giải mã runtime. Cần dump động: frida-dexdump / FRIDA-DEXDump / "
            "dump /proc/pid/mem khi app chạy. Dùng tab 'Memory Dump' upload file dump."
        )
    elif not found:
        fallback = "Không tìm thấy DEX nào. APK có thể rỗng hoặc định dạng lạ."

    return {
        "status": "ok",
        "output": "\n".join(logs) if logs else "Done",
        "files": found,
        "shells": shells,
        "fallback": fallback,
    }

# ============ PROCESS MEMORY DUMP ============

def process_memory_dump(mem_path: str, jobdir: str) -> dict:
    """Quét DEX trong file memory dump (từ /proc/pid/mem, frida, GG...)"""
    found = []
    size = os.path.getsize(mem_path)
    CHUNK = 64 * 1024 * 1024  # 64MB/chunk
    overlap = 1024 * 1024     # overlap 1MB để không miss DEX ở ranh giới

    with open(mem_path, "rb") as f:
        offset = 0
        carry = b""
        while True:
            chunk = f.read(CHUNK)
            if not chunk: break
            buf = carry + chunk
            hits = scan_dex_in_buffer(buf)
            for idx, dex_data in hits:
                sha = dex_sha1(dex_data)
                out = f"mem_{offset+idx:012x}_{sha[:8]}.dex"
                if not os.path.exists(os.path.join(jobdir, out)):
                    with open(os.path.join(jobdir, out), "wb") as o:
                        o.write(dex_data)
                    found.append({"name": out, "size": len(dex_data), "shell": None})
            carry = buf[-overlap:] if len(buf) > overlap else buf
            offset += len(chunk)
            if offset > 4 * 1024 * 1024 * 1024:  # giới hạn 4GB
                break

    fallback = ""
    if not found:
        fallback = ("Không tìm thấy DEX trong memory dump. "
                    "Có thể dump sai vùng nhớ, hoặc DEX bị mã hóa trong RAM.")
    return {
        "status": "ok",
        "output": f"Quét {offset} bytes, tìm được {len(found)} DEX",
        "files": found,
        "fallback": fallback,
    }