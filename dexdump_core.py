import os, re, struct, zipfile, hashlib, shutil, io

SHELL_SIGNATURES = {
    "360 (Qihoo)": {"files":["libjiagu.so","libjiagu_art.so","libjiagu_a64.so","libjiagu_x86.so"],
        "assets":["libjiagu.so"],"strings":[b"libjiagu",b"qihoo",b"com.qihoo.util"],
        "type":"dynamic","note":"360 Jiagu — DEX mã hóa native, dump động"},
    "Tencent Legu": {"files":["libshella.so","libshellx.so","libtosprotection.so"],
        "assets":["0OO00l111l1l","o0oooOO0ooOo.dat","tosversion"],
        "strings":[b"legu",b"tencent",b"com.tencent.StubShell"],
        "type":"dynamic","note":"Tencent Legu — dump động"},
    "Bangcle (SecNeo)": {"files":["libsecexe.so","libsecmain.so","libDexHelper.so"],
        "assets":["classes.dex.dat","mfc.dat"],
        "strings":[b"bangcle",b"secneo",b"com.secneo"],
        "type":"dynamic","note":"Bangcle — dump động"},
    "IJiami": {"files":["libexec.so","libexecmain.so","libijiami.so"],
        "assets":["ijiami.ajm","ijiami.dat"],"strings":[b"ijiami",b"com.ijiami"],
        "type":"dynamic","note":"IJiami — dump động"},
    "Alibaba": {"files":["libmobisec.so","libsgmain.so"],
        "assets":["ali.dat","mobisec"],"strings":[b"mobisec",b"com.ali.mobisecenhance"],
        "type":"dynamic","note":"Alibaba — dump động"},
    "Naga (Yidun)": {"files":["libchaosvmp.so","libddog.so","libfdog.so"],
        "assets":["naga.dat"],"strings":[b"naga",b"yidun",b"libchaosvmp"],
        "type":"dynamic","note":"Naga VM — cực khó"},
    "Baidu": {"files":["libbaiduprotect.so"],"assets":["baiduprotect"],
        "strings":[b"baiduprotect"],"type":"dynamic","note":"Baidu Protect"},
    "Virbox": {"files":["libvirbox.so"],"assets":["virbox"],
        "strings":[b"virbox"],"type":"dynamic","note":"Virbox VM"},
    "DexProtector": {"files":["libdexprotector.so"],"assets":["dexprotector"],
        "strings":[b"dexprotector"],"type":"dynamic","note":"DexProtector"},
    "Tencent Mobile": {"files":["libtup.so","libtxgame.so"],
        "assets":["txgame"],"strings":[b"txgame",b"tencent game"],
        "type":"dynamic","note":"Tencent Game"},
}

DEX_MAGIC = b"dex\n"
DEX_VERSIONS = (b"035", b"037", b"038", b"039")


def is_valid_dex(data):
    if len(data) < 112: return False
    if data[:4] != DEX_MAGIC: return False
    if data[4:7] not in DEX_VERSIONS: return False
    try:
        file_size = struct.unpack("<I", data[32:36])[0]
        header_size = struct.unpack("<I", data[36:40])[0]
        endian = struct.unpack("<I", data[40:44])[0]
        if file_size < 112 or file_size > len(data)+16: return False
        if header_size != 0x70: return False
        if endian != 0x12345678: return False
        return True
    except Exception:
        return False


def detect_shell(zip_names, apk_bytes):
    detected = []
    names_lower = [n.lower() for n in zip_names]
    apk_lower = apk_bytes.lower()
    for shell_name, sig in SHELL_SIGNATURES.items():
        score = 0; hits = []
        for f in sig.get("files", []):
            if any(f.lower() in n for n in names_lower):
                score += 3; hits.append(f)
        for a in sig.get("assets", []):
            if any(a.lower() in n for n in names_lower):
                score += 2; hits.append(a)
        for s in sig.get("strings", []):
            if s.lower() in apk_lower:
                score += 1; hits.append(s.decode('utf-8','ignore'))
        if score >= 2:
            detected.append({"name": shell_name, "score": score,
                "hits": list(set(hits))[:10], "type": sig["type"], "note": sig["note"]})
    detected.sort(key=lambda x: -x["score"])
    return detected


def scan_dex_in_buffer(data):
    results = []; pos = 0
    while True:
        idx = data.find(DEX_MAGIC, pos)
        if idx == -1: break
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


def try_xor_decrypt(data):
    candidates = []
    for k in range(1, 256):
        if len(data) >= 4 and data[0]^k == ord('d') and data[1]^k == ord('e') and data[2]^k == ord('x'):
            dec = bytes(b ^ k for b in data)
            if is_valid_dex(dec):
                candidates.append((f"xor_{k:02x}", dec))
    return candidates


def try_aes_ecb_decrypt(data, keys):
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
            if DEX_MAGIC in dec[:8192]:
                idx = dec.find(DEX_MAGIC)
                chunk = dec[idx:]
                if is_valid_dex(chunk):
                    candidates.append((f"aes_{key.hex()[:8]}", chunk))
        except Exception:
            continue
    return candidates


def extract_keys_from_apk(z):
    keys = []
    patterns = [rb'[A-Za-z0-9+/]{16,32}={0,2}',
                rb'[\x20-\x7e]{16}', rb'[\x20-\x7e]{24}', rb'[\x20-\x7e]{32}']
    for name in z.namelist():
        if name.endswith("/"): continue
        if not (name.startswith("assets/") or name.startswith("lib/")): continue
        try: data = z.read(name)
        except Exception: continue
        for pat in patterns:
            for m in re.finditer(pat, data):
                keys.append(m.group())
        if len(keys) > 800: break
    seen = set(); uniq = []
    for k in keys:
        if k not in seen:
            seen.add(k); uniq.append(k)
    return uniq[:300]


def process_apk(apk_path, jobdir):
    found = []; fallback = ""; logs = []
    if not zipfile.is_zipfile(apk_path):
        return {"status":"error","output":"Không phải ZIP/APK","files":[],"fallback":"","shells":[]}
    with open(apk_path, "rb") as fp:
        apk_bytes = fp.read()

    with zipfile.ZipFile(apk_path, "r") as z:
        names = z.namelist()
        shells = detect_shell(names, apk_bytes)
        if shells:
            logs.append("[!] Phát hiện shell: " + ", ".join(s['name'] for s in shells))

        # 1. classes*.dex
        for name in names:
            base = os.path.basename(name)
            if base.startswith("classes") and base.endswith(".dex"):
                data = z.read(name)
                if is_valid_dex(data):
                    with open(os.path.join(jobdir, base), "wb") as o: o.write(data)
                    found.append({"name": base, "size": len(data), "shell": None})
                    logs.append(f"[+] OK: {base} ({len(data)} bytes)")
                else:
                    logs.append(f"[!] {base} không hợp lệ (mã hóa?)")
                    # thử XOR
                    for tag, dec in try_xor_decrypt(data[:5000000]):
                        out = f"dec_{tag}_{base}"
                        with open(os.path.join(jobdir, out), "wb") as o: o.write(dec)
                        found.append({"name": out, "size": len(dec), "shell": None})
                        logs.append(f"[+] XOR decode: {base} -> {out}")

        # 2. Quét DEX ẩn trong assets, res/raw, lib
        for name in names:
            if name.endswith("/"): continue
            b = os.path.basename(name)
            if b.startswith("classes") and b.endswith(".dex"): continue
            if not (name.startswith("assets/") or name.startswith("res/raw/") or name.startswith("lib/")): continue
            try: data = z.read(name)
            except Exception: continue
            if len(data) < 112: continue
            for idx, dex_data in scan_dex_in_buffer(data):
                out = f"embedded_{b}_{idx:08x}.dex"
                with open(os.path.join(jobdir, out), "wb") as o: o.write(dex_data)
                found.append({"name": out, "size": len(dex_data), "shell": None})
                logs.append(f"[+] Embedded: {out} ({len(dex_data)} bytes)")

        # 3. Thử giải mã assets đáng ngờ
        keys = extract_keys_from_apk(z)
        for name in names:
            if not name.startswith("assets/"): continue
            try: data = z.read(name)
            except Exception: continue
            if len(data) < 200 or len(data) > 100*1024*1024: continue
            for tag, dec in try_xor_decrypt(data[:5000000]):
                out = f"dec_{tag}_{os.path.basename(name)}.dex"
                with open(os.path.join(jobdir, out), "wb") as o: o.write(dec)
                found.append({"name": out, "size": len(dec), "shell": None})
                logs.append(f"[+] XOR assets: {out}")
            for tag, dec in try_aes_ecb_decrypt(data[:5000000], keys):
                out = f"dec_{tag}_{os.path.basename(name)}.dex"
                with open(os.path.join(jobdir, out), "wb") as o: o.write(dec)
                found.append({"name": out, "size": len(dec), "shell": None})
                logs.append(f"[+] AES assets: {out}")

    # dedup theo sha1
    seen = set(); uniq = []
    for f in found:
        p = os.path.join(jobdir, f['name'])
        if not os.path.exists(p): continue
        sha = hashlib.sha1(open(p,'rb').read()).hexdigest()
        if sha in seen:
            os.remove(p); continue
        seen.add(sha); uniq.append(f)
    found = uniq

    if not found and shells:
        fallback = ("⚠️ APK bị shell pack. DEX gốc mã hóa runtime. "
                    "Dùng frida-dexdump / FART / BlackDex để dump động, "
                    "rồi upload memory dump vào tab Memory Dump.")
    elif not found:
        fallback = "Không tìm thấy DEX nào trong APK."

    return {"status":"ok", "output":"\n".join(logs) or "Done",
            "files":found, "shells":shells, "fallback":fallback,
            "total_entries": len(names)}


def process_memory_dump(mem_path, jobdir):
    found = []
    CHUNK = 64*1024*1024; overlap = 2*1024*1024
    offset = 0
    with open(mem_path, "rb") as f:
        carry = b""
        while True:
            chunk = f.read(CHUNK)
            if not chunk: break
            buf = carry + chunk
            for idx, dex_data in scan_dex_in_buffer(buf):
                sha = hashlib.sha1(dex_data).hexdigest()
                out = f"mem_{offset+idx:012x}_{sha[:8]}.dex"
                p = os.path.join(jobdir, out)
                if not os.path.exists(p):
                    with open(p, "wb") as o: o.write(dex_data)
                    found.append({"name": out, "size": len(dex_data), "shell": None})
            carry = buf[-overlap:] if len(buf) > overlap else buf
            offset += len(chunk)
            if offset > 4*1024*1024*1024: break
    fallback = "" if found else "Không tìm thấy DEX trong memory dump."
    return {"status":"ok", "output":f"Quét {offset} bytes, tìm {len(found)} DEX",
            "files":found, "fallback":fallback}


def unpack_apk_full(apk_path, jobdir):
    """Unpack toàn bộ APK thành ZIP có cấu trúc thư mục"""
    unpack_dir = os.path.join(jobdir, "unpacked")
    os.makedirs(unpack_dir, exist_ok=True)
    total = 0
    with zipfile.ZipFile(apk_path, "r") as z:
        for info in z.infolist():
            try:
                z.extract(info, unpack_dir)
                total += 1
            except Exception:
                continue
    zip_name = "unpacked.zip"
    zip_path = os.path.join(jobdir, zip_name)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(unpack_dir):
            for file in files:
                fp = os.path.join(root, file)
                arc = os.path.relpath(fp, unpack_dir)
                zf.write(fp, arc)
    return {"zip_name": zip_name, "zip_size": os.path.getsize(zip_path), "total_entries": total}


def decompile_dex_basic(dex_data):
    """Trích info cơ bản từ DEX header + strings"""
    info = {
        "magic": dex_data[:8].decode('latin1'),
        "version": dex_data[4:7].decode('latin1'),
        "checksum": struct.unpack("<I", dex_data[8:12])[0],
        "signature": dex_data[12:32].hex(),
        "file_size": struct.unpack("<I", dex_data[32:36])[0],
        "header_size": struct.unpack("<I", dex_data[36:40])[0],
        "string_ids_size": struct.unpack("<I", dex_data[56:60])[0],
        "type_ids_size": struct.unpack("<I", dex_data[64:68])[0],
        "proto_ids_size": struct.unpack("<I", dex_data[72:76])[0],
        "field_ids_size": struct.unpack("<I", dex_data[80:84])[0],
        "method_ids_size": struct.unpack("<I", dex_data[88:92])[0],
        "class_defs_size": struct.unpack("<I", dex_data[96:100])[0],
    }
    # Trích strings (đơn giản, chỉ lấy ascii printable)
    try:
        str_off = struct.unpack("<I", dex_data[60:64])[0]
        str_size = info["string_ids_size"]
        strings = []
        max_str = min(str_size, 200)
        for i in range(max_str):
            off = struct.unpack("<I", dex_data[str_off+i*4:str_off+i*4+4])[0]
            if off >= len(dex_data): continue
            # uleb128 length
            j = off; length = 0; shift = 0
            while j < len(dex_data):
                b = dex_data[j]; j += 1
                length |= (b & 0x7f) << shift
                if (b & 0x80) == 0: break
                shift += 7
            end = min(j + length, len(dex_data))
            s = dex_data[j:end]
            try:
                decoded = s.decode('utf-8')
                if all(32 <= ord(c) < 127 for c in decoded) and len(decoded) >= 3:
                    strings.append(decoded)
            except Exception:
                pass
        info["sample_strings"] = strings[:80]
        info["total_strings"] = str_size
    except Exception as e:
        info["sample_strings"] = []
        info["error"] = str(e)
    return info