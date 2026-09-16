import os, io, zipfile, time, hashlib, json, re, base64
from flask import Flask, request, jsonify, send_file, render_template_string, Response

from dexdump_core import (
    process_apk, process_memory_dump, SHELL_SIGNATURES,
    is_valid_dex, scan_dex_in_buffer, unpack_apk_full,
    decompile_dex_basic
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 800 * 1024 * 1024
OUT = os.path.abspath("./jobs")
os.makedirs(OUT, exist_ok=True)

PAGE = r"""
<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SikeMod DEX Dumper PRO</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'JetBrains Mono',Consolas,monospace;padding:14px;max-width:1100px;margin:auto}
h1{color:#58a6ff;font-size:20px}
.sub{color:#8b949e;font-size:12px;margin:4px 0 16px}
.tabs{display:flex;gap:4px;margin-bottom:14px;border-bottom:1px solid #30363d;overflow-x:auto}
.tab{padding:9px 14px;cursor:pointer;color:#8b949e;border-bottom:2px solid transparent;white-space:nowrap;font-size:13px}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.panel{display:none}.panel.active{display:block}
.drop{border:2px dashed #30363d;border-radius:12px;padding:28px 16px;text-align:center;background:#161b22;transition:.2s;cursor:pointer}
.drop:hover,.drop.hover{border-color:#58a6ff;background:#1c2128}
.drop input{display:none}
.btn{background:#238636;color:#fff;border:0;padding:11px 20px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:13px;margin-top:10px;font-weight:600}
.btn:hover{background:#2ea043}
.btn:disabled{background:#30363d;cursor:not-allowed}
.btn.alt{background:#1f6feb}.btn.alt:hover{background:#388bfd}
.btn.warn{background:#9e6a03}.btn.warn:hover{background:#bb8009}
pre{background:#161b22;padding:12px;border:1px solid #30363d;border-radius:8px;max-height:380px;overflow:auto;font-size:12px;line-height:1.5;white-space:pre-wrap;word-break:break-all}
.file{display:flex;justify-content:space-between;align-items:center;background:#161b22;padding:9px 12px;border:1px solid #30363d;border-radius:6px;margin:5px 0;font-size:13px}
.file a{color:#58a6ff;text-decoration:none;flex:1}
.file a:hover{text-decoration:underline}
.size{color:#8b949e;font-size:11px;margin-left:8px}
.bar{height:5px;background:#30363d;border-radius:3px;overflow:hidden;margin-top:10px}
.bar>div{height:100%;background:#58a6ff;width:0;transition:.2s}
.tag{display:inline-block;padding:2px 7px;border-radius:4px;font-size:10px;background:#30363d;margin-left:6px}
.tag.red{background:#f85149}.tag.green{background:#2ea043}.tag.blue{background:#1f6feb}.tag.yellow{background:#9e6a03}
.box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;margin:10px 0;font-size:12px}
.box.err{background:#3d1f1f;border-color:#f85149}
.box.ok{background:#1f3d1f;border-color:#2ea043}
.stat{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;margin:10px 0}
.stat>div{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px;text-align:center}
.stat b{display:block;color:#58a6ff;font-size:18px}
.stat span{color:#8b949e;font-size:11px}
.dlall{background:#1f6feb;color:#fff;border:0;padding:9px 16px;border-radius:6px;cursor:pointer;font-family:inherit;font-size:13px;margin:10px 0}
.dlall:hover{background:#388bfd}
.copybar{background:#238636;color:#fff;border:0;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:11px;margin-left:6px}
</style></head><body>

<h1>👑 SikeMod DEX Dumper PRO</h1>
<div class="sub">Bóc DEX · Unpack APK · Nhận diện shell · Dump memory · Decompile cơ bản · Hỗ trợ mã hóa XOR/AES</div>

<div class="tabs">
  <div class="tab active" onclick="tab(0)">📦 APK → DEX</div>
  <div class="tab" onclick="tab(1)">🧠 Memory Dump</div>
  <div class="tab" onclick="tab(2)">🔓 Unpack Full</div>
  <div class="tab" onclick="tab(3)">🛡️ Shell Info</div>
  <div class="tab" onclick="tab(4)">📖 DEX Info</div>
</div>

<!-- APK TAB -->
<div class="panel active">
  <div class="drop" id="drop0">
    <input type="file" id="file0" accept=".apk,.zip,.xapk,.apks">
    <div id="label0">📦 Kéo thả APK vào đây hoặc click chọn</div>
    <div class="bar"><div id="bar0"></div></div>
  </div>
  <button class="btn" id="btn0" disabled onclick="uploadApk()">🚀 BÓC DEX MẠNH</button>
  <pre id="log0">[idle] chờ file...</pre>
  <div id="stats0"></div>
  <div id="results0"></div>
</div>

<!-- MEM TAB -->
<div class="panel">
  <div class="sub">Upload file memory dump (frida-dexdump, /proc/pid/mem, GameGuardian, FART...)</div>
  <div class="drop" id="drop1">
    <input type="file" id="file1">
    <div id="label1">🧠 Kéo thả memory dump vào đây</div>
    <div class="bar"><div id="bar1"></div></div>
  </div>
  <button class="btn alt" id="btn1" disabled onclick="uploadMem()">🔍 SCAN DEX</button>
  <pre id="log1">[idle] chờ file...</pre>
  <div id="results1"></div>
</div>

<!-- UNPACK TAB -->
<div class="panel">
  <div class="sub">Bóc toàn bộ nội dung APK: manifest, resources, lib, assets, dex — tải về ZIP</div>
  <div class="drop" id="drop2">
    <input type="file" id="file2" accept=".apk,.zip">
    <div id="label2">📂 Kéo thả APK cần unpack vào đây</div>
    <div class="bar"><div id="bar2"></div></div>
  </div>
  <button class="btn warn" id="btn2" disabled onclick="uploadUnpack()">📦 UNPACK FULL APK</button>
  <pre id="log2">[idle] chờ file...</pre>
  <div id="results2"></div>
</div>

<!-- SHELL TAB -->
<div class="panel">
  <pre id="shellinfo">Loading...</pre>
</div>

<!-- DEX INFO TAB -->
<div class="panel">
  <div class="sub">Upload file .dex → xem thông tin header, strings, checksum</div>
  <div class="drop" id="drop3">
    <input type="file" id="file3" accept=".dex">
    <div id="label3">🔎 Kéo thả DEX vào đây</div>
    <div class="bar"><div id="bar3"></div></div>
  </div>
  <button class="btn" id="btn3" disabled onclick="uploadDexInfo()">📖 PHÂN TÍCH DEX</button>
  <pre id="log3">[idle] chờ file...</pre>
  <div id="results3"></div>
</div>

<script>
const state={};
function tab(i){
  document.querySelectorAll('.tab').forEach((t,j)=>t.classList.toggle('active',i===j));
  document.querySelectorAll('.panel').forEach((p,j)=>p.classList.toggle('active',i===j));
}
['0','1','2','3'].forEach(n=>{
  const drop=document.getElementById('drop'+n), file=document.getElementById('file'+n),
        label=document.getElementById('label'+n), btn=document.getElementById('btn'+n);
  if(!drop) return;
  drop.onclick=()=>file.click();
  drop.ondragover=e=>{e.preventDefault();drop.classList.add('hover')};
  drop.ondragleave=()=>drop.classList.remove('hover');
  drop.ondrop=e=>{e.preventDefault();drop.classList.remove('hover');
    if(e.dataTransfer.files.length){file.files=e.dataTransfer.files;upd(n)}};
  file.onchange=()=>upd(n);
  function upd(n){
    const f=file.files[0]; if(!f){btn.disabled=true;return;}
    label.textContent='📦 '+f.name+' ('+(f.size/1024/1024).toFixed(2)+' MB)';
    btn.disabled=false;
  }
  state[n]={drop,file,label,btn};
});

function renderFiles(container, job, files){
  if(!files || !files.length){ container.innerHTML='<div class="box err">⚠️ Không có file DEX nào</div>'; return; }
  let h='<button class="dlall" onclick="downloadAll(\''+job+'\',\''+encodeURIComponent(JSON.stringify(files.map(f=>f.name)))+'\')">⬇ TẢI TẤT CẢ ('+files.length+' file)</button>';
  h+='<h3 style="margin:12px 0 8px;color:#58a6ff;font-size:14px">📥 File DEX:</h3>';
  files.forEach(f=>{
    const tag = f.shell ? '<span class="tag red">SHELL: '+f.shell+'</span>' : '<span class="tag green">CLEAN</span>';
    h+=`<div class="file">
      <a href="/download/${job}/${encodeURIComponent(f.name)}" download>⬇ ${f.name}${tag}</a>
      <span class="size">${(f.size/1024).toFixed(1)} KB</span>
    </div>`;
  });
  container.innerHTML=h;
}
function downloadAll(job, namesJson){
  const names = JSON.parse(decodeURIComponent(namesJson));
  names.forEach((n,i)=>{
    setTimeout(()=>{
      const a=document.createElement('a');
      a.href='/download/'+job+'/'+encodeURIComponent(n);
      a.download=n; document.body.appendChild(a); a.click(); a.remove();
    }, i*400);
  });
}
function renderStats(el, j){
  if(!j.shells && !j.files) return;
  let h='<div class="stat">';
  h+=`<div><b>${(j.files||[]).length}</b><span>DEX tìm được</span></div>`;
  h+=`<div><b>${(j.shells||[]).length}</b><span>Shell phát hiện</span></div>`;
  if(j.apk_size) h+=`<div><b>${(j.apk_size/1024/1024).toFixed(1)}MB</b><span>APK size</span></div>`;
  if(j.total_entries) h+=`<div><b>${j.total_entries}</b><span>Entries</span></div>`;
  h+='</div>';
  el.innerHTML=h;
}
function uploadApk(){
  const f=state['0'].file.files[0]; if(!f) return;
  const fd=new FormData(); fd.append('apk',f);
  const xhr=new XMLHttpRequest(); xhr.open('POST','/dump/apk');
  const log=document.getElementById('log0');
  log.textContent='[*] Upload & phân tích...\n';
  document.getElementById('results0').innerHTML='';
  document.getElementById('stats0').innerHTML='';
  state['0'].btn.disabled=true;
  xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('bar0').style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{state['0'].btn.disabled=false;
    try{const j=JSON.parse(xhr.responseText);
      log.textContent=JSON.stringify({status:j.status,output:j.output,shells:j.shells,fallback:j.fallback},null,2);
      renderStats(document.getElementById('stats0'),j);
      renderFiles(document.getElementById('results0'),j.job,j.files);
    }catch(e){log.textContent+='[!] '+e.message;}};
  xhr.onerror=()=>{state['0'].btn.disabled=false;log.textContent+='[!] Network error';};
  xhr.send(fd);
}
function uploadMem(){
  const f=state['1'].file.files[0]; if(!f) return;
  const fd=new FormData(); fd.append('mem',f);
  const xhr=new XMLHttpRequest(); xhr.open('POST','/dump/memory');
  const log=document.getElementById('log1');
  log.textContent='[*] Upload & scan...\n';
  document.getElementById('results1').innerHTML='';
  state['1'].btn.disabled=true;
  xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('bar1').style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{state['1'].btn.disabled=false;
    try{const j=JSON.parse(xhr.responseText);log.textContent=JSON.stringify(j,null,2);
      renderFiles(document.getElementById('results1'),j.job,j.files);}catch(e){log.textContent+='[!] '+e.message;}};
  xhr.onerror=()=>{state['1'].btn.disabled=false;log.textContent+='[!] Network error';};
  xhr.send(fd);
}
function uploadUnpack(){
  const f=state['2'].file.files[0]; if(!f) return;
  const fd=new FormData(); fd.append('apk',f);
  const xhr=new XMLHttpRequest(); xhr.open('POST','/unpack');
  const log=document.getElementById('log2');
  log.textContent='[*] Unpack...\n';
  document.getElementById('results2').innerHTML='';
  state['2'].btn.disabled=true;
  xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('bar2').style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{state['2'].btn.disabled=false;
    try{const j=JSON.parse(xhr.responseText);log.textContent=JSON.stringify(j,null,2);
      if(j.zip_url){
        document.getElementById('results2').innerHTML=
          `<a class="dlall" href="${j.zip_url}" download>⬇ TẢI FULL UNPACK ZIP</a>
           <div class="box ok">✅ Đã unpack ${j.total_entries} entries · ${(j.zip_size/1024/1024).toFixed(2)} MB</div>`;
      }
    }catch(e){log.textContent+='[!] '+e.message;}};
  xhr.onerror=()=>{state['2'].btn.disabled=false;log.textContent+='[!] Network error';};
  xhr.send(fd);
}
function uploadDexInfo(){
  const f=state['3'].file.files[0]; if(!f) return;
  const fd=new FormData(); fd.append('dex',f);
  const xhr=new XMLHttpRequest(); xhr.open('POST','/dexinfo');
  const log=document.getElementById('log3');
  log.textContent='[*] Phân tích DEX...\n';
  state['3'].btn.disabled=true;
  xhr.onload=()=>{state['3'].btn.disabled=false;
    try{const j=JSON.parse(xhr.responseText);log.textContent=JSON.stringify(j,null,2);}catch(e){log.textContent+='[!] '+e.message;}};
  xhr.onerror=()=>{state['3'].btn.disabled=false;log.textContent+='[!] Network error';};
  xhr.send(fd);
}
fetch('/shells').then(r=>r.json()).then(j=>{
  document.getElementById('shellinfo').textContent=JSON.stringify(j,null,2);
});
</script></body></html>
"""

@app.route("/")
def home():
    return render_template_string(PAGE)

@app.route("/shells")
def shells():
    return jsonify(SHELL_SIGNATURES)

@app.route("/dump/apk", methods=["POST"])
def dump_apk():
    if 'apk' not in request.files:
        return jsonify(status='error', output='no file'), 400
    f = request.files['apk']
    job = hashlib.md5(f"{f.filename}{time.time()}".encode()).hexdigest()[:12]
    jobdir = os.path.join(OUT, job); os.makedirs(jobdir, exist_ok=True)
    apk_path = os.path.join(jobdir, "input.apk")
    f.save(apk_path)
    try:
        result = process_apk(apk_path, jobdir)
        result['apk_size'] = os.path.getsize(apk_path)
    except Exception as e:
        return jsonify(status='error', output=str(e), job=job, files=[]), 500
    return jsonify(job=job, **result)

@app.route("/dump/memory", methods=["POST"])
def dump_memory():
    if 'mem' not in request.files:
        return jsonify(status='error', output='no file'), 400
    f = request.files['mem']
    job = hashlib.md5(f"{f.filename}{time.time()}".encode()).hexdigest()[:12]
    jobdir = os.path.join(OUT, job); os.makedirs(jobdir, exist_ok=True)
    mem_path = os.path.join(jobdir, "input.bin")
    f.save(mem_path)
    try:
        result = process_memory_dump(mem_path, jobdir)
    except Exception as e:
        return jsonify(status='error', output=str(e), job=job, files=[]), 500
    return jsonify(job=job, **result)

@app.route("/unpack", methods=["POST"])
def unpack():
    if 'apk' not in request.files:
        return jsonify(status='error', output='no file'), 400
    f = request.files['apk']
    job = hashlib.md5(f"{f.filename}{time.time()}".encode()).hexdigest()[:12]
    jobdir = os.path.join(OUT, job); os.makedirs(jobdir, exist_ok=True)
    apk_path = os.path.join(jobdir, "input.apk")
    f.save(apk_path)
    try:
        result = unpack_apk_full(apk_path, jobdir)
    except Exception as e:
        return jsonify(status='error', output=str(e)), 500
    return jsonify(status='ok', job=job,
                   zip_url=f"/download/{job}/{result['zip_name']}",
                   zip_size=result['zip_size'],
                   total_entries=result['total_entries'])

@app.route("/dexinfo", methods=["POST"])
def dexinfo():
    if 'dex' not in request.files:
        return jsonify(status='error', output='no file'), 400
    f = request.files['dex']
    data = f.read()
    if len(data) < 112 or data[:4] != b"dex\n":
        return jsonify(status='error', output='Không phải DEX hợp lệ'), 400
    info = decompile_dex_basic(data)
    info['filename'] = f.filename
    return jsonify(status='ok', **info)

@app.route("/download/<job>/<name>")
def download(job, name):
    if any(c in job for c in '/\\..') or any(c in name for c in '/\\..'):
        return "bad", 400
    path = os.path.join(OUT, job, name)
    if not os.path.isfile(path):
        return "not found", 404
    return send_file(path, as_attachment=True, download_name=name)

@app.route("/health")
def health():
    return jsonify(ok=True, ts=time.time())

if __name__ == "__main__":
    app.run("0.0.0.0", int(os.environ.get("PORT", 10000)))