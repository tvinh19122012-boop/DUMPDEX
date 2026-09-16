import os, io, zipfile, time, hashlib, json, re
from flask import Flask, request, jsonify, send_file, render_template_string
from dexdump_core import process_apk, process_memory_dump, SHELL_SIGNATURES

# ============ BẮT BUỘC PHẢI CÓ DÒNG NÀY ============
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 800 * 1024 * 1024

OUT = os.path.abspath("./jobs")
os.makedirs(OUT, exist_ok=True)

PAGE = r"""
<!DOCTYPE html><html><head><meta charset="utf-8">
<title>SikeMod DEX Dumper</title>
<style>
*{box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:'JetBrains Mono',monospace;padding:24px;max-width:1000px;margin:auto}
h1{color:#58a6ff;margin-bottom:2px}
.sub{color:#8b949e;margin-bottom:20px;font-size:13px}
.tabs{display:flex;gap:8px;margin-bottom:16px;border-bottom:1px solid #30363d}
.tab{padding:10px 16px;cursor:pointer;color:#8b949e;border-bottom:2px solid transparent}
.tab.active{color:#58a6ff;border-bottom-color:#58a6ff}
.panel{display:none}.panel.active{display:block}
.drop{border:2px dashed #30363d;border-radius:12px;padding:36px;text-align:center;
      background:#161b22;transition:.2s;cursor:pointer}
.drop:hover,.drop.hover{border-color:#58a6ff;background:#1c2128}
.drop input{display:none}
.btn{background:#238636;color:#fff;border:0;padding:11px 22px;border-radius:6px;
     cursor:pointer;font-family:inherit;font-size:14px;margin-top:12px}
.btn:hover{background:#2ea043}
.btn:disabled{background:#30363d;cursor:not-allowed}
.btn.alt{background:#1f6feb}.btn.alt:hover{background:#388bfd}
pre{background:#161b22;padding:14px;border:1px solid #30363d;border-radius:8px;
    max-height:420px;overflow:auto;font-size:12.5px;line-height:1.5}
.file{display:flex;justify-content:space-between;align-items:center;
      background:#161b22;padding:10px 14px;border:1px solid #30363d;
      border-radius:6px;margin:6px 0}
.file a{color:#58a6ff;text-decoration:none}
.file a:hover{text-decoration:underline}
.size{color:#8b949e;font-size:12px}
.bar{height:6px;background:#30363d;border-radius:3px;overflow:hidden;margin-top:10px}
.bar > div{height:100%;background:#58a6ff;width:0;transition:.2s}
.shell{background:#3d1f1f;border:1px solid #f85149;padding:10px;border-radius:6px;margin:8px 0}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;background:#30363d;margin-right:4px}
.tag.red{background:#f85149}.tag.green{background:#2ea043}
</style></head><body>
<h1>👑 SikeMod DEX Dumper</h1>
<div class="sub">Bóc DEX gốc từ APK · nhận diện shell pack · dump memory</div>

<div class="tabs">
  <div class="tab active" onclick="tab(0)">📦 APK</div>
  <div class="tab" onclick="tab(1)">🧠 Memory Dump</div>
  <div class="tab" onclick="tab(2)">ℹ️ Shell Info</div>
</div>

<div class="panel active">
  <div class="drop" id="drop0">
    <input type="file" id="file0" accept=".apk,.zip,.xapk,.apks">
    <div id="label0">📦 Kéo thả APK vào đây hoặc click chọn</div>
    <div class="bar"><div id="bar0"></div></div>
  </div>
  <button class="btn" id="btn0" disabled onclick="uploadApk()">BÓC DEX</button>
  <pre id="log0">[idle] chờ file...</pre>
  <div id="results0"></div>
</div>

<div class="panel">
  <div class="sub">Upload file memory dump để bóc DEX ra</div>
  <div class="drop" id="drop1">
    <input type="file" id="file1">
    <div id="label1">🧠 Kéo thả memory dump vào đây</div>
    <div class="bar"><div id="bar1"></div></div>
  </div>
  <button class="btn alt" id="btn1" disabled onclick="uploadMem()">SCAN DEX</button>
  <pre id="log1">[idle] chờ file...</pre>
  <div id="results1"></div>
</div>

<div class="panel">
  <pre id="shellinfo">Loading...</pre>
</div>

<script>
const state={};
function tab(i){
  document.querySelectorAll('.tab').forEach((t,j)=>t.classList.toggle('active',i===j));
  document.querySelectorAll('.panel').forEach((p,j)=>p.classList.toggle('active',i===j));
}
['0','1'].forEach(n=>{
  const drop=document.getElementById('drop'+n), file=document.getElementById('file'+n),
        label=document.getElementById('label'+n), btn=document.getElementById('btn'+n);
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
  if(!files || !files.length){ container.innerHTML='<div class="shell">⚠️ Không có file DEX nào</div>'; return; }
  let h='<h3>📥 File tải về:</h3>';
  files.forEach(f=>{
    h+=`<div class="file">
      <a href="/download/${job}/${encodeURIComponent(f.name)}" download>⬇ ${f.name}</a>
      <span class="size">${(f.size/1024).toFixed(1)} KB</span>
    </div>`;
  });
  container.innerHTML=h;
}
function uploadApk(){
  const f=state['0'].file.files[0]; if(!f) return;
  const fd=new FormData(); fd.append('apk',f);
  const xhr=new XMLHttpRequest(); xhr.open('POST','/dump/apk');
  const log=document.getElementById('log0'); log.textContent='[*] Upload...\n';
  document.getElementById('results0').innerHTML='';
  state['0'].btn.disabled=true;
  xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('bar0').style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{state['0'].btn.disabled=false;
    try{const j=JSON.parse(xhr.responseText);log.textContent=JSON.stringify(j,null,2);
    renderFiles(document.getElementById('results0'),j.job,j.files);}catch(e){log.textContent+='[!] '+e.message;}};
  xhr.onerror=()=>{state['0'].btn.disabled=false;log.textContent+='[!] Network error';};
  xhr.send(fd);
}
function uploadMem(){
  const f=state['1'].file.files[0]; if(!f) return;
  const fd=new FormData(); fd.append('mem',f);
  const xhr=new XMLHttpRequest(); xhr.open('POST','/dump/memory');
  const log=document.getElementById('log1'); log.textContent='[*] Upload...\n';
  document.getElementById('results1').innerHTML='';
  state['1'].btn.disabled=true;
  xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('bar1').style.width=(e.loaded/e.total*100)+'%'};
  xhr.onload=()=>{state['1'].btn.disabled=false;
    try{const j=JSON.parse(xhr.responseText);log.textContent=JSON.stringify(j,null,2);
    renderFiles(document.getElementById('results1'),j.job,j.files);}catch(e){log.textContent+='[!] '+e.message;}};
  xhr.onerror=()=>{state['1'].btn.disabled=false;log.textContent+='[!] Network error';};
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

@app.route("/download/<job>/<name>")
def download(job, name):
    if any(c in job for c in '/\\..') or any(c in name for c in '/\\..'):
        return "bad", 400
    path = os.path.join(OUT, job, name)
    if not os.path.isfile(path):
        return "not found", 404
    return send_file(path, as_attachment=True, download_name=name)

if __name__ == "__main__":
    app.run("0.0.0.0", int(os.environ.get("PORT", 10000)))