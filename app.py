"""Certificate Verify - upload a certificate, get a link + QR code (data stored in MySQL).
Scanning the QR opens a public "Verified" page that shows the certificate document.

Run:  ADMIN_PASSWORD=yourpassword python3 app.py
Admin: http://localhost:5000/admin      Public page: /v/<id>
"""
import os
import secrets
import time
from functools import wraps
from pathlib import Path

import mysql.connector
from mysql.connector import errors as myerr
from flask import (Flask, abort, redirect, render_template_string, request,
                   send_file, session, url_for)

BASE = Path(__file__).parent
_env = BASE / ".env"
if _env.exists():  # simple KEY=VALUE loader so you only run: python3 app.py
    for _l in _env.read_text().splitlines():
        _l = _l.strip()
        if _l and not _l.startswith("#") and "=" in _l:
            _k, _v = _l.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))
DATA = BASE / "data"
FILES = DATA / "files"
FILES.mkdir(parents=True, exist_ok=True)

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
ALLOWED = {".pdf", ".png", ".jpg", ".jpeg"}
MAX_MB = 10

key_file = DATA / "secret.key"
if not key_file.exists():
    key_file.write_text(secrets.token_hex(32))

app = Flask(__name__)
app.secret_key = key_file.read_text()
app.config.update(MAX_CONTENT_LENGTH=MAX_MB * 1024 * 1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

# ---------- MySQL ----------
DBCFG = dict(host=os.environ.get("MYSQL_HOST", "127.0.0.1"), port=int(os.environ.get("MYSQL_PORT", 3306)),
             user=os.environ.get("MYSQL_USER", "root"), password=os.environ.get("MYSQL_PASSWORD", ""),
             database=os.environ.get("MYSQL_DATABASE", "certificate_verify"), charset="utf8mb4")


def db():
    return mysql.connector.connect(connection_timeout=8, **DBCFG)


def q(sql, args=(), one=False, write=False):
    c = db()
    try:
        cur = c.cursor(dictionary=True)
        cur.execute(sql, args)
        if write:
            c.commit()
            return cur.rowcount
        return cur.fetchone() if one else cur.fetchall()
    finally:
        c.close()


def init_db():
    root = {k: v for k, v in DBCFG.items() if k != "database"}   # connect without a database first
    c = mysql.connector.connect(connection_timeout=8, **root)
    try:
        c.cursor().execute("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4" % DBCFG["database"].replace("`", ""))
    finally:
        c.close()
    q("""CREATE TABLE IF NOT EXISTS certificates (
        id VARCHAR(20) NOT NULL PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        course VARCHAR(200) NOT NULL DEFAULT '',
        period VARCHAR(100) NOT NULL DEFAULT '',
        cert_no VARCHAR(60) NOT NULL,
        institute VARCHAR(150) NOT NULL DEFAULT '',
        ext VARCHAR(8) NOT NULL,
        created DATETIME NOT NULL,
        revoked TINYINT(1) NOT NULL DEFAULT 0,
        UNIQUE KEY uq_cert_no (cert_no)
    ) CHARACTER SET utf8mb4""", write=True)


def row(r):
    if r and not isinstance(r["created"], str):
        r["created"] = r["created"].strftime("%Y-%m-%d %H:%M")
    return r


def admin_only(fn):
    @wraps(fn)
    def w(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return w


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    if request.path.startswith(("/admin", "/v/")):
        r.headers["Cache-Control"] = "no-store"
    return r


STYLE = """
<style>
:root{--bg:#f4f5f7;--card:#fff;--ink:#1c1f24;--muted:#6b7280;--line:#e2e5ea;--brand:#1f6feb;--ok:#1a8a3c;--bad:#c0392b}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1d2026;--ink:#e8eaed;--muted:#9aa1ac;--line:#2c313a;--brand:#4c8dff;--ok:#3fb862;--bad:#ef6b5b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
.wrap{max-width:900px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px;margin-bottom:16px}
h1,h2{margin:0 0 10px}label{display:block;font-size:12px;color:var(--muted);margin:10px 0 3px}
input[type=text],input[type=password],input[type=file]{width:100%;padding:8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink)}
button,.btn{padding:8px 14px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--ink);cursor:pointer;text-decoration:none;font-size:14px;display:inline-block}
.primary{background:var(--brand);color:#fff;border-color:var(--brand);font-weight:600}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}@media(max-width:640px){.grid{grid-template-columns:1fr}}
.rec{display:flex;gap:14px;flex-wrap:wrap;align-items:flex-start;border-top:1px solid var(--line);padding:14px 0}
.rec:first-child{border-top:0}.rec canvas{width:120px;height:120px;border:1px solid var(--line);background:#fff;border-radius:6px}
.rec .info{flex:1;min-width:220px}.muted{color:var(--muted);font-size:13px}
.tag{font-size:12px;padding:2px 8px;border-radius:10px;border:1px solid var(--line)}.tag.bad{color:var(--bad);border-color:var(--bad)}
.link{display:flex;gap:6px;margin:6px 0}.link input{flex:1;font-size:12px}
</style>"""

LOGIN = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Admin login</title>""" + STYLE + """</head><body><div class=wrap style="max-width:380px"><div class=card>
<h2>Admin login</h2>{% if err %}<p style="color:var(--bad)">{{err}}</p>{% endif %}
<form method=post><label>Password</label><input type=password name=password autofocus required>
<p><button class=primary>Login</button></p></form></div></div></body></html>"""

ADMIN = """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Certificate admin</title>""" + STYLE + """</head><body><div class=wrap>
<div style="display:flex;justify-content:space-between;align-items:center"><h1>Certificates</h1><a class=btn href="{{url_for('logout')}}">Logout</a></div>
{% if msg %}<div class=card style="border-color:var(--ok)">{{msg}}</div>{% endif %}
<div class=card><h2>Upload a certificate</h2>
<form method=post action="{{url_for('upload')}}" enctype=multipart/form-data>
<div class=grid>
<div><label>Student name *</label><input type=text name=name required maxlength=120></div>
<div><label>Course</label><input type=text name=course maxlength=200></div>
<div><label>Period (e.g. 01/06/2026 to 30/07/2026)</label><input type=text name=period maxlength=100></div>
<div><label>Certificate no. (empty = auto)</label><input type=text name=cert_no maxlength=60></div>
<div><label>Institute</label><input type=text name=institute maxlength=150 value="{{institute}}"></div>
<div><label>Certificate file (PDF / PNG / JPG, max {{mb}} MB) *</label><input type=file name=file accept=".pdf,.png,.jpg,.jpeg" required></div>
</div>
<p><button class=primary>Upload &amp; create QR</button></p></form>
<label>Public website address used inside the QR (must be reachable from the phone that scans)</label>
<input type=text id=base value="{{base}}"></div>
<div class=card><h2>Uploaded ({{records|length}})</h2>
{% for id, r in records %}
<div class=rec>
<canvas data-id="{{id}}" width=240 height=240></canvas>
<div class=info>
<b>{{r.name}}</b> {% if r.revoked %}<span class="tag bad">REVOKED</span>{% endif %}<br>
<span class=muted>{{r.course}}{% if r.period %} &middot; {{r.period}}{% endif %}<br>No: {{r.cert_no}} &middot; {{r.created}}</span>
<div class=link><input type=text readonly data-link="{{id}}"><button type=button onclick="copyLink('{{id}}')">Copy</button></div>
<a class=btn href="{{url_for('verify', cid=id)}}" target=_blank>Open page</a>
<button type=button onclick="dlQr('{{id}}','{{r.cert_no}}')">Download QR</button>
<form method=post action="{{url_for('toggle', cid=id)}}" style="display:inline"><button>{{'Restore' if r.revoked else 'Revoke'}}</button></form>
<form method=post action="{{url_for('delete', cid=id)}}" style="display:inline" onsubmit="return confirm('Delete permanently?')"><button>Delete</button></form>
</div></div>
{% else %}<p class=muted>Nothing uploaded yet.</p>{% endfor %}
</div></div>
<script src="{{url_for('static', filename='qrcode.min.js')}}"></script>
<script>
const baseEl=document.getElementById('base');
try{const s=localStorage.getItem('cv_base'); if(s) baseEl.value=s;}catch(e){}
function linkFor(id){return baseEl.value.replace(/\\/$/,'')+'/v/'+id;}
function draw(c,text){
  const q=qrcode(0,'M');q.addData(text);q.make();const n=q.getModuleCount(),m=4,cell=Math.floor(c.width/(n+2*m)),off=Math.floor((c.width-cell*n)/2);
  const x=c.getContext('2d');x.fillStyle='#fff';x.fillRect(0,0,c.width,c.height);x.fillStyle='#000';
  for(let r=0;r<n;r++)for(let k=0;k<n;k++)if(q.isDark(r,k))x.fillRect(off+k*cell,off+r*cell,cell,cell);
}
function refresh(){
  try{localStorage.setItem('cv_base',baseEl.value);}catch(e){}
  document.querySelectorAll('canvas[data-id]').forEach(c=>draw(c,linkFor(c.dataset.id)));
  document.querySelectorAll('input[data-link]').forEach(i=>i.value=linkFor(i.dataset.link));
}
baseEl.addEventListener('input',refresh);refresh();
function copyLink(id){const i=document.querySelector('input[data-link="'+id+'"]');i.select();navigator.clipboard?navigator.clipboard.writeText(i.value):document.execCommand('copy');}
function dlQr(id,no){const c=document.createElement('canvas');c.width=c.height=800;draw(c,linkFor(id));draw(c,linkFor(id));
  c.toBlob(b=>{const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='QR-'+no+'.png';a.click();});}
</script></body></html>"""

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Certificate verification</title>""" + STYLE + """
<style>.top{text-align:center}.ico{width:72px;height:72px;border-radius:50%;margin:0 auto 10px;color:#fff;font-size:42px;line-height:72px}
table{width:100%;border-collapse:collapse;margin:14px 0}th,td{padding:9px;border-bottom:1px solid var(--line);text-align:left}th{width:38%;color:var(--muted);font-weight:600}
.doc{width:100%;border:1px solid var(--line);border-radius:8px;background:#fff}iframe.doc{height:78vh}</style></head><body><div class=wrap style="max-width:720px">
<div class="card top">
{% if state=='ok' %}<div class=ico style="background:var(--ok)">&#10003;</div><h1 style="color:var(--ok)">Certificate Verified</h1>
<p>This is a genuine certificate issued by <b>{{r.institute or 'the institute'}}</b>.</p>
{% elif state=='revoked' %}<div class=ico style="background:var(--bad)">!</div><h1 style="color:var(--bad)">Certificate Revoked</h1><p>This certificate is no longer valid.</p>
{% else %}<div class=ico style="background:var(--bad)">&times;</div><h1 style="color:var(--bad)">Not Verified</h1><p>No certificate was found for this code.</p>{% endif %}
</div>
{% if state=='ok' %}
<div class=card><table>
<tr><th>Name</th><td>{{r.name}}</td></tr>{% if r.course %}<tr><th>Course</th><td>{{r.course}}</td></tr>{% endif %}
{% if r.period %}<tr><th>Period</th><td>{{r.period}}</td></tr>{% endif %}<tr><th>Certificate no.</th><td>{{r.cert_no}}</td></tr>
<tr><th>Status</th><td style="color:var(--ok);font-weight:700">VALID</td></tr></table>
<h2 style="margin-top:6px">Certificate</h2>
{% if r.ext=='.pdf' %}<iframe class=doc src="{{url_for('file', cid=cid)}}" title="Certificate"></iframe>
{% else %}<img class=doc src="{{url_for('file', cid=cid)}}" alt="Certificate">{% endif %}
<p><a class=btn href="{{url_for('file', cid=cid)}}" target=_blank>Open full size</a></p></div>
{% endif %}</div></body></html>"""


@app.route("/")
def home():
    return redirect(url_for("admin"))


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    err = ""
    if request.method == "POST":
        time.sleep(0.5)  # slow down guessing
        if secrets.compare_digest(request.form.get("password", ""), ADMIN_PASSWORD):
            session["admin"] = True
            return redirect(url_for("admin"))
        err = "Wrong password."
    return render_template_string(LOGIN, err=err)


@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/admin")
@admin_only
def admin():
    rows = q("SELECT * FROM certificates ORDER BY created DESC")
    records = [(r["id"], type("R", (), row(r))) for r in rows]
    base = os.environ.get("BASE_URL") or request.host_url.rstrip("/")
    return render_template_string(ADMIN, records=records, base=base, mb=MAX_MB,
                                  institute=os.environ.get("INSTITUTE", ""),
                                  msg=request.args.get("msg", ""))


@app.route("/admin/upload", methods=["POST"])
@admin_only
def upload():
    f = request.files.get("file")
    name = request.form.get("name", "").strip()
    if not f or not f.filename or not name:
        abort(400)
    ext = Path(f.filename).suffix.lower()
    if ext not in ALLOWED:
        abort(400, "Only PDF, PNG or JPG files are allowed.")
    head = f.stream.read(8)
    f.stream.seek(0)
    ok = (ext == ".pdf" and head.startswith(b"%PDF")) or (ext == ".png" and head.startswith(b"\x89PNG")) \
        or (ext in (".jpg", ".jpeg") and head.startswith(b"\xff\xd8"))
    if not ok:
        abort(400, "File content does not match its type.")
    cid = secrets.token_urlsafe(8)
    f.save(FILES / (cid + ext))
    cert_no = request.form.get("cert_no", "").strip()[:60] or "CERT" + time.strftime("%Y") + secrets.token_hex(3).upper()
    try:
        q("INSERT INTO certificates (id,name,course,period,cert_no,institute,ext,created,revoked) "
          "VALUES (%s,%s,%s,%s,%s,%s,%s,NOW(),0)",
          (cid, name[:120], request.form.get("course", "").strip()[:200], request.form.get("period", "").strip()[:100],
           cert_no, request.form.get("institute", "").strip()[:150], ext), write=True)
    except myerr.IntegrityError:
        (FILES / (cid + ext)).unlink(missing_ok=True)
        abort(400, "This certificate number already exists.")
    return redirect(url_for("admin", msg="Uploaded. Your QR code and link are in the list below."))


@app.post("/admin/toggle/<cid>")
@admin_only
def toggle(cid):
    q("UPDATE certificates SET revoked = 1 - revoked WHERE id=%s", (cid,), write=True)
    return redirect(url_for("admin"))


@app.post("/admin/delete/<cid>")
@admin_only
def delete(cid):
    r = q("SELECT ext FROM certificates WHERE id=%s", (cid,), one=True)
    if r:
        q("DELETE FROM certificates WHERE id=%s", (cid,), write=True)
        (FILES / (cid + r["ext"])).unlink(missing_ok=True)
    return redirect(url_for("admin"))


@app.route("/v/<cid>")
def verify(cid):
    r = row(q("SELECT * FROM certificates WHERE id=%s", (cid,), one=True))
    if not r:
        return render_template_string(PAGE, state="none", r=None, cid=cid), 404
    if r["revoked"]:
        return render_template_string(PAGE, state="revoked", r=None, cid=cid)
    return render_template_string(PAGE, state="ok", r=type("R", (), r), cid=cid)


@app.route("/f/<cid>")
def file(cid):
    r = q("SELECT * FROM certificates WHERE id=%s", (cid,), one=True)
    if not r or r["revoked"]:
        abort(404)
    p = FILES / (cid + r["ext"])
    if not p.exists():
        abort(404)
    mime = {".pdf": "application/pdf", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg"}[r["ext"]]
    return send_file(p, mimetype=mime, download_name=f"{r['cert_no']}{r['ext']}")


if __name__ == "__main__":
    try:
        init_db()
    except Exception as e:
        raise SystemExit(f"Cannot connect to MySQL ({DBCFG['user']}@{DBCFG['host']}:{DBCFG['port']}/{DBCFG['database']}): {e}\n"
                         "Set MYSQL_USER / MYSQL_PASSWORD / MYSQL_DATABASE (see README.txt).")
    if ADMIN_PASSWORD == "admin123":
        print("WARNING: using default password 'admin123'. Set ADMIN_PASSWORD before going public.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
