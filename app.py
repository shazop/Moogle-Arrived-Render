import json
import os
import re
import secrets
import time
import base64
import hmac
import hashlib
from urllib.parse import urlparse, unquote
import requests
from flask import (
    Flask, request, Response, render_template,
    jsonify, redirect, url_for, make_response
)
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.environ.get("SECRET_KEY", secrets.token_hex(32)))

if os.environ.get("AWS_LAMBDA_FUNCTION_NAME") or os.environ.get("NETLIFY") or not os.access(os.path.dirname(os.path.abspath(__file__)), os.W_OK):
    BASE_DATA_DIR = os.path.join(os.environ.get("TMPDIR", "/tmp"), "moogle_data")
else:
    BASE_DATA_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DATA_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 15 * 1024 * 1024

PORT = int(os.environ.get("PORT", 5000))
MAX_STORAGE_PER_USER = 10 * 1024 * 1024
MAX_FILES_PER_USER = 5
FLAG = os.environ.get("FLAG", "$N1PH€RSxTCTF{w04h!_y0u_3xpl0t3d_7H3_33RF_X33_JW7_C0nfus10n_csadsa3}")

# ─── RSA Key Pair Generation (RS256 - Persisted to avoid invalidation on reload) ──
RSA_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jwt_rsa_key.pem")
if os.environ.get("JWT_RSA_KEY"):
    _private_key_obj = serialization.load_pem_private_key(os.environ["JWT_RSA_KEY"].encode("utf-8"), password=None)
elif os.path.exists(RSA_KEY_FILE):
    with open(RSA_KEY_FILE, "rb") as _kf:
        _private_key_obj = serialization.load_pem_private_key(_kf.read(), password=None)
else:
    _private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        with open(RSA_KEY_FILE, "wb") as _kf:
            _kf.write(_private_key_obj.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
    except Exception:
        pass

RSA_PRIVATE_KEY_PEM = _private_key_obj.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode("utf-8")

RSA_PUBLIC_KEY_PEM = _private_key_obj.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")

USERS = {}
SESSIONS = {}
FILES_DB = {}
REVIEW_LOGS = {}

DB_FILE = os.path.join(BASE_DATA_DIR, "state_db.json")

def load_state():
    global USERS, SESSIONS, FILES_DB, REVIEW_LOGS
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                USERS.update(data.get("USERS", {}))
                SESSIONS.update(data.get("SESSIONS", {}))
                FILES_DB.update(data.get("FILES_DB", {}))
                REVIEW_LOGS.update(data.get("REVIEW_LOGS", {}))
        except Exception:
            pass

def save_state():
    try:
        os.makedirs(BASE_DATA_DIR, exist_ok=True)
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "USERS": USERS,
                "SESSIONS": SESSIONS,
                "FILES_DB": FILES_DB,
                "REVIEW_LOGS": REVIEW_LOGS
            }, f)
    except Exception:
        pass

load_state()

_loopback_started = False
def start_background_loopback(port=None):
    global _loopback_started
    if _loopback_started:
        return
    _loopback_started = True
    target_port = port or PORT
    import threading
    from wsgiref.simple_server import make_server, WSGIRequestHandler

    class SilentHandler(WSGIRequestHandler):
        def log_message(self, format, *args):
            pass

    def _run():
        try:
            server = make_server("127.0.0.1", target_port, app, handler_class=SilentHandler)
            server.serve_forever()
        except Exception:
            pass

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    time.sleep(0.2)

# ─── Base64URL Helpers ───────────────────────────────────────────────────────
def b64url_encode(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

def b64url_decode(data_str):
    rem = len(data_str) % 4
    if rem > 0:
        data_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data_str)

# ─── JWT Creation & Vulnerable Verification (Algorithm Confusion) ───────────
def generate_jwt(payload):
    """Generate a standard RS256 JWT signed with RSA Private Key."""
    header = {"alg": "RS256", "typ": "JWT"}
    h_b64 = b64url_encode(json.dumps(header))
    p_b64 = b64url_encode(json.dumps(payload))
    signing_input = f"{h_b64}.{p_b64}".encode("utf-8")
    signature = _private_key_obj.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h_b64}.{p_b64}.{b64url_encode(signature)}"

def verify_jwt(token):
    """
    ╔══════════════════════════════════════════════════════════════╗
    ║   VULNERABLE JWT VALIDATOR — Algorithm Confusion (RS->HS)    ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        header = json.loads(b64url_decode(parts[0]).decode("utf-8"))
        payload = json.loads(b64url_decode(parts[1]).decode("utf-8"))
        signature = b64url_decode(parts[2])
        signing_input = f"{parts[0]}.{parts[1]}".encode("utf-8")
        alg = header.get("alg", "RS256")
        
        # ── Flaw: If header specifies HS256, uses RSA_PUBLIC_KEY as HMAC secret!
        if alg == "HS256":
            # Support exact PEM and stripped PEM (jwt_tool and other tools strip trailing newlines)
            candidate_keys = [
                RSA_PUBLIC_KEY_PEM,
                RSA_PUBLIC_KEY_PEM.strip(),
                RSA_PUBLIC_KEY_PEM.strip() + "\n",
                RSA_PUBLIC_KEY_PEM.replace("\r\n", "\n"),
                RSA_PUBLIC_KEY_PEM.strip().replace("\r\n", "\n")
            ]
            for key_str in candidate_keys:
                expected_sig = hmac.new(key_str.encode("utf-8"), signing_input, hashlib.sha256).digest()
                if hmac.compare_digest(signature, expected_sig):
                    return payload
            return None
        elif alg == "RS256":
            _private_key_obj.public_key().verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
            return payload
        else:
            return None
    except Exception:
        return None

# ─── Auth decorator ───────────────────────────────────────────────────────────
def get_current_user():
    # 1. Check for JWT authentication (used by admin or forged algorithm confusion tokens)
    token = request.cookies.get("jwt_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
    if token:
        jwt_user = verify_jwt(token)
        if jwt_user:
            return jwt_user

    # 2. Check for standard regular user session cookie
    sess_id = request.cookies.get("session_token") or request.cookies.get("session_id")
    if sess_id:
        if sess_id not in SESSIONS:
            load_state()
        if sess_id in SESSIONS:
            return SESSIONS[sess_id]

    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            if request.path.startswith("/api/") or request.path.startswith("/drive/v2/"):
                return jsonify({"error": "Session expired or unauthorized. Please log in again."}), 401
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ════════════════════════════════════════════════════════════════════════════
#  INTERNAL KEYS ENDPOINT (Only reachable via SSRF / Internal backend fetcher)
# ════════════════════════════════════════════════════════════════════════════
@app.route("/keys.json")
def internal_keys():
    # 1. Reject remote addresses outside local loopback
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return Response("403 Forbidden", status=403, mimetype="text/plain")

    # 2. Reject forwarded external requests from proxies, tunnels, or public IP
    forwarded = request.headers.get("X-Forwarded-For") or request.headers.get("X-Real-IP")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
        if client_ip not in ("127.0.0.1", "::1", "localhost"):
            return Response("403 Forbidden", status=403, mimetype="text/plain")

    # 3. Reject direct access (browser, curl, direct client visits)
    # Only internal SSRF requests issued by the application's backend fetcher are permitted
    is_internal_fetch = request.headers.get("X-Moogle-Internal-Fetch") == "true" or "MoogleDrive-Internal-Fetcher" in request.headers.get("User-Agent", "")
    if not is_internal_fetch:
        return Response("403 Forbidden", status=403, mimetype="text/plain")

    return Response(
        json.dumps({
            "service": "Moogle Auth Key Distribution Service",
            "algorithm": "RS256",
            "format": "PKCS#8 PEM",
            "public_key": RSA_PUBLIC_KEY_PEM
        }, indent=2),
        headers={"Content-Type": "application/json"}
    )

# ════════════════════════════════════════════════════════════════════════════
#  ADMIN CONSOLE (/admin) — Holds the flag
# ════════════════════════════════════════════════════════════════════════════
@app.route("/admin")
def admin_console():
    user = get_current_user()
    if not user:
        return redirect(url_for("login_page"))
    
    user_role = str(user.get("role", "")).lower()
    user_email = str(user.get("email", "")).lower()
    user_name = str(user.get("name", ""))
    user_avatar = str(user.get("avatar", ""))
    user_color = str(user.get("color", ""))

    # 1. Reject if role is un-escalated 'admin'
    if user_role == "admin":
        return Response(
            """<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;background:#f8fafd">
            <h1 style="color:#c5221f">403 Forbidden: Privilege Escalation Required</h1>
            <p>Access Denied: Standard <code>admin</code> role is insufficient to view the Flag Console.</p>
            <p>You must escalate your privileges to <code>superadmin</code> while preserving the administrative identity profile.</p>
            <p><a href="/drive">← Return to Drive</a></p></body></html>""",
            status=403, mimetype="text/html"
        )

    # 2. Reject if role is not 'superadmin'
    if user_role != "superadmin":
        return Response(
            """<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;background:#f8fafd">
            <h1 style="color:#c5221f">403 Forbidden: Not Authorized</h1>
            <p>You are not authorized to view this resource.</p>
            <p><a href="/drive">← Return to Drive</a></p></body></html>""",
            status=403, mimetype="text/html"
        )

    # 3. Reject if required user variables / values are missing or altered
    if user_email != "admin@moogle.com" or user_name != "Moogle Administrator" or user_avatar != "A" or user_color != "#1a73e8":
        return Response(
            """<!DOCTYPE html><html><body style="font-family:sans-serif;padding:40px;background:#f8fafd">
            <h1 style="color:#c5221f">403 Forbidden: Invalid Administrator Profile</h1>
            <p>The token must contain all user variable names and values (<code>email</code>, <code>name</code>, <code>avatar</code>, <code>color</code>) with <code>role</code> escalated to <code>superadmin</code>.</p>
            <p><a href="/drive">← Return to Drive</a></p></body></html>""",
            status=403, mimetype="text/html"
        )

    return render_template("admin.html", user=user, flag=FLAG)

# ════════════════════════════════════════════════════════════════════════════
#  PUBLIC & AUTH PAGES (Standard Session ID for Regular Users)
# ════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    if get_current_user():
        return redirect(url_for("drive_home"))
    return redirect(url_for("login_page"))

@app.route("/login", methods=["GET", "POST"])
def login_page():
    error = None
    if request.method == "POST":
        load_state()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        user = USERS.get(email)
        if user and user["password"] == password:
            # Issue standard session token for regular user (no RS256 JWT given to normal user)
            sess_token = "sess_" + secrets.token_hex(16)
            SESSIONS[sess_token] = {
                "email": email,
                "name": user["name"],
                "role": "user",
                "avatar": user["avatar"],
                "color": user["color"]
            }
            save_state()
            resp = redirect(url_for("drive_home"))
            resp.set_cookie("session_token", sess_token, httponly=False)
            resp.delete_cookie("jwt_token")
            return resp
        else:
            error = "Invalid email or password. Please try again."
    return render_template("login.html", error=error)

@app.route("/signup", methods=["GET", "POST"])
def signup_page():
    error = None
    if request.method == "POST":
        load_state()
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        if not name or not email or not password:
            error = "All fields are required."
        elif "@" not in email:
            error = "Please enter a valid email address."
        elif email in USERS:
            error = "An account with this email already exists."
        else:
            avatar_letter = name[0].upper() if name else "U"
            colors = ["#1a73e8", "#ea4335", "#34a853", "#fbbc04", "#673ab7", "#e91e63"]
            user_color = colors[len(USERS) % len(colors)]
            USERS[email] = {
                "password": password,
                "name": name,
                "avatar": avatar_letter,
                "color": user_color
            }
            # Issue standard session token for regular user (no RS256 JWT given to normal user)
            sess_token = "sess_" + secrets.token_hex(16)
            SESSIONS[sess_token] = {
                "email": email,
                "name": name,
                "role": "user",
                "avatar": avatar_letter,
                "color": user_color
            }
            save_state()
            resp = redirect(url_for("drive_home"))
            resp.set_cookie("session_token", sess_token, httponly=False)
            resp.delete_cookie("jwt_token")
            return resp
    return render_template("signup.html", error=error)

@app.route("/logout")
def logout():
    load_state()
    sess_id = request.cookies.get("session_token")
    if sess_id and sess_id in SESSIONS:
        del SESSIONS[sess_id]
        save_state()
    resp = redirect(url_for("login_page"))
    resp.delete_cookie("jwt_token")
    resp.delete_cookie("session_token")
    return resp

@app.route("/drive")
@login_required
def drive_home():
    user = get_current_user()
    return render_template("drive.html", user=user)

# ════════════════════════════════════════════════════════════════════════════
#  MOOGLE DRIVE REST API v2 & IP NORMALIZER (Strict Octal SSRF Bypass)
# ════════════════════════════════════════════════════════════════════════════
def is_octal_ip(host):
    """
    Validates whether host is strictly an octal-formatted IPv4 address (e.g. 0177.0.0.1).
    Must have 4 dotted parts, contain only octal digits (0-7),
    and at least one octet must have a leading zero with len > 1 (e.g. '0177').
    """
    if not host or not isinstance(host, str):
        return False
    parts = host.split(".")
    if len(parts) != 4:
        return False
    has_octal_prefix = False
    for p in parts:
        p = p.strip()
        if not p.isdigit():
            return False
        if p.startswith("0") and len(p) > 1:
            has_octal_prefix = True
            if any(c in p for c in "89"):
                return False
    return has_octal_prefix

def resolve_octal_ip(host):
    """
    Simulates standard POSIX inet_aton socket resolver behavior for octal IPv4.
    e.g. '0177.0.0.1' -> '127.0.0.1', '0177.00.00.01' -> '127.0.0.1'.
    """
    if not host or not isinstance(host, str):
        return host
    
    parts = host.split(".")
    if len(parts) == 4:
        try:
            nums = [int(p, 8) if p.startswith("0") and len(p) > 1 else int(p, 10) for p in parts]
            if all(0 <= n <= 255 for n in nums):
                return ".".join(str(n) for n in nums)
        except (ValueError, OverflowError):
            pass
    return host

@app.route("/drive/v2/files", methods=["GET"])
@login_required
def drive_v2_list():
    user = get_current_user()
    user_email = user.get("email")
    user_files = [f for f in FILES_DB.values() if f.get("owner") == user_email]
    query = request.args.get("q", "").lower()
    if query:
        user_files = [f for f in user_files if query in f["title"].lower()]
    used_bytes = sum(int(f.get("fileSize", 0)) for f in user_files)
    # Strip internal URLs from user-facing response
    sanitized = [{k: v for k, v in f.items() if k not in ("downloadUrl", "webContentLink", "webViewLink")} for f in user_files]
    return jsonify({
        "kind": "drive#fileList",
        "items": sanitized,
        "total": len(user_files),
        "quota": {
            "usedBytes": used_bytes,
            "maxBytes": MAX_STORAGE_PER_USER,
            "fileCount": len(user_files),
            "maxFiles": MAX_FILES_PER_USER
        }
    })

@app.route("/drive/v2/files/<path:file_id>", methods=["GET"])
def drive_v2_get_file(file_id):
    alt = request.args.get("alt", "")
    clean_id = file_id.split("?")[0]
    if clean_id not in FILES_DB:
        return jsonify({"error": {"code": 404, "message": "File not found"}}), 404
    file_item = FILES_DB[clean_id]
    if alt == "media" or "alt=media" in request.query_string.decode("utf-8", errors="ignore"):
        filepath = os.path.join(UPLOAD_FOLDER, clean_id)
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                content = f.read()
            return Response(content, mimetype=file_item["mimeType"])
        return Response("File data unavailable", status=404)
    return jsonify({
        "kind": "drive#file",
        "id": file_item["id"],
        "title": file_item["title"],
        "mimeType": file_item["mimeType"],
        "fileSize": file_item["fileSize"],
        "modifiedDate": file_item["modifiedDate"],
        "owner": file_item.get("owner", "user@moogle.com")
    })

@app.route("/drive/v2/download/<file_id>")
def drive_v2_download(file_id):
    clean_id = file_id.split("?")[0]
    if clean_id not in FILES_DB:
        return Response("File not found", status=404)
    file_item = FILES_DB[clean_id]
    filepath = os.path.join(UPLOAD_FOLDER, clean_id)
    if os.path.exists(filepath):
        with open(filepath, "rb") as f:
            content = f.read()
        return Response(
            content,
            mimetype=file_item["mimeType"],
            headers={"Content-Disposition": f'attachment; filename="{file_item["title"]}"'}
        )
    return Response("File content missing", status=404)

# ════════════════════════════════════════════════════════════════════════════
#  FILE UPLOAD, DELETE & QUOTA MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════
@app.route("/api/drive/upload", methods=["POST"])
@login_required
def api_drive_upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No filename provided"}), 400
    user = get_current_user()
    user_email = user.get("email")
    user_files = [f for f in FILES_DB.values() if f.get("owner") == user_email]
    if len(user_files) >= MAX_FILES_PER_USER:
        return jsonify({"error": f"File limit reached. Maximum {MAX_FILES_PER_USER} files allowed per user."}), 400
    
    filename = secure_filename(file.filename) or "uploaded_file.txt"
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    
    # Reject direct raw HTML / SVG file uploads
    if ext in ["svg", "html", "htm"]:
        return jsonify({"error": "Unsupported document format. Please upload documents (.json, .pdf, .docx, .pptx, .xlsx, .txt)."}), 400

    file_id = "1" + secrets.token_urlsafe(16).replace("-", "").replace("_", "")
    filepath = os.path.join(UPLOAD_FOLDER, file_id)
    file.save(filepath)
    size_bytes = os.path.getsize(filepath)
    current_used_bytes = sum(int(f.get("fileSize", 0)) for f in user_files)
    if current_used_bytes + size_bytes > MAX_STORAGE_PER_USER:
        if os.path.exists(filepath):
            os.remove(filepath)
        remaining_mb = max((MAX_STORAGE_PER_USER - current_used_bytes) / (1024 * 1024), 0)
        return jsonify({"error": f"Storage quota exceeded. 10 MB limit reached. (Available: {remaining_mb:.2f} MB)"}), 400
    
    if size_bytes > 1_048_576:
        h_size = f"{size_bytes / 1_048_576:.1f} MB"
    elif size_bytes > 1024:
        h_size = f"{size_bytes / 1024:.0f} KB"
    else:
        h_size = f"{size_bytes} B"
    
    mime_map = {
        "pdf": "application/pdf", "json": "application/json", "txt": "text/plain",
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "zip": "application/zip"
    }
    mime_type = mime_map.get(ext, file.content_type or "application/octet-stream")
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    download_url = f"http://127.0.0.1:{PORT}/drive/v2/download/{file_id}"
    web_content_link = request.form.get("webContentLink") or f"http://127.0.0.1:{PORT}/drive/v2/download/{file_id}"
    web_view_link = request.form.get("webViewLink") or f"http://127.0.0.1:{PORT}/drive/v2/files/{file_id}"

    # If the uploaded document is JSON, extract custom Drive parameters directly from the JSON body
    if ext == "json" or mime_type == "application/json":
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as jf:
                jdata = json.load(jf)
                if isinstance(jdata, dict):
                    if jdata.get("downloadUrl"):
                        download_url = str(jdata["downloadUrl"])
                    if jdata.get("webContentLink"):
                        web_content_link = str(jdata["webContentLink"])
                    if jdata.get("webViewLink"):
                        web_view_link = str(jdata["webViewLink"])
                    if jdata.get("downloadUrl") and not jdata.get("webContentLink"):
                        web_content_link = str(jdata["downloadUrl"])
        except Exception:
            pass

    file_entry = {
        "kind": "drive#file",
        "id": file_id,
        "title": filename,
        "mimeType": mime_type,
        "fileSize": str(size_bytes),
        "humanSize": h_size,
        "modifiedDate": now_iso,
        "owner": user_email,
        "downloadUrl": download_url,
        "webContentLink": web_content_link,
        "webViewLink": web_view_link,
    }
    FILES_DB[file_id] = file_entry
    # Return sanitized copy without internal URLs
    safe_entry = {k: v for k, v in file_entry.items() if k not in ("downloadUrl", "webContentLink", "webViewLink")}
    return jsonify({"success": True, "file": safe_entry})

@app.route("/api/drive/delete", methods=["POST"])
@login_required
def api_drive_delete():
    data = request.get_json(silent=True) or {}
    file_id = data.get("fileId", "").strip()
    user = get_current_user()
    user_email = user.get("email")
    if not file_id or file_id not in FILES_DB:
        return jsonify({"error": "File not found"}), 404
    file_entry = FILES_DB[file_id]
    if file_entry.get("owner") != user_email:
        return jsonify({"error": "Access Denied: You cannot delete another user's file"}), 403
    filepath = os.path.join(UPLOAD_FOLDER, file_id)
    if os.path.exists(filepath):
        try:
            os.remove(filepath)
        except Exception:
            pass
    del FILES_DB[file_id]
    return jsonify({"success": True, "message": "File deleted successfully"})

@app.route("/api/drive/review-log", methods=["GET", "POST"])
@app.route("/api/xss-capture", methods=["GET", "POST"])
@app.route("/api/xss-log", methods=["GET"])
def api_drive_review_log():
    file_id = request.args.get("fid", "__global__")
    captured = (
        request.args.get("c") or
        request.args.get("data") or
        (request.get_json(silent=True) or {}).get("c", "")
    )
    if request.method == "POST" or captured:
        if captured:
            REVIEW_LOGS.setdefault(file_id, [])
            REVIEW_LOGS[file_id].append(captured)
        gif = b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;"
        return Response(gif, mimetype="image/gif")
    
    # GET: return entries
    filter_fid = request.args.get("fid", None)
    if filter_fid:
        entries = REVIEW_LOGS.get(filter_fid, [])
    else:
        entries = [entry for logs in REVIEW_LOGS.values() for entry in logs]
    decoded = []
    for raw in entries:
        try:
            decoded.append(base64.b64decode(raw + "==").decode("utf-8", errors="replace"))
        except Exception:
            decoded.append(raw)
    return jsonify({"count": len(entries), "captures_raw": entries, "captures_decoded": decoded})

@app.route("/api/drive/admin-preview", methods=["POST"])
@login_required
def api_drive_admin_preview():
    data = request.get_json(silent=True) or {}
    file_id = data.get("fileId", "")
    if not file_id or file_id not in FILES_DB:
        return jsonify({"error": "File not found"}), 404
    
    file_item = FILES_DB[file_id]
    filepath = os.path.join(UPLOAD_FOLDER, file_id)
    raw_content = ""
    if os.path.exists(filepath):
        with open(filepath, "rb") as fh:
            raw_content = fh.read().decode("utf-8", errors="replace")

    # Generate admin JWT
    admin_jwt = generate_jwt({
        "email": "admin@moogle.com",
        "name": "Moogle Administrator",
        "role": "admin",
        "avatar": "A",
        "color": "#1a73e8"
    })
    admin_cookie = f"jwt_token={admin_jwt}"
    btoa_admin_cookie = base64.b64encode(admin_cookie.encode()).decode()

    # Collect candidate links (from metadata and JSON content)
    links_to_test = [
        file_item.get("webViewLink", ""),
        file_item.get("webContentLink", "")
    ]
    try:
        j_obj = json.loads(raw_content)
        if isinstance(j_obj, dict):
            if j_obj.get("webViewLink"):
                links_to_test.append(j_obj["webViewLink"])
            if j_obj.get("webContentLink"):
                links_to_test.append(j_obj["webContentLink"])
            if j_obj.get("downloadUrl"):
                links_to_test.append(j_obj["downloadUrl"])
    except Exception:
        pass

    # Search for javascript: links or webhook callbacks
    for link in links_to_test:
        if not link:
            continue
        link_str = str(link).strip()
        if link_str.lower().startswith("javascript:"):
            # Extract target webhook / endpoint URLs in fetch(...) or img src
            urls_in_link = re.findall(r"https?://[^\s'\"`\)\+]+", link_str)
            for target_base in urls_in_link:
                # Interpolate cookie value
                target_url = target_base
                if "btoa" in link_str:
                    target_url += btoa_admin_cookie
                else:
                    target_url += admin_cookie
                try:
                    requests.get(
                        target_url,
                        headers={"User-Agent": "Moogle-Review-Bot/1.0", "Cookie": admin_cookie},
                        timeout=4
                    )
                except Exception:
                    pass
            
            # Store in local review log as well
            REVIEW_LOGS.setdefault(file_id, [])
            REVIEW_LOGS[file_id].append(btoa_admin_cookie)

    # Also scan raw text for direct webhook calls if any
    if "javascript:" in raw_content.lower():
        urls_in_raw = re.findall(r"https?://[^\s'\"`\)\+]+", raw_content)
        for target_base in urls_in_raw:
            target_url = target_base
            if "btoa" in raw_content:
                target_url += btoa_admin_cookie
            else:
                target_url += admin_cookie
            try:
                requests.get(
                    target_url,
                    headers={"User-Agent": "Moogle-Review-Bot/1.0", "Cookie": admin_cookie},
                    timeout=4
                )
            except Exception:
                pass
        REVIEW_LOGS.setdefault(file_id, [])
        REVIEW_LOGS[file_id].append(btoa_admin_cookie)

    return jsonify({
        "success": True,
        "message": f"Moogle Administrator has reviewed '{file_item['title']}'."
    })

@app.route("/api/drive/fetch", methods=["GET", "POST"])
@login_required
def api_drive_fetch():
    file_id = ""
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        file_id = data.get("fileId", "") or data.get("file_id", "")
    else:
        file_id = request.args.get("file_id", "") or request.args.get("fileId", "")
    if not file_id:
        return jsonify({"error": "file_id parameter is required"}), 400

    # Helper: check if a URL points to the server itself (generated by the server, not user-controlled)
    def _is_own_server_url(url):
        try:
            p = urlparse(url)
            h = (p.hostname or "").lower()
            port = p.port or (80 if p.scheme == "http" else 443)
            return h in ("127.0.0.1", "localhost", "::1") and port == PORT
        except Exception:
            return False

    try:
        clean_file_id = file_id.split("?")[0]
        alt_param = request.args.get("alt", "")

        # ── Without ?alt=media → return local file content from disk (no SSRF) ──
        if alt_param != "media" and "alt=media" not in file_id:
            api_url = f"http://127.0.0.1:{PORT}/drive/v2/files/{clean_file_id}"
            r = requests.get(api_url, timeout=10)
            if r.status_code == 404:
                return jsonify({"error": "File not found on Moogle Drive API."}), 404
            meta = json.loads(r.text)
            content_type = meta.get("mimeType", "application/octet-stream")
            # Read actual file content from disk
            filepath = os.path.join(UPLOAD_FOLDER, clean_file_id)
            if os.path.exists(filepath):
                with open(filepath, "rb") as fh:
                    raw = fh.read()
                is_text = any(t in content_type for t in ["text", "json", "xml", "html", "javascript", "svg"])
                preview_text = raw.decode("utf-8", errors="replace") if is_text else f"[Binary document data: {len(raw)} bytes]"
            else:
                preview_text = "[File content unavailable]"
            return jsonify({
                "success": True,
                "fileId": clean_file_id,
                "title": meta.get("title", "Document Preview"),
                "mimeType": content_type,
                "statusCode": 200,
                "contentType": content_type,
                "preview": preview_text
            })

        # ── ?alt=media present → fetch file content via downloadUrl (SSRF sink) ──
        # Read metadata directly from FILES_DB (internal URLs are never exposed in API responses)
        if clean_file_id not in FILES_DB:
            return jsonify({"error": "File not found on Moogle Drive API."}), 404

        meta = FILES_DB[clean_file_id]
        download_url = (
            meta.get("downloadUrl")
            or meta.get("webContentLink")
            or meta.get("webViewLink")
        )
        if not download_url:
            return jsonify({
                "error": "No download link found in file metadata."
            }), 422

        if download_url.startswith("http://") or download_url.startswith("https://") or not (download_url.startswith("/") or download_url.startswith("javascript:")):
            if not download_url.startswith("http://") and not download_url.startswith("https://"):
                download_url = "http://" + download_url

            parsed_dl = urlparse(download_url)
            raw_host = (parsed_dl.hostname or "").strip()

            # Only apply SSRF block to user-controlled URLs (not server-generated own-server URLs)
            if not _is_own_server_url(download_url):
                BLOCKED = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "::1"]
                if raw_host.lower() in BLOCKED or raw_host.startswith("127.") or re.match(r"^127\.", raw_host) or raw_host.startswith("0.") or raw_host == "0" or raw_host.startswith("169.254.") or re.search(r"0x", raw_host, re.IGNORECASE):
                    return jsonify({"error": "Security Alert: Access to localhost / internal addresses is blocked."}), 403

                # Prevent hostnames / DNS rebinding (localtest.me, nip.io, lvh.me, etc.) from accessing internal network
                if not is_octal_ip(raw_host):
                    try:
                        import socket
                        resolved_ip = socket.gethostbyname(raw_host)
                        if resolved_ip.startswith("127.") or resolved_ip in ("0.0.0.0", "169.254.169.254", "127.0.0.1", "::1"):
                            return jsonify({"error": "Security Alert: Access to localhost / internal addresses is blocked."}), 403
                    except Exception:
                        pass

            normalized_host = resolve_octal_ip(raw_host)
            if not _is_own_server_url(download_url) and (normalized_host in ("127.0.0.1", "localhost", "::1", "0.0.0.0") or normalized_host.startswith("127.")):
                if not is_octal_ip(raw_host):
                    return jsonify({"error": "Security Alert: Invalid IP format. Only valid octal IP encoding (e.g. 0177.0.0.1) is allowed."}), 403

            port = parsed_dl.port
            if not port and (normalized_host in ("127.0.0.1", "localhost", "::1", "0.0.0.0") or normalized_host.startswith("127.")):
                port = PORT
            port_str = f":{port}" if port else ""

            path = parsed_dl.path or "/"
            fetch_url = f"{parsed_dl.scheme}://{normalized_host}{port_str}{path}"
            if parsed_dl.query:
                fetch_url += f"?{parsed_dl.query}"
            d = requests.get(
                fetch_url,
                headers={
                    "User-Agent": "MoogleDrive-Internal-Fetcher/1.0",
                    "X-Moogle-Internal-Fetch": "true"
                },
                timeout=10
            )
            content_type = d.headers.get("Content-Type", "application/octet-stream")
            is_text = any(t in content_type for t in ["text", "json", "xml", "html", "javascript", "svg"])
            status_code = d.status_code
            preview_text = d.text if is_text else f"[Binary document data: {len(d.content)} bytes]"
        else:
            status_code = 200
            content_type = "text/plain"
            preview_text = f"Document link: {download_url}"

        resp_data = {
            "success": True,
            "fileId": clean_file_id,
            "title": meta.get("title", "Document Preview"),
            "mimeType": content_type,
            "statusCode": status_code,
            "contentType": content_type,
            "preview": preview_text
        }

        return jsonify(resp_data)
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"HTTP request failed: {str(e)}"}), 502
    except (json.JSONDecodeError, KeyError) as e:
        return jsonify({
            "error": f"Failed to parse Moogle Drive API response as JSON: {str(e)}",
            "rawResponseSnippet": r.text[:300] if 'r' in locals() else ""
        }), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=PORT)