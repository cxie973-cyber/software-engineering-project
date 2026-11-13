"""投稿審查系統。Python 標準函式庫 + SQLite，不需 pip install。"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from http.cookies import SimpleCookie
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import webbrowser

ROOT = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("SUBMISSION_DB", str(ROOT / "data" / "submissions.sqlite3")))
HOST, PORT = "127.0.0.1", int(os.environ.get("SUBMISSION_PORT", "8765"))
CATEGORIES = ("校園生活", "科技新知", "文學創作", "學習心得")
ATTEMPTS = {}
ATTEMPTS_LOCK = threading.Lock()

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
 password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('author','editor')));
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 csrf TEXT NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS manuscripts (
 id TEXT PRIMARY KEY, author_id TEXT NOT NULL REFERENCES users(id),
 category TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('draft','review','approved')),
 version INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, manuscript_id TEXT NOT NULL REFERENCES manuscripts(id) ON DELETE CASCADE,
 actor_id TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL, note TEXT NOT NULL DEFAULT '',
 title TEXT NOT NULL, content TEXT NOT NULL, category TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_manuscripts_author ON manuscripts(author_id);
CREATE INDEX IF NOT EXISTS idx_manuscripts_status ON manuscripts(status);
CREATE INDEX IF NOT EXISTS idx_history_manuscript ON history(manuscript_id);
"""


def connect():
    db = sqlite3.connect(DB_PATH, timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def stamp():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210000).hex()
    return salt + ":" + digest


def verify_password(password, saved):
    return hmac.compare_digest(password_hash(password, saved.split(":")[0]), saved)


def public_user(row):
    return {key: row[key] for key in ("id", "username", "name", "role")}


def add_history(db, m, actor, action, note=""):
    db.execute("INSERT INTO history(manuscript_id,actor_id,action,note,title,content,category,created_at) VALUES(?,?,?,?,?,?,?,?)",
               (m["id"], actor, action, note, m["title"], m["content"], m["category"], stamp()))


def initialize():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript(SCHEMA)
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return
        users = [("author-1", "author", "王小明", "author"),
                 ("author-2", "author2", "林小雨", "author"),
                 ("editor-1", "editor", "陳編輯", "editor")]
        for uid, username, name, role in users:
            db.execute("INSERT INTO users VALUES(?,?,?,?,?)", (uid, username, name, password_hash("Demo1234!"), role))
        examples = [
            ("author-1", "校園生活", "在校園裡，找到自己的閱讀角落", "draft", "午休時，圖書館是我最常去的地方。\n\n靠窗的座位、安靜的走廊，還有午後灑進來的陽光，讓閱讀變成一天中值得期待的事。\n\n這篇文章記錄我走訪校園幾個角落的觀察，也想邀請同學分享自己的閱讀地點。"),
            ("author-1", "科技新知", "數位筆記，如何改變我的學習方式", "review", "過去，我把課堂筆記分散在不同的紙本筆記本中。準備考試時，常常花很多時間尋找同一個主題。\n\n這學期開始，我嘗試以課程和主題整理數位筆記，記錄每次複習時遇到的問題。\n\n工具本身並不會自動改善學習。真正有幫助的是，每週固定回顧內容，並用自己的話重新整理。"),
            ("author-1", "學習心得", "第一個個人專題教會我的事", "approved", "我從一張功能清單開始，把投稿流程拆成新增、編輯、送出與審查。\n\n實作過程中，我發現狀態與權限必須一起考慮。例如稿件送出後，作者應該暫時無法修改。\n\n完成專題後，我更了解如何把需求變成可操作、可測試的功能。"),
            ("author-2", "文學創作", "午後的街道，和一場沒有下完的雨", "review", "雨停在屋簷的邊緣，遲遲沒有落下。\n\n我站在騎樓下，看著人們把傘收起，又重新撐開。街道在水光裡安靜了一會兒，連腳步聲也變得柔軟。\n\n等到公車轉過街角，我才發現，手裡那杯咖啡早已不再燙手。"),
        ]
        for author, category, title, status, content in examples:
            mid, now = secrets.token_hex(12), stamp()
            db.execute("INSERT INTO manuscripts VALUES(?,?,?,?,?,?,?,?,?)", (mid, author, category, title, content, status, 1, now, now))
            m = db.execute("SELECT * FROM manuscripts WHERE id=?", (mid,)).fetchone()
            add_history(db, m, author, "create")
            if status != "draft":
                add_history(db, m, author, "submit")
            if status == "approved":
                add_history(db, m, "editor-1", "approve", "結構完整，內容清楚，同意刊登。")


class ApiError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message


class Handler(BaseHTTPRequestHandler):
    server_version = "SubmissionLab/1.0"

    def log_message(self, fmt, *args):
        # Do not log request bodies, cookies or credentials.
        print(f"[{self.log_date_time_string()}] {fmt % args}")

    def send(self, code, body, content_type="application/json; charset=utf-8", cookie=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def body(self):
        if not self.headers.get("Content-Type", "").startswith("application/json"):
            raise ApiError(415, "請使用 JSON 格式。")
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 200000:
                raise ApiError(413, "請求大小不正確。")
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ValueError()
            return data
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "無效的 JSON 內容。")

    def session(self, db):
        cookies = SimpleCookie()
        try:
            cookies.load(self.headers.get("Cookie", ""))
            token = cookies["submission_session"].value
        except (KeyError, Exception):
            raise ApiError(401, "請先登入。")
        digest = hashlib.sha256(token.encode()).hexdigest()
        row = db.execute("SELECT u.*,s.csrf FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires>?", (digest, int(time.time()))).fetchone()
        if not row:
            raise ApiError(401, "登入已過期，請重新登入。")
        return row, digest

    def origin_check(self):
        origin = self.headers.get("Origin")
        if origin and origin != f"http://{self.headers.get('Host')}":
            raise ApiError(403, "不允許跨網站操作。")

    def manuscript(self, db, mid, user):
        row = db.execute("SELECT m.*,u.name author_name FROM manuscripts m JOIN users u ON m.author_id=u.id WHERE m.id=?", (mid,)).fetchone()
        if not row or (user["role"] == "author" and row["author_id"] != user["id"]):
            raise ApiError(404, "找不到稿件。")
        return row

    def fields(self, data):
        vals = [data.get(k) for k in ("category", "title", "content")]
        if not all(isinstance(v, str) for v in vals):
            raise ApiError(400, "請填寫類別、標題與內容。")
        category, title, content = [v.strip() for v in vals]
        if category not in CATEGORIES or not 1 <= len(title) <= 100 or not 1 <= len(content) <= 20000:
            raise ApiError(400, "標題限 1–100 字、內容限 1–20000 字，並請選擇有效類別。")
        return category, title, content

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_PUT(self):
        self.handle_request("PUT")

    def do_DELETE(self):
        self.handle_request("DELETE")

    def handle_request(self, method):
        try:
            path = urlparse(self.path).path
            if not path.startswith("/api/"):
                if method != "GET":
                    raise ApiError(405, "不支援的操作。")
                files = {"/": ("index.html", "text/html"), "/index.html": ("index.html", "text/html"),
                         "/style.css": ("style.css", "text/css"), "/app.js": ("app.js", "text/javascript")}
                if path not in files:
                    raise ApiError(404, "找不到頁面。")
                filename, mime = files[path]
                return self.send(200, (ROOT / "static" / filename).read_bytes(), mime + "; charset=utf-8")
            if method == "GET" and path == "/api/health":
                return self.send(200, {"ok": True, "storage": "SQLite"})
            if method != "GET":
                self.origin_check()
            with connect() as db:
                if method == "POST" and path in ("/api/login", "/api/register"):
                    data = self.body()
                    username, password = data.get("username", ""), data.get("password", "")
                    if not isinstance(username, str) or not 1 <= len(username.strip()) <= 40:
                        raise ApiError(400, "帳號需填寫 1–40 個字元。")
                    if not isinstance(password, str) or not 1 <= len(password) <= 200:
                        raise ApiError(400, "密碼需填寫 1–200 個字元。")
                    username = username.strip().lower()
                    ip = self.client_address[0]
                    with ATTEMPTS_LOCK:
                        failures = ATTEMPTS.get(ip, [])
                        failures = [t for t in failures if time.time() - t < 300]
                        ATTEMPTS[ip] = failures
                        if len(failures) >= 8:
                            raise ApiError(429, "嘗試次數過多，請五分鐘後再試。")
                    if path == "/api/register":
                        name = data.get("name", "")
                        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 30:
                            raise ApiError(400, "姓名需填寫 1–30 個字，可以使用中文。")
                        simple_account = re.fullmatch(r"[a-z0-9_-]+", username)
                        email_account = re.fullmatch(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", username)
                        if not 3 <= len(username) <= 40 or not (simple_account or email_account):
                            raise ApiError(400, "帳號需 3–40 個半形英數、底線、連字號，或使用電子郵件地址。")
                        if len(password) < 8:
                            raise ApiError(400, "建立帳號的密碼至少需要 8 個字元，不要求特定符號。")
                        try:
                            # Registration always creates authors; clients cannot assign editor privileges.
                            db.execute("INSERT INTO users VALUES(?,?,?,?,?)", (secrets.token_hex(12), username, name.strip(), password_hash(password), "author"))
                        except sqlite3.IntegrityError:
                            raise ApiError(409, "這個帳號已被使用；若是你建立的帳號，請切換到登入。")
                    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                    dummy = "0" * 32 + ":" + "0" * 64
                    valid = verify_password(password, row["password_hash"] if row else dummy)
                    if not row or not valid:
                        with ATTEMPTS_LOCK:
                            ATTEMPTS[ip].append(time.time())
                        raise ApiError(401, "帳號或密碼不正確。")
                    with ATTEMPTS_LOCK:
                        ATTEMPTS.pop(ip, None)
                    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
                    db.execute("DELETE FROM sessions WHERE expires<?", (int(time.time()),))
                    db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), row["id"], csrf, int(time.time()) + 28800))
                    db.commit()
                    return self.send(200, {"user": public_user(row), "csrf": csrf}, cookie=f"submission_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800")
                user, digest = self.session(db)
                if method == "GET" and path == "/api/me":
                    return self.send(200, {"user": public_user(user), "csrf": user["csrf"]})
                if method != "GET" and not hmac.compare_digest(self.headers.get("X-CSRF-Token", ""), user["csrf"]):
                    raise ApiError(403, "驗證已過期，請重新登入。")
                if method == "POST" and path == "/api/logout":
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                    db.commit()
                    return self.send(200, {"ok": True}, cookie="submission_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                if method == "GET" and path in ("/api/manuscripts", "/api/export"):
                    where, params = (" WHERE m.author_id=?", (user["id"],)) if user["role"] == "author" else ("", ())
                    rows = [dict(r) for r in db.execute("SELECT m.*,u.name author_name FROM manuscripts m JOIN users u ON m.author_id=u.id" + where + " ORDER BY m.updated_at DESC,m.id", params)]
                    if path == "/api/export":
                        out = io.StringIO()
                        writer = csv.writer(out)
                        writer.writerow(["標題", "作者", "類別", "狀態", "更新時間"])
                        for r in rows:
                            values = [r["title"], r["author_name"], r["category"], {"draft":"編輯中", "review":"審查中", "approved":"已通過"}[r["status"]], r["updated_at"]]
                            writer.writerow(["'" + v if v.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else v for v in values])
                        return self.send(200, "\ufeff" + out.getvalue(), "text/csv; charset=utf-8")
                    return self.send(200, {"items": rows})
                if method == "POST" and path == "/api/manuscripts":
                    if user["role"] != "author":
                        raise ApiError(403, "只有作者可以新增稿件。")
                    data = self.body()
                    category, title, content = self.fields(data)
                    mid, now = secrets.token_hex(12), stamp()
                    db.execute("INSERT INTO manuscripts VALUES(?,?,?,?,?,?,?,?,?)", (mid, user["id"], category, title, content, "draft", 1, now, now))
                    m = self.manuscript(db, mid, user)
                    add_history(db, m, user["id"], "create")
                    db.commit()
                    return self.send(201, {"item": dict(m)})
                parts = path.strip("/").split("/")
                if len(parts) not in (3, 4) or parts[:2] != ["api", "manuscripts"]:
                    raise ApiError(404, "找不到此 API。")
                mid = parts[2]
                if method == "GET" and len(parts) == 3:
                    m = self.manuscript(db, mid, user)
                    history = [dict(r) for r in db.execute("SELECT h.*,u.name actor_name FROM history h JOIN users u ON h.actor_id=u.id WHERE h.manuscript_id=? ORDER BY h.id DESC", (mid,))]
                    return self.send(200, {"item": dict(m), "history": history})
                # Serialize writes. Status, owner and revision are rechecked inside the transaction.
                db.execute("BEGIN IMMEDIATE")
                m = self.manuscript(db, mid, user)
                data = self.body()
                if type(data.get("version")) is not int or data["version"] != m["version"]:
                    raise ApiError(409, "稿件已被更新，請關閉並重新開啟後再操作。")
                own_draft = user["role"] == "author" and m["author_id"] == user["id"] and m["status"] == "draft"
                action = parts[3] if len(parts) == 4 else ""
                note = ""
                if method == "PUT" and not action:
                    if not own_draft:
                        raise ApiError(403, "只能修改自己的編輯中稿件。")
                    category, title, content = self.fields(data)
                    db.execute("UPDATE manuscripts SET category=?,title=?,content=?,version=version+1,updated_at=? WHERE id=?", (category, title, content, stamp(), mid))
                    event = "save"
                elif method == "DELETE" and not action:
                    if not own_draft:
                        raise ApiError(403, "只能刪除自己的編輯中稿件。")
                    db.execute("DELETE FROM manuscripts WHERE id=?", (mid,))
                    db.commit()
                    return self.send(200, {"ok": True})
                elif method == "POST" and action == "submit":
                    if not own_draft:
                        raise ApiError(403, "只能送出自己的編輯中稿件。")
                    db.execute("UPDATE manuscripts SET status='review',version=version+1,updated_at=? WHERE id=?", (stamp(), mid))
                    event = "submit"
                elif method == "POST" and action == "review":
                    if user["role"] != "editor" or m["status"] != "review":
                        raise ApiError(403, "只有編輯可以處理審查中的稿件。")
                    decision, note = data.get("decision"), data.get("note", "")
                    if decision not in ("approve", "return") or not isinstance(note, str) or len(note.strip()) > 2000:
                        raise ApiError(400, "審查選項無效，或意見超過 2000 字。")
                    note = note.strip()
                    if decision == "return" and not note:
                        raise ApiError(400, "退回時請填寫修改建議。")
                    status = "approved" if decision == "approve" else "draft"
                    db.execute("UPDATE manuscripts SET status=?,version=version+1,updated_at=? WHERE id=?", (status, stamp(), mid))
                    event = decision
                else:
                    raise ApiError(405, "不支援的操作。")
                m = self.manuscript(db, mid, user)
                add_history(db, m, user["id"], event, note)
                db.commit()
                return self.send(200, {"item": dict(m)})
        except ApiError as e:
            self.send(e.status, {"error": e.message})
        except Exception as e:
            print("Server error:", type(e).__name__)
            self.send(500, {"error": "伺服器暫時無法處理，請稍後再試。"})


if __name__ == "__main__":
    initialize()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"投稿審查系統：http://{HOST}:{PORT}")
    print("示範帳號：author / author2 / editor；密碼皆為 Demo1234!")
    print("按 Ctrl+C 關閉。資料保存在 data/submissions.sqlite3。")
    if os.environ.get("SUBMISSION_NO_BROWSER") != "1":
        threading.Timer(0.7, lambda: webbrowser.open(f"http://{HOST}:{PORT}")).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
