import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(APP_DIR / "data")))
UPLOAD_DIR = DATA_DIR / "uploads"
DB_PATH = DATA_DIR / "library.db"
STATIC_DIR = APP_DIR / "static"
MAX_FILE_SIZE = 50 * 1024 * 1024

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="Nangarhar University Digital Library", version="2.0.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "CHANGE_THIS_SECRET_BEFORE_DEPLOYMENT"),
    same_site="lax",
    https_only=os.getenv("COOKIE_SECURE", "false").lower() == "true",
    max_age=60 * 60 * 24 * 7,
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def db():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 240_000)
    return salt.hex() + "$" + digest.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        test = hash_password(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
        return hmac.compare_digest(test, digest_hex)
    except (ValueError, TypeError):
        return False


def initialize_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );
        CREATE TABLE IF NOT EXISTS books (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            author TEXT NOT NULL DEFAULT '',
            department TEXT NOT NULL DEFAULT '',
            category_id INTEGER,
            description TEXT NOT NULL DEFAULT '',
            tags TEXT NOT NULL DEFAULT '',
            stored_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            uploader_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            downloads INTEGER NOT NULL DEFAULT 0,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE SET NULL,
            FOREIGN KEY(uploader_id) REFERENCES users(id) ON DELETE SET NULL
        );
        CREATE TABLE IF NOT EXISTS favorites (
            user_id INTEGER NOT NULL,
            book_id INTEGER NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY(user_id, book_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(book_id) REFERENCES books(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_books_status ON books(status);
        CREATE INDEX IF NOT EXISTS idx_books_title ON books(title);
        """)
        for name in ["جیولوجي او معدن", "طب", "انجنیري", "کرنه", "ښوونه او روزنه", "اقتصاد", "کمپیوټر ساینس", "نور"]:
            conn.execute("INSERT OR IGNORE INTO categories(name) VALUES (?)", (name,))
        admin_user = os.getenv("ADMIN_USERNAME", "").strip()
        admin_pass = os.getenv("ADMIN_PASSWORD", "")
        if admin_user and admin_pass:
            exists = conn.execute("SELECT id FROM users WHERE username=?", (admin_user,)).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO users(username, full_name, password_hash, role) VALUES(?,?,?,?)",
                    (admin_user, "Library Administrator", hash_password(admin_pass), "admin")
                )


initialize_db()


def clean(value: str, limit: int) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())[:limit]


def current_user(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        return None
    with db() as conn:
        row = conn.execute("SELECT id, username, full_name, role FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="د دې کار لپاره لومړی خپل حساب ته ننوځئ.")
    return user


def require_admin(request: Request):
    user = require_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="یوازې مدیر دا کار ترسره کولی شي.")
    return user


@app.get("/", response_class=HTMLResponse)
def home():
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/me")
def me(request: Request):
    return {"user": current_user(request)}


@app.post("/api/register")
def register(request: Request, username: str = Form(...), full_name: str = Form(...), password: str = Form(...)):
    username = clean(username, 40).lower()
    full_name = clean(full_name, 100)
    if not re.fullmatch(r"[a-z0-9_.-]{3,40}", username):
        raise HTTPException(400, "د کارن نوم باید ۳ تر ۴۰ تورو وي؛ انګلیسي توري او شمېرې وکاروئ.")
    if len(full_name) < 2:
        raise HTTPException(400, "بشپړ نوم ولیکئ.")
    if len(password) < 8:
        raise HTTPException(400, "پټ نوم باید لږ تر لږه ۸ توري ولري.")
    with db() as conn:
        if conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            raise HTTPException(409, "دا کارن نوم له مخکې کارول شوی.")
        cur = conn.execute(
            "INSERT INTO users(username, full_name, password_hash) VALUES(?,?,?)",
            (username, full_name, hash_password(password))
        )
        request.session.clear()
        request.session["user_id"] = cur.lastrowid
    return {"message": "حساب مو جوړ شو.", "user": current_user(request)}


@app.post("/api/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    username = clean(username, 40).lower()
    with db() as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        raise HTTPException(401, "د کارن نوم یا پټ نوم ناسم دی.")
    request.session.clear()
    request.session["user_id"] = user["id"]
    return {"message": "په بریالیتوب داخل شوئ.", "user": current_user(request)}


@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"message": "له حسابه ووتلئ."}


@app.get("/api/categories")
def categories():
    with db() as conn:
        return [dict(r) for r in conn.execute("SELECT id, name FROM categories ORDER BY name").fetchall()]


@app.get("/api/books")
def books(
    request: Request,
    search: str = "",
    category_id: int = 0,
    department: str = "",
    sort: str = "newest",
    page: int = 1,
    limit: int = 12,
    mine: bool = False,
):
    page = max(1, page)
    limit = min(30, max(1, limit))
    user = current_user(request) if request else None
    clauses = ["b.status='approved'"]
    params = []
    if search.strip():
        term = "%" + clean(search, 120) + "%"
        clauses.append("(b.title LIKE ? OR b.author LIKE ? OR b.department LIKE ? OR b.description LIKE ? OR b.tags LIKE ?)")
        params.extend([term] * 5)
    if category_id:
        clauses.append("b.category_id=?")
        params.append(category_id)
    if department.strip():
        clauses.append("b.department LIKE ?")
        params.append("%" + clean(department, 100) + "%")
    if mine:
        if not user:
            raise HTTPException(401, "خپل حساب ته داخل شئ.")
        clauses.append("b.uploader_id=?")
        params.append(user["id"])
    order = {"oldest": "b.id ASC", "popular": "b.downloads DESC, b.id DESC", "title": "b.title COLLATE NOCASE ASC"}.get(sort, "b.id DESC")
    where = " AND ".join(clauses)
    with db() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM books b WHERE {where}", params).fetchone()[0]
        rows = conn.execute(f"""
            SELECT b.id,b.title,b.author,b.department,b.description,b.tags,b.file_size,
                   b.downloads,b.uploaded_at,c.name AS category,
                   CASE WHEN f.user_id IS NULL THEN 0 ELSE 1 END AS is_favorite
            FROM books b
            LEFT JOIN categories c ON c.id=b.category_id
            LEFT JOIN favorites f ON f.book_id=b.id AND f.user_id=?
            WHERE {where}
            ORDER BY {order}
            LIMIT ? OFFSET ?
        """, [user["id"] if user else -1] + params + [limit, (page-1)*limit]).fetchall()
    return {"items": [dict(r) for r in rows], "total": total, "page": page, "pages": max(1, (total+limit-1)//limit)}


@app.post("/api/books")
async def upload_book(
    request: Request,
    title: str = Form(...),
    author: str = Form(""),
    department: str = Form(""),
    category_id: int = Form(0),
    description: str = Form(""),
    tags: str = Form(""),
    file: UploadFile = File(...),
):
    user = require_user(request)
    title = clean(title, 200)
    if not title:
        raise HTTPException(400, "د کتاب نوم اړین دی.")
    original = Path(file.filename or "").name
    if Path(original).suffix.lower() != ".pdf":
        raise HTTPException(400, "یوازې PDF فایلونه منل کېږي.")
    content = await file.read(MAX_FILE_SIZE + 1)
    if not content or len(content) > MAX_FILE_SIZE:
        raise HTTPException(413, "فایل تش دی یا له 50MB څخه لوی دی.")
    if not content.startswith(b"%PDF-"):
        raise HTTPException(400, "دا معتبر PDF فایل نه ښکاري.")
    stored = uuid4().hex + ".pdf"
    (UPLOAD_DIR / stored).write_bytes(content)
    with db() as conn:
        if category_id and not conn.execute("SELECT id FROM categories WHERE id=?", (category_id,)).fetchone():
            (UPLOAD_DIR / stored).unlink(missing_ok=True)
            raise HTTPException(400, "ټاکل شوې ډله موجوده نه ده.")
        cur = conn.execute("""
            INSERT INTO books(title,author,department,category_id,description,tags,stored_name,original_name,file_size,uploader_id,status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?)
        """, (
            title, clean(author,150), clean(department,150), category_id or None,
            clean(description,1000), clean(tags,250), stored, original, len(content), user["id"], "pending"
        ))
        book_id = cur.lastrowid
    return {"message": "کتاب پورته شو او د مدیر تایید ته ولېږل شو.", "id": book_id}


@app.get("/api/my-books")
def my_books(request: Request):
    user = require_user(request)
    with db() as conn:
        rows = conn.execute("""
            SELECT id,title,author,department,status,downloads,uploaded_at
            FROM books WHERE uploader_id=? ORDER BY id DESC
        """, (user["id"],)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/books/{book_id}/favorite")
def toggle_favorite(book_id: int, request: Request):
    user = require_user(request)
    with db() as conn:
        book = conn.execute("SELECT id FROM books WHERE id=? AND status='approved'", (book_id,)).fetchone()
        if not book:
            raise HTTPException(404, "کتاب ونه موندل شو.")
        exists = conn.execute("SELECT 1 FROM favorites WHERE user_id=? AND book_id=?", (user["id"], book_id)).fetchone()
        if exists:
            conn.execute("DELETE FROM favorites WHERE user_id=? AND book_id=?", (user["id"], book_id))
            return {"favorite": False}
        conn.execute("INSERT INTO favorites(user_id,book_id) VALUES(?,?)", (user["id"], book_id))
        return {"favorite": True}


@app.get("/api/favorites")
def favorites(request: Request):
    user = require_user(request)
    with db() as conn:
        rows = conn.execute("""
            SELECT b.id,b.title,b.author,b.department,b.description,b.tags,b.file_size,b.downloads,
                   b.uploaded_at,c.name AS category,1 AS is_favorite
            FROM favorites f JOIN books b ON b.id=f.book_id
            LEFT JOIN categories c ON c.id=b.category_id
            WHERE f.user_id=? AND b.status='approved' ORDER BY f.created_at DESC
        """, (user["id"],)).fetchall()
    return {"items": [dict(r) for r in rows], "total": len(rows), "page": 1, "pages": 1}


@app.get("/api/books/{book_id}/download")
def download(book_id: int):
    with db() as conn:
        row = conn.execute("SELECT stored_name,original_name FROM books WHERE id=? AND status='approved'", (book_id,)).fetchone()
        if not row:
            raise HTTPException(404, "کتاب ونه موندل شو یا لا تر اوسه تایید شوی نه دی.")
        path = UPLOAD_DIR / row["stored_name"]
        if not path.is_file():
            raise HTTPException(404, "د PDF فایل په سرور کې نشته.")
        conn.execute("UPDATE books SET downloads=downloads+1 WHERE id=?", (book_id,))
    return FileResponse(path, media_type="application/pdf", filename=row["original_name"])


@app.get("/api/public-stats")
def public_stats():
    with db() as conn:
        return {
            "books": conn.execute("SELECT COUNT(*) FROM books WHERE status='approved'").fetchone()[0],
            "downloads": conn.execute("SELECT COALESCE(SUM(downloads),0) FROM books WHERE status='approved'").fetchone()[0],
        }


@app.get("/api/admin/stats")
def admin_stats(request: Request):
    require_admin(request)
    with db() as conn:
        return {
            "books": conn.execute("SELECT COUNT(*) FROM books").fetchone()[0],
            "pending": conn.execute("SELECT COUNT(*) FROM books WHERE status='pending'").fetchone()[0],
            "users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "downloads": conn.execute("SELECT COALESCE(SUM(downloads),0) FROM books").fetchone()[0],
        }


@app.get("/api/admin/books")
def admin_books(request: Request, status: str = "pending"):
    require_admin(request)
    if status not in ("pending", "approved", "rejected"):
        raise HTTPException(400, "ناسم حالت.")
    with db() as conn:
        rows = conn.execute("""
            SELECT b.id,b.title,b.author,b.department,b.description,b.file_size,b.status,b.uploaded_at,
                   u.full_name AS uploader
            FROM books b LEFT JOIN users u ON u.id=b.uploader_id
            WHERE b.status=? ORDER BY b.id DESC
        """, (status,)).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/books/{book_id}/approve")
def approve_book(book_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        cur = conn.execute("UPDATE books SET status='approved' WHERE id=? AND status='pending'", (book_id,))
        if not cur.rowcount:
            raise HTTPException(404, "کتاب د تایید لپاره ونه موندل شو.")
    return {"message": "کتاب تایید او خپور شو."}


@app.post("/api/admin/books/{book_id}/reject")
def reject_book(book_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        cur = conn.execute("UPDATE books SET status='rejected' WHERE id=? AND status='pending'", (book_id,))
        if not cur.rowcount:
            raise HTTPException(404, "کتاب ونه موندل شو.")
    return {"message": "کتاب رد شو."}


@app.delete("/api/admin/books/{book_id}")
def delete_book(book_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        row = conn.execute("SELECT stored_name FROM books WHERE id=?", (book_id,)).fetchone()
        if not row:
            raise HTTPException(404, "کتاب ونه موندل شو.")
        conn.execute("DELETE FROM books WHERE id=?", (book_id,))
    (UPLOAD_DIR / row["stored_name"]).unlink(missing_ok=True)
    return {"message": "کتاب حذف شو."}


@app.post("/api/admin/categories")
def add_category(request: Request, name: str = Form(...)):
    require_admin(request)
    name = clean(name, 100)
    if not name:
        raise HTTPException(400, "د ډلې نوم ولیکئ.")
    try:
        with db() as conn:
            conn.execute("INSERT INTO categories(name) VALUES(?)", (name,))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "دا ډله له مخکې شته.")
    return {"message": "ډله اضافه شوه."}


@app.delete("/api/admin/categories/{category_id}")
def delete_category(category_id: int, request: Request):
    require_admin(request)
    with db() as conn:
        cur = conn.execute("DELETE FROM categories WHERE id=?", (category_id,))
        if not cur.rowcount:
            raise HTTPException(404, "ډله ونه موندل شوه.")
    return {"message": "ډله حذف شوه."}


@app.get("/health")
def health():
    return {"status": "ok"}
