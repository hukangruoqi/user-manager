import sqlite3
import os
import re
import uuid
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "users.db")


def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户（密码已哈希）"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            balance INTEGER
        )
    """)
    # 兼容旧数据库：若 balance 列不存在则添加
    try:
        c.execute("ALTER TABLE users ADD COLUMN balance INTEGER")
    except sqlite3.OperationalError:
        pass

    # 插入默认用户（密码已哈希），INSERT OR IGNORE 防止重复
    admin_pw = generate_password_hash("admin123")
    alice_pw = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ('admin', admin_pw, 'admin@example.com', '13800138000', 1000))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)",
              ('alice', alice_pw, 'alice@example.com', '13900139001', 100))
    # 迁移：若旧数据库中密码还是明文，则更新为哈希值
    c.execute("UPDATE users SET password = ? WHERE username = ? AND password = ?",
              (admin_pw, 'admin', 'admin123'))
    c.execute("UPDATE users SET password = ? WHERE username = ? AND password = ?",
              (alice_pw, 'alice', 'alice2025'))
    # 兼容旧数据库：若 balance 为 NULL（从旧表迁移过来的数据），设置初始余额
    c.execute("UPDATE users SET balance = 1000 WHERE username = 'admin' AND balance IS NULL")
    c.execute("UPDATE users SET balance = 100 WHERE username = 'alice' AND balance IS NULL")
    conn.commit()
    conn.close()
    print("[init_db] 数据库初始化完成")


def get_user_by_username(username):
    """根据用户名查询用户（参数化查询，防止 SQL 注入）"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sql = "SELECT * FROM users WHERE username = ?"
    print(f"[SQL] {sql} 参数: username='{username}'")
    c.execute(sql, (username,))
    row = c.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None


def search_users(keyword):
    """根据关键词搜索用户（参数化查询，防止 SQL 注入，仅返回脱敏数据）"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f'%{keyword}%'
    print(f"[SQL] {sql} 参数: like='%{keyword}%'")
    c.execute(sql, (like_pattern, like_pattern))
    rows = c.fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        # 手机号脱敏
        if d.get("phone") and len(d["phone"]) == 11:
            d["phone"] = d["phone"][:3] + "****" + d["phone"][-4:]
        # 邮箱脱敏
        if d.get("email") and "@" in d["email"]:
            parts = d["email"].split("@")
            if len(parts[0]) >= 2:
                d["email"] = parts[0][0] + "***" + parts[0][-1] + "@" + parts[1]
            else:
                d["email"] = parts[0][0] + "***@" + parts[1]
        result.append(d)
    return result


@app.route("/")
def index():
    username = session.get("username")
    user = None
    results = None
    keyword = request.args.get("keyword", "")

    if username:
        user = get_user_by_username(username)

    if keyword:
        results = search_users(keyword)

    return render_template("index.html", user=user, results=results, keyword=keyword)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_user_by_username(username)
        # 使用 check_password_hash 比对密码哈希
        if user and check_password_hash(user["password"], password):
            session["username"] = username
            return redirect("/")
        else:
            error = "用户名或密码错误"
    success_msg = request.args.get("success", "")
    return render_template("login.html", error=error, success=success_msg)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        if not username or not password:
            error = "用户名和密码不能为空"
        elif email and not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            error = "邮箱格式不正确"
        elif phone and not re.match(r'^1\d{10}$', phone):
            error = "手机号格式不正确（需为11位数字，以1开头）"
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                c = conn.cursor()
                hashed_pw = generate_password_hash(password)
                sql = "INSERT INTO users (username, password, email, phone, balance) VALUES (?, ?, ?, ?, ?)"
                print(f"[SQL] {sql} 参数: username='{username}', email='{email}', phone='{phone}'")
                c.execute(sql, (username, hashed_pw, email, phone, 0))
                conn.commit()
                conn.close()
                return redirect("/login?success=注册成功，请登录")
            except sqlite3.IntegrityError:
                error = "用户名已存在"
    return render_template("register.html", error=error)


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    if not keyword:
        return redirect("/")
    results = search_users(keyword)

    username = session.get("username")
    user = get_user_by_username(username) if username else None

    return render_template("index.html", user=user, results=results, keyword=keyword)


@app.route("/change-password", methods=["POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    old_pw = request.form.get("old_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")
    user = get_user_by_username(username)

    if not user:
        return redirect("/")

    # 使用 check_password_hash 比对旧密码
    if not check_password_hash(user["password"], old_pw):
        return render_template("index.html", user=user, pw_error="旧密码错误")

    if new_pw != confirm_pw:
        return render_template("index.html", user=user, pw_error="两次新密码输入不一致")

    if len(new_pw) < 6:
        return render_template("index.html", user=user, pw_error="新密码长度至少6位")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    hashed_pw = generate_password_hash(new_pw)
    sql = "UPDATE users SET password = ? WHERE username = ?"
    print(f"[SQL] {sql} 参数: username='{username}'")
    c.execute(sql, (hashed_pw, username))
    conn.commit()
    conn.close()

    user = get_user_by_username(username)
    return render_template("index.html", user=user, pw_success="密码修改成功")


@app.route("/profile")
def profile():
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_id = request.args.get("user_id")
    if not user_id:
        return redirect("/")

    current_user = get_user_by_username(username)
    # 只能查看自己的个人中心
    if str(current_user["id"]) != str(user_id):
        return render_template("profile.html", error="无权访问其他用户的个人信息")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return render_template("profile.html", error="用户不存在")

    user = dict(row)
    return render_template("profile.html", user=user)


@app.route("/recharge", methods=["POST"])
def recharge():
    username = session.get("username")
    if not username:
        return redirect("/login")

    user_id = request.form.get("user_id")
    amount_str = request.form.get("amount", "0")

    current_user = get_user_by_username(username)
    if not current_user:
        return redirect("/login")

    # 只能给自己充值
    if str(current_user["id"]) != str(user_id):
        return render_template("profile.html", user=current_user, error="只能给自己充值")

    # 校验金额合法性
    try:
        amount = int(amount_str)
    except (ValueError, TypeError):
        return render_template("profile.html", user=current_user, error="金额必须为整数")

    if amount <= 0:
        return render_template("profile.html", user=current_user, error="充值金额必须为正整数")

    if amount > 1000000:
        return render_template("profile.html", user=current_user, error="单次充值金额不能超过100万元")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")


UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "uploads")
UPLOAD_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}


def _validate_image(file_storage):
    """校验文件后缀名和文件头魔数，合法图片返回 True，否则返回 False"""
    # 1. 校验文件后缀
    filename = file_storage.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in UPLOAD_EXTENSIONS:
        return False

    # 2. 校验文件头魔数（magic bytes）
    magic = file_storage.read(12)  # WebP 需要最多 12 字节
    file_storage.seek(0)  # 重置文件指针，不影响后续 save()

    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if ext == '.png' and magic[:8] == b'\x89PNG\r\n\x1a\n':
        return True
    # JPEG: FF D8 FF
    if ext in ('.jpg', '.jpeg') and magic[:3] == b'\xff\xd8\xff':
        return True
    # GIF: GIF87a 或 GIF89a
    if ext == '.gif' and magic[:6] in (b'GIF87a', b'GIF89a'):
        return True
    # WebP: RIFF .... WEBP
    if ext == '.webp' and magic[:4] == b'RIFF' and magic[8:12] == b'WEBP':
        return True

    return False


@app.route("/upload", methods=["GET", "POST"])
def upload():
    username = session.get("username")
    if not username:
        return redirect("/login")

    error = None
    file_url = None

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            error = "请选择一个文件"
        elif not _validate_image(file):
            error = "只允许上传 PNG、JPG/JPEG、GIF、WebP 格式的图片文件"
        else:
            try:
                ext = os.path.splitext(file.filename)[1].lower()
                new_filename = uuid.uuid4().hex + ext
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                save_path = os.path.join(UPLOAD_DIR, new_filename)
                file.save(save_path)
                file_url = url_for("static", filename=f"uploads/{new_filename}")
            except Exception:
                error = "文件上传失败，请重试"

    return render_template("upload.html", error=error, file_url=file_url)


@app.errorhandler(413)
def request_entity_too_large(error):
    return render_template("upload.html", error="文件大小超过限制（最大 16MB）"), 413


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug_mode, host="0.0.0.0", port=8083)
