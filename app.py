import sqlite3
import os
import re
import uuid
import urllib.request
import urllib.error
import socket
from urllib.parse import urlparse
from ipaddress import ip_address, ip_network
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
csrf = CSRFProtect(app)


@app.errorhandler(400)
def csrf_error_handler(error):
    """CSRF 验证失败时返回友好错误页面"""
    if "csrf" in str(error).lower():
        return render_template("error.html", message="请求已过期或来源非法，请刷新页面后重试"), 400
    return render_template("error.html", message="错误的请求"), 400


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

    target_username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if new_password != confirm_password:
        return redirect("/profile")

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    hashed_pw = generate_password_hash(new_password)
    sql = "UPDATE users SET password = ? WHERE username = ?"
    print(f"[SQL] {sql} 参数: username='{target_username}'")
    c.execute(sql, (hashed_pw, target_username))
    conn.commit()
    conn.close()

    return redirect(f"/profile")


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


PAGES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pages")
PAGE_ALLOWLIST = {"help", "about", "terms", "privacy"}


@app.route("/page")
def page():
    name = request.args.get("name", "")
    page_content = None

    if name:
        # 白名单校验：只允许加载预设的页面
        clean_name = os.path.normpath(name).lstrip("/")
        if clean_name not in PAGE_ALLOWLIST:
            page_content = "页面不存在"
        else:
            filepath = os.path.join(PAGES_DIR, clean_name + ".html")
            try:
                # 安全校验：确认文件在 pages 目录内
                real_path = os.path.realpath(filepath)
                if not real_path.startswith(os.path.realpath(PAGES_DIR) + os.sep):
                    page_content = "页面不存在"
                elif os.path.isfile(real_path):
                    with open(real_path, "r", encoding="utf-8") as f:
                        page_content = f.read()
                else:
                    page_content = "页面不存在"
            except (OSError, ValueError):
                page_content = "页面不存在"

    username = session.get("username")
    user = get_user_by_username(username) if username else None
    return render_template("index.html", user=user, page_content=page_content)


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    username = session.get("username")
    if not username:
        return redirect("/login")

    url = request.form.get("url", "")
    status_code = None
    content_preview = None
    error_msg = None

    if url:
        # SSRF 防护1：只允许 http/https 协议
        if not url.startswith(("http://", "https://")):
            error_msg = "只允许访问 http:// 和 https:// 协议的 URL"
        else:
            try:
                parsed = urlparse(url)
                hostname = parsed.hostname

                # SSRF 防护2：解析域名并检查是否为内网地址
                try:
                    addr = ip_address(hostname)
                except ValueError:
                    # 域名而非 IP，需要解析
                    try:
                        addr = ip_address(socket.gethostbyname(hostname))
                    except socket.gaierror:
                        error_msg = f"无法解析域名: {hostname}"

                if not error_msg:
                    # SSRF 防护3：禁止内网/私有地址
                    private_networks = [
                        ip_network("127.0.0.0/8"),      # 本地回环
                        ip_network("10.0.0.0/8"),       # A 类私有
                        ip_network("172.16.0.0/12"),    # B 类私有
                        ip_network("192.168.0.0/16"),   # C 类私有
                        ip_network("169.254.0.0/16"),   # 链路本地(含云元数据)
                        ip_network("0.0.0.0/8"),        # 零地址
                        ip_network("::1/128"),          # IPv6 回环
                        ip_network("fc00::/7"),         # IPv6 唯一本地
                    ]
                    if any(addr in net for net in private_networks):
                        error_msg = "禁止访问内网或保留地址"

            except Exception as e:
                error_msg = f"URL 校验失败: {str(e)}"

        # 校验通过后执行抓取
        if not error_msg and url:
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (compatible; Bot)"}
                )
                with urllib.request.urlopen(req, timeout=10) as response:
                    status_code = response.status
                    raw = response.read()
                    content_preview = raw.decode("utf-8", errors="replace")[:5000]
            except urllib.error.HTTPError as e:
                status_code = e.code
                content_preview = str(e)
            except urllib.error.URLError as e:
                error_msg = f"URL 访问失败: {e.reason}"
            except Exception as e:
                error_msg = f"发生错误: {str(e)}"

    user = get_user_by_username(username)
    return render_template("index.html", user=user,
                           fetch_status=status_code,
                           fetch_content=content_preview,
                           fetch_error=error_msg,
                           fetch_url=url)


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug_mode, host="0.0.0.0", port=8083)
