import sqlite3
import os
import re
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev-key-2025"

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
            phone TEXT
        )
    """)
    # 插入默认用户（密码已哈希），INSERT OR IGNORE 防止重复
    admin_pw = generate_password_hash("admin123")
    alice_pw = generate_password_hash("alice2025")
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ('admin', admin_pw, 'admin@example.com', '13800138000'))
    c.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
              ('alice', alice_pw, 'alice@example.com', '13900139001'))
    # 迁移：若旧数据库中密码还是明文，则更新为哈希值
    c.execute("UPDATE users SET password = ? WHERE username = ? AND password = ?",
              (admin_pw, 'admin', 'admin123'))
    c.execute("UPDATE users SET password = ? WHERE username = ? AND password = ?",
              (alice_pw, 'alice', 'alice2025'))
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
    """根据关键词搜索用户（参数化查询，防止 SQL 注入）"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sql = "SELECT * FROM users WHERE username LIKE ? OR email LIKE ?"
    like_pattern = f'%{keyword}%'
    print(f"[SQL] {sql} 参数: like='%{keyword}%'")
    c.execute(sql, (like_pattern, like_pattern))
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


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
                sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
                print(f"[SQL] {sql} 参数: username='{username}', email='{email}', phone='{phone}'")
                c.execute(sql, (username, hashed_pw, email, phone))
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    init_db()
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug_mode, host="0.0.0.0", port=8083)
