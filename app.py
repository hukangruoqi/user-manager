import json
import os
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev-key-2025"

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.json")


def load_users():
    """从 users.json 加载用户数据"""
    if not os.path.exists(USERS_FILE):
        init_users()
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users(users):
    """将用户数据写回 users.json"""
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=4)


def init_users():
    """首次运行时自动初始化 users.json"""
    from werkzeug.security import generate_password_hash
    default_users = {
        "admin": {
            "username": "admin",
            "password": generate_password_hash("admin@2025_Secure"),
            "role": "admin",
            "email": "admin@example.com",
            "phone": "13800138000",
            "balance": 99999
        },
        "alice": {
            "username": "alice",
            "password": generate_password_hash("Alice@2025!"),
            "role": "user",
            "email": "alice@example.com",
            "phone": "13900139001",
            "balance": 100
        }
    }
    save_users(default_users)
    print(f"[app] 已自动创建 {USERS_FILE}")


@app.route("/")
def index():
    username = session.get("username")
    user = None
    if username:
        users = load_users()
        if username in users:
            user = users[username]
    return render_template("index.html", user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        users = load_users()
        if username in users and check_password_hash(users[username]["password"], password):
            session["username"] = username
            return redirect("/")
        else:
            error = "用户名或密码错误"
    return render_template("login.html", error=error)


@app.route("/change-password", methods=["POST"])
def change_password():
    username = session.get("username")
    if not username:
        return redirect("/login")

    old_pw = request.form.get("old_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    users = load_users()

    if username not in users:
        return redirect("/")

    if not check_password_hash(users[username]["password"], old_pw):
        return render_template("index.html", user=users[username], pw_error="旧密码错误")

    if new_pw != confirm_pw:
        return render_template("index.html", user=users[username], pw_error="两次新密码输入不一致")

    if len(new_pw) < 6:
        return render_template("index.html", user=users[username], pw_error="新密码长度至少6位")

    users[username]["password"] = generate_password_hash(new_pw)
    save_users(users)

    users = load_users()
    return render_template("index.html", user=users[username], pw_success="密码修改成功")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_ENV") == "development"
    app.run(debug=debug_mode, host="0.0.0.0", port=8083)
