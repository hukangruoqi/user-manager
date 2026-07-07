"""
init_users.py - 初始化用户数据文件 users.json
首次运行时创建 users.json，使用 werkzeug.security 对密码加盐哈希存储
"""
import json
import os
from werkzeug.security import generate_password_hash

USERS_DATA = {
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


def init_users(filepath="users.json"):
    """如果 users.json 不存在则创建，写入哈希后的用户数据"""
    if not os.path.exists(filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(USERS_DATA, f, ensure_ascii=False, indent=4)
        print(f"[init_users] 已创建 {filepath}")
        for username, data in USERS_DATA.items():
            print(f"  - {username}: 密码哈希已写入")
    else:
        print(f"[init_users] {filepath} 已存在，跳过初始化")


if __name__ == "__main__":
    init_users()
