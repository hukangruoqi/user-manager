# 用户管理系统 🔐

一个基于 Flask 的安全用户管理系统，支持用户登录、个人信息查看和密码修改功能。

## ✨ 功能特性

- **用户登录** — 用户名密码认证，密码加盐哈希存储
- **个人信息展示** — 手机号脱敏显示，余额仅管理员可见
- **密码修改** — 登录后可修改密码，需验证旧密码
- **退出登录** — 清除会话，安全退出

## 🛠️ 技术栈

| 技术 | 说明 |
|------|------|
| **Flask** | Python Web 框架 |
| **Werkzeug Security** | 密码加盐哈希（scrypt） |
| **Jinja2** | 模板引擎 |
| **JSON File** | 轻量级数据存储 |

## 🚀 快速启动

### 1. 克隆项目

```bash
git clone https://github.com/你的用户名/仓库名.git
cd 仓库名
```

### 2. 安装依赖

```bash
pip install flask werkzeug
```

### 3. 初始化用户数据

首次运行会自动创建 `users.json`，也可以手动执行：

```bash
python init_users.py
```

### 4. 启动服务

```bash
bash start_flask.sh
# 或直接
python app.py
```

服务将运行在 **http://0.0.0.0:8083**

### 5. 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| `admin` | `admin@2025_Secure` | 管理员 |
| `alice` | `Alice@2025!` | 普通用户 |

> ⚠️ 生产环境部署前请修改默认密码！

## 🔒 安全措施

- ✅ **密码哈希存储** — 使用 `werkzeug.security` 的 scrypt 算法加盐哈希
- ✅ **无硬编码密码** — 密码不存储在源码中
- ✅ **隐私脱敏** — 手机号中间四位脱敏显示
- ✅ **权限控制** — 敏感信息（如余额）仅管理员可见
- ✅ **Debug 模式可配置** — 通过环境变量 `FLASK_ENV=development` 控制
- ✅ **密码修改** — 需验证旧密码，新密码长度至少 6 位

## 📁 项目结构

```
user-management/
├── app.py              # Flask 应用主入口
├── init_users.py       # 用户数据初始化脚本
├── start_flask.sh      # 启动脚本
├── .gitignore          # Git 忽略配置
├── static/
│   └── css/
│       └── style.css   # 页面样式
└── templates/
    ├── base.html       # 基础模板
    ├── index.html      # 首页（个人信息+修改密码）
    └── login.html      # 登录页面
```

## 📜 开源协议

MIT
