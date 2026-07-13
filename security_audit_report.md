# user-management 安全审计与修复报告

> **项目：** user-management（Flask 用户管理系统）
> **审计时间：** 2026-07-12
> **审计类型：** 白盒代码审计

---

## 第一部分：漏洞报告

### 目录

| # | 漏洞 | 类型 | 严重等级 |
|---|------|------|---------|
| 1 | recharge 无认证越权充值 | 越权/业务逻辑 | 🔴 严重 |
| 2 | profile 无认证信息泄露 | 越权/IDOR | 🔴 严重 |
| 3 | 搜索结果泄露全量手机号/邮箱 | 信息泄露 | 🟡 中危 |
| 4 | Flask Secret Key 硬编码 | 认证绕过 | 🟡 中危 |
| 5 | 充值金额零校验 | 业务逻辑 | 🟢 低危 |

---

### 🔴 漏洞 1：recharge 接口无认证 — 任意用户余额修改

**风险等级：** 严重

**影响文件：** `app.py` — `recharge()` 路由（119-126行）

**漏洞代码：**

```python
@app.route("/recharge", methods=["POST"])
def recharge():
    user_id = request.form.get("user_id")       # ❌ 未校验当前登录身份
    amount = request.form.get("amount", "0")     # ❌ 未校验金额合法性

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (amount, user_id))
    conn.commit()
    conn.close()

    return redirect(f"/profile?user_id={user_id}")
```

**问题分析：**
- `user_id` 完全由请求参数控制，后端未校验当前登录用户身份
- 未检查 `session` 中是否存在用户
- `amount` 未经任何校验直接拼入 SQL 更新语句
- 可传递负数余额，实现恶意扣款

**利用方式：**

```http
# 无需登录，给 admin（id=1）充值 99999
POST /recharge
Content-Type: application/x-www-form-urlencoded

user_id=1&amount=99999

# 给 alice（id=2）扣款
POST /recharge
Content-Type: application/x-www-form-urlencoded

user_id=2&amount=-5000
```

**危害：** 攻击者可任意操纵所有用户的余额，包括添加巨额资金或清零。

---

### 🔴 漏洞 2：profile 接口无认证 — 任意用户信息查看

**风险等级：** 严重

**影响文件：** `app.py` — `profile()` 路由（107-117行）

**漏洞代码：**

```python
@app.route("/profile")
def profile():
    user_id = request.args.get("user_id")
    if not user_id:
        return redirect("/")

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
```

**问题分析：**
- 未校验 `session` 登录状态
- 未校验 `user_id` 是否属于当前用户
- API 返回完整的未脱敏信息，包括手机号、邮箱、余额

**利用方式：**

```http
# 无需登录，遍历 user_id
GET /profile?user_id=1   → 获取 admin 所有信息
GET /profile?user_id=2   → 获取 alice 所有信息
```

**危害：** 任意用户（含未登录访客）可遍历 user_id 获取系统内所有用户的敏感个人信息。

---

### 🟡 漏洞 3：搜索功能泄露全量手机号/邮箱

**风险等级：** 中危

**影响文件：** `app.py` — `search_users()` 函数（40-52行）、`index.html` 模板

**漏洞代码：**

```python
def search_users(keyword):
    ...
    c.execute("SELECT * FROM users WHERE username LIKE ? OR email LIKE ?")
    ...
    return [dict(r) for r in rows]      # ❌ 返回原始数据
```

模板中直接渲染：
```html
<td>{{ r["phone"] }}</td>      <!-- 明文显示完整手机号 -->
<td>{{ r["email"] }}</td>      <!-- 明文显示完整邮箱 -->
```

**问题分析：**
- 主页个人信息区的手机号做了脱敏处理（`{{ user["phone"][:3] }}****{{ user["phone"][-4:] }}`）
- 但搜索结果的手机号和邮箱**未脱敏**，原始数据直接暴露
- 已登录用户可以搜索任意关键字枚举其他用户的完整手机号和邮箱

**利用方式：**
1. 登录任意账号
2. 访问 `/?keyword=@example.com` — 批量获取所有用户的手机号和邮箱

**危害：** 敏感信息批量泄露，可用于社工攻击、撞库。

---

### 🟡 漏洞 4：Flask Secret Key 硬编码

**风险等级：** 中危

**影响文件：** `app.py` — 第7行

**漏洞代码：**

```python
app.secret_key = "dev-key-2025"
```

**问题分析：**
- Flask 使用 `secret_key` 对 session cookie 进行签名
- 密钥固定为 `dev-key-2025`，攻击者可：
  1. 伪造任意用户的 session（`session["username"]="admin"`）
  2. 解密合法用户的 session 数据
- GitHub 公开仓库中明文暴露此密钥

**利用方式：**

```python
from flask.sessions import SecureCookieSessionInterface
from flask import Flask

app = Flask(__name__)
app.secret_key = "dev-key-2025"

# 伪造 admin 的 session cookie
serializer = SecureCookieSessionInterface().get_signing_serializer(app)
cookie = serializer.dumps({"username": "admin"})
print(cookie)  # 直接用于请求即可冒充 admin
```

**危害：** 完全绕过登录认证，以任意身份（包括管理员）访问系统。

---

### 🟢 漏洞 5：充值金额零校验

**风险等级：** 低危

**影响文件：** `app.py` — `recharge()` 路由

**漏洞代码：**

```python
amount = request.form.get("amount", "0")  # 字符串直接传入 SQL
```

**问题分析：**
- `amount` 为字符串，未做类型转换和范围校验
- 可传入负数、浮点数、超长数字、非数字字符串
- SQLite 容忍类型不匹配，但迁移到 MySQL/PostgreSQL 时会引发异常

**利用方式：**

```http
POST /recharge
Content-Type: application/x-www-form-urlencoded

user_id=1&amount=-999999   → 巨额扣款
user_id=1&amount=abc       → SQLite 静默转为 0
user_id=1&amount=1e10      → 浮点数精度问题
```

**危害：** 结合漏洞1可随意扣款；金额无上限可能导致数据库整数溢出或业务逻辑异常。

---

## 第二部分：修复报告

### 修复概览

| 漏洞 | 修复方式 | 涉及文件 |
|------|---------|---------|
| recharge 越权充值 | 添加 session 认证 + 身份校验 + 金额合法性校验 | `app.py` |
| profile 信息泄露 | 添加 session 认证 + 身份校验 | `app.py` |
| 搜索结果脱敏 | 搜索层做手机号/邮箱脱敏，限制查询字段 | `app.py` |
| Secret Key 硬编码 | 使用环境变量 + fallback 随机密钥 | `app.py` |
| 金额类型校验 | 整数转换 + 正数 + 上限检查 | `app.py` |

---

### 修复详情

#### 修复 1：recharge — 添加认证、身份校验、金额校验

**修改内容：** 对 `recharge()` 路由添加三层校验：

```python
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
```

**修复要点：**
- ✅ `session.get("username")` 检查登录状态
- ✅ 仅允许操作自己的账号（`str(current_user["id"]) != str(user_id)`）
- ✅ `int()` 转换 + 异常捕获，拒绝非数字
- ✅ 金额必须为正整数（`amount <= 0` 拒绝）
- ✅ 单次上限 100 万（防止滥用/溢出）

---

#### 修复 2：profile — 添加登录认证与身份校验

```python
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

    # ... 后续查询逻辑不变
```

**修复要点：**
- ✅ 未登录用户重定向到登录页
- ✅ 仅允许查看自己的资料，禁止遍历他人信息

---

#### 修复 3：搜索脱敏处理

```python
def search_users(keyword):
    # 仅查询 id, username, email, phone（不再查全部字段）
    c.execute("SELECT id, username, email, phone FROM users WHERE ...")
    ...
    for r in rows:
        d = dict(r)
        # 手机号脱敏：138****8000
        if d.get("phone") and len(d["phone"]) == 11:
            d["phone"] = d["phone"][:3] + "****" + d["phone"][-4:]
        # 邮箱脱敏：a***b@example.com
        if d.get("email") and "@" in d["email"]:
            parts = d["email"].split("@")
            if len(parts[0]) >= 2:
                d["email"] = parts[0][0] + "***" + parts[0][-1] + "@" + parts[1]
            else:
                d["email"] = parts[0][0] + "***@" + parts[1]
        result.append(d)
```

**修复要点：**
- ✅ SQL 查询仅选择必要字段（不再 `SELECT *` 带出 password）
- ✅ 手机号中间四位替换为 `****`
- ✅ 邮箱用户名中间部分替换为 `***`

---

#### 修复 4：Secret Key 使用环境变量

```python
app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())
```

**修复要点：**
- ✅ 优先从环境变量 `FLASK_SECRET_KEY` 读取
- ✅ 无环境变量时使用 `os.urandom(32)` 生成强随机密钥
- ✅ 生产环境应当设置固定密钥以保证 session 持久性

---

#### 修复 5：充值金额校验

整合在修复1中完成，校验规则：

| 检查项 | 处理方式 |
|--------|---------|
| 非数字字符串 | 返回错误「金额必须为整数」 |
| 负数或零 | 返回错误「充值金额必须为正整数」 |
| 超过 1,000,000 | 返回错误「单次充值金额不能超过100万元」 |
| 浮点数 | 拒绝（`int()` 会抛出异常） |
| 合法范围（1-1,000,000） | 通过 |

---

### 修复后安全对照表

| 漏洞 | 修复前 | 修复后 |
|------|--------|--------|
| recharge 越权 | ❌ 无认证、无身份校验 | ✅ 登录 + 仅限自己 + 金额校验 |
| profile 信息泄露 | ❌ 无认证 | ✅ 登录 + 仅限自己 |
| 搜索信息泄露 | ❌ 明文手机号/邮箱 | ✅ 手机号/邮箱脱敏 |
| Secret Key | ❌ 硬编码 `dev-key-2025` | ✅ 环境变量 / 随机生成 |
| 金额校验 | ❌ 字符串直传 | ✅ int 转换 + 正数 + 上限 |

---

### 生产环境建议

除本次修复外，建议补充以下措施：

1. **HTTPS 强制** — 所有接口使用 HTTPS 防止中间人拦截 session cookie
2. **Session 过期机制** — 添加 `app.permanent_session_lifetime = timedelta(hours=2)`
3. **操作审计日志** — 记录充值、密码修改等敏感操作
4. **CSRF 防护** — 对 POST 接口添加 CSRF token（当前未防护，但 session 机制降低了风险）
5. **速率限制** — 对搜索、登录接口添加频率限制

---

*报告生成时间：2026-07-12*
*修复后代码已验证无语法错误且可正常启动运行。*
