================================================================
          白盒安全审计报告
          Flask 用户管理系统
================================================================

项目名称：   Flask 用户管理系统
审计日期：   2026-07-14
审计方法：   白盒源代码审计
审计范围：   所有路由、模板、配置文件
代码行数：   app.py 428行 + 模板 5个 + CSS 1个
风险评级：   🔴 严重 (Critical)

目  录：
  1. 漏洞汇总
  2. SSRF 服务端请求伪造
  3. IDOR 水平越权
  4. XSS 跨站脚本攻击
  5. SSTI 服务端模板注入
  6. 路径遍历
  7. 敏感信息泄露
  8. 权限控制缺失
  9. 会话安全
  10. 其他安全问题
  11. 修复建议优先级
  12. 审计结论

================================================================
1. 漏洞汇总
================================================================

编号       严重程度    类型                    路由                 行号
----------  ----------  ---------------------  -------------------  -----
SEC-001    🔴 严重     SSRF (file:// 协议)     /fetch-url           390-421
SEC-002    🔴 严重     SSRF (内网探测)          /fetch-url           390-421
SEC-003    🔴 严重     IDOR 越权改密           /change-password     192-214
SEC-004    🟠 高危     XSS (反射型)             /page                361-387
SEC-005    🟠 高危     XSS (URL 抓取结果)      /fetch-url           390-421
SEC-006    🟠 高危     路径遍历 (历史遗留)      /page (旧版本)        (已修复)
SEC-007    🟠 高危     敏感信息泄露             /profile             217-243
SEC-008    🟡 中危     弱密码策略               /register            148-176
SEC-009    🟡 中危     Session 固定             /login               131-145
SEC-010    🟡 中危     信息泄露 (500 错误)     全局                  -
SEC-011    🟡 中危     开放重定向              /page, /fetch-url     -
SEC-012    🟢 低危     默认凭据                init_db()            53-58

================================================================
2. SSRF 服务端请求伪造
================================================================

漏洞编号： SEC-001, SEC-002
严重程度： 🔴 严重
文件位置： app.py:390-421

【代码片段】

@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    ...
    url = request.form.get("url", "")
    if url:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as response:
            ...

【漏洞描述】

/fetch-url 路由直接将用户输入的 URL 传给 urllib.request.urlopen()，
未做任何限制：

  a) 未限制协议类型 → 支持 file:// 协议读取任意本地文件
  b) 未限制目标 IP  → 可访问 127.0.0.1、10.x.x.x、192.168.x.x 等内网地址
  c) 未限制端口     → 可扫描内网端口
  d) 未设置超时以外任何防护

【攻击场景】

场景1 — 读取服务器本地文件：
  POST /fetch-url
  url=file:///etc/passwd
  → 返回 /etc/passwd 文件内容前 5000 字符

场景2 — 探测内网服务：
  POST /fetch-url
  url=http://127.0.0.1:8083/   （自访问）
  url=http://10.0.0.1:22/       （内网 SSH 扫描）
  url=http://192.168.1.1:80/    （内网网关探测）

场景3 — 云原数据面提取（AWS/GCP/Azure）：
  url=http://169.254.169.254/latest/meta-data/
  → 获取云服务器实例凭据

【影响】
  • 任意文件读取（服务器本地文件）
  • 内网资产探测与端口扫描
  • 云服务元数据泄露（可能导致云账户接管）

【修复建议】
  // 方案1：限制允许的协议
  if not url.startswith(('http://', 'https://')):
      return "不支持的协议", 400

  // 方案2：禁止内网地址
  from ipaddress import ip_address, is_private
  parsed = urlparse(url)
  host = parsed.hostname
  if is_private(ip_address(host)):
      return "禁止访问内网地址", 400

================================================================
3. IDOR 水平越权
================================================================

漏洞编号： SEC-003
严重程度： 🔴 严重
文件位置： app.py:192-214

【代码片段】

@app.route("/change-password", methods=["POST"])
def change_password():
    username = session.get("username")        # 登录检查 ✅
    if not username:
        return redirect("/login")

    target_username = request.form.get("username", "")  # ← 来自表单！
    ...
    c.execute("UPDATE users SET password = ? WHERE username = ?",
              (hashed_pw, target_username))    # ← 使用表单中的用户名

【漏洞描述】

修改密码接口中，目标用户名 target_username 来自 HTTP 表单参数，
而非当前登录会话 (session["username"])。攻击者只需在表单中提交
任意已存在用户名即可修改该用户的密码。

【攻击场景】

  1. 攻击者以普通用户 alice 身份登录
  2. 构造 POST 请求：
     username=admin&new_password=hacked&confirm_password=hacked
  3. admin 密码被改为 "hacked"
  4. 攻击者以 admin/hacked 登录 → 完全接管系统

【影响】
  • 任意用户密码被篡改
  • 管理员账户可被低权限用户接管

【修复建议】
  // 关键修复：从 session 获取用户名，而不是表单
  target_username = session.get("username")   # 只改自己的密码

================================================================
4. XSS 跨站脚本攻击
================================================================

漏洞编号： SEC-004, SEC-005
严重程度： 🟠 高危
文件位置： templates/index.html:22, 84

【代码片段 — index.html:22】

<div class="card page-content">
    {{ page_content | safe }}      ← | safe 过滤器
</div>

【代码片段 — index.html:84】

<pre>{{ fetch_content }}</pre>     ← 外部内容直接输出

【漏洞描述】

  a) page_content 使用 | safe 过滤器，绕过 Jinja2 自动转义
  b) fetch_content 来自外部 URL 抓取结果，直接渲染到页面
  c) 如果 attacker 控制的页面内容被抓取，或 page 参数可控，
     可嵌入恶意 JS 代码

【攻击场景】

  攻击者构造含 <script> 标签的 URL 并诱导管理员点击抓取：
  → 抓取内容中的脚本在管理员浏览器中执行
  → 窃取管理员 Cookie / 执行恶意操作

【修复建议】
  移除 | safe 过滤器，或使用 markupsafe.escape() 转义

================================================================
5. 敏感信息泄露
================================================================

漏洞编号： SEC-007
严重程度： 🟠 高危
文件位置： templates/profile.html:11-15

【代码片段】

<li><strong>ID：</strong>{{ user["id"] }}</li>
<li><strong>用户名：</strong>{{ user["username"] }}</li>
<li><strong>邮箱：</strong>{{ user["email"] }}</li>
<li><strong>手机号：</strong>{{ user["phone"] }}</li>    ← 明文
<li><strong>余额：</strong>{{ user["balance"] }} 元</li>

【漏洞描述】

profile.html 直接展示用户的手机号、邮箱、余额等敏感信息，
未做脱敏处理。与 index.html（已脱敏）不一致。

【影响】
  • 用户手机号、邮箱明文暴露
  • 一旦越权访问他人 profile 页面即可获取完整个人信息

【修复建议】
  对手机号做脱敏处理：{{ user["phone"][:3] }}****{{ user["phone"][-4:] }}

================================================================
6. 权限控制缺失
================================================================

漏洞编号： 同 SEC-003（补充分析）
严重程度： 🟡 中危
文件位置： app.py:192-214 (change-password), 246-281 (recharge)

【补充分析 — /recharge】

current_user = get_user_by_username(username)
if str(current_user["id"]) != str(user_id):
    return render_template(..., error="只能给自己充值")

/recharge 做了 user_id 校验（只能给自己充值），但
/change-password 完全没做类似校验。两处逻辑不一致。

此外，session 中的 username 在 login 时设置后永不过期，
无任何超时机制。

================================================================
7. 会话安全
================================================================

漏洞编号： SEC-009
严重程度： 🟡 中危
文件位置： app.py:131-145

【代码分析】

@app.route("/login", methods=["GET", "POST"])
def login():
    ...
    if user and check_password_hash(user["password"], password):
        session["username"] = username    # 无 session 重置
        return redirect("/")

【问题】
  • 登录成功后未调用 session.regenerate() 或重新生成 session
  • 攻击者可利用 session fixation 攻击
  • session 无超时机制（永不过期）
  • secret_key 每次重启随机生成，导致所有 session 失效

【修复建议】
  // 登录成功后重置 session
  session.clear()
  session["username"] = username

================================================================
8. 其他安全问题
================================================================

8.1 弱密码策略 (SEC-008)
────────────────────────
  • 注册时仅校验不为空，无长度/复杂度要求
  • 默认密码 admin123 和 alice2025 过于简单
  • 修复：增加密码复杂度校验（大小写+数字+特殊字符，最少8位）

8.2 信息泄露 (SEC-010)
────────────────────────
  • debug_mode 可由环境变量 FLASK_ENV=development 开启
  • 开启后 Werkzeug 调试器可在浏览器执行 Python 代码
  • 建议: debug 模式永不用于生产环境

8.3 开放重定向 (SEC-011)
────────────────────────
  • /page 和 /fetch-url 无 Referer 校验
  • redirect() 目标均由用户输入控制（如 /login?success=...）

8.4 默认凭据 (SEC-012)
────────────────────────
  • admin/admin123, alice/alice2025 为固定默认账号
  • 部署后若未修改，攻击者可轻易登录

================================================================
9. 安全评分一览
================================================================

类别                 发现数  严重  高危  中危  低危
------------------  ------  ----  ----  ----  ----
SSRF                   2     2     -     -     -
IDOR/越权              2     1     -     1     -
XSS                    2     -     2     -     -
敏感信息泄露           1     -     1     -     -
会话安全               1     -     -     1     -
弱密码策略             1     -     -     1     -
信息泄露               1     -     -     1     -
默认凭据               1     -     -     -     1
────────────────────────────────────────────────
合计                  11     3     3     4     1

================================================================
10. 修复建议优先级
================================================================

优先级  漏洞编号   修复措施                          预估工时
------  ---------  --------------------------------  --------
P0      SEC-001    限制 /fetch-url 协议 + 内网 IP    1h
P0      SEC-002    限制 /fetch-url 协议 + 内网 IP    1h
P0      SEC-003    change-password 使用 session      0.5h
                         用户名而非表单
P1      SEC-004    移除 | safe 过滤器                 0.5h
P1      SEC-005    转义 fetch_content                  0.5h
P1      SEC-007    profile.html 手机号脱敏            0.5h
P2      SEC-008    增加密码复杂度校验                  1h
P2      SEC-009    登录后重置 session                 0.5h
P2      SEC-010    生产环境禁用 debug                 0.5h
P2      SEC-011    增加 Referer 校验                  0.5h
P3      SEC-012    强制首次登录修改默认密码            2h

================================================================
11. 审计结论
================================================================

┌──────────────────────────────────────────────────────────┐
│                                                          │
│  整体安全评级： 🔴 严重 (Critical)                       │
│                                                          │
│  系统存在 11 个安全漏洞，其中：                           │
│    🔴 严重 3 个 — SSRF + IDOR 可导致完整服务器沦陷      │
│    🟠 高危 3 个 — XSS + 敏感信息泄露                     │
│    🟡 中危 4 个 — 会话/密码/信息泄露                    │
│    🟢 低危 1 个 — 默认凭据                               │
│                                                          │
│  最严重攻击链：                                          │
│    1. 利用 IDOR 越权 (/change-password)                  │
│       修改管理员密码 → 接管 admin 账户                   │
│    2. 利用 SSRF (/fetch-url)                             │
│       file:///etc/shadow → 读取服务器敏感文件            │
│       http://169.254.169.254/ → 获取云元数据             │
│    3. 利用 XSS (/page) + SSRF 联合攻击                   │
│       窃取管理员 session → 持久化控制                    │
│                                                          │
│  核心问题根因：                                          │
│    • 对用户输入缺乏任何校验（URL、username）             │
│    • 未遵循最小权限原则（session vs 表单参数）           │
│    • 模板输出未合理转义（| safe 滥用）                   │
│                                                          │
│  建议立即修复 P0 级别漏洞，否则系统面临完整沦陷风险。    │
│                                                          │
└──────────────────────────────────────────────────────────┘

================================================================
                          报告结束
================================================================
