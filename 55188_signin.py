import requests
import time
import os
import re
import json
import traceback
from datetime import datetime
import urllib3
from wx_msg import send_wx

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置：官方域名
BASE_HOST = "www.55188.com"
BASE_URL = f"https://{BASE_HOST}"

corpid = os.getenv("WX_CORPID") or ""
corpsecret = os.getenv("WX_CORPSECRET") or ""
agentid = os.getenv("WX_AGENTID") or ""


def mask_username(username):
    username = username.strip()
    if len(username) <= 1:
        return username
    elif len(username) == 2:
        return username[0] + "*"
    else:
        return username[0] + "*" * (len(username) - 2) + username[-1]


def check_signed_in_page(html_text):
    """通过正则与关键字精准判断页面是否已处于已签到状态"""
    keywords = ["今日已签到", "您的签到排名", "已签到"]
    return any(kw in html_text for kw in keywords)


def sign_in(cookie_str, index=1):
    print("\n" + "=" * 60)
    print(f"[START] 账号 {index}")

    session = requests.Session()

    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "Referer": f"{BASE_URL}/plugin.php?id=sign",
        "Origin": BASE_URL,
        "X-Requested-With": "XMLHttpRequest",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin"
    })

    if "MY_COOKIE=" in cookie_str:
        cookie_str = cookie_str.split("MY_COOKIE=", 1)[-1]

    # 解析并设置 Cookie
    session.cookies.update(
        dict(
            i.strip().split("=", 1)
            for i in cookie_str.split(";")
            if "=" in i
        )
    )

    # 1. 请求签到主页，获取 HTML & formhash
    html = ""
    try:
        print(f"[REQUEST GET] 打开签到主页 -> {BASE_URL}/plugin.php?id=sign")
        r1 = session.get(f"{BASE_URL}/plugin.php?id=sign", timeout=20, verify=False)
        r1.encoding = r1.apparent_encoding
        html = r1.text
    except Exception as e:
        print("[WARN GET SIGN PAGE]", e)

    # 提取 formhash
    formhash = ""
    fh_patterns = [
        r'name=["\']formhash["\']\s+value=["\']([a-zA-Z0-9]+)["\']',
        r'formhash=([a-zA-Z0-9]+)',
        r'formhash["\']?\s*[:=]\s*["\']([a-zA-Z0-9]+)["\']'
    ]
    for p in fh_patterns:
        m = re.search(p, html)
        if m:
            formhash = m.group(1).strip()
            break

    if not formhash:
        formhash = "768f68e4"

    print(f"[DEBUG] 提取到的 formhash: {formhash}")

    # 提取用户名
    username = f"账号{index}"
    patterns = [r'您好：([^<]+)</a>', r'欢迎您回来，([^<]+)<', r'欢迎您，([^<]+)<']
    for p in patterns:
        m = re.search(p, html)
        if m:
            username = m.group(1).strip()
            break
    username_show = mask_username(username)

    # 2. 判断状态与发起签到 POST
    if "游客" in html and len(html) > 500:
        msg = "❌ Cookie失效"
    elif check_signed_in_page(html):
        print("[INFO] GET 主页已被判定为【已签到】状态")
        msg = "✅ 今日已签到"
    else:
        try:
            sign_action_url = f"{BASE_URL}/plugin.php?id=sign&mod=add&formhash={formhash}"

            session.headers.update({
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
            })

            # --- 第 1 次 POST 提交（探针：获取服务端最新 nonce）---
            post_data_1 = {
                "id": "sign",
                "mod": "add",
                "formhash": formhash
            }

            print(f"[REQUEST POST 第1次] 提交探针 -> {sign_action_url}")
            r2 = session.post(sign_action_url, data=post_data_1, timeout=20, verify=False)
            r2.encoding = r2.apparent_encoding
            res_text = r2.text
            print(f"[DEBUG POST 第1次] Status: {r2.status_code}, Res text: {res_text}")

            fresh_nonce = ""
            try:
                res_json = json.loads(res_text)
                if res_json.get("status") == "nonce_expired" and res_json.get("nonce"):
                    fresh_nonce = res_json.get("nonce")
            except Exception:
                pass

            # --- 第 2 次 POST 提交（装载 sign_nonce 发起二次签到）---
            if fresh_nonce:
                print(f"[INFO] 捕获到服务器最新 Nonce: {fresh_nonce}，装载 sign_nonce 发起二次签到...")
                post_data_2 = {
                    "id": "sign",
                    "mod": "add",
                    "formhash": formhash,
                    "sign_nonce": fresh_nonce
                }

                r3 = session.post(sign_action_url, data=post_data_2, timeout=20, verify=False)
                r3.encoding = r3.apparent_encoding
                res_text = r3.text
                print(f"[DEBUG POST 第2次] Status: {r3.status_code}, Res text: {res_text}")

            # 3. 结果判断：做二次 Get 确认，防止接口抛出无脑 success
            r_check = session.get(f"{BASE_URL}/plugin.php?id=sign", timeout=10, verify=False)
            r_check.encoding = r_check.apparent_encoding

            try:
                res_json = json.loads(res_text)
                status = res_json.get("status", "")
                message = str(res_json.get("msg", res_json.get("message", "")))

                # 双重校验：通过页面结构验证是否真正变更为“已签到”
                if check_signed_in_page(r_check.text):
                    if fresh_nonce:
                        msg = "🎉 签到成功"
                    else:
                        msg = "✅ 今日已签到"
                elif status == "success" or "成功" in message:
                    msg = "🎉 签到成功"
                elif "signed" in status or "已签" in message:
                    msg = "✅ 今日已签到"
                else:
                    msg = f"⚠️ 签到返回: {message or status or res_text}"
            except Exception:
                if check_signed_in_page(r_check.text):
                    msg = "🎉 签到成功" if fresh_nonce else "✅ 今日已签到"
                else:
                    msg = f"⚠️ 未知结果: {res_text[:60]}"

        except Exception as e:
            print("[SIGN ACTION ERROR]", e)
            msg = "❌ 签到失败"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = f"""
[55188] 签到结果

账号：{username_show}
时间：{now}

{msg}
"""
    print(result)
    send_wx(result, corpid, corpsecret, agentid)


if __name__ == "__main__":
    cookies = os.getenv("MY_COOKIE") or ""

    if not cookies.strip():
        print("❌ 未检测到 COOKIE")
        exit()

    cookie_list = [c.strip() for c in cookies.split("\n") if c.strip()]
    for i, cookie in enumerate(cookie_list, 1):
        try:
            sign_in(cookie, i)
        except Exception:
            err = traceback.format_exc()
            print(err)
            send_wx(f"[55188] 全局异常\n账号{i}\n\n{err}", corpid, corpsecret, agentid)
        time.sleep(2)
