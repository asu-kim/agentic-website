#!/usr/bin/env python3

import os, re, argparse, hmac, hashlib, binascii
from io import BytesIO
from time import sleep
from typing import Optional, Tuple, List
from dataclasses import dataclass
from PIL import Image
from time import sleep

from dotenv import load_dotenv
import helium
from helium import Link, Text, click, scroll_down
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from smolagents import CodeAgent, tool, TransformersModel
from smolagents.agents import ActionStep
from smolagents import Model

from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

from urllib.parse import urlparse, parse_qs
import subprocess, shlex, json, base64, os, re

load_dotenv()
here = os.path.dirname(__file__)

temp_dir = f"~/data/tmp/helium_data_{os.getpid()}"
firefox_options = webdriver.FirefoxOptions()
firefox_options.add_argument("--force-device-scale-factor=1")
firefox_options.add_argument("--window-size=700,900")
firefox_options.add_argument("--window-position=0,0")
firefox_options.set_preference("intl.accept_languages", "en-US, en")

driver = helium.start_firefox(headless=False, options=firefox_options)

CONFIG_PATH = 'configs/net1/highTrustAgent.config'

HEX32 = re.compile(r"\b[a-fA-F0-9]{32}\b")

# -------------------------
# get session key

def _abs(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

def _parse_last_json_line(stdout: str) -> dict:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)
    raise ValueError("No JSON line found in Node output")

def fetch_session_keys(config_path: str, key_id: int):
    agent_dir = _abs(os.path.join(here, '../iotauth/entity/node/example_entities'))
    cmd = f'node agent.js {shlex.quote(config_path)} keyId {int(key_id)}'
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=agent_dir)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip() or "node error")

    data = _parse_last_json_line(p.stdout)
    print(data)
    session_key_value = []
    for k in data.get("session_keys", []):
        session_key_value.append({
            "id": int(k["id"]), 
            "cipherKey": (k["cipherKey_b64"]),  
            "macKey": base64.b64decode(k["macKey_b64"]),       
            "absValidity": k.get("absValidity"),
            "relValidity": k.get("relValidity"),
        })
    if not session_key_value:
        raise ValueError("Empty session_keys in JSON")
    return session_key_value


# ex) _exists(By.ID, "ap_email")
def _exists(by: By, val: str) -> bool:  
    try:
        driver.find_element(by, val)
        return True
    except Exception:
        return False
    
def _text_or_value(el):
    try:
        v = el.get_attribute("value")
        if v: return v.strip()
    except Exception:
        pass
    try:
        t = el.text
        if t: return t.strip()
    except Exception:
        pass
    return ""

@tool
def get_session_key(key_id: int) -> str:
    """
    Look up a session key by its integer key ID and return the raw key string.

    Args:
        key_id: The numeric ID of the session key to retrieve.

    Returns:
        The cipher key (session key) associated with the given key ID.
    """
    session_key_value = fetch_session_keys(CONFIG_PATH, int(key_id))
    session_key = session_key_value[0]["cipherKey"]
    return session_key

@tool
def go_to(url: str) -> str:
    """
    Navigate the browser (Selenium driver) to the specified URL.

    Use this when you want the agent's browser to open a new page.

    Args:
        url: The absolute URL to open.

    Returns:
        A short status message indicating the destination URL.
    """    
    driver.get(url)
    return f"Navigated to {url}"

@tool
def finish_session() -> str:
    """
    Gracefully close the current browser session.

    This waits briefly to allow any in-flight actions to complete,
    then quits the Selenium WebDriver.

    Returns:
        A status message confirming the browser was closed.
    """
    sleep(5)
    driver.quit()
    return "Browser closed"

@tool
def hmac_sha256_hex(session_key: bytes, nonce_hex: bytes) -> str:
    """
    Compute HMAC-SHA256 over the given message with the given key,
    and return the result as a 64-character lowercase hex string.

    Args:
        session_key: Secret key as raw bytes.
        nonce_hex: Message to authenticate as raw bytes.

    Returns:
        The HMAC-SHA256 digest encoded as a hex string.
    """  
    key_bytes = base64.b64decode(session_key)
    nonce_bytes = binascii.unhexlify(nonce_hex)    
    return hmac.new(key_bytes, nonce_bytes, hashlib.sha256).hexdigest()

@tool
def get_nonce() -> str:
    """
    Extract a 32-digit hex nonce from the current page.

    This tool searches for:
      1. An element with ID 'nonceHex' and tries its text/value.
      2. Any visible text on the page via helium.find_all(Text).

    As soon as a 32-hex-digit substring is found, it is returned.

    Returns:
        A 32-character hexadecimal nonce string.

    Raises:
        RuntimeError: If no 32-hex-digit nonce can be found on the page.
    """ 
    sleep(5.0)
    try:
        temp = driver.find_element(By.ID, "nonceHex")
        return temp.get_attribute("value")
    except Exception:
        pass
    
    try:
        for sel in [
            (By.ID, "nonceHex"),
        ]:
            els = driver.find_elements(*sel)
    except Exception:
        pass
    val = _text_or_value(els)
    m = HEX32.search(val or "")
    if m:
        return m.group(0)
    
    try:
        texts = helium.find_all(Text)
        for t in texts:
            v = str(t.web_element.text).strip()
            m = HEX32.search(v)
            if m:
                return m.group(0)
    except Exception:
        pass

    raise RuntimeError("Nonce (32 hex) not found on page")

@tool
def login(hmac_hex: str, tokenId: str) -> str:
    """
    Fill in the HMAC input field on the current page and submit the login/verify form.

    The tool tries several selectors to locate the HMAC input:
      - id='hmac'
      - name='hmac'
      - input with placeholder containing 'HMAC'
      - input with aria-label containing 'HMAC'

    If none of these are found, it falls back to helium.write(..., into='HMAC-SHA256 (64-hex)').

    Then it attempts to click:
      1. A button labeled "Verify" (via helium.click).
      2. Or a clickable submit/primary button via CSS:
         button[type='submit'], button.primary

    Args:
        hmac_hex: The 64-character hex HMAC value to enter.
        tokenId: Session Key Id to get session key from auth.

    Returns:
        A status message indicating that the login was submitted.

    Raises:
        RuntimeError: If no HMAC input or submit button can be found.
    """    
    hmac_input = None
    selectors = [
        (By.ID, "hmac"),
        (By.CSS_SELECTOR, "input[placeholder*='64-digit hex']"),
    ]
    for sel in selectors:
        try:
            el = WebDriverWait(driver, 3).until(
                EC.presence_of_element_located(sel)
            )
            if el:
                hmac_input = el
                break
        except Exception:
            pass

    if hmac_input is None:
        try:
            helium.write(hmac_hex, into="HMAC-SHA256 (64-hex)")
        except Exception:
            raise RuntimeError("HMAC input not found")
    else:
        hmac_input.clear()
        hmac_input.send_keys(hmac_hex)   

    toekn_input = None
    selectors = [
        (By.ID, "tokenId"),
        (By.CSS_SELECTOR, "input[placeholder*='00000000']"),
    ]
    for sel in selectors:
        try:
            el = WebDriverWait(driver, 3).until(
                EC.presence_of_element_located(sel)
            )
            if el:
                token_input = el
                break
        except Exception:
            pass

    if toekn_input is None:
        try:
            helium.write(tokenId, into="00000000")
        except Exception:
            raise RuntimeError("TokenId input not found")
    else:
        toekn_input.clear()
        toekn_input.send_keys(tokenId)    


    clicked = False
    try:
        helium.click("Verify")
        clicked = True
    except Exception:
        pass
    
    if not clicked:
        try:
            btn = WebDriverWait(driver, 2).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "button[type='submit'], button.primary"))
            )
            btn.click()
            clicked = True
        except Exception:
            pass

    if not clicked:
        raise RuntimeError("Submit button not found")

    sleep(60)
    return "Login submitted"

@tool
def get_items(item: str) -> str:
    """
    Click the dashboard cards for the requested items (scopes) and
    return their results as a JSON string.

    Args:
        item:
            A string describing which items to fetch.
            Supported scopes: email, address, cardNumber, phone

    Behavior:
        For each scope:
          1. Click the corresponding "Request <Label>" button on the dashboard
             (by id='btn-request-<scope>' if available, otherwise by text).
          2. Wait briefly for the response to appear.
          3. Read the status and JSON body from the card.
        Returns a JSON string like:
          {
            "email": {"status": "200", "body": {"email": "s@example.com"}},
            "address": {"status": "403", "body": {"error": "forbidden"}}
          }
    """
    SCOPE_LABELS = {
        "email": "Email",
        "address": "Address",
        "cardNumber": "Card Number",
        "phone": "Phone Number",
    }

    raw = (item or "").strip().lower()
    if not raw:
        raise RuntimeError("get_items: no item specified")

    if raw == "all":
        scopes = list(SCOPE_LABELS.keys())
    else:
        parts = re.split(r"[,\s;]+", raw)
        scopes = []
        for p in parts:
            if not p:
                continue
            if p in SCOPE_LABELS:
                scopes.append(p)
            elif p == "card" or p == "cardnumber":
                scopes.append("cardNumber")
            else:
                raise RuntimeError(f"Unknown scope in get_items: {p}")

    results = {}

    def click_scope(scope: str):
        label = SCOPE_LABELS[scope]

        try:
            btn = WebDriverWait(driver, 2).until(
                EC.element_to_be_clickable((By.ID, f"btn-request-{scope}"))
            )
            btn.click()
            return f"clicked btn-request-{scope}"
        except Exception:
            pass

        try:
            helium.click(f"Request {label}")
            return f"clicked button by text 'Request {label}'"
        except Exception:
            pass

        try:
            card = WebDriverWait(driver, 2).until(
                EC.visibility_of_element_located((By.ID, f"card-{scope}"))
            )
            btn = card.find_element(By.CSS_SELECTOR, "button.btn.primary")
            btn.click()
            return f"clicked primary button inside card-{scope}"
        except Exception:
            pass

        raise RuntimeError(f"Request button not found for scope={scope}")

    def read_scope(scope: str):
        status_text = ""
        try:
            el = WebDriverWait(driver, 1.5).until(
                EC.visibility_of_element_located((By.ID, f"status-{scope}"))
            )
            status_text = (el.text or "").strip()
        except Exception:
            try:
                card = driver.find_element(By.ID, f"card-{scope}")
                st = card.find_element(By.XPATH, ".//*[contains(., 'Status')]")
                status_text = (st.text or "").strip()
            except Exception:
                status_text = ""

        m = re.search(r"(\d{3})", status_text)
        status_norm = m.group(1) if m else status_text

        body_text = ""
        try:
            pre = driver.find_element(By.ID, f"response-{scope}")
            body_text = pre.text
        except Exception:
            try:
                card = driver.find_element(By.ID, f"card-{scope}")
                pre = card.find_element(By.CSS_SELECTOR, "pre.code-block")
                body_text = pre.text
            except Exception:
                body_text = ""

        body_norm = body_text
        try:
            body_norm = json.loads(body_text)
        except Exception:
            pass

        return {"status": status_norm, "body": body_norm}

    for scope in scopes:
        click_scope(scope)
        sleep(0.5) 
        results[scope] = read_scope(scope)

    return json.dumps(results, ensure_ascii=False, indent=2)



AGENT_SYSTEM_PROMPT = """
- Always call the registered tools functions directly.
- Print each steps' description.
- Do NOT invent or assume any functions that are not in the registered tool list.
- The code must run without syntax errors.
- The final line must call final_answer(items_json).
- Do not process the session_key and nonce. Use raw value of session_key and nonce.
- Use the tools directly as normal Python functions.
- If get_session_key() times out or raises an exception, handle it in Python and then call final_answer(...) to report the issue.
"""

def build_agent():
    model_id = "openai/gpt-oss-20b" # "meta-llama/Llama-3.1-8B-Instruct"

    model = TransformersModel(model_id=model_id)

    agent = CodeAgent(
        tools=[
            go_to, finish_session, get_session_key, get_nonce, hmac_sha256_hex, login, get_items
        ],
        model=model,
        max_steps=10,
        verbosity_level=2,
         additional_authorized_imports=["helium", "re", "hmac", "hashlib", "base64", "binascii"]
    )
    agent.python_executor("from helium import *")
    return agent

def parse_args():
    ap = argparse.ArgumentParser(description="Interact with website on behalf of users")
    ap.add_argument("--keyId", required=True, type=int, help="Session Key Id from user")
    ap.add_argument("--items", required=True, help="")
    return ap.parse_args()

def main():
    args = parse_args()
    agent = build_agent()

    task = f"""
        Follow these steps exactly and output results cleanly.
        1. Go to http://localhost:3000/agent-login  
        2. Use get_nonce() to read the 32-hex nonce from the page.  
        3. Use get_session_key({args.keyId}) to get the base64 session key.  
        4. Compute the HMAC using: hmac_sha256_hex(<session_key>, <nonce>) 
        5. Login with login(<hmac_hex>, <{args.keyId}>).  
        6. After login, use get_items({args.items}) to get the requested data.  
        """
    out = agent.run(task + AGENT_SYSTEM_PROMPT)
    print("\n=== FINAL OUTPUT ===")
    print(out)

if __name__ == "__main__":
    try:
        main()
    finally:
        pass

