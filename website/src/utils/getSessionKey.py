import subprocess, shlex, json, base64, os, re

here = os.path.dirname(__file__)

def _abs(p: str) -> str:
    return os.path.abspath(os.path.expanduser(p))

def _parse_last_json_line(stdout: str) -> dict:
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            return json.loads(line)
    raise ValueError("No JSON line found in Node output")

def fetch_session_keys(config_path: str, key_id: int):
    agent_dir = _abs(os.path.join(here, '../../../iotauth/entity/node/example_entities'))
    cmd = f'node website.js {shlex.quote(config_path)} keyId {int(key_id)}'
    p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30, cwd=agent_dir)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or p.stdout.strip() or "node error")

    data = _parse_last_json_line(p.stdout)
    print(data)
    session_key_value = []
    for k in data.get("session_keys", []):
        session_key_value.append({
            "id": int(k["id"]), 
            "cipherKey": (k["cipherKey_b64"]),  # bytes
            "macKey": base64.b64decode(k["macKey_b64"]),        # bytes
            "absValidity": k.get("absValidity"),
            "relValidity": k.get("relValidity"),
        })
    if not session_key_value:
        raise ValueError("Empty session_keys in JSON")
    return session_key_value


