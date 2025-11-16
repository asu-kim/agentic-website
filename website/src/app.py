import base64
import os
import sqlite3
import hashlib, hmac, binascii, os
import json
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify, g, make_response
from datetime import datetime, timezone
from flask_cors import CORS
from utils.getSessionKey import fetch_session_keys
from functools import wraps

app = Flask(__name__)
CORS(app)

fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

here = os.path.dirname(__file__)

DATABASE = "users.db"
CONFIG_PATH = 'configs/net1/website.config'
DB_PATH = os.path.join(os.path.dirname(__file__), DATABASE)

TRUST_LEVELS = ("high", "medium", "low")
SCOPES = ("email", "address", "cardNumber", "phone")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


SCHEMA_SQL = r"""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    email TEXT,
    address TEXT,
    cardNumber TEXT,
    phone TEXT
);

CREATE TABLE IF NOT EXISTS policies (
  username TEXT NOT NULL,
  trust_level TEXT NOT NULL,
  scope TEXT NOT NULL,
  allowed INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (username, trust_level, scope)
);
"""


def hmac_sha256_hex(key_bytes: bytes, msg_bytes: bytes) -> str:
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

@app.post("/api/agent/verify")
def agent_verify():
    data = request.get_json(silent=True) or {}
    token_id = data.get("token_id", "")
    nonce_hex = data.get("nonce_hex", "")
    user_hmac_hex = (data.get("user_hmac_hex", "") or "").lower()

    if not token_id or not nonce_hex or not user_hmac_hex:
        return jsonify(error="missing fields"), 400
    if not (len(nonce_hex) == 32 and all(c in "0123456789abcdefABCDEF" for c in nonce_hex)):
        return jsonify(error="invalid nonce format"), 400
    if not (len(user_hmac_hex) == 64 and all(c in "0123456789abcdef" for c in user_hmac_hex)):
        return jsonify(error="invajlid hmac format"), 400

    print('token id: ', token_id)
    # get token with session key ID 
    session_key_value = fetch_session_keys(CONFIG_PATH, int(token_id))
    session_key = session_key_value[0]["cipherKey"]
    session_validity = session_key_value[0]["relValidity"]
    agent_group = session_key_value[0]["owner"]

    print(session_key)
    if not session_key:
        return jsonify(error="Cannot get the session Key"), 401

    try:
        key_bytes = base64.b64decode(session_key)
        nonce_bytes = binascii.unhexlify(nonce_hex)
    except binascii.Error:
        return jsonify(error="bad hex"), 400

    server_hmac_hex = hmac_sha256_hex(key_bytes, nonce_bytes)  # website's calcuation result
    print(server_hmac_hex)

    ok = hmac.compare_digest(server_hmac_hex, user_hmac_hex)
    if not ok:
        return jsonify(error="verification failed"), 401
    
    if agent_group == "HighTrustAgents":
        trust_level = "high"
    elif agent_group == "MediumTrustAgents":
        trust_level = "medium"
    elif agent_group == "LowTrustAgents":
        trust_level = "low"
    else:
        return jsonify(error="Unrecognized agent trust level"), 401
    
    resp_json = {
        "ok": True,
        "trust_level": trust_level,
        "session_validity": session_validity,
    }

    # resp.set_cookie("session", session_token, httponly=True, secure=True, samesite="Strict")
    return jsonify(resp_json), 200



@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(SCHEMA_SQL)
    db.commit()



def hash_password(password: str, salt: str = None):
    if not salt:
        salt = os.urandom(16).hex()
    salted = salt + password
    hashed = hashlib.sha256(salted.encode()).hexdigest()
    return f"{salt}${hashed}"

def verify_password(stored_hash: str, password: str):
    try:
        salt, stored = stored_hash.split("$")
        check = hashlib.sha256((salt + password).encode()).hexdigest()
        return stored == check
    except Exception:
        return False
    
def is_allowed(username: str, trust_level: str, scope: str) -> bool:
    if trust_level not in TRUST_LEVELS or scope not in SCOPES:
        return False
    db = get_db()
    row = db.execute(
        "SELECT allowed FROM policies WHERE username = ? AND trust_level = ? AND scope = ?",
        (username, trust_level, scope),
    ).fetchone()
    if not row:
        return False
    return bool(row["allowed"])

def get_agent_from_request():
    return {"username": request.headers.get("X-user"), "trust_level": request.headers.get("X-Trust-Level")}

def require_scope(scope):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            agent = get_agent_from_request()
            if not agent:
                return jsonify(error="unauthorized"), 401
            if not is_allowed(agent["username"], agent["trust_level"], scope):
                return jsonify(error="forbidden", reason=f"scope '{scope}' not allowed for trust '{agent['trust_level']}'"), 403
            request.agent = agent
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@app.route("/api/policy", methods=["GET"])
def get_policy():
    username = request.args.get("username")
    if not username:
        return jsonify(error="username required"), 400

    db = get_db()
    out = {lvl: {s: False for s in SCOPES} for lvl in TRUST_LEVELS}
    for row in db.execute(
        "SELECT trust_level, scope, allowed FROM policies WHERE username = ?",
        (username,),
    ):
        out[row["trust_level"]][row["scope"]] = bool(row["allowed"])
    return jsonify({"username": username, "policy": out})


@app.route("/api/policy", methods=["POST"])
def save_policy():
    """
    Body: { "username": "<user>", "policy": { "low": {"email": true, ...}, "medium": {...}, "high": {...} } }
    """
    data = request.get_json(force=True)
    username = data.get("username")
    policy = data.get("policy", {})
    if not username or not isinstance(policy, dict):
        return jsonify(error="username and policy required"), 400

    db = get_db()
    for lvl in TRUST_LEVELS:
        scopes = policy.get(lvl, {}) or {}
        for s in SCOPES:
            allowed = 1 if scopes.get(s) else 0
            db.execute(
                """
                INSERT INTO policies (username, trust_level, scope, allowed)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(username, trust_level, scope)
                DO UPDATE SET allowed=excluded.allowed
                """,
                (username, lvl, s, allowed),
            )
    db.commit()
    return jsonify(status="ok")


@app.route("/api/resource/<scope>")
@require_scope(scope="dynamic")  
def get_resource(scope):
    return jsonify(error="misconfigured"), 500

@app.route("/api/resource/email")
@require_scope("email")
def res_email():
    username = request.agent["username"]
    db = get_db()
    row = db.execute("SELECT email FROM users WHERE username=?", (username,)).fetchone()
    return jsonify(email=(row["email"] if row and row["email"] else None))

@app.route("/api/resource/address")
@require_scope("address")
def res_address():
    username = request.agent["username"]
    db = get_db()
    row = db.execute("SELECT address FROM users WHERE username=?", (username,)).fetchone()
    return jsonify(address=(row["address"] if row and row["address"] else None))

@app.route("/api/resource/cardNumber")
@require_scope("cardNumber")
def res_card():
    username = request.agent["username"]
    db = get_db()
    row = db.execute("SELECT cardNumber FROM users WHERE username=?", (username,)).fetchone()
    return jsonify(cardNumber=(row["cardNumber"] if row and row["cardNumber"] else None))

@app.route("/api/resource/phone")
@require_scope("phone")
def res_phone():
    username = request.agent["username"]
    db = get_db()
    row = db.execute("SELECT phone FROM users WHERE username=?", (username,)).fetchone()
    return jsonify(phone=(row["phone"] if row and row["phone"] else None))



@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "Username or password is missing"}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        return jsonify({"success": False, "message": "Duplicated user"}), 400

    hashed_pw = hash_password(password)
    db.execute(
        "INSERT INTO users (username, password_hash, created_at, email, address, cardNumber, phone) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (username, hashed_pw, datetime.now(timezone.utc).isoformat(), "test@email.com", "1151 S Forest Ave, Tempe, AZ", "1234 1234 1234 1234", "000-000-0000")
    )
    db.commit()
    return jsonify({"success": True, "message": "Register success"}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    print(data)
    username = data.get("username", "")
    password = data.get("password", "")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user and verify_password(user["password_hash"], password):
        payload = {
            "user_id": user["id"],
            "username": user["username"],
            "last_seen": datetime.now(timezone.utc).isoformat()
        }
        token = fernet.encrypt(json.dumps(payload).encode()).decode()
        return jsonify({"success": True, "token": token}), 200
    else:
        return jsonify({"success": False, "message": "Log in failed"}), 401

@app.route("/verify-token", methods=["POST"])
def verify_token():
    data = request.json
    token = data.get("token")
    try:
        decrypted = fernet.decrypt(token.encode()).decode()
        return jsonify({"valid": True, "data": json.loads(decrypted)}), 200
    except Exception:
        return jsonify({"valid": False}), 401

if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(port=5000, debug=True)
