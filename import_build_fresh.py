#!/usr/bin/env python3
"""
Clean out reauthRequired build accounts and import fresh validated OAuth accounts.
"""
import os, sys, json, base64, hashlib, secrets, socket
from datetime import datetime, timezone
import requests
import psycopg2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CREDENTIAL_ENC_KEY_B64 = "YO0V+CVE7UKJKAZFggtnV9g+sxFuCnoLXjyeweNQQ0I="
DB_HOST = "ep-calm-art-b121900i-pooler.c-5.eu-central-1.aws.neon.tech"
DB_PASS = "npg_J9ZPKOTi3xHp"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"

AES_KEY = base64.b64decode(CREDENTIAL_ENC_KEY_B64)
_aesgcm = AESGCM(AES_KEY)
NONCE_SIZE = 12

def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    nonce = secrets.token_bytes(NONCE_SIZE)
    ct = _aesgcm.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).rstrip(b"=").decode()

def hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

def decode_jwt_payload(token: str) -> dict:
    try:
        parts = token.split(".")
        payload = parts[1]
        rem = len(payload) % 4
        if rem > 0:
            payload += "=" * (4 - rem)
        return json.loads(base64.urlsafe_b64decode(payload.encode()))
    except Exception:
        return {}

session = requests.Session()

def validate_and_refresh_oauth(refresh_tok: str):
    url = "https://auth.x.ai/oauth2/token"
    payload = {
        "grant_type": "refresh_token",
        "client_id": CLIENT_ID,
        "refresh_token": refresh_tok
    }
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    try:
        r = session.post(url, data=payload, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            new_access = data.get("access_token")
            new_refresh = data.get("refresh_token") or refresh_tok
            return True, new_access, new_refresh, None
        return False, None, None, f"HTTP {r.status_code}: {r.text[:60]}"
    except Exception as e:
        return False, None, None, str(e)

def main():
    print("Connecting to database...", end=" ", flush=True)
    db_ipv4 = socket.gethostbyname(DB_HOST)
    conn = psycopg2.connect(
        host=DB_HOST,
        hostaddr=db_ipv4,
        user="neondb_owner",
        password=DB_PASS,
        dbname="neondb",
        sslmode="require"
    )
    conn.autocommit = False
    cur = conn.cursor()
    print("Connected!\n", flush=True)

    # 1. Clean out dead reauthRequired build accounts
    cur.execute("SELECT id FROM provider_accounts WHERE provider = 'grok_build' AND auth_status = 'reauthRequired'")
    dead_ids = [r[0] for r in cur.fetchall()]
    if dead_ids:
        print(f"Cleaning out {len(dead_ids)} dead reauthRequired build accounts...")
        cur.execute("DELETE FROM account_credentials WHERE account_id = ANY(%s)", (dead_ids,))
        cur.execute("DELETE FROM account_model_capabilities WHERE account_id = ANY(%s)", (dead_ids,))
        cur.execute("DELETE FROM provider_accounts WHERE id = ANY(%s)", (dead_ids,))
        conn.commit()
        print(f"Cleaned {len(dead_ids)} accounts.\n")

    # 2. Gather fresh files
    fresh_dirs = [
        "/Users/chinmayawasthi/grok2api/20261003-134026/CPA",
        "/Users/chinmayawasthi/grok2api/20261003-130920/CPA",
        "/Users/chinmayawasthi/grok2api/20261003-124848/CPA",
        "/Users/chinmayawasthi/grok2api/20261003-030719/CPA",
        "/Users/chinmayawasthi/grok2api/20261003-013339/CPA",
    ]
    files = []
    # 060153 files 10:20
    split_dir = "/Users/chinmayawasthi/grok2api/20261004-060153/CPA"
    if os.path.exists(split_dir):
        files.extend(sorted([os.path.join(split_dir, f) for f in os.listdir(split_dir) if f.endswith(".json")])[10:20])

    for d in fresh_dirs:
        if os.path.isdir(d):
            files.extend(sorted([os.path.join(d, f) for f in os.listdir(d) if f.endswith(".json")]))

    print(f"Found {len(files)} target files for grok_build...")

    build_models = ["grok-4.7", "grok-4.6", "grok-4.5", "grok-composer-2.5-fast"]
    now = datetime.now(timezone.utc)
    inserted = 0

    for idx, fpath in enumerate(files, 1):
        with open(fpath) as f:
            data = json.load(f)
        email = data.get("email", "").strip()
        user_id = data.get("sub", "").strip()
        refresh_tok = data.get("refresh_token", "").strip()

        print(f"[{idx}/{len(files)}] Refreshing {email} ({os.path.basename(fpath)})...", end=" ", flush=True)
        ok, new_access, new_refresh, err = validate_and_refresh_oauth(refresh_tok)
        if not ok:
            print(f"FAILED ({err})")
            continue

        source_key = "import:" + hash_token(f"grok_build|{CLIENT_ID}|{user_id}")
        identity_key = hashlib.sha256(f"grok_build\x00{source_key}".encode()).hexdigest()

        jwt_payload = decode_jwt_payload(new_access)
        exp_ts = jwt_payload.get("exp")
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else None
        team_id = jwt_payload.get("team_id", "").strip()

        enc_primary = encrypt(new_access)
        enc_refresh = encrypt(new_refresh)

        cur.execute("SELECT id FROM provider_accounts WHERE source_key = %s", (source_key,))
        row = cur.fetchone()
        if row:
            account_id = row[0]
            cur.execute("""
                UPDATE provider_accounts
                SET email = %s, user_id = %s, team_id = %s, enabled = TRUE, auth_status = 'active', updated_at = %s
                WHERE id = %s
            """, (email, user_id, team_id, now, account_id))
            cur.execute("""
                UPDATE account_credentials
                SET encrypted_primary = %s, encrypted_refresh = %s, expires_at = %s,
                    last_refresh_error = '', last_refresh_error_message = '',
                    refresh_failures = 0, updated_at = %s
                WHERE account_id = %s
            """, (enc_primary, enc_refresh, expires_at, now, account_id))
            print(f"SUCCESS -> Updated active account_id={account_id}")
        else:
            cur.execute("""
                INSERT INTO provider_accounts
                    (identity_key, provider, name, email, user_id, team_id, source_key,
                     enabled, auth_status, priority, max_concurrent, minimum_remaining,
                     failure_count, build_api_fallback, build_route_mode,
                     build_super_entitled, egress_node_id, egress_assignment_mode,
                     created_at, updated_at)
                VALUES
                    (%s, 'grok_build', %s, %s, %s, %s, %s,
                     TRUE, 'active', 1, 8, 0.0,
                     0, FALSE, 'auto',
                     FALSE, NULL, '',
                     %s, %s)
                RETURNING id
            """, (identity_key, email, email, user_id, team_id, source_key, now, now))
            account_id = cur.fetchone()[0]

            cur.execute("""
                INSERT INTO account_credentials
                    (account_id, auth_type, client_id,
                     encrypted_primary, encrypted_refresh, encrypted_cloudflare_cookie,
                     expires_at, refresh_due_at, last_refresh_at,
                     refresh_failures, refresh_unclassified_auth_failures,
                     last_refresh_error_status, last_refresh_error, last_refresh_error_message,
                     last_refresh_error_response, refresh_permanent, build_bot_flag_source,
                     updated_at)
                VALUES
                    (%s, 'oauth', %s,
                     %s, %s, '',
                     %s, NULL, NULL,
                     0, 0, 0, '', '', '', FALSE, 0,
                     %s)
            """, (account_id, CLIENT_ID, enc_primary, enc_refresh, expires_at, now))
            inserted += 1
            print(f"SUCCESS -> Inserted active account_id={account_id}")

        for m in build_models:
            cur.execute("""
                INSERT INTO account_model_capabilities (account_id, upstream_model)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, (account_id, m))

    conn.commit()
    conn.close()

    print("\n" + "="*50)
    print(f"Build accounts import complete! Total inserted/updated: {inserted}")
    print("="*50)

if __name__ == "__main__":
    main()
