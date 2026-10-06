#!/usr/bin/env python3
"""
Import valid accounts from /Users/chinmayawasthi/grok2api/CPA
into Neon PostgreSQL as grok_build accounts.
Validates OAuth refresh token against https://auth.x.ai/oauth2/token before importing.
"""
import os, sys, json, base64, hashlib, secrets, socket, time
from datetime import datetime, timezone
import requests
import psycopg2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Config ────────────────────────────────────────────────────────────────────
CREDENTIAL_ENC_KEY_B64 = "YO0V+CVE7UKJKAZFggtnV9g+sxFuCnoLXjyeweNQQ0I="
DB_HOST = "ep-calm-art-b121900i-pooler.c-5.eu-central-1.aws.neon.tech"
CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
PROVIDER = "grok_build"
AUTH_TYPE = "oauth"

DIR_PATH = sys.argv[1] if len(sys.argv) > 1 else "/Users/chinmayawasthi/grok2api/CPA"

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

def compute_source_key(client_id: str, identity: str) -> str:
    joined = f"{PROVIDER}|{client_id}|{identity}"
    return "import:" + hash_token(joined)

def compute_identity_key(source_key: str) -> str:
    return hashlib.sha256(f"{PROVIDER}\x00{source_key}".encode()).hexdigest()

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

http_session = requests.Session()

def validate_and_refresh_token(refresh_tok: str):
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
        r = http_session.post(url, data=payload, headers=headers, timeout=12)
        if r.status_code == 200:
            data = r.json()
            new_access = data.get("access_token")
            new_refresh = data.get("refresh_token") or refresh_tok
            return True, new_access, new_refresh, None
        return False, None, None, f"HTTP {r.status_code}: {r.text[:80]}"
    except Exception as e:
        return False, None, None, str(e)

def main():
    target_dir = DIR_PATH
    if os.path.isdir(os.path.join(DIR_PATH, "CPA")):
        target_dir = os.path.join(DIR_PATH, "CPA")

    files = sorted([os.path.join(target_dir, f) for f in os.listdir(target_dir) if f.endswith(".json")])
    print(f"Scanning {len(files)} files in {target_dir}...")

    print("Connecting to Neon database (IPv4)...", end=" ", flush=True)
    db_ipv4 = socket.gethostbyname(DB_HOST)
    conn = psycopg2.connect(
        host=DB_HOST,
        hostaddr=db_ipv4,
        user="neondb_owner",
        password="npg_J9ZPKOTi3xHp",
        dbname="neondb",
        sslmode="require"
    )
    conn.autocommit = False
    cur = conn.cursor()
    print("Connected!\n", flush=True)

    now = datetime.now(timezone.utc)
    valid_count = 0
    invalid_count = 0
    inserted_count = 0
    updated_count = 0

    for idx, fpath in enumerate(files, 1):
        fname = os.path.basename(fpath)
        with open(fpath) as f:
            data = json.load(f)

        email = data.get("email", "").strip()
        user_id = data.get("sub", "").strip()
        refresh_tok = data.get("refresh_token", "").strip()
        access_tok = data.get("access_token", "").strip()

        if not refresh_tok:
            print(f"[{idx}/{len(files)}] [skip] {fname} ({email}): No refresh_token found")
            invalid_count += 1
            continue

        print(f"[{idx}/{len(files)}] Validating OAuth for {email} ...", end=" ", flush=True)
        is_valid, fresh_access, fresh_refresh, err = validate_and_refresh_token(refresh_tok)
        if not is_valid:
            print(f"INVALID ({err})")
            invalid_count += 1
            continue

        valid_count += 1
        access_tok = fresh_access or access_tok
        refresh_tok = fresh_refresh or refresh_tok

        # Parse JWT expiry
        claims = decode_jwt_payload(access_tok)
        exp_ts = claims.get("exp")
        expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else None
        team_id = claims.get("team_id", "").strip()
        if not user_id:
            user_id = claims.get("sub", "")

        identity = user_id or email.lower()
        source_key = compute_source_key(CLIENT_ID, identity)
        identity_key = compute_identity_key(source_key)

        enc_primary = encrypt(access_tok)
        enc_refresh = encrypt(refresh_tok)

        # Check if already exists in DB
        cur.execute("SELECT id FROM provider_accounts WHERE identity_key = %s", (identity_key,))
        existing = cur.fetchone()

        if existing:
            account_id = existing[0]
            cur.execute("""
                UPDATE account_credentials
                SET encrypted_primary = %s,
                    encrypted_refresh = %s,
                    expires_at = %s,
                    refresh_due_at = NULL,
                    last_refresh_at = NULL,
                    refresh_failures = 0,
                    refresh_unclassified_auth_failures = 0,
                    last_refresh_error_status = 0,
                    last_refresh_error = '',
                    last_refresh_error_message = '',
                    last_refresh_error_response = '',
                    refresh_permanent = FALSE,
                    updated_at = %s
                WHERE account_id = %s
            """, (enc_primary, enc_refresh, expires_at, now, account_id))

            cur.execute("""
                UPDATE provider_accounts
                SET email = %s,
                    user_id = %s,
                    team_id = %s,
                    source_key = %s,
                    enabled = TRUE,
                    auth_status = 'active',
                    updated_at = %s
                WHERE id = %s
            """, (email, user_id, team_id, source_key, now, account_id))
            print(f"VALID! Updated -> account_id={account_id}")
            updated_count += 1
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

            print(f"VALID! Inserted -> account_id={account_id}")
            inserted_count += 1

        # Populate capabilities for grok_build models
        build_models = ["grok-4.7", "grok-4.6", "grok-4.5", "grok-composer-2.5-fast"]
        for m in build_models:
            cur.execute("""
                INSERT INTO account_model_capabilities (account_id, upstream_model)
                VALUES (%s, %s)
                ON CONFLICT DO NOTHING
            """, (account_id, m))

    conn.commit()
    conn.close()

    print("\n" + "="*50)
    print(f"Total files:       {len(files)}")
    print(f"Valid OAuth tokens: {valid_count}")
    print(f"Invalid tokens:    {invalid_count}")
    print(f"Inserted to DB:    {inserted_count}")
    print(f"Updated in DB:     {updated_count}")
    print("="*50)

if __name__ == "__main__":
    main()
