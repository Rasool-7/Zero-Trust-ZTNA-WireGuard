from flask import Flask, redirect, request, jsonify, send_file, session, render_template_string, render_template
import requests
import jwt
import os
import subprocess
import tempfile
import json
import time
from functools import wraps
from jwt import PyJWKClient
from datetime import datetime, timedelta, timezone
from threading import Timer

app = Flask(__name__)
app.secret_key = "rasool"

# --- Keycloak Config ---
KEYCLOAK_URL = "http://192.168.39.128:8080"
REALM = "Company"
CLIENT_ID = "vpn-access-client"
CLIENT_SECRET = "0zheIKn2m3ENVfj9fjFcrTy3MhTQ1JIp"
REDIRECT_URI = "http://192.168.39.129:5000/callback"

# --- OAuth2 Endpoints ---
AUTH_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token"
JWKS_URL = f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/certs"

# --- WireGuard Config ---
WG_SERVER_PUBLIC_KEY = "TJmL+jaJX546+h2F1TOgid4EpRcbqoG5xgokLJS2By8="
WG_ENDPOINT = "192.168.39.129:51820"
WG_ALLOWED_IPS = "192.168.139.128/32"
WG_INTERFACE = "wg0"
PEER_DB = "peer.json"

# --- Utility Functions ---
def schedule_cleanup():
    cleanup_expired_peers()
    Timer(60, schedule_cleanup).start()  # Run every 60s
def assign_ip(username, roles):
    def hash_index(name, size):
        return sum(ord(c) for c in name) % size

    if "admin" in roles:
        base_ip = 16
        index = hash_index(username, 2)
        return f"10.10.0.{base_ip + index}/32"
    elif "developer" in roles:
        base_ip = 32
        index = hash_index(username, 4)
        return f"10.10.0.{base_ip + index}/32"
    elif "guest" in roles:
        base_ip = 64
        index = hash_index(username, 8)
        return f"10.10.0.{base_ip + index}/32"
    else:
        raise Exception("Unknown role or no valid role assigned.")
def generate_peer(username, roles):
    private_key = subprocess.check_output("wg genkey", shell=True).decode().strip()
    public_key = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode().strip()
    client_ip = assign_ip(username, roles)
    # Set peer expiry time (e.g., 1  X now)
    expiry_minutes = 30
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)
    
    peer = {
        "private_key": private_key,
        "public_key": public_key,
        "ip": client_ip,
        "enabled": True,
        "expires_at": expires_at.timestamp()
    }

    peers = load_peers()
    peers[username] = peer
    save_peers(peers)
    ensure_peer_enabled(public_key, client_ip)
    return peer

def load_peers():
    if not os.path.exists(PEER_DB):
        return {}
    with open(PEER_DB, "r") as f:
        return json.load(f)

def save_peers(peers):
    with open(PEER_DB, "w") as f:
        json.dump(peers, f, indent=4)

def ensure_peer_enabled(public_key, client_ip):
    subprocess.run([
        "sudo", "wg", "set", WG_INTERFACE,
        "peer", public_key,
        "allowed-ips", client_ip
    ], check=True)

def disable_peer(public_key, client_ip):
    subprocess.run([
        "sudo", "wg", "set", WG_INTERFACE, "peer", public_key, "allowed-ips", client_ip, "remove"], check=True)
def should_refresh_token():
    exp = session.get("access_token_exp")
    if not exp:
        return True  # If no expiry stored, better to refresh

    remaining = exp - int(time.time())
    return remaining < 30  # Refresh only if access token will expire in next 30 seconds

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("access_token")
        refresh_token = session.get("refresh_token")

        if not token:
            print("[Session] No access token found.")
            return redirect("/login")

        # ? Hard session limit (e.g., 3 minutes)
        session_start = session.get("session_start", 0)
        if time.time() - session_start > 180:  # 3 * 60
            print("[Session] Hard session expired, force logout.")
            # ? Disable peer
            username = session.get("username")
            peers = load_peers()
            if username in peers:
                peer = peers[username]
                if peer.get("enabled"):
                    print(f"[Session Expired] Disabling peer for {username}")
                    disable_peer(peer["public_key"], peer["ip"])
                    peer["enabled"] = False
                    save_peers(peers)

            session.clear()
            return redirect("/logout")

        # ? Refresh token expiry check
        refresh_exp = session.get("refresh_token_exp", 0)
        if time.time() > refresh_exp:
            print("[Token] Refresh token expired, force logout.")
            # ? Disable peer
            username = session.get("username")
            peers = load_peers()
            if username in peers:
                peer = peers[username]
                if peer.get("enabled"):
                    print(f"[Refresh Expired] Disabling peer for {username}")
                    disable_peer(peer["public_key"], peer["ip"])
                    peer["enabled"] = False
                    save_peers(peers)
            session.clear()
            return redirect("/logout")

        # ? Refresh access token if it's about to expire
        if should_refresh_token():
            print("[Access Token] About to expire, refreshing...")
            if not refresh_token:
                print("[Token] No refresh token found.")
                session.clear()
                return redirect("/logout")

            data = {
                "grant_type": "refresh_token",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "refresh_token": refresh_token
            }
            resp = requests.post(TOKEN_URL, data=data)
            if resp.status_code != 200:
                print("[Token Refresh] Failed to refresh token.")
                session.clear()
                return redirect("/logout")

            new_token_data = resp.json()
            session["access_token"] = new_token_data["access_token"]
            session["refresh_token"] = new_token_data.get("refresh_token", refresh_token)

            # Decode and store new expiration
            access_decoded = jwt.decode(session["access_token"], options={"verify_signature": False})
            refresh_decoded = jwt.decode(session["refresh_token"], options={"verify_signature": False})
            session["access_token_exp"] = access_decoded["exp"]
            # For real use it is 30 min
            #session["refresh_token_exp"] = refresh_decoded["exp"]
            #For testing we put it 2 min
            session["refresh_token_exp"] = int(time.time())+120 #
            print("\n=== TOKEN INFO (Refreshed) ===")
            print(f"Access Token: {session['access_token']}")
            print(f"Access Token Expires At: {datetime.fromtimestamp(access_decoded['exp'])}")
            #print(f"Refresh Token Expires At: {datetime.fromtimestamp(refresh_decoded['exp'])}")
            simulated_exp = session.get("refresh_token_exp", refresh_decoded["exp"])
            print(f"Refresh Token Expires At: {datetime.fromtimestamp(simulated_exp)} (simulated for testing)")
            print("===============================\n")

        # ? Decode access token to confirm user info
        try:
            jwks_client = PyJWKClient(JWKS_URL)
            signing_key = jwks_client.get_signing_key_from_jwt(session["access_token"]).key
            decoded = jwt.decode(session["access_token"], signing_key, algorithms=["RS256"], options={"verify_aud": False})
            session["username"] = decoded.get("preferred_username")
            session["roles"] = decoded.get("realm_access", {}).get("roles", [])
        except Exception as e:
            print(f"[JWT Error] {e}")
            session.clear()
            return redirect("/login")

        return f(*args, **kwargs)
    return decorated

@app.route('/')
@token_required
def index():
    access_token = session.get('access_token')
    username = session.get('username')

    if not username:
        return redirect(url_for('login'))

    peers = load_peers()
    peer_info = peers.get(username)


    if peer_info:
        now = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(peer_info['expires_at'], timezone.utc)
        peer_valid = expires_at > now
        remaining_minutes = int((expires_at - now).total_seconds() / 60)

        return render_template('index.html',
                               username=username,
                               peer_exists=True,
                               peer_valid=peer_valid,
                               expires_at=expires_at.strftime('%Y-%m-%d %H:%M:%S UTC'),
                               remaining_minutes=remaining_minutes)
    else:
        # No peer exists_user likely just logged in_let /download_config handle generation
        return render_template('index.html', username=username, peer_exists=False)

@app.route("/login")
def login():
    return redirect(
        f"{AUTH_URL}?client_id={CLIENT_ID}&response_type=code&scope=openid&redirect_uri={REDIRECT_URI}"
    )

@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "Error: no code in callback", 400

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    token_response = requests.post(TOKEN_URL, data=data)
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    refresh_token = token_json.get("refresh_token")

    if not access_token:
        return "Login failed", 401

    session["access_token"] = access_token
    session["refresh_token"] = refresh_token

    # Parse token for username and roles
    jwks_client = PyJWKClient(JWKS_URL)
    signing_key = jwks_client.get_signing_key_from_jwt(access_token).key
    decoded = jwt.decode(access_token, signing_key, algorithms=["RS256"], options={"verify_aud": False})
    username = decoded.get("preferred_username")
    roles = decoded.get("realm_access", {}).get("roles", [])

    session["username"] = username
    session["roles"] = roles

    # Enable existing peer if present
    peers = load_peers()
    if username in peers:
        peer = peers[username]
        now= time.time()
        if peer.get("expires_at",0) > now:
          peer["enabled"] = True
          ensure_peer_enabled(peer["public_key"], peer["ip"])
          save_peers(peers)
          print(f"[Login] Re-enabled peer for {username}")
        else:
          print(f"[Login] Peer for {username} expired, will regenerate at /download-config.")

    # Decode tokens to print expiry info
    access_decoded = jwt.decode(access_token, options={"verify_signature": False})
    refresh_decoded = jwt.decode(refresh_token, options={"verify_signature": False})
    # Save expiration times in session
    session["access_token_exp"] = access_decoded["exp"]
    #session["refresh_token_exp"] = refresh_decoded["exp"]
    session["refresh_token_exp"] = int(time.time())+120
    session["session_start"] = time.time()


    access_exp = datetime.fromtimestamp(access_decoded['exp'], timezone.utc)
    refresh_exp = datetime.fromtimestamp(refresh_decoded['exp'], timezone.utc)
    now = datetime.now(timezone.utc)

    print("\n=== TOKEN INFO (Login) ===")
    print(f"Access Token: {access_token}")
    print(f"Access Token Expires At: {access_exp} ({(access_exp - now).seconds} seconds from now)")
    print()
    print(f"Refresh Token: {refresh_token}")
    #print(f"Refresh Token Expires At: {refresh_exp} ({(refresh_exp - now).seconds} seconds from now)")
    simulated_exp = session.get("refresh_token_exp", int(time.time()) + 120)
    print(f"Refresh Token Expires At: {datetime.fromtimestamp(simulated_exp)} (simulated for testing)")

    print(f"Logged in user: {username} with roles: {roles}")
    print("===========================\n")

    return redirect("/")

@app.route("/download-config")
@token_required
def download_config():
    username = session.get("username")
    roles = session.get("roles")
    peers = load_peers()

    if username in peers:
        peer = peers[username]
        if peer.get("expires_at", 0) < time.time():
          print(f"[Download] Peer expired for {username}, regenerating...")
          peer = generate_peer(username, roles)
    else:
        peer = generate_peer(username, roles)


    config_content = f"""
[Interface]
PrivateKey = {peer['private_key']}
Address = {peer['ip']}
DNS = 10.0.0.1

[Peer]
PublicKey = {WG_SERVER_PUBLIC_KEY}
Endpoint = {WG_ENDPOINT}
AllowedIPs = {WG_ALLOWED_IPS}
PersistentKeepalive = 25
"""

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".conf")
    tmp.write(config_content.encode())
    tmp.close()

    return send_file(tmp.name, as_attachment=True, download_name=f"{username}.conf")

@app.route("/logout")
def logout():
    username = session.get("username")
    peers = load_peers()
    if username in peers:
        peer = peers[username]
        peer["enabled"] = False
        disable_peer(peer["public_key"], peer["ip"])
        save_peers(peers)

    session.clear()
    logout_url = (
        f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/logout"
        f"?client_id={CLIENT_ID}"
        f"&post_logout_redirect_uri=http://192.168.39.129:5000/"
    )
    return redirect(logout_url)
def cleanup_expired_peers():
    peers = load_peers()
    now = time.time()
    changed = False
    for username, peer in peers.items():
        if peer.get("enabled") and peer.get("expires_at", 0) < now:
            print(f"[Cleanup] Disabling expired peer: {username}")
            disable_peer(peer["public_key"], peer["ip"])
            peer["enabled"] = False
            changed = True
    if changed:
        save_peers(peers)


if __name__ == "__main__":
    schedule_cleanup()
    app.run(host="0.0.0.0", port=5000)
