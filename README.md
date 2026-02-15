# 🔐 Zero Trust Network Access (ZTNA) Prototype  

A prototype implementation of **Zero Trust Network Access** using open-source tools:  
- **Keycloak** → Identity & Access Management (IAM)  
- **Flask** → Access Gateway + Policy Enforcement  
- **WireGuard** → Encrypted VPN tunnel provider  
- **iptables** → Role-based firewall enforcement  

---

## 📂 Project Structure
```
.
├── app4.py           # Flask Access Gateway
├── peer.json         # Peer database (dynamic WireGuard clients)
├── wg0.conf          # WireGuard base server configuration
├── firewall.sh       # Role-based firewall rules
└── README.md         # Project documentation
```

---

## ⚙️ Requirements
- Python 3.9+  
- Flask  
- requests  
- PyJWT  
- WireGuard installed on the gateway VM  
- Keycloak running on a separate VM  

Install Python dependencies:  
```bash
pip install flask requests pyjwt
```

---

## 🚀 Setup & Run

### 1. Keycloak (Authentication Server)
- Create a **Realm**: `Company`  
- Add a **Client**: `vpn-access-client` (confidential, OIDC enabled)  
- Configure redirect URI → `http://<flask_vm_ip>:5000/callback`  
- Create **roles**: `admin`, `developer`, `guest`  
- Assign roles to users and enable **MFA (TOTP)**  

### 2. WireGuard (VPN Server)
- Configure `wg0.conf` with server private/public keys  
- Enable IP forwarding and NAT:  
  ```bash
  sysctl -w net.ipv4.ip_forward=1
  ```
- Start service:  
  ```bash
  wg-quick up wg0
  ```

### 3. Flask Access Gateway
- Update **Keycloak URLs, client_id, and secret** inside `app4.py`  
- Run Flask:  
  ```bash
  python3 app4.py
  ```
- Routes:  
  - `/login` → Redirects to Keycloak  
  - `/callback` → Handles token exchange  
  - `/download-config` → Generates WireGuard config  
  - `/logout` → Revokes peer + session  

### 4. Firewall Enforcement
Apply role-based rules with:  
```bash
sudo bash firewall.sh
```

---

## 🧪 Tests
- ✅ Login with MFA → config generated  
- ✅ Session timeout (e.g., 3 min) → peer removed  
- ✅ Replay attack with expired token → rejected  
- ✅ Direct connection attempt to WireGuard bypassing Flask → denied  
- ✅ Brute force on credentials → blocked by MFA  

---

## 📌 Notes
- Access tokens are short-lived → Flask refreshes them automatically.  
- Refresh tokens expire based on Keycloak session lifetime.  
- All user traffic is forced through WireGuard → no direct access to resources.  
