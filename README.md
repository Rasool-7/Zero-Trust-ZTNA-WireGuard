# 🔐 Zero Trust Network Access (ZTNA) Implementation Using Open-Source Tools

---

## 📌 Overview

This project implements a **Zero Trust Network Access (ZTNA)** architecture using fully open-source technologies.  
The system follows the principle of *“Never Trust, Always Verify”* by enforcing strict identity validation, role-based access control, and continuous session monitoring.

---

## 🛠 Technologies Used

- **Keycloak** – Identity & Access Management (IAM)
- **WireGuard** – Secure VPN tunnel
- **Flask** – Access Gateway / Policy Enforcement Point (PEP)
- **VMware** – Virtual lab environment
- **Google Authenticator** – Multi-Factor Authentication (MFA)

---

## 🎯 Security Objectives

This implementation enforces:

- Continuous authentication
- Role-Based Access Control (RBAC)
- Dynamic WireGuard peer provisioning
- Session-based access revocation
- Least-privilege network segmentation
- Token expiration enforcement

---

## 🏗 Architecture

> Replace the placeholder below with your architecture diagram image if available.

```text
                 ┌──────────────────────┐
                 │        User          │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │     Keycloak (IAM)   │
                 │   OAuth2 + OIDC + MFA│
                 └──────────┬───────────┘
                            │  JWT Token
                            ▼
                 ┌──────────────────────┐
                 │     Flask Gateway    │
                 │ Token Validation     │
                 │ Role Verification    │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │    WireGuard Server  │
                 │ Dynamic Peer Config  │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │  Protected Resources │
                 └──────────────────────┘
```

---

## 🔁 Workflow

1. User authenticates via **Keycloak**.
2. Keycloak issues a signed **JWT token**.
3. Flask Gateway validates the JWT signature and claims.
4. If valid, a WireGuard peer configuration is dynamically generated.
5. A role-based IP address is assigned.
6. Firewall (`iptables`) rules enforce resource-level access.
7. When the token expires, the peer is automatically disabled.
8. Re-authentication is required to regain access.

---

## 🔒 Security Features

- OAuth2 + OpenID Connect (OIDC)
- Signed JWT validation
- Multi-Factor Authentication (TOTP)
- Role-based IP binding
- `iptables` network enforcement
- Continuous authentication checks
- Automatic session expiration & peer revocation
- Least-privilege access model

---

## 🧪 Testing & Validation

The system was tested for:

- Role isolation verification
- Unauthorized lateral movement prevention
- Token expiration enforcement
- Mandatory re-authentication
- Proper peer revocation
- Network segmentation integrity

---

## 📊 Zero Trust Principles Applied

| Principle | Implementation |
|------------|----------------|
| Verify Explicitly | OAuth2 + MFA via Keycloak |
| Least Privilege | Role-based IP assignment |
| Assume Breach | Network segmentation + firewall enforcement |
| Continuous Validation | Token expiration & peer revocation |

---

## 📚 Related Work

This implementation is inspired by:

- **NIST SP 800-207 – Zero Trust Architecture**
- Zero Trust VPN (ZT-VPN) framework
- WireGuard vs OpenVPN performance comparison studies

---

## 🚀 Future Improvements

- Device posture validation
- Hardware-based authentication (FIDO2)
- Automated certificate/key rotation
- SIEM integration for logging & monitoring
- Kubernetes-based deployment
- Policy engine enhancement (OPA integration)

---

## 📂 Project Structure (Example)

```text
/ztna-project
│
├── flask-gateway/
│   ├── app.py
│   ├── auth.py
│   └── peer_manager.py
│
├── wireguard/
│   ├── wg0.conf
│   └── peer_templates/
│
├── keycloak/
│   └── realm-config.json
│
└── README.md
```

---

## 📄 License

This project is developed for **educational and research purposes**.  
Feel free to fork and improve.

---


---

⭐ If you found this project useful, consider giving it a star!
