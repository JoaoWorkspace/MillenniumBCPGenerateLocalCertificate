# Millennium BCP Certificate Generator

This script (`generate_certificate.py`) automates the **entire certificate provisioning flow** for Millennium BCP’s SOAP API.  
The bank requires a **client certificate** for authentication in its Internet Banking for Companies (MCertificados).

---

## 📋 Flow Overview
1. **CreateLogin** → establish an initial login session.  
2. **ValidaChave** → validate the activation key with the bank’s systems.  
3. **GenerateCertificate** → generate the final X.509 certificate bound to your user.  

The script:
- Handles SOAP requests to Millennium BCP.  
- Encrypts all sensitive payloads with the **bank’s public certificate**.  
- Generates a **private key (local)** and matching **CSR**.  
- Receives the **signed certificate (public)** from Millennium BCP.  
- Builds a **PFX (PKCS#12)** file containing both private + public certificates.  

The resulting `.pfx` is installable on your OS/browser for client authentication.

---

## 🔑 Cryptography: Public vs Private Keys

### 1. Bank’s Public Key
- Distributed as `MCertificados.Certificates.comcert.cer`.  
- Used to **encrypt sensitive messages** to the SOAP API.  
- Only Millennium BCP can decrypt them.

### 2. Your Private Key
- Generated locally when creating the CSR.  
- **Never leaves your machine.**  
- Critical for proving your identity.  
- Saved as `{CertificateFriendlyName}_private_key.pem`.

### 3. Your Certificate (Signed by BCP)
- CSR contains your **public key**.  
- Sent via SOAP → `GenerateCertificate`.  
- Signed by BCP’s CA.  
- Returned as a valid X.509 certificate.  
- Bundled with your private key to create `.pfx`.

---

## 📂 Files Produced

- `private_key.pem` → your **private key** (keep secure!).  
- `certificate.pem` → the signed certificate from Millennium BCP.  
- `certificate.pfx` → PKCS#12 bundle (private + public), optionally password-protected.  
- `response_generate.xml` → raw SOAP response for audit/debug.

---

## ⚙️ Usage

### 1. Run the script
```bash
python generate_certificate.py
```
The script will:
- Generate RSA keypair.
- Perform SOAP calls (CreateLogin, ValidaChave, SendAuthenticationMessage, GenerateCertificate).
- Parse the response and build a .pfx.

---

### 2. Install the Certificate

#### Windows (Chrome / Edge / IE)
1. Double-click the `.pfx` file.  
2. Choose **Import to Current User → Personal store**.  
3. Enter the PFX password (if set).  
4. Verify installation:  
   - Run `certmgr.msc`  
   - Navigate to **Personal → Certificates**  
   - You should see the certificate with the message:  
     **“You have a private key that corresponds to this certificate.”**

#### Firefox
1. Open **Preferences → Privacy & Security → Certificates → View Certificates**.  
2. Import the `.pfx` file.  

---

### 3. Test in Browser
1. Visit the Millennium BCP portal.  
2. Browser detects that the server requires **client authentication**.  
3. You’ll be prompted to select your installed certificate.  
4. Authentication proceeds using the certificate you generated and installed.  

---

## 🖼️ Key Flow Diagram

```text
                ┌───────────────────────┐
                │  Bank Public Key (CER)│
                │   (encrypt SOAP data) │
                └──────────┬────────────┘
                           │
                           ▼
                 ┌─────────────────┐
                 │   SOAP Request  │
                 │ (CreateLogin,   │
                 │  ValidaChave,   │
                 │  GenerateCert)  │
                 └─────────────────┘
                           │
   ┌───────────────────────┴─────────────────────────┐
   │                                                 │
   ▼                                                 ▼
Local Machine                                Millennium BCP
─────────────                                ───────────────
Generate RSA Keypair                         Receives CSR
(private + public)                           Signs CSR → Issues Certificate
        │                                            │
        │                                            │
        ▼                                            ▼
Private Key (PEM)                             Signed Certificate (PEM)
(saved locally, never sent)                   (returned via SOAP)
        │                                            │
        └──────────────┬─────────────────────────────┘
                       ▼
              Build PKCS#12 (PFX)
        (Private Key + Signed Certificate)
                       │
                       ▼
         ┌──────────────────────────┐
         │   Install into Browser   │
         │  (Windows, Firefox, etc) │
         └─────────────┬────────────┘
                       ▼
        Browser uses PFX for TLS mutual auth
        when connecting to Millennium BCP
```

## 🛡️ Security Notes

- Keep private_key.pem safe – compromise = identity theft.
- Use password-protected PFX (BestAvailableEncryption).
- Never share PEM or PFX outside secure environments.
- Rotate/revoke certificate if compromised.

## 🧩 Why This Works

- Requests to Millennium BCP SOAP API are encrypted with the bank’s public key.
- The CSR proves you control a keypair; the bank signs and issues a certificate.
- Combining your private key + issued certificate → a .pfx for browser auth.
- Browsers use this PFX for TLS mutual authentication with Millennium BCP.
