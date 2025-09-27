#!/usr/bin/env python3
"""
generate_certificate_bcp_refactored.py

- Full Millennium BCP flow: CreateLogin → ValidaChave → GenerateCertificate(NONE) → SendAuthenticationMessage(SMS) → GenerateCertificate(SMS)
- Generates CSR, encrypts payloads with bank public cert, handles SOAP requests
- Saves private key and returned PFX
"""

import base64, getpass, json, os, requests, sys
from datetime import datetime, timezone
from lxml import etree, html
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization        
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

# ---------- DEBUG ----------
DEBUG = "--debug" in sys.argv

# ---------- CONFIG ----------
CERT_PATH = "MCertificados.Certificates.comcert.cer"
ENDPOINT = "https://emp.millenniumbcp.pt/webpages/UIOpenServices/Certificates.asmx"
SOAP_ACTION_CREATELOGIN = "http://millenniumbcp.pt/CreateLogin"
SOAP_ACTION_VALIDACHAVE = "http://millenniumbcp.pt/ValidaChave"
SOAP_ACTION_SENDAUTHENTICATIONMESSAGE = "http://millenniumbcp.pt/sendAuthenticationMessage"
SOAP_ACTION_GENERATE = "http://millenniumbcp.pt/GenerateCertificate"
OUTPUT_DIR = os.path.abspath("output_mcert")
CHUNK_SIZE = 80  # bytes for RSA encryption
SESSION = requests.Session()

# ---------- HARDCODED CREDENTIALS ----------
USERNAME = ""                           # UserCode
PASSWORD = ""                           # UserPassword
LANGUAGE = ""                           # Language
CERTIFICATE_ACTIVATION_KEY = ""         # CertificateActivationKey
CERTIFICATE_NAME = ""                   # The FriendlyName for the certificate I'm generating

# ---------- UTILITY FUNCTIONS ----------
def load_public_key(cert_path: str):
    with open(cert_path, "rb") as f:
        data = f.read()
    try:
        cert = x509.load_pem_x509_certificate(data)
        if cert: print("Public Key Certificate Ready")
    except ValueError:
        cert = x509.load_der_x509_certificate(data)
    return cert.public_key()

def encrypt_string_dotnet(input_str: str, public_key) -> str:
    input_bytes = input_str.encode("utf-8")
    chunks = []
    for i in range(0, len(input_bytes), CHUNK_SIZE):
        chunk = input_bytes[i:i + CHUNK_SIZE]
        encrypted = public_key.encrypt(
            chunk,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA1()),
                         algorithm=hashes.SHA1(), label=None)
        )
        chunks.append(base64.b64encode(encrypted).decode("ascii"))
    return "\n".join(chunks)


def escape_xml(s: str) -> str:
    return (s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&apos;"))


def soap_post(session: requests.Session, xml_body: str, action: str):
    headers = {
        "Content-Type": "text/xml; charset=utf-8", 
        "SOAPAction": action,
        "User-Agent": "Mozilla/5.0"
    }
    resp = session.post(ENDPOINT, data=xml_body.encode("utf-8"), headers=headers, allow_redirects=True)
    return resp.text


def build_soap_envelope(action_tag: str, input_str: str) -> str:
    return f"""<?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                       xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                       xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
          <soap:Body>
            <{action_tag} xmlns="http://millenniumbcp.pt/">
              <inputStr>{escape_xml(input_str)}</inputStr>
            </{action_tag}>
          </soap:Body>
        </soap:Envelope>"""

def generate_csr(friendly_name: str) -> tuple[str, bytes]:
    """
    Generate a Certificate Signing Request (CSR) and RSA private key.

    This function replicates the behavior of the .NET method:
    `CertificateUtils.GenerateCSR(string name)` which internally uses
    Microsoft's X509Enrollment COM interfaces.

    Steps:
    1. Generate a 2048-bit RSA private key (non-exportable, user context).
    2. Construct a subject CN (Common Name) following the .NET pattern:
           "MillenniumBCP <friendly_name> <timestamp>"
       where the timestamp is UTC in "YYYY-MM-DD HH:MM:SS" format.
    3. Build a PKCS#10 CSR with:
       - Subject Name: CN as above
       - Key Usage (critical): DigitalSignature, KeyEncipherment
       - Extended Key Usage (EKU): Client Authentication (1.3.6.1.5.5.7.3.2)
    4. Sign the CSR with SHA-256.
    5. Return the CSR in Base64-encoded DER format (equivalent to
       `EncodingType.XCN_CRYPT_STRING_BASE64` in .NET).
    6. Return the private key in PEM format for local storage.

    Args:
        friendly_name (str): User-friendly name to embed in the certificate CN.

    Returns:
        tuple[str, bytes]:
            csr_b64 (str)  : Base64 string of the DER-encoded PKCS#10 CSR.
                             This is what must be sent to the SOAP service.
            key_pem (bytes): PEM-encoded private RSA key for secure storage.

    Example:
        >>> csr_b64, private_key = generate_csr("TestUser")
        >>> print(csr_b64[:60])
        "MIICvDCCAaQCAQAwgZMxCzAJBgNVBAYTAk5MMRMwEQYDVQQIDAp..."
        >>> open("private.key", "wb").write(private_key)

    Notes:
        - This mirrors the .NET code that uses:
          `CX509CertificateRequestPkcs10`, `CX509PrivateKey`,
          `CX509EnrollmentClass`, etc.
        - The generated CSR is intended for submission to
          MillenniumBCP's SOAP method `GenerateCertificate`.
        - The private key **must** be preserved, as it will be needed
          to install the signed certificate once issued.
    """
    # Generate private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # Subject name: matches .NET pattern "MillenniumBCP <friendly_name> <timestamp>"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    subject_cn = f"MillenniumBCP {friendly_name} {timestamp}"
    print(subject_cn)
    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)
        ]))
        # .NET KeyUsage: DigitalSignature + KeyEncipherment
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extended Key Usage: ClientAuth
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    )

    # Sign CSR with SHA256
    csr = csr_builder.sign(key, hashes.SHA256())

    # Export CSR as Base64 DER (matches .NET CreateRequest XCN_CRYPT_STRING_BASE64)
    csr_der = csr.public_bytes(serialization.Encoding.DER)
    csr_b64 = base64.b64encode(csr_der).decode("ascii")

    # Export private key (PEM format)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    return csr_b64, key_pem

def save_file(blob: bytes, filename: str) -> str:
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(blob)
    return path

def log_soap_response(xml_response:str, step:int):
    response_path = save_file(xml_response.encode("utf-8"), f"step_{step}_response.xml")
    print(f"Raw SOAP response saved to {response_path}")

# ---------- Flow Functions ----------
def create_login(username: str, password: str, language: str, public_key):
    payload = {"UserName": username, "Password": password, "Language": language}
    json_payload = json.dumps(payload, separators=(",", ":"))
    encrypted_payload = encrypt_string_dotnet(json_payload, public_key)
    xml = build_soap_envelope("CreateLogin", encrypted_payload)
    resp = soap_post(SESSION, xml, SOAP_ACTION_CREATELOGIN)
    return resp

# --- Will Extract from LoginResponse the Digital Certificate Unique Code Positions ---
# EXAMPLE LoginResponse:
# <?xml version="1.0" encoding="utf-8"?>
#   <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
#       <soap:Body>
#           <CreateLoginResponse xmlns="http://millenniumbcp.pt/"><CreateLoginResult>
#               <Status><success>true</success></Status>
#               <PosicoesChaveAtivacao><string>14</string><string>5</string><string>3</string><string>7</string><string>8</string></PosicoesChaveAtivacao>
#           </CreateLoginResult></CreateLoginResponse>
#       </soap:Body>
#   </soap:Envelope>
def extract_positions_from_response(xml_response: str) -> list[str]:
    """Extracts the dynamic positions requested by the bank."""
    ns = {'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
          'ns': 'http://millenniumbcp.pt/'}
    root = etree.fromstring(xml_response.encode("utf-8"))
    body = root.find('soap:Body', ns)
    if body is None:
        body = root.find(".//{http://schemas.xmlsoap.org/soap/envelope/}Body")
    pos_nodes = body.findall('.//ns:PosicoesChaveAtivacao/ns:string', ns) or \
                body.findall('.//PosicoesChaveAtivacao/string')
    return [int(n.text) for n in pos_nodes]


def valida_chave(cert_activation_key: str, positions: list[int], public_key):
    # Make sure we have exactly 5 positions as strings
    digits = [str(cert_activation_key[p-1]) for p in positions]  # force string
    payload = {"Posicoes": digits}  # matches the .NET expectation
    json_payload = json.dumps(payload, separators=(",", ":"))
    encrypted_payload = encrypt_string_dotnet(json_payload, public_key)
    xml = build_soap_envelope("ValidaChave", encrypted_payload)
    resp = soap_post(SESSION, xml, SOAP_ACTION_VALIDACHAVE)
    return resp

# --- Will Extract the Success Element ---
# EXAMPLE ValidaChaveResponse:
# <?xml version="1.0" encoding="utf-8"?>
#   <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
#       <soap:Body>
#           <ValidaChaveResponse xmlns="http://millenniumbcp.pt/"><ValidaChaveResult>
#               <CredentialType>SMS</CredentialType>
#               <Status>
#                   <errorList><BridgeError><errorCode>1</errorCode><errorDescription>-</errorDescription></BridgeError></errorList>
#                   <success>true</success>
#               </Status>
#           </ValidaChaveResult></ValidaChaveResponse>
#       </soap:Body>
#   </soap:Envelope>
def extract_success_from_response(xml_response: str) -> bool:
    """
    Looks for any <success> node in the SOAP response and returns True if any are 'true'.
    """
    ns = {
        "soap": "http://schemas.xmlsoap.org/soap/envelope/",
        "m": "http://millenniumbcp.pt/"
    }
    root = etree.fromstring(xml_response.encode("utf-8"))

    # findall will search for all <success> elements under the Millennium namespace
    success_nodes = root.findall(".//m:success", ns)
    for node in success_nodes:
        if node.text and node.text.strip().lower() == "true":
            return True
    return False

def send_authentication_message(activation_type: str, public_key):
    payload = {"CredentialType": activation_type}  # SMS
    json_payload = json.dumps(payload, separators=(",", ":"))
    encrypted_payload = encrypt_string_dotnet(json_payload, public_key)
    xml = build_soap_envelope("sendAuthenticationMessage", encrypted_payload)
    resp = soap_post(SESSION, xml, SOAP_ACTION_SENDAUTHENTICATIONMESSAGE)
    return resp

def generate_certificate(csr_b64: str, friendly_name: str, credential_type: str, sms_code: str = "", public_key=None):
    """
    Generate a certificate via SOAP API.

    Args:
        csr_b64 (str): Base64 CSR
        friendly_name (str): Friendly certificate name
        credential_type (str): "NONE" for registration, "SMS" for final SMS submission
        sms_code (str, optional): SMS code if credential_type="SMS"
        public_key: Public key for encryption

    Returns:
        str: SOAP response
    """
    payload = {
        "CardNumber": "",
        "CredentialType": credential_type,
        "ChaveCodigoAtivacao": sms_code if credential_type == "SMS" else "",
        "CertificateRequest": csr_b64,
        "CertificateName": f"MillenniumBCP {friendly_name} {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}"
    }
    json_payload = json.dumps(payload, separators=(",", ":"))
    encoded_payload = encrypt_string_dotnet(json_payload, public_key)
    xml = build_soap_envelope("GenerateCertificate", encoded_payload)
    resp = soap_post(SESSION, xml, SOAP_ACTION_GENERATE)
    return resp

def extract_and_build_pfx(xml_response: str, private_key_pem: bytes, pfx_password: str, output_file: str) -> str:
    """
    Extracts the Base64 certificate from the GenerateCertificate SOAP response,
    combines it with the local private key, and saves a usable PFX file.
    """
    ns = {'soap': 'http://schemas.xmlsoap.org/soap/envelope/',
          'm': 'http://millenniumbcp.pt/'}
    root = etree.fromstring(xml_response.encode("utf-8"))
    cert_element = root.find('.//m:GenerateCertificateResult/m:Certificado', ns)
    if cert_element is None or not cert_element.text:
        raise ValueError("Certificate not found in response")
    
    # Clean the PEM text
    cert_pem = cert_element.text.strip().replace('\r','')
    
    # Load certificate as PEM
    cert = x509.load_pem_x509_certificate(cert_pem.encode())

    # Load private key
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Build PFX
    pfx_bytes = serialize_key_and_certificates(
        name=cert.subject.rfc4514_string().encode(),
        key=private_key,
        cert=cert,
        cas=None,
        encryption_algorithm=BestAvailableEncryption(pfx_password.encode()) if pfx_password else serialization.NoEncryption()
    )

    # Save PFX
    with open(output_file, "wb") as f:
        f.write(pfx_bytes)
    
    return output_file

# ---------- Main Automation ----------
def run(debug: bool=False):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("== Millennium BCP Certificate Generator ==")

    if not os.path.exists(CERT_PATH):
        print(f"ERROR: public certificate not found at {CERT_PATH}")
        sys.exit(1)

    public_key = load_public_key(CERT_PATH)
    username = USERNAME or input("Username: ")
    password = PASSWORD or getpass.getpass("Password: ")
    language = LANGUAGE or input("Language (pt/en) [pt]: ").strip() or "pt"
    certificate_activation_key = CERTIFICATE_ACTIVATION_KEY or input("Certificate Activation Key: ").strip()

    # --- Step 1: Login ---
    print(f"[1] Invoked: CreateLogin")
    login_response = create_login(username, password, language, public_key)
    log_soap_response(login_response, 1)
    if debug:
        print("\nTHIS IS THE CreateLogin RESPONSE\n", login_response)
    is_success = extract_success_from_response(login_response)
    if not is_success:
        print("Step 1 - CreateLogin failed.")
        return
    positions = extract_positions_from_response(login_response)
    if debug:
        print("Positions requested:", positions)


    # --- Step 2: Validate activation key ---
    print(f"[2] Invoked: ValidaChave for positions {positions}")
    validate_key_response = valida_chave(certificate_activation_key, positions, public_key)
    log_soap_response(validate_key_response, 2)
    if debug:
        print("\nTHIS IS THE ValidaChave RESPONSE\n", validate_key_response)
    is_success = extract_success_from_response(validate_key_response)
    if not is_success:
        print("Step 2 - ValidaChave failed.")
        return

    # --- Step 3: Generate CSR locally ---
    friendly = CERTIFICATE_NAME or input("Certificate Friendly Name: ").strip() or "MyCert"
    print(f"[3] Generating CertificateSigningRequest [cn={friendly}] locally...")
    csr_b64, private_key_pem = generate_csr(friendly)
    key_path = save_file(private_key_pem, f"{friendly.replace(' ','_')}_private_key.pem")
    print(f"Private key saved to {key_path} (KEEP SAFE)")

    # --- Step 4: Register CSR without credentials (CredentialType=NONE) ---
    print("[4] Invoked: GenerateCertificate | CredentialType=NONE (register CSR)")
    certificate_response = generate_certificate(csr_b64, friendly, "NONE", public_key=public_key)
    log_soap_response(certificate_response, 4)
    if debug:
        print("\nTHIS IS THE GenerateCertificate(NONE) RESPONSE\n", certificate_response)
    is_success = extract_success_from_response(certificate_response)
    if not is_success:
        print("Step 4 - GenerateCertificate(NONE) failed.")
        return

    # --- Step 5: Send SMS for authentication ---
    print("[5] Invoked: SendAuthenticationMessage")
    sms_response = send_authentication_message("SMS", public_key)
    log_soap_response(sms_response, 5)
    if debug:
        print("\nTHIS IS THE SendAuthenticationMessage(SMS) RESPONSE\n", sms_response)
    is_success = extract_success_from_response(sms_response)
    if not is_success:
        print("Step 5 - SendAuthenticationMessage(SMS) failed.")
        return
    sms_code = input("SMS Code Received (May take minutes...): ").strip()

    # --- Step 6: Generate final certificate with SMS ---
    print("[6] Invoked: GenerateCertificate | CredentialType=SMS")
    certificate_signed_response = generate_certificate(csr_b64, friendly, "SMS", sms_code, public_key)
    log_soap_response(certificate_signed_response, 6)
    if debug: 
        print("\nTHIS IS THE GenerateCertificate(SMS) RESPONSE\n", certificate_signed_response)
    is_success = extract_success_from_response(certificate_signed_response)
    if not is_success:
        print("Step 6 - GenerateCertificate(SMS) failed.")
        return

    # --- Final Step: Combine local private key with signed certificate to build usable PFX ---
    print(f"[Final] Combining Certificate [cn={friendly}] with CSR Private Key into PFX...")
    pfx_path = extract_and_build_pfx(xml_response=certificate_signed_response, private_key_pem=private_key_pem, pfx_password=None, output_file=os.path.join(OUTPUT_DIR, f"{friendly.replace(' ', '_')}.pfx"))
    print(f"PFX file saved to {pfx_path} (KEEP SAFE!)")

if __name__ == "__main__":
    run(debug=(DEBUG))
