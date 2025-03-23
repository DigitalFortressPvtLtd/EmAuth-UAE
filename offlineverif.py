import base64
import struct
import datetime
import pytz
import tzlocal
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from masterurl import *

public_key_b64='LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFQ0xDcndadkNUWVBZYXZ6eTljcHE2Yk5JWkVsRgprcjk0Y0pwUXhkNmlkZlVrSzZjcm1JSUVrV2R2VnFsZDd3YWJWc2pBdlYxdXRpU1ZDdFBIUUFMSUtnPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='

def verify_signature2(signature_b64):
    public_key_pem = base64.b64decode(public_key_b64)
    public_key = serialization.load_pem_public_key(public_key_pem)
    signed_data = base64.b64decode(signature_b64)
    text_len = struct.unpack(">H", signed_data[:2])[0]
    text_bytes = signed_data[2 : 2 + text_len]
    text = text_bytes.decode()
    signature = signed_data[2 + text_len :]
    try:
        public_key.verify(signature, text_bytes, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return False, "Verification failed: Invalid signature"
    try:
        domain, datetime_str = text.split("|")
        dt = datetime.datetime.strptime(datetime_str, "%Y-%m-%d %H:%M")
    except ValueError:
        return False, "Verification failed: Invalid text format"
    local_tz = tzlocal.get_localzone()
    now = datetime.datetime.now(pytz.timezone("Asia/Kolkata"))
    if now.year != dt.year or now.month != dt.month or now.day != dt.day or now.hour != dt.hour:
        return False, "Verification failed: Timestamp mismatch"
    if domain != deployed_domain:
        return False, "Verification failed: Domain mismatch"
    if not check_domain_valid():
        return False, "Verification failed: Domain validation error"

    return True, "Verified"  

def verify_signature(sign):
    try:
        return verify_signature2(sign)[0]
    except:
        return False
