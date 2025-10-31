"""
verify_pdf.py – Kiểm tra chữ ký PDF (hoạt động mọi môi trường)
--------------------------------------------------------------
Dựa trên asn1crypto để đọc cấu trúc PKCS#7 (CMS) từ vùng /Contents.
Không cần cryptography.pkcs7.
"""

import re, sys
from cryptography import x509
from asn1crypto import cms

def extract_signature(pdf_bytes):
    # Tìm /ByteRange [a b c d]
    m = re.search(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]", pdf_bytes)
    if not m:
        raise RuntimeError("Không tìm thấy /ByteRange trong PDF.")
    a, b, c, d = map(int, m.groups())

    contents = pdf_bytes[b:c].strip(b"\x00")
    to_be_signed = pdf_bytes[:b] + pdf_bytes[c:]
    return to_be_signed, contents

def verify_signature(pdf_path, cert_path):
    pdf_bytes = open(pdf_path, "rb").read()
    to_be_signed, der_sig = extract_signature(pdf_bytes)
    cert = x509.load_pem_x509_certificate(open(cert_path, "rb").read())

    # Dùng asn1crypto parse PKCS#7
    try:
        pkcs7 = cms.ContentInfo.load(der_sig)
    except Exception as e:
        print("❌ Không đọc được PKCS#7:", e)
        return

    if pkcs7['content_type'].native != 'signed_data':
        print("❌ Không phải kiểu SignedData.")
        return

    signed_data = pkcs7['content']
    signer_infos = signed_data['signer_infos']
    certs = signed_data['certificates']

    print("📘 Thuật toán ký:", cert.signature_algorithm_oid._name)
    print("📄 Kích thước chữ ký:", len(der_sig), "bytes")
    print(f"🔍 PKCS#7 có {len(certs)} chứng chỉ và {len(signer_infos)} signer(s).")

    if len(certs) > 0 and len(signer_infos) > 0:
        print("✅ Cấu trúc chữ ký hợp lệ (có signer & cert).")
    else:
        print("❌ Thiếu thông tin signer hoặc cert trong chữ ký.")

    # Gợi ý xác thực hash thật bằng OpenSSL
    print("\n👉 Để kiểm chứng thật:")
    print("openssl cms -verify -inform DER -in signature.der -content data.bin -noverify -certfile demo_cert.pem")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Cách dùng: python verify_pdf.py signed.pdf demo_cert.pem")
        sys.exit(1)
    verify_signature(sys.argv[1], sys.argv[2])
