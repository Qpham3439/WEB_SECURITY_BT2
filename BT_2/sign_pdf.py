"""
sign_pdf.py – Phiên bản ổn định, chạy được chắc chắn
----------------------------------------------------
Ký file PDF theo mô phỏng chuẩn PAdES (PKCS#7 detached)
"""

import sys
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder, PKCS7Options
from cryptography.x509.oid import NameOID
from pypdf import PdfReader, PdfWriter

CONTENTS_SIZE = 8192  # số byte dự trữ cho chữ ký

# === B1: Sinh khóa & chứng chỉ ===
def create_key_and_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SV58KTPM-Student")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    return key, cert


# === B2: Tạo file PDF tạm có ByteRange & vùng placeholder thật ===
def create_interim_pdf(src_pdf, interim_pdf):
    reader = PdfReader(src_pdf)
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)

    # Ghi file tạm ban đầu
    with open(interim_pdf, "wb") as f:
        writer.write(f)

    # Thêm dòng ByteRange và vùng 0x00 thật vào cuối
    with open(interim_pdf, "ab") as f:
        f.write(b"\n% ByteRange placeholder\n")
        f.write(b"/ByteRange [0 ********** ********** **********]\n")
        f.write(b"\x00" * CONTENTS_SIZE)

    print(f"📄 Đã tạo file tạm có ByteRange & placeholder: {interim_pdf}")


# === B3: Chèn chữ ký vào vùng placeholder ===
def insert_signature(interim_pdf, signed_pdf, pkcs7_der):
    with open(interim_pdf, "rb") as f:
        pdf_bytes = f.read()

    placeholder = b"\x00" * CONTENTS_SIZE
    idx = pdf_bytes.find(placeholder)
    if idx == -1:
        raise RuntimeError("Không tìm thấy vùng placeholder trong PDF tạm.")

    contents_start, contents_end = idx, idx + len(placeholder)
    byte_range = [0, contents_start, contents_end, len(pdf_bytes) - contents_end]

    # Ghi chữ ký DER vào vùng placeholder
    final_bytes = bytearray(pdf_bytes)
    final_bytes[contents_start:contents_start + len(pkcs7_der)] = pkcs7_der

    # Cập nhật /ByteRange trong file
    br_text = f"/ByteRange [{byte_range[0]} {byte_range[1]} {byte_range[2]} {byte_range[3]}]"
    br_index = pdf_bytes.find(b"/ByteRange [")
    if br_index == -1:
        raise RuntimeError("Không tìm thấy /ByteRange để cập nhật.")
    end_idx = pdf_bytes.find(b"]", br_index)
    old_range = pdf_bytes[br_index:end_idx + 1]
    new_range = br_text.encode("ascii").ljust(len(old_range), b" ")
    final_bytes[br_index:end_idx + 1] = new_range

    with open(signed_pdf, "wb") as f:
        f.write(final_bytes)

    print(f"✅ Đã tạo file ký: {signed_pdf}")
    print("ByteRange:", byte_range)


# === B4: Main ký ===
def main():
    if len(sys.argv) != 3:
        print("Cách dùng: python sign_pdf.py original.pdf signed.pdf")
        sys.exit(1)

    src_pdf, signed_pdf = sys.argv[1], sys.argv[2]
    interim_pdf = src_pdf.replace(".pdf", "_interim.pdf")

    create_interim_pdf(src_pdf, interim_pdf)
    key, cert = create_key_and_cert()

    # Đọc file tạm (để tính dữ liệu cần ký)
    with open(interim_pdf, "rb") as f:
        data = f.read()

    placeholder = b"\x00" * CONTENTS_SIZE
    idx = data.find(placeholder)
    contents_start, contents_end = idx, idx + len(placeholder)
    to_sign = data[:contents_start] + data[contents_end:]

    # Ký thành PKCS#7 detached
    pkcs7 = PKCS7SignatureBuilder().set_data(to_sign).add_signer(cert, key, hashes.SHA256())
    pkcs7_der = pkcs7.sign(Encoding.DER, [PKCS7Options.DetachedSignature])

    insert_signature(interim_pdf, signed_pdf, pkcs7_der)

    # Lưu key & cert
    with open("demo_key.pem", "wb") as f:
        f.write(key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    with open("demo_cert.pem", "wb") as f:
        f.write(cert.public_bytes(Encoding.PEM))
    print("🔑 Đã lưu demo_key.pem và demo_cert.pem")


if __name__ == "__main__":
    main()
