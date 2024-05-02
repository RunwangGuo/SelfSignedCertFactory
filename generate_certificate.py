import sys
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta


def generate_certificate(domain_name):
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 创建证书请求
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain_name),
    ])

    # 设置证书的有效期为100年
    not_valid_after = datetime.utcnow() + timedelta(days=100*365)

    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        not_valid_after
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(domain_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())

    # 创建名为 "cert/self-signed-域名" 的文件夹，并将证书和私钥保存在该文件夹下
    cert_dir = "cert/self-signed-" + domain_name
    if not os.path.exists(cert_dir):
        os.makedirs(cert_dir)

    # 将证书保存为PEM格式
    with open(os.path.join(cert_dir, "certificate.pem"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # 将私钥保存为PEM格式
    with open(os.path.join(cert_dir, "private_key.pem"), "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print(f"证书和私钥已在 {cert_dir} 目录下生成。")


if __name__ == "__main__":
    # 检查是否有域名作为参数传入
    if len(sys.argv) < 2:
        print("用法: python generate_certificate.py <domain_name1> <domain_name2> ...")
        sys.exit(1)

    # 处理每个域名
    for domain_name in sys.argv[1:]:
        generate_certificate(domain_name)
