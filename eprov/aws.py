import os

import boto3
import click
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes


def create_key(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    privkey_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(f"certs/{name}.key", "wb") as f:
        f.write(privkey_pem)
    return key


def create_csr(name, priv_key):
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Narnia"),
        # x509.NameAttribute(NameOID.LOCALITY_NAME, ""),
        # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        # x509.NameAttribute(NameOID.COMMON_NAME, ""),
    ])).sign(priv_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(f"certs/{name}.csr", "wb") as f:
        f.write(csr_pem)
    return csr_pem.decode()


def upload_csr(thing_name, csr_pem):
    client = boto3.client('iot')
    response = client.create_certificate_from_csr(
        certificateSigningRequest=csr_pem,
        setAsActive=False
    )
    click.echo(f"ARN: {response['certificateArn']}")
    click.echo(f"certificateId: {response['certificateId']}")

    with open(f"certs/{thing_name}.crt", "w") as f:
        f.write(response["certificatePem"])
    return response["certificatePem"]

def create_certs(thing_name):
    # if "certs/{thing_name}.key" exists use that
    key = create_key(thing_name)
    # if "certs/{thing_name}.csr" exists use that
    csr_pem = create_csr(thing_name, key)
    response = upload_csr(thing_name, csr_pem)
    click.echo("Done.")
