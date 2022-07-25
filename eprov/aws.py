import json
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
        # Fields needed by the standard but not requested by AWS:
        # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Narnia"),
        # x509.NameAttribute(NameOID.LOCALITY_NAME, ""),
        # x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        # x509.NameAttribute(NameOID.COMMON_NAME, ""),
    ])).sign(priv_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(f"certs/{name}.csr", "wb") as f:
        f.write(csr_pem)
    return csr_pem.decode()


def upload_csr(thing_name, csr_pem, client):
    response = client.create_certificate_from_csr(
        certificateSigningRequest=csr_pem,
        setAsActive=True
    )
    click.echo(f"ARN: {response['certificateArn']}")
    click.echo(f"certificateId: {response['certificateId']}")

    with open(f"certs/{thing_name}.crt", "w") as f:
        f.write(response["certificatePem"])
    return response["certificateArn"]


def attach_thingprincipal(client, thing_name, cert_arn):
    return client.attach_thing_principal(thingName=thing_name, principal=cert_arn)


def attach_policy(client, policy_name, cert_arn):
    return client.attach_policy(policyName=policy_name, target=cert_arn)


def get_certificate_arn(client, thing_name):
    with open(f"certs/{thing_name}.crt", "rb") as f:
        crt_data = f.read()
    crt = x509.load_pem_x509_certificate(crt_data)
    fp = crt.fingerprint(hashes.SHA256())
    response = client.describe_certificate(certificateId=fp.hex())
    return response["certificateDescription"]["certificateArn"]


def create_certs_if_needed(boto_client, thing_name):
    if os.path.exists(f"certs/{thing_name}.key"):
        if not os.path.exists(f"certs/{thing_name}.crt"):
            raise click.ClickException("Private key found but not public. To generate new please delete private key.")
        click.echo(f"'{thing_name}' keys existing, using those.")
        cert_arn = get_certificate_arn(boto_client, thing_name)
    else:
        key = create_key(thing_name)
        csr_pem = create_csr(thing_name, key)
        cert_arn = upload_csr(thing_name, csr_pem, boto_client)
    click.echo("Certs done.")
    return cert_arn


def existing_in_response(response, object_list, matching_attribute, name_to_find):
    exists = False
    for thing in response[object_list]:
        if thing[matching_attribute] == name_to_find:
            exists = True
            click.echo(f"'{name_to_find}' already existing in AWS '{object_list}'.")
    return exists


def create_thing_if_needed(client, thing_name):
    response = client.list_things()
    thing_exists = existing_in_response(response, "things", "thingName", thing_name)
    if not thing_exists:
        client.create_thing(thingName=thing_name)
        click.echo(f"{thing_name} created to AWS.")


def create_policy_if_needed(client, policy_name):
    response = client.list_policies()
    policy_existing = existing_in_response(response, "policies", "policyName", policy_name)
    if not policy_existing:
        client.create_policy(
            policyName=policy_name,
            policyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                      "Effect": "Allow",
                      "Action": "iot:*",
                      "Resource": "*"
                    }
                  ]
                })
        )
        click.echo(f"Created '{policy_name}' policy.")


def attach_cert(client, thing_name, cert_arn, policy_name):
    # We activate cert while creating, othervise:
    # response = client.update_certificate(
    #    certificateId=cert_arn,
    #    newStatus='ACTIVE'
    create_thing_if_needed(client, thing_name)
    create_policy_if_needed(client, policy_name)
    attach_thingprincipal(client, thing_name, cert_arn)
    attach_policy(client, policy_name, cert_arn)
    click.echo(f"Thing '{thing_name}' updated.")


def manage_certificate(device_name, policy_name):
    boto_client = boto3.client('iot')
    cert_arn = create_certs_if_needed(boto_client, device_name)
    attach_cert(boto_client, device_name, cert_arn, policy_name)

# TODO use pathlib