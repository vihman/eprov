import base64
import os
import re

import click
from balena import Balena

CERTS_DIR = "certs"
CERT_CONSTANTS = {'crt': "AWS_IOT_CERT", 'key': "AWS_IOT_KEY"}


def list_files(path, sfilter=r''):
    entries = os.scandir(path)
    result = []
    for item in entries:
        if item.is_file():
            name = item.name
            if re.match(sfilter, name):
                result.append('{}/{}'.format(path, name))
    return result


def verify_certs(ctx, param, value):
    entries = {x: 0 for x in CERT_CONSTANTS.keys()}
    files = list_files(CERTS_DIR, value)
    for filename in files:
        for extension in CERT_CONSTANTS.keys():
            if filename.endswith(extension):
                entries[extension] += 1
    for counter in entries.values():
        if counter != 1:
            raise click.BadParameter("Keyfiles and certicates have to be present once in the filter in correct path.")
    return files


def verify_device(ctx, param, value):
    balena = Balena()
    balena.auth.login_with_token(BALENA_TOKEN)
    device = balena.models.device.get_by_name(value)
    if not device:
        raise click.BadParameter("Cannot find device with such name.")
    return device


def encode_certs(cert_files):
    for file in cert_files:
        with open(file) as f:
            f.read()
    result = base64.b64encode("TODO")
    return result


def find_endpoint():
    pass


def find_client_id():
    pass


def find_port():
    pass


def bal_main(cert_filter, device_name):
    encode_certs(cert_filter)
    find_endpoint()
    find_client_id()
    find_port()

    """
    export AWS_IOT_CERT=eh
    export AWS_IOT_KEY=eh
    export AWS_IOT_HOST=eh
    export AWS_IOT_PORT=eh
    export AWS_IOT_CLIENT_ID=eh
    """

    pass
