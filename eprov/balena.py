import base64
import logging
import os
import re

import boto3
import click
from balena import Balena

CERTS_DIR = "certs"
CERT_CONSTANTS = {'crt': "AWS_IOT_CERT", 'key': "AWS_IOT_KEY"}
SERVICE_NAME = "main"
logger = logging.getLogger(__name__)


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
    logger.debug("Verifying cert file existance and count.")
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


def verify_balena(ctx, param, value):
    logger.debug("Verifying balena token...")
    with open(value) as f:
        token = f.read()
    balena = Balena()
    balena.auth.login_with_token(token)
    return balena


def verify_device(ctx, param, value):
    balena = ctx.params["balena"]
    device = balena.models.device.get_by_name(value)
    if not device:
        raise click.BadParameter("Cannot find device with such name.")
    return device.pop()


def load_certs(files):
    result = {}
    cert_types = CERT_CONSTANTS.keys()
    for fname in files:
        for type_ in cert_types:
            if fname.endswith(type_):
                with open(fname, "rb") as f:
                    content = f.read()
                content = base64.b64encode(content).decode()
                result[CERT_CONSTANTS[type_]] = content
    return result


def find_endpoint():
    client = boto3.client('iot')
    endpoint = client.describe_endpoint(endpointType='iot:Data-ATS')
    return endpoint["endpointAddress"]


def find_client_id(filenames):
    result, _ = os.path.splitext(os.path.basename(filenames.pop()))
    return result


def send_data(balena, device_name, env_vars):
    dsev = balena.models.environment_variables.device_service_environment_variable
    envs_on_device = dsev.get_all(device_name["uuid"])
    existing_envs = {x[0]: x[1] for x in map(lambda x: (x['name'], x['id']), envs_on_device)}
    for key, val in env_vars.items():
        if key in existing_envs.keys():
            dsev.update(existing_envs[key], val)
            logger.info(f"Updated Balena variable {key}.")
        else:
            dsev.create(device_name["uuid"], SERVICE_NAME, key, val)
            logger.info(f"Inserted Balena variable {key}")


def update_balena_certs(cert_filter, balena, device_name):
    env_vars = load_certs(cert_filter)
    env_vars["AWS_IOT_HOST"] = find_endpoint()
    env_vars["AWS_IOT_PORT"] = "8883"
    env_vars["AWS_IOT_CLIENT_ID"] = find_client_id(cert_filter)
    send_data(balena, device_name, env_vars)
    logger.info("Done.")


def list_balena_devices(balena):
    devices = balena.models.device.get_all()
    click.echo("device_name, uuid, ip_address, api_heartbeat_state, is_active, os_variant")
    for d in devices:
        click.echo(f"{d['device_name']}, {d['uuid']}, {d['ip_address']}, {d['api_heartbeat_state']}, {d['is_active']}, {d['os_variant']}")
        """
        d['cpu_usage']
        d['cpu_temp']
        d['storage_usage']
        d['storage_total']
        d['memory_usage']
        d['memory_total']
        """