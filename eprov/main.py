import logging

import click

from eprov.aws import manage_certificate
from eprov.balena import verify_device, verify_certs, update_balena_certs, verify_balena, list_balena_devices

logger = logging.getLogger(__name__)


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """Balena cloud services and AWS IoT certificates management utility.
    """


@cli.command()
@click.argument("cert_filter", callback=verify_certs)
@click.argument("device_name", callback=verify_device)
@click.option("-b", "--balena", default="certs/API-KEY",
              help="Balena API auth token filename. Default is certs/API-KEY",
              callback=verify_balena, is_eager=True)
@click.option("-o", "--out",  help="Don't send variables to Balena, just print them out.", is_flag=True)
# @click.pass_context
def up(cert_filter, device_name, balena, out):
    """Update or add  Balena device certs for AWS authentication to Balena Cloud using SDK.
    AWS access keys and variables are supposed to be setup in system (e.g. ~/.aws/credentials).
    Balena API login is done via Balena API key. Client id will be cert filename without extension.

    \b
    CERT_FILTER: The beginning of certificates filename in certs directory so that they will be distinguishable.
                 This should have files with crt and pem extension.
    DEVICE_NAME: Balena device name.
    """
    update_balena_certs(cert_filter=cert_filter,
                        balena=balena,
                        device_name=device_name,
                        out=out)

@cli.command()
@click.option("-b", "--balena", default="certs/API-KEY",
              help="Balena API auth token filename. Default is certs/API-KEY",
              callback=verify_balena, is_eager=True)
def ls(balena):
    """ List balena devices. List AWS things
    """
    list_balena_devices(balena)


@cli.command()
@click.argument("device_name")
@click.option("-p", "policy", help="Policy name to attach to Certificate. Will be created if not existing.",
              default="iot_all")
def gen(device_name, policy):
    """
    Create private key and CSR.
    Get CSR signend and activate certificate by AWS. Get public key.
    Save all to files in cert dir and public key in AWS.
    Create thing if needed.Create policy if needed. Attach certificate to policy and thing.

    \b
    DEVICE_NAME: AWS thing name.
    """
    manage_certificate(device_name, policy)


# TODO: add autocomplete from some contrib library
# TODO: add aws things ls
# TODO: rm from aws
# TODO: progress bar

#


if __name__ == "__main__":
    cli()
