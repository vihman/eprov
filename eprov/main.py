import logging

import click

from eprov.update import verify_device, verify_certs, update_balena_certs, verify_balena, list_balena_devices

logger = logging.getLogger(__name__)

@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """Balena cloud services and AWS IoT certificates management utilities.
    """


@cli.command()
@click.argument("cert_filter", callback=verify_certs)
@click.argument("device_name", callback=verify_device)
@click.option("-b", "--balena", default="certs/API-KEY",
              help="Balena API auth token filename. Default is certs/API-KEY",
              callback=verify_balena, is_eager=True)
# @click.pass_context
def up(cert_filter, device_name, balena):
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
                        device_name=device_name)

@cli.command()
@click.option("-b", "--balena", default="certs/API-KEY",
              help="Balena API auth token filename. Default is certs/API-KEY",
              callback=verify_balena, is_eager=True)
def ls(balena):
    """ List balena devices.
    """
    list_balena_devices(balena)


# TODO: make boto3 cert generate command
# TODO: add autocomplete from some contrib library
# TODO: make balena devices ls
# TODO: progress bar


if __name__ == "__main__":
    cli()
