from balena import Balena
import boto3
import click

from edge_provision.update import verify_device, verify_certs, bal_main


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    """Balena cloud services and AWS IoT certificates management utilities.
    """


@cli.command()
@click.argument("cert_filter", callback=verify_certs)
@click.argument("device_name", callback=verify_device)
def bal(cert_filter, device_name):
    """Update or add  Balena device active certs to Cloud using SDK.

    \b
    FILTER: The beginning of certificates filename in directory so that they will be extinguishable.
    DEVICE_NAME: Balena device name.
    """
    bal_main(cert_filter, device_name)
    click.echo('Name: %s' % device_name)
    click.echo('CERTS: %s' % list(filter))


# OK: make group that has -h help context
# OK: make balena command
# OK: get parameter of balena device name and parameter of certificates files
# OK: get file listing function from libfault
# OK: validate parameters
# TODO: load files
# TODO: encode files
# TODO: put all the parameters in dict
# TODO: use { x[0] : x[1] for x in map(lambda: x: (x['id'], x['name'], deviceservicevariables }

# TODO: write docstrings everywhere
# TODO: make balena token read from file and added to context by bal.
# TODO: make boto3 cert generate command
# TODO: add autocomplete from some contrib library
# TODO: make balena devices ls