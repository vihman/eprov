import logging

import click

from eprov.aws import manage_certificate, generate_presigned_url
from eprov.balena import update_balena_certs, verify_balena, list_balena_devices

logger = logging.getLogger(__name__)


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
@click.version_option()
def cli():
    """Balena cloud services and AWS IoT certificates management utility.
    """


@cli.command()
@click.argument("device_name")  # callback=verify_device
@click.option("-b", "--balena", default="certs/API-KEY",
              help="Balena API auth token filename. Default is certs/API-KEY",
              callback=verify_balena, is_eager=True)
@click.option("-f", "--fleet", help="Update fleet variables. Otherwise only device.", is_flag=True)
@click.option("-o", "--out",  help="Don't send variables to Balena, just print them out.", is_flag=True)
def up(device_name, balena, fleet, out):
    """Update or add Balena device keys and certs.
     The certs are used for AWS authentication to Balena Cloud .
    AWS access keys and variables are supposed to be setup in system environment (e.g. ~/.aws/credentials).
    Balena API login is done via Balena API key. Client id will be cert filename without extension.

    \b
    DEVICE_NAME: Balena device name. This should have files with crt and pem extension. If fleet option is used,
    then this should be fleet name.
    """
    update_balena_certs(balena=balena,
                        device=device_name, fleet=fleet,
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
    Create private key and CSR for IOT Core devices in AWS.
    Get CSR signend and activate certificate by AWS. Get public key.
    Save all to files in cert dir and public key in AWS.
    Create thing if needed.Create policy if needed. Attach certificate to policy and thing.

    \b
    DEVICE_NAME: AWS thing name.
    """
    manage_certificate(device_name, policy)

@cli.command()
@click.argument("object")
@click.option("-b", "bucket", help="Bucket name to store data.",
              default="hydromastdata")
@click.option("-e", "expires", help="Signed URL expiration time in seconds.",
              default=60*60*24*3)
@click.option("-g", "--get", help="Default key for file upload. Use this for download.", is_flag=True)
def pre(object, bucket, expires, get):
    """
    Generate pre-shared URL to access files in AWS S3.
    URL-s can be used to give access without any extra credentials or headers needed.

    \b
    For uploading:
        curl -X PUT --data-binary @<object> "<URL>".
    For downloading:
        curl -o <filename> "<URL>".
    OBJECT: Object path to store in AWS. Usually directory/filename.
    """
    generate_presigned_url(object, bucket, expires, get)

# TODO: add autocomplete from some contrib library
# TODO: add aws things ls
# TODO: rm from aws
# TODO: progress bar


if __name__ == "__main__":
    cli()
