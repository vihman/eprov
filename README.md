# Edge devices provisioner.
Manage specific IoT devices integrated with Balena Cloud and AWS IoT.

## Quick usage
```
pip install -e .
eprov -h
```

## Installing and using from Linux with Python3
(Balena CLI pre-installed, AWS CLI not installed)
- git clone current repo
- cd eprov
- Install python 3.9 (and -devel maybe? packages)
- Generate API key in balena.io web interface, user configuration and copy this from balena to eprov folder `certs/API-KEY`
- virtualenv -p python3.9 .venv
- source .venv/bin/activate
- pip install -e .
- eprov -h
- Generate ~/.aws/config with contents:
    ```
    [default]
    region=eu-central-1
    ```
- Create Amazon Access key (from AWS console top right user menu - Security credentials)  and copy key to `~/.aws/credentials`, contents (use same name, “default”):
    ```
    [default]
    aws_access_key_id = YYYYYYYYYYYYYYYYYYYY
    aws_secret_access_key = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    ```

    These can be also given as environment variables `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`

- Run
  `eprov gen {iot_device}`

If you get the error:
> Private key found but not public. To generate new please delete private key.

Then delete `certs/{iot_device}.crs` and `.key` and try again.
May still be an access problem with connecting to AWS if this errors comes up again.