#!/usr/bin/env python3
# coding: utf-8

#
# This script will build docker image and deploy it to Google Cloud Run
# You need to run it with environment variables set, they are in J2_VARS dictionary.
# If variable in dictionary is not pre-set, script will fail if it is not defined.
# Variables used to process jinja2 Dockerfile template
#
# Also, before deploying, you need to do standard steps with gcloud console
# Login to google cloud, set project
# Allow login to docker with gcloud helper:
#   gcloud auth configure-docker
#

import os
import sys
import subprocess
import logging
import atexit
from logging import debug, info, warning, error

logging.basicConfig(level=logging.DEBUG)


J2_ENV_VARS = {
    "PORT": 5000,
    "APP_ENVIRONMENT": None,
    "GOOGLE_CLIENT_ID": None,
    "GOOGLE_CLIENT_SECRET": None,
    "DATABASE_PERMSTORE_URL": None,
    "GCS_BUCKET": None,
}


def run(cmd):
    debug(f"running: {cmd}")
    return os.system(cmd)


def cleanup():
    try:
        os.unlink("Dockerfile.tmp")
    except FileNotFoundError:
        pass
atexit.register(cleanup)


if __name__ == "__main__":
    for var in J2_ENV_VARS:
        env_val = os.environ.get(var)
        if env_val is not None:
            J2_ENV_VARS[var] = env_val
        if J2_ENV_VARS[var] is None:
            error(f"Mandatory environment variable {var} is not set.")
            sys.exit(1)

    j2_defs = " ".join([f"-D '{key}={value}'" for key, value in J2_ENV_VARS.items()])
    if run(f"jinja2 {j2_defs} --strict Dockerfile -o Dockerfile.tmp") != 0:
        error(f"Failed to run jinja2")
        sys.exit(1)

    if run(f"docker build -f Dockerfile.tmp -t gcr.io/timekprw/timekprw:v1 .") != 0:
        error(f"Failed to build docker image")
        sys.exit(1)


    if run(f"docker push gcr.io/timekprw/timekprw:v1") != 0:
        error(f"Failed to push docker image")
        sys.exit(1)

    if run(f"gcloud run deploy timekprw --image gcr.io/timekprw/timekprw:v1"
           f" --allow-unauthenticated --platform managed --region europe-west1"
           ) != 0:
        error(f"Failed to deploy app to GCR")
        sys.exit(1)


#run(f"gcloud app deploy {app_config_real} -q --project timekprw --version dev")
#run(f'gcloud builds submit ./ --gcs-source-staging-dir="gs://timekprw-builds/cloudbuild-custom" --config gc-build.yaml')
