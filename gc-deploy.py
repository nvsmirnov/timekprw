#!/usr/bin/env python3
# coding: utf-8

import os
import sys
import subprocess
import logging
from logging import debug, info, warning, error

app_config_real = "gc-app-local.yaml"
app_config_template = "gc-app.yaml"

logging.basicConfig(level=logging.DEBUG)

def run(cmd):
    debug(f"running: {cmd}")
    return os.system(cmd)

if not os.path.exists(app_config_real):
    error(f"No {app_config_real} found, you may want to create it as a copy of {app_config_template}")
    sys.exit(1)

#run(f"gcloud app deploy {app_config_real} -q --project timekprw --version dev")
run(f'gcloud builds submit --gcs-source-staging-dir="gs://timekprw-builds/cloudbuild-custom" --config gc-build.yaml')
