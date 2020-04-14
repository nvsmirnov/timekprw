#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import subprocess
import requests
import logging
from logging import debug, info, warning, error

rest_url = "https://nvsbook.h.nvs.pp.ru:5000"
sleep = 30
host_uuid = '59e8368c-7dbc-11ea-923e-7cb0c2957d37'

logging.basicConfig(level=logging.INFO)

info("started")

class TimekrpwCliException(Exception):
    """Exception raised by timekprw-cli"""
    pass

try:
    while True:
        try:
            # TODO: turn on verify on production
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = requests.get(rest_url + "/rest/overrides/" + host_uuid, verify=False)
        except requests.exceptions.RequestException as e:
            raise TimekrpwCliException(f"Failed to perform request: {e}")
        if response.status_code != 200:
            raise TimekrpwCliException(f"got status code {response.status_code}")
        answer = response.json()
        debug(f'got answer: {answer}')
        try:
            # TODO: turn on verify on production
            response = requests.get(rest_url + "/rest/overrides_ack/" + host_uuid, verify=False)
        except requests.exceptions.RequestException as e:
            raise TimekrpwCliException(f"Failed to send acknowledge request: {e}")
        for user in answer:
            try:
                amount = 0
                if not re.match('^[\w\-\.]+$', user):
                    raise TimekrpwCliException(f'bad username in answer: {user}')
                try:
                    amount = int(answer[user])
                except ValueError:
                    raise TimekrpwCliException(f'bad amount given for user {user}: {amount}')
                debug(f"trying to add {amount} for {user}")
                try:
                    p = subprocess.run(["/usr/bin/timekpra", "--settimeleft", str(user), "+", str(amount)])
                except Exception as e:
                    raise TimekrpwCliException(f'failed to run timekpra: {e}')
                if p.returncode != 0:
                    raise TimekrpwCliException(f'timekpra exited with return code {p.returncode}')
                info(f"added {amount} of time to {user}")
            except TimekrpwCliException as e:
                error(str(e))
        debug(f"sleeping for {sleep} seconds...")
        time.sleep(sleep)
except KeyboardInterrupt:
    info("Interrupted, exiting")
    sys.exit(0)
