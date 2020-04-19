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

rest_url = os.environ.get('TIMEKPRW_RESTURL', 'https://timekprw.ew.r.appspot.com')
sleep = 30
host_uuid = '59e8368c-7dbc-11ea-923e-7cb0c2957d37'

ssl_verify = True  # verify TLS certificate of https server

if os.environ.get('APP_ENVIRONMENT', None) == "dev":
    # disable TLS verify in dev environment
    ssl_verify = False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

info("started")
if len(os.environ.get('TIMEKPRW_DEBUG', '')):
    logging.getLogger().setLevel(logging.DEBUG)
    debug("enabled debug")

class TimekrpwCliException(Exception):
    """Exception raised by timekprw-cli"""
    pass

def rest(url, type, params=None, required_members=None):
    """
    Perfom request to timekprw server.
    Check if there is valid "success" value in answer.
    When something went wrong, raise TimekrpwCliException('Text reason').
    :param url: REST URL in form "/rest/..."
    :param type: "GET"/"POST"
    :param params: json for POST request, ignored for GET
    :param required_members: check if specified dictionary member is in request (may be str or list)
    :return: json with server answer
    """
    try:
        if type.upper() == "GET":
            response = requests.get(rest_url + url, verify=ssl_verify)
    except requests.exceptions.RequestException as e:
        raise TimekrpwCliException(f"Failed to perform request {url}: {e}")
    if response.status_code != 200:
        raise TimekrpwCliException(f"Got status code {response.status_code} from {url}")
    try:
        answer = response.json()
    except Exception as e:
        raise TimekrpwCliException(f'Failed to interpret server answer as json from {url}')
    debug(f'Got json answer from {url}: {answer}')
    # TODO: test all of following
    if "success" not in answer:
        raise TimekrpwCliException(f"Bad answer from server to {url} (not contains 'success' field)")
    elif not answer["success"]:
        if "message" in answer:
            raise TimekrpwCliException(f"Request {url} success=False, reason: '{answer['message']}'")
        else:
            raise TimekrpwCliException(f"Request {url} success=False, no reason given")
    if required_members:
        if isinstance(required_members, str):
            required_members = [required_members]
        for member in required_members:
            if member not in answer:
                raise TimekrpwCliException(f"No '{member}' in server answer from {url}")
    return answer


try:
    while True:
        try:
            answer = rest(url=f"/rest/overrides/{host_uuid}", type="GET", required_members="overrides")
            overrides = answer["overrides"]

            for user in overrides:
                try:
                    amount = 0
                    if not re.match('^[\w\-\.]+$', user):
                        raise TimekrpwCliException(f'bad username in answer: {user}')
                    try:
                        amount = int(overrides[user])
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
            # acknowledge that we've got data
            debug("send ack to server")
            rest(url=f"/rest/overrides-ack/{host_uuid}", type="GET")
        except TimekrpwCliException as e:
            error(str(e))
        debug(f"sleeping for {sleep} seconds...")
        time.sleep(sleep)
except KeyboardInterrupt:
    info("Interrupted, exiting")
    sys.exit(0)
