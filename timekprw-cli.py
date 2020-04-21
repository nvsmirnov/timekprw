#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import subprocess
import requests
import argparse
import configparser
import logging
from logging import debug, info, warning, error

logging.basicConfig(level=logging.INFO, format='%(message)s')

ENVNAME_TIMEKPRW_DEBUG   = 'TIMEKPRW_DEBUG'
ENVNAME_TIMEKPRW_CREDS   = 'TIMEKPRW_CREDS'
ENVNAME_TIMEKPRW_RESTURL = 'TIMEKPRW_RESTURL'

credentials_path = os.environ.get(ENVNAME_TIMEKPRW_CREDS, '/var/lib/timekprw-cli/timekprw-cli.conf')
rest_url = os.environ.get(ENVNAME_TIMEKPRW_RESTURL, 'https://timekprw.ew.r.appspot.com')

sleep_interval = 30

ssl_verify = True  # verify TLS certificate of https server

host_uuid = None
host_authkey = None

class TimekrpwCliException(Exception):
    """Exception raised by timekprw-cli"""
    pass

def rest(url, type, data=None, required_members=None):
    """
    Perfom request to timekprw server.
    Check if there is valid "success" value in answer.
    When something went wrong, raise TimekrpwCliException('Text reason').
    :param url: REST URL in form "/rest/..."
    :param type: "GET"/"POST"
    :param data: json for POST request, ignored for GET
    :param required_members: check if specified dictionary member is in request (may be str or list)
    :return: json with server answer
    """
    try:
        if type.upper() == "GET":
            response = requests.get(rest_url + url, verify=ssl_verify)
        elif type.upper() == "POST":
            response = requests.post(rest_url + url, verify=ssl_verify, json=data)
        else:
            raise Exception(f"Internal error: unknown method {type} in rest()")
    except requests.exceptions.RequestException as e:
        raise TimekrpwCliException(f"Failed to perform request {url}: {e}")
    if response.status_code != 200:
        raise TimekrpwCliException(f"Got status code {response.status_code} from {url}")
    try:
        answer = response.json()
    except Exception as e:
        debug(f'Failed to interpret server answer as json, got exception {type(e).__name__}({e}), "'
              f'trace follows:', exc_info=True)
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


def parse_args():
    global rest_url
    global credentials_path
    global ssl_verify

    parser = argparse.ArgumentParser(description=f'Client for timekprw ({rest_url})',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--init', metavar='PIN',
                        help=f'Initialize this client and create credentials config file. Obtain PIN from web-interface {rest_url}.')
    parser.add_argument('-u', '--url', default=rest_url,
                        help=f'RESTful URL (also used from {ENVNAME_TIMEKPRW_CREDS} env)')
    parser.add_argument('-c', '--config', default=credentials_path,
                        help=f'Credentials config file (also used from {ENVNAME_TIMEKPRW_RESTURL} env)')
    parser.add_argument('-k', '--insecure', default=not ssl_verify, action='store_true',
                        help=f'Do not verify TLS certificate of web-server')
    parser.add_argument('-d', '--debug', default=False, action='store_true',
                        help=f'Enable debugging output (also used from {ENVNAME_TIMEKPRW_DEBUG} env)')
    parser.add_argument('-D', '--httpdebug', default=False, action='store_true',
                        help=f'Enable debugging of http requests')

    args = parser.parse_args()

    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.INFO)
    requests_log.propagate = True

    if args.debug or len(os.environ.get(ENVNAME_TIMEKPRW_DEBUG, '')):
        logging.getLogger().setLevel(logging.DEBUG)
        debug("enabled debug")
    if args.httpdebug:
        import http.client as http_client

        http_client.HTTPConnection.debuglevel = 1
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    if args.url:
        rest_url = args.url
    if args.config:
        credentials_path = args.config
    if args.insecure or os.environ.get('APP_ENVIRONMENT', None) == "dev":
        ssl_verify = False
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.init:
        try:
            pin = str(args.init)
            # first, create and write config to make sure that we can do it
            os.makedirs(os.path.dirname(credentials_path), exist_ok=True)
            config = configparser.ConfigParser()
            config['credentials'] = {}
            config['credentials']['host'] = "unknown"
            with open(credentials_path, "w") as config_file:
                config.write(config_file)
            os.chmod(credentials_path, 0o0600)
            answer = rest(url=f"/rest/host-getauthkey", data={"pin": pin}, type="POST",
                          required_members=["authkey", "hostuuid"])
            config['credentials']['host'] = answer["hostuuid"]
            config['credentials']['authkey'] = answer["authkey"]
            with open(credentials_path, "w") as config_file:
                config.write(config_file)
        except TimekrpwCliException as e:
            raise
        except Exception as e:
            debug(f'got exception {type(e).__name__}({e}) while creating {credentials_path}, trace follows:', exc_info=True)
            raise TimekrpwCliException(f'Failed to create {credentials_path}: {type(e).__name__}({str(e)})')
        sys.exit(1)


def read_config():
    global rest_url
    global credentials_path
    global host_uuid
    global host_authkey

    msg_please_recreate = f"please create host or pin on web-server ({rest_url})" \
                          f" and run {__file__} with -i option."
    if not os.path.exists(credentials_path):
        error(f"No credentials found, " + msg_please_recreate)
        sys.exit(1)

    try:
        config = configparser.ConfigParser()
        config.read_file(open(credentials_path, "r"))
        try:
            host_uuid = config['credentials']['host']
            if host_uuid == "unknown":
                # this is a config generated by us, but not recreated with real data for some reason
                raise TimekrpwCliException(f'You need to re-initialize this program, ' + msg_please_recreate)
            host_authkey = config['credentials']['authkey']
        except KeyError as e:
            raise TimekrpwCliException(f'Failed to read {credentials_path}, no such section or parameter: {e}')
    except TimekrpwCliException as e:
        raise
    except Exception as e:
        debug(f'got exception {type(e).__name__}({e}) while reading {credentials_path}, trace follows:', exc_info=True)
        raise TimekrpwCliException(f'Failed to read {credentials_path}: {type(e).__name__}({str(e)})')


if __name__ == "__main__":
    try:  # just raise TimekprwCliException from this block and it will show this error and exit
        parse_args()
        read_config()
        creds = {"authkey": host_authkey}

        info("started")
        while True:
            try:
                answer = rest(url=f"/rest/overrides/{host_uuid}", data=creds, type="POST", required_members="overrides")
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
                rest(url=f"/rest/overrides-ack/{host_uuid}", type="POST", data=creds)
            except TimekrpwCliException as e:
                error(str(e))
            debug(f"sleeping for {sleep_interval} seconds...")
            time.sleep(sleep_interval)
    except KeyboardInterrupt:
        info("Interrupted, exiting")
        sys.exit(0)
    except TimekrpwCliException as e:
        error(str(e))
        sys.exit(1)
