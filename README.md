Web-based interface timekpr.
============================

This interface is intentionally made very simple.
You can't fullty manage timekpr with it, only add/reduce time for user.

First, install and configure timekpr.

In short:
- Copy timekprw-cli.py to /usr/local/bin/
- Go to https://timekprw.ew.r.appspot.com/, log in with google account.
- There, create new host with some name.
- Get pin from host's page and run timekprw-cli.py -i pin.
- On web page, in the created host host, add user that is already managed by timekpr.

Now you can add time for this user on web page.

The client synchronizes with web every 30 seconds.
