#
# This is template file in jinja2 format
# To create real file you need to process it with jinja2
# it is used in gcr-deploy script
# Probably it is better to do that with docker-compose, but didn't pay time to that :)
#

FROM python:3.8

# this is for OAuth2 to work behind a reverse proxy
ENV OAUTHLIB_INSECURE_TRANSPORT 1
# some dirty hacks for OAuth2 to work behind reverse proxy when backend is without TLS
ENV REVERSE_PROXY_FIX 1

COPY requirements.txt /
RUN pip install -r requirements.txt

COPY . /app
EXPOSE {{ PORT }}
ENV PORT {{ PORT }}
ENV APP_ENVIRONMENT {{ APP_ENVIRONMENT }}
ENV GOOGLE_CLIENT_ID {{ GOOGLE_CLIENT_ID }}
ENV GOOGLE_CLIENT_SECRET {{ GOOGLE_CLIENT_SECRET }}
ENV DATABASE_PERMSTORE_URL {{ DATABASE_PERMSTORE_URL }}
ENV GCS_BUCKET {{ GCS_BUCKET }}

WORKDIR /app

CMD exec gunicorn --bind :$PORT main:app --workers 1 --threads 1 --timeout 60
# that's for testing and debugging
#CMD exec python main.py
