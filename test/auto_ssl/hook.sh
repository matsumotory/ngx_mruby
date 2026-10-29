#!/usr/bin/env bash
# The dehydrated hook of test/t/cases/auto_ssl.rb. It is the hook of
# test/conf/auto-ssl/ngx_mruby-hook.sh with two differences: the hook server
# is the nginx that the case starts on port 18173, and the hooks that this
# file does not handle exit with 0, because dehydrated 0.7 calls a few more
# (startup_hook, generate_csr, ...) and stops when an unknown one fails.
# HOOK_SECRET comes from Nginx::SSL::ACME::Dehydrated#auto_cert_deploy.

set -e -u
HOOK_SERVER_PORT=18173

deploy_challenge() {
  local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

  curl --silent --show-error --fail --max-time 30 -XPOST \
    --header "X-Hook-Secret: $HOOK_SECRET" \
    --data-urlencode "domain=$DOMAIN" \
    --data-urlencode "token_filename=$TOKEN_FILENAME" \
    --data-urlencode "token_value=$TOKEN_VALUE" \
    "http://127.0.0.1:$HOOK_SERVER_PORT/deploy-challenge"
}

deploy_cert() {
  local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}"

  curl --silent --show-error --fail --max-time 30 -XPOST \
    --header "X-Hook-Secret: $HOOK_SECRET" \
    --data "domain=$DOMAIN" \
    --data "privkey=$KEYFILE" \
    --data "cert=$CERTFILE" \
    --data "fullchain=$FULLCHAINFILE" \
    "http://127.0.0.1:$HOOK_SERVER_PORT/deploy-cert"
}

HANDLER=${1:-}
[ $# -gt 0 ] && shift
case "$HANDLER" in
  deploy_challenge | deploy_cert)
    "$HANDLER" "$@"
    ;;
esac
exit 0
