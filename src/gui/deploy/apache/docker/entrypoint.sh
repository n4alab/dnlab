#!/bin/sh
set -eu

export APACHE_LOG_DIR="${APACHE_LOG_DIR:-/var/log/apache2}"
mkdir -p "$APACHE_LOG_DIR"

if [ "${DNLAB_PROXY_MODE:-tls}" = "tls" ]; then
    : "${DNLAB_PROXY_SERVER_NAME:?set DNLAB_PROXY_SERVER_NAME for tls mode}"
    export DNLAB_PROXY_SERVER_ADMIN="${DNLAB_PROXY_SERVER_ADMIN:-dnlab@example.invalid}"
    export DNLAB_PROXY_CERT_FILE="${DNLAB_PROXY_CERT_FILE:-/etc/ssl/dnlab/dnlab-gui.crt}"
    export DNLAB_PROXY_CERT_KEY_FILE="${DNLAB_PROXY_CERT_KEY_FILE:-/etc/ssl/dnlab/dnlab-gui.key}"
    case "$DNLAB_PROXY_SERVER_NAME" in
        # Apache's ServerName directive cannot represent a bare IPv6 literal
        # unambiguously.  The sole vhost remains the default vhost, so omit it.
        *:*) export DNLAB_PROXY_APACHE_SERVER_NAME_DIRECTIVE="# ServerName omitted for IPv6 literal." ;;
        *) export DNLAB_PROXY_APACHE_SERVER_NAME_DIRECTIVE="ServerName $DNLAB_PROXY_SERVER_NAME" ;;
    esac

    if /usr/local/bin/dnlab-validate-webui-hostname "$DNLAB_PROXY_SERVER_NAME"; then
        export DNLAB_PROXY_WEBUI_SUFFIX="${DNLAB_PROXY_WEBUI_SUFFIX:-$DNLAB_PROXY_SERVER_NAME}"
        if [ "$DNLAB_PROXY_WEBUI_SUFFIX" != "$DNLAB_PROXY_SERVER_NAME" ]; then
            echo "DNLAB_PROXY_WEBUI_SUFFIX must match DNLAB_PROXY_SERVER_NAME" >&2
            exit 2
        fi
        export DNLAB_PROXY_WEBUI_SERVER_ALIAS="ServerAlias *.${DNLAB_PROXY_WEBUI_SUFFIX}"
    else
        export DNLAB_PROXY_WEBUI_SERVER_ALIAS="# Device Web UI wildcard aliases disabled: public name is not an FQDN."
        echo "DNLAB_PROXY_SERVER_NAME is not an FQDN; GUI is available but device Web UI proxying is disabled" >&2
    fi
    envsubst '${DNLAB_PROXY_SERVER_NAME} ${DNLAB_PROXY_APACHE_SERVER_NAME_DIRECTIVE} ${DNLAB_PROXY_WEBUI_SERVER_ALIAS} ${DNLAB_PROXY_SERVER_ADMIN} ${DNLAB_PROXY_CERT_FILE} ${DNLAB_PROXY_CERT_KEY_FILE}' \
        < /etc/apache2/templates/dnlab-gui-prod.conf.template \
        > /etc/apache2/sites-available/000-dnlab-gui.conf
fi

exec "$@"
