FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends apache2 ca-certificates curl gettext-base \
    && a2enmod headers proxy proxy_http proxy_wstunnel rewrite ssl \
    && rm -rf /var/lib/apt/lists/*

COPY deploy/apache/docker/dnlab-gui-dev.conf /etc/apache2/sites-available/000-dnlab-gui.conf
COPY deploy/apache/docker/dnlab-gui-prod.conf.template /etc/apache2/templates/dnlab-gui-prod.conf.template
COPY deploy/apache/docker/entrypoint.sh /usr/local/bin/dnlab-apache-entrypoint
COPY deploy/apache/docker/validate-webui-hostname.sh /usr/local/bin/dnlab-validate-webui-hostname
COPY deploy/apache/error/ /opt/dnlab-gui/deploy/apache/error/
COPY app/views/static/img/ /opt/dnlab-gui/app/views/static/img/

RUN a2dissite 000-default.conf \
    && a2ensite 000-dnlab-gui.conf \
    && mkdir -p /var/www/acme-challenge \
    && chmod +x /usr/local/bin/dnlab-apache-entrypoint /usr/local/bin/dnlab-validate-webui-hostname \
    && mkdir -p /usr/share/doc/dnlab/third-party \
    && printf '%s\n' \
        '# dNLab Third-Party Notices' \
        '' \
        'This image contains the dNLab proxy plus Debian and Apache HTTP Server packages.' \
        'Release builds must attach a generated SBOM and full notice bundle for the exact image tag.' \
        'See the public dNLab THIRD_PARTY_NOTICES.md for policy details.' \
        > /usr/share/doc/dnlab/third-party/THIRD_PARTY_NOTICES.md

EXPOSE 80 443
ENTRYPOINT ["dnlab-apache-entrypoint"]
CMD ["apachectl", "-D", "FOREGROUND"]
