FROM mcr.microsoft.com/mssql/server:latest

USER root

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app

ENV DEBIAN_FRONTEND=noninteractive
ENV ACCEPT_EULA=Y
ENV SA_PASSWORD=Knime_Password

# The root issue is a bug in the base image, which fails to run apt-get update & install, hence, clear out the cache.
# should be root to delete.
RUN rm -rf /var/lib/apt/lists
RUN apt-get update && apt-get install -y vim

COPY krb5.conf /etc/
COPY mssql.keytab /var/opt/mssql/secrets/
COPY ["mssql.conf", "krb5.conf", "/var/opt/mssql/"]
COPY mssqlserver_file /usr/src/app

# RUN chown mssql:mssql /var/opt/mssql/secrets/mssql.keytab
RUN chmod 400 /var/opt/mssql/secrets/mssql.keytab
RUN chmod +x /usr/src/app/run-initialization.sh

CMD /bin/bash ./entrypoint.sh