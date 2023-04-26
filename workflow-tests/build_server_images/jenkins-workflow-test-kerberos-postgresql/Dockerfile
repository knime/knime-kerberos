
# Use official postgres image from ubunutu
# https://hub.docker.com/_/postgres
FROM ubuntu/postgres

RUN apt-get update && apt-get install -y vim

#Install kerberos related packages
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install krb5-user

# Copy kerberos configuration file, POSTGRES user keytab file and pg_hba.conf on PG server
COPY krb5.conf /etc/
COPY postgres.pg.ad.testing.knime.keytab /etc/postgresql/
COPY pg_hba.conf /etc/


# Copy mysql and shell scripts to docker entry point initdb dir, the scripts are executed once //
# default databse and user are created.
COPY init_user.sql /docker-entrypoint-initdb.d/
COPY krb_conf.sh /docker-entrypoint-initdb.d/
