#!/bin/bash

# Replace pg_hba.conf to allow all local connections and only GSS authentication with Kerberos for remote connection. 
mv /var/lib/postgresql/data/pg_hba.conf /var/lib/postgresql/data/pg_hba.conf_bkp
cp /etc/pg_hba.conf /var/lib/postgresql/data/

# And add ``listen_addresses`` to ``/etc/postgresql/9.3/main/postgresql.conf``
echo "listen_addresses='*'" >> /var/lib/postgresql/data/postgresql.conf
echo "krb_server_keyfile = '/etc/postgresql/postgres.pg.ad.testing.knime.keytab'" >> /var/lib/postgresql/data/postgresql.conf
