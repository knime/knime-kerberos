#!/bin/bash
docker run -u root \
-e "ACCEPT_EULA=Y" -e "MSSQL_SA_PASSWORD=Knime_Password" \
-p 1433:1433 --name mssqlserver_test \
--dns-search ad.testing.knime \
--dns 172.29.1.42 \
--add-host ec2amaz-r27ajvi.ad.testing.knime:172.29.1.42 \
--add-host ad.testing.knime:172.29.1.42 \
--add-host testing.knime:172.29.1.42 \
--add-host ad:172.29.1.42 \
-h mssqlserver.ad.testing.knime \
-d mssqlserver:latest
