#!/bin/bash
# Shell script to replace the workspace directory in preference file. 
preferencesPath="${WORKSPACE}/workflow-tests/preferences.epf"
sedi "s|workspace_placeholder|${WORKSPACE}|g" "${preferencesPath}"
cat "${preferencesPath}"

# Get IP address and add KDC and PG server in etc hosts.
PgServerIP=$(echo ${KNIME_POSTGRES_ADDRESS} | cut -d ':' -f1)
echo "172.29.1.42	ec2amaz-r27ajvi.ad.testing.knime" >> /etc/hosts
echo "${PgServerIP}	pg.ad.testing.knime" >> /etc/hosts
MSSQLServerIP=$(echo ${KNIME_MSSQL_ADDRESS} | cut -d ':' -f1)
echo "${MSSQLServerIP}	mssqlserver.ad.testing.knime" >> /etc/hosts
