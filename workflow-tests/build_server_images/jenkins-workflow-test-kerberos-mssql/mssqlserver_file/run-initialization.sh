#!/bin/bash

# Run init-script with long timeout - and make it run in the background
sleep 40s
/opt/mssql-tools/bin/sqlcmd -S localhost -U SA -P Knime_Password -i init.sql