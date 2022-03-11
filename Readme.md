TEST COMMIT

# KNIME Kerberos Authentication Framework

Kerberos is a widely used authentication scheme for services in both standard enterprise IT (e.g. ActiveDirectory), as well as Hadoop clusters.
The KNIME Kerberos Authentication Framework makes it easier to connect to Kerberos-secured services for users of KNIME Analytics Platform as well as customers KNIME Server customers.

On a technical level, the core idea is to manage the Kerberos login from within KNIME. With this, it is no more necessary to use kinit or MIT Kerberos Client for Windows to log into KNIME.

## Maven build 

Compile project and run tests:

    `mvn clean verify`

