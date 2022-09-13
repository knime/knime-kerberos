/*
 * ------------------------------------------------------------------------
 *
 *  Copyright by KNIME AG, Zurich, Switzerland
 *  Website: http://www.knime.com; Email: contact@knime.com
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License, Version 3, as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses>.
 *
 *  Additional permission under GNU GPL version 3 section 7:
 *
 *  KNIME interoperates with ECLIPSE solely via ECLIPSE's plug-in APIs.
 *  Hence, KNIME and ECLIPSE are both independent programs and are not
 *  derived from each other. Should, however, the interpretation of the
 *  GNU GPL Version 3 ("License") under any applicable laws result in
 *  KNIME and ECLIPSE being a combined program, KNIME AG herewith grants
 *  you the additional permission to use and propagate KNIME together with
 *  ECLIPSE with only the license terms in place for ECLIPSE applying to
 *  ECLIPSE and the GNU GPL Version 3 applying for KNIME, provided the
 *  license terms of ECLIPSE themselves allow for the respective use and
 *  propagation of ECLIPSE together with KNIME.
 *
 *  Additional permission relating to nodes for KNIME that extend the Node
 *  Extension (and in particular that are based on subclasses of NodeModel,
 *  NodeDialog, and NodeView) and that only interoperate with KNIME through
 *  standard APIs ("Nodes"):
 *  Nodes are deemed to be separate and independent programs and to not be
 *  covered works.  Notwithstanding anything to the contrary in the
 *  License, the License does not apply to Nodes, you are not required to
 *  license Nodes under the License, and you are granted a license to
 *  prepare and propagate Nodes, in each case even if such Nodes are
 *  propagated with or for interoperation with KNIME.  The owner of a Node
 *  may freely choose the license terms applicable to such Node, including
 *  when such Node is propagated with or for interoperation with KNIME.
 * ---------------------------------------------------------------------
 *
 * History
 *   Sep 13, 2022 (bjoern): created
 */
package org.knime.kerberos.testing;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.client.ClientUtil;
import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.apache.kerby.kerberos.kerb.server.SimpleKdcServer;
import org.apache.kerby.util.NetworkUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * KDC based on Apache Directory Server that can be embedded in testcases.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class TestKDC {

    private static final Logger LOG = LoggerFactory.getLogger(TestKDC.class);

    /** Valid username for testing */
    public static final String USER = "user";

    /** Valid Password for testing */
    public static final String PWD = "password";

    /** Valid Keytab user for testing */
    public static final String KEYTAB_USER = "keytabuser";

    private static final Map<KdcConfigKey, Object> DEFAULT_KDC_CONF = new HashMap<>();
    static {
        DEFAULT_KDC_CONF.put(KdcConfigKey.MAXIMUM_RENEWABLE_LIFETIME, 8640000);
        DEFAULT_KDC_CONF.put(KdcConfigKey.MAXIMUM_TICKET_LIFETIME, 60);
        DEFAULT_KDC_CONF.put(KdcConfigKey.KDC_SERVICE_NAME, "TestKrbServer");
    }

    private final SimpleKdcServer m_kdcServer;

    private final String m_realm;

    private final String m_host;

    private final int m_port;

    private final Path m_tempDir;

    private final Path m_confDir;

    private final Path m_krbClientConfig;

    private final File m_keytabFile;

    private final String m_keytabPrincipal;

    public TestKDC() throws Exception {
        this(DEFAULT_KDC_CONF);
    }

    public TestKDC(final Map<KdcConfigKey, Object> kdcConfigs) throws Exception {
        m_realm = "TEST";
        m_host = "localhost";
        m_port = NetworkUtil.getServerPort();
        m_tempDir = Files.createTempDirectory("testkdc_");
        m_confDir = m_tempDir.resolve("conf");
        Files.createDirectories(m_confDir);

        m_krbClientConfig = writeKrbClientConfig();
        try {
            if (!kdcConfigs.isEmpty()) {
                writeKdcConfig(kdcConfigs);
                m_kdcServer = new SimpleKdcServer(m_confDir.toFile(), ClientUtil.getConfig(m_confDir.toFile()));
            } else {
                m_kdcServer = new SimpleKdcServer();
            }
            m_kdcServer.setWorkDir(m_tempDir.toFile());
            m_kdcServer.setKdcHost(m_host);
            m_kdcServer.setKdcRealm(m_realm);
            m_kdcServer.setKdcTcpPort(m_port);
            m_kdcServer.setKdcUdpPort(m_port);
            // m_kdcServer.setAllowUdp(false);
            m_kdcServer.init();
            m_kdcServer.start();

            m_keytabFile = m_tempDir.resolve("keytab").toFile();
            createPrincipal(m_keytabFile, KEYTAB_USER);
            m_keytabPrincipal = KEYTAB_USER + "@" + m_realm;

            m_kdcServer.createPrincipal(USER, PWD);

        } catch (KrbException ex) {
            ex.printStackTrace();
            throw new IOException("Failed to setup KDC", ex);
        }
    }

    private Path writeKrbClientConfig() throws IOException {
        final var tmpConfig = Paths.get(KrbConfigUtil.createValidKrb5(getRealm(), getKDCHost(), false));
        final var krbConf = m_confDir.resolve("krb5.conf");
        Files.move(tmpConfig, krbConf);
//        try (var writer = Files.newBufferedWriter(krbConf)) {
//            writer.append("[libdefaults]");
//            writer.newLine();
//
//            writer.append("default_realm = " + m_realm);
//            writer.newLine();
//
//            writer.append("udp_preference_limit = 1");
//            writer.newLine();
//
//            writer.append("[realms]");
//            writer.newLine();
//            writer.append(String.format("%s = {%nkdc = %s:%d%n}", m_realm, m_host, m_port));
//            writer.newLine();
//        }
        return krbConf;
    }

    /**
     * @return the realm
     */
    public String getRealm() {
        return m_realm;
    }

    /**
     * @return the host
     */
    public String getKDCHost() {
        return m_host + ":" + m_port;
    }

    /**
     * @return the port
     */
    public int getPort() {
        return m_port;
    }

    /**
     * @return the path of the keytab file
     */
    public String getKeytabFilePath() {
        return m_keytabFile.getAbsolutePath();
    }

    /**
     * @return the keytabPrincipal
     */
    public String getKeytabPrincipal() {
        return m_keytabPrincipal;
    }

    public Path getKrbClientConfig() {
        return m_krbClientConfig;
    }

    /**
     * @return principal of preconfigured user.
     */
    public String getUserPrincipal() {
        return USER + "@" + m_realm;
    }

    private void writeKdcConfig(final Map<KdcConfigKey, Object> kdcConfigs) throws IOException {
        final var effectiveConf = new HashMap<>(DEFAULT_KDC_CONF);
        effectiveConf.putAll(kdcConfigs);

        final var kdcConf = m_confDir.resolve("kdc.conf");
        try (var writer = Files.newBufferedWriter(kdcConf)) {
            writer.append("[kdcdefaults]");
            writer.newLine();
            for (var key : effectiveConf.keySet()) {
                writer.append(String.format("%s = %s", //
                    key.getPropertyKey(), //
                    effectiveConf.get(key).toString()));
                writer.newLine();
            }
        }
    }

    /**
     * Stops the TestKDC
     */
    public synchronized void stop() {
        try {
            m_kdcServer.stop();
        } catch (KrbException e) {
            LOG.error("Error while stopping KDC", e);
        } finally {
            try {
                FileUtils.deleteDirectory(m_tempDir.toFile());
            } catch (IOException ex) { // NOSONAR ignore silently
            }
        }
    }

    /**
     * Creates a principal in the KDC with the given user and password.
     *
     * @param principal The principal to add to the KDC (do not include realm)
     * @param password The password to set.
     * @throws Exception thrown if something went wrong
     */
    public synchronized void createPrincipal(final String principal, final String password) throws Exception {
        m_kdcServer.createPrincipal(principal, password);
    }

    /**
     * Creates one or multiple principals in the KDC and adds them to a keytab file.
     *
     * @param keytabFile The keytab file to write to (will be overwritten if it exists).
     * @param principals The principals to add to the KDC (do not include realm)
     * @throws Exception thrown if something went wrong
     */
    private void createPrincipal(final File keytabFile, final String... principals) throws Exception {
        m_kdcServer.createPrincipals(principals);
        Files.deleteIfExists(keytabFile.toPath());
        for (var principal : principals) {
            m_kdcServer.getKadmin().exportKeytab(keytabFile, principal);
        }
    }
}
