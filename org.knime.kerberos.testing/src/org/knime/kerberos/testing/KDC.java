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
 *   Jan 31, 2019 (bjoern): created
 */
package org.knime.kerberos.testing;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Properties;

import org.apache.hadoop.minikdc.MiniKdc;

import sun.security.krb5.internal.ccache.FileCredentialsCache;

/**
 * A KDC for unit-testing purposes, based on Hadoop's MiniKDC.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KDC {

    private final File m_kdcDir;

    private final Properties kdcConf;

    private final String m_krbConfPath;

    private final MiniKdc m_kdc;

    private final File m_keytabFile;

    private final String m_keytabPrincipal;

    private final String m_realm;

    private final String m_kdcHost;

    private final String m_ccFile;

    /** Valid username for testing */
    public static final String USER = "user";

    /** Valid Password for testing */
    public static final String PWD = "password";

    /** Valid Keytab user for testing */
    public static final String KEYTAB_USER = "keytabuser";

    /**
     * Creates and starts a MiniKDC for unit testing
     * @throws Exception
     */
    public KDC() throws Exception {
        m_kdcDir = Files.createTempDirectory("knime_kerberos_testing").toFile();
        kdcConf = MiniKdc.createConf();
        kdcConf.setProperty(MiniKdc.MAX_RENEWABLE_LIFETIME, "8640000");
        kdcConf.setProperty(MiniKdc.MAX_TICKET_LIFETIME, "60000");
        kdcConf.setProperty(MiniKdc.MIN_TICKET_LIFETIME, "60");
        m_kdc = new MiniKdc(kdcConf, m_kdcDir);
        m_kdc.start();
        m_krbConfPath = m_kdc.getKrb5conf().getAbsolutePath();
        m_keytabFile = new File(m_kdcDir, "keytab");
        m_realm = m_kdc.getRealm();
        m_kdcHost = m_kdc.getHost() + ":" + m_kdc.getPort();

        m_kdc.createPrincipal(m_keytabFile, KEYTAB_USER);
        m_keytabPrincipal = KEYTAB_USER + "@" + m_realm;

        m_kdc.createPrincipal(USER, PWD);
        File ccFile = new File(FileCredentialsCache.getDefaultCacheName());
        m_ccFile = ccFile.getAbsolutePath();
    }





    /**
     * Stops the KDC
     * @throws IOException
     */
    public void stop() throws IOException {
        m_kdc.stop();
        Files.walk(m_kdcDir.toPath()).sorted(Collections.reverseOrder()).forEach(p -> {
            try {
                Files.delete(p);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        try {
            Files.delete(Paths.get(m_ccFile));
        } catch (NoSuchFileException e) {
            // ignore
        }
    }

    /**
     * @return the m_keytabFile
     */
    public String getKeytabFilePath() {
        return m_keytabFile.getAbsolutePath();
    }

    /**
     * @return the m_principal
     */
    public String getKeytabPrincipal() {
        return m_keytabPrincipal;
    }

    /**
     * @return the m_realm
     */
    public String getRealm() {
        return m_realm;
    }


    /**
     * @return the m_kdcHost
     */
    public String getKDCHost() {
        return m_kdcHost;
    }

    /**
     * @return principal of preconfigured user.
     */
    public String getUserPrincipal() {
        return USER + "@" + m_realm;
    }

    /**
     * @return the ccFile
     */
    public String getCcFile() {
        return m_ccFile;
    }

    /**
     * @return the kdcConfPath
     */
    public String getKdcConfPath() {
        return m_krbConfPath;
    }
}
