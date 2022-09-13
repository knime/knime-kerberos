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
package org.knime.kerberos.api;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.AccessController;
import java.util.HashMap;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.apache.kerby.kerberos.kerb.server.KdcConfigKey;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.testing.KrbConfigUtil;
import org.knime.kerberos.testing.TestKDC;
import org.knime.kerberos.testing.Util;

/**
 * Testcase for {@link KerberosProvider} with weak crypto support. This is its own class (vs being part of
 * {@link KerberosProviderTest}) because it requires the KDC instance to be configured accordingly.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KerberosProviderWeakCryptoTest extends KerberosProviderTestBase {

    private static TestKDC testKDC;

    /**
     * Sets up a test KDC.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        var config = new HashMap<KdcConfigKey, Object>();
        config.put(KdcConfigKey.ENCRYPTION_TYPES, "arcfour-hmac rc4-hmac");
        testKDC = new TestKDC(config);
    }

    /**
     * Tears down the test KDC.
     *
     * @throws Exception
     */
    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        testKDC.stop();
    }

    /**
     * Test Kerberos keytab login with a keytab which contains only a "weak" key (see AP-19484)
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuth_keytab_weak_crypto() throws Exception {

        // does not allow weak crypto
        final var regularConfig = testKDC.getKrbClientConfig().toAbsolutePath().toString();
        var config = new KerberosPluginConfig(KerberosConfigSource.FILE, regularConfig, "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);
        config.save();

        Exception failedWith = null;
        try {
            Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
                return null;
            }));
        } catch (Exception e) { // should fail
            failedWith = e;
        }

        assertNotNull("Login should not work when weak crypto is disallowed", failedWith);
        assertTrue("Login should fail with IllegalArgumentException", failedWith instanceof IllegalArgumentException);

        // allows weak crypto
        final var weakCryptoConfig = KrbConfigUtil.createValidKrb5(testKDC.getRealm(), testKDC.getKDCHost(), true);
        config = new KerberosPluginConfig(KerberosConfigSource.FILE, weakCryptoConfig, "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);
        config.save();

        Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
            final Subject s = Subject.getSubject(AccessController.getContext());
            assertEquals(testKDC.getKeytabPrincipal(),
                s.getPrincipals(KerberosPrincipal.class).iterator().next().getName());
            return null;
        }));
        assertAuthenticated(testKDC.getKeytabPrincipal());
    }

}
