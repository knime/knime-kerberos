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
 *   29.03.2019 (Mareike Hoeger, KNIME GmbH, Konstanz, Germany): created
 */
package org.knime.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.time.Instant;
import java.util.List;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.knime.core.node.NodeLogger.LEVEL;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.logger.KerberosLogger;
import org.knime.kerberos.logger.LogForwarder;
import org.knime.kerberos.testing.KDC;
import org.knime.kerberos.testing.Util;

/**
 * Tests for the Kerberos Logger
 *
 * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
 */
public class KerberosLoggerTest {

    private static KDC testKDC;

    private LogForwarder m_mockedLogForwarder;


    /**
     * Sets up a test testKDC.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        testKDC = new KDC();
    }

    /**
     * Tears down the test testKDC.
     *
     * @throws Exception
     */
    @AfterClass
    public static void tearDownAfterClass() throws Exception {
        testKDC.stop();
    }

    /**
     * Rolls back to initial state after each test
     *
     * @throws Exception
     */
    @After
    public void rollBack() throws Exception {
        try {
            Util.awaitFuture(KerberosInternalAPI.logout());
        } catch (IllegalStateException e) {
            // do nothing
        }
        System.clearProperty("sun.security.krb5.principal");
    }

    /**
     * Setup for each individual test method.
     */
    @Before
    public void setup() {
        m_mockedLogForwarder = mock(LogForwarder.class);
        KerberosLogger.setLogForwarderForTesting(m_mockedLogForwarder);
    }

    private static void testSuccessfulKeyTabLogin(final KerberosPluginConfig config) throws Exception {
        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, null));

        final KerberosState state = KerberosAuthManager.getKerberosState();
        assertTrue(state.isAuthenticated());
        assertEquals(testKDC.getKeytabPrincipal(), state.getPrincipal());
        assertTrue(Instant.now().isBefore(state.getTicketValidUntil()));
        assertFalse(KerberosLogger.getCapturedLines().isEmpty());
    }

    /**
     * Test a login and subsequent logout.
     *
     * @throws Exception
     */
    @Test
    public void test_login_logout() throws Exception {
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        testSuccessfulKeyTabLogin(config);
        List<String> logLines = KerberosLogger.getCapturedLines();
        assertFalse(logLines.isEmpty());
        Util.awaitFuture(KerberosInternalAPI.logout());
        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
    }

    /**
     * Test a login and logging.
     *
     * @throws Exception
     */
    @Test
    public void test_start_stop_logger() throws Exception {

        String testString = "Test String";
        String testString2 = "Test String 2";
        synchronized(System.out) {
            KerberosLogger.startCapture(true, LEVEL.DEBUG);
            System.out.println(testString);
            System.out.println(testString2);
            List<String> logLines = KerberosLogger.getCapturedLines();
            assertTrue(logLines.size() == 2);
            assertTrue(logLines.get(0).equalsIgnoreCase(testString));
            assertTrue(logLines.get(1).equalsIgnoreCase(testString2));
            KerberosLogger.stopCapture();
            System.out.println("Should not be in log");
            logLines = KerberosLogger.getCapturedLines();
            assertTrue(logLines.size() == 2);
        }
    }

}
