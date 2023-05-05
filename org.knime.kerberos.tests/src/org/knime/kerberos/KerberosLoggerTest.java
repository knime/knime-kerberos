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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.knime.core.node.NodeLogger.LEVEL;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.logger.KerberosLogger;
import org.knime.kerberos.testing.TestKDC;
import org.knime.kerberos.testing.Util;

/**
 * Tests for the Kerberos Logger
 *
 * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
 */
public class KerberosLoggerTest {

    private static TestKDC testKDC;

    /**
     * Sets up a test testKDC.
     *
     * @throws Exception
     */
    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        testKDC = new TestKDC();
    }

    /**
     * Tears down the test testKDC.
     *
     * @throws Exception
     */
    @AfterAll
    public static void tearDownAfterClass() throws Exception {
        testKDC.stop();
    }

    /**
     * Rolls back to initial state after each test
     *
     * @throws Exception
     */
    @AfterEach
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
    @BeforeEach
    public void setup() {
        // deactivates the multiplexing of Kerberos log messages into a KNIME NodeLogger,
        // which requires a fully booted KNIME and OSGI container, which we do not want.
        KerberosLogger.setUseNodeLoggerForwarder(false);
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

        final String regexTemplate = "[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+  %s";

        String testString = "Test String";
        String testString2 = "Test String 2";
        synchronized(System.out) {
            KerberosLogger.startCapture(LEVEL.DEBUG);
            System.out.println(testString);
            System.out.println(testString2);
            System.out.flush();
        }

        synchronized(System.out) {

        List<String> logLines = KerberosLogger.getCapturedLines();
        assertEquals(2, logLines.size());
        assertTrue(Pattern.matches(String.format(regexTemplate, testString), logLines.get(0)));
        assertTrue(Pattern.matches(String.format(regexTemplate, testString2), logLines.get(1)));

        KerberosLogger.stopCapture();
        System.out.println("Should not be in log");
        logLines = KerberosLogger.getCapturedLines();
        assertTrue(logLines.size() == 2);
        }
    }

    /**
     * Tests thread-safety of the KerberosLogger.
     *
     * @throws InterruptedException
     */
    @Test
    public void test_concurrent_sysout_logging() throws InterruptedException {
        final ForkJoinPool pool = new ForkJoinPool();

        KerberosLogger.startCapture(LEVEL.DEBUG);

        final String msgTemplate = "This is message %d.%d bla bla bla blub";
        for (int i = 0; i < 100; i++) {
            final int taskId = i;
            pool.execute(() -> {
                for (int j = 0; j < 1000; j++) {
                    System.out.println(String.format(msgTemplate, taskId, j));
                }
            });
        }
        pool.shutdown();
        pool.awaitTermination(30, TimeUnit.SECONDS);

        final List<String> capturedLines = KerberosLogger.getCapturedLines();
        KerberosLogger.stopCapture();

        assertEquals(1000 * 100, capturedLines.size());

        final Pattern msgRegex = Pattern
            .compile("[0-9]+-[0-9]+-[0-9]+ [0-9]+:[0-9]+:[0-9]+  This is message [0-9]+.[0-9]+ bla bla bla blub");
        for (String msg : capturedLines) {
            assertTrue(msgRegex.matcher(msg).matches(), msg + " does not match the expected regex");
        }
    }

    /**
     * Test whether a single large log message can be logged to System.out without error.
     *
     * @throws InterruptedException
     */
    @Test
    public void test_large_log_message() throws InterruptedException {
        KerberosLogger.startCapture(LEVEL.DEBUG);

        final byte[] randomBytes = new byte[40 * 1024];
        ThreadLocalRandom.current().nextBytes(randomBytes);
        final String base64EncodedRandom = Base64.getEncoder().encodeToString(randomBytes);

        System.out.println(base64EncodedRandom);
        final List<String> capturedLines = KerberosLogger.getCapturedLines();
        KerberosLogger.stopCapture();

        assertEquals(1, capturedLines.size());
        assertTrue(capturedLines.get(0).endsWith(base64EncodedRandom));
        assertEquals(21 + base64EncodedRandom.length(), capturedLines.get(0).length());
    }
}
