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
package org.knime.kerberos.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

import java.security.AccessController;
import java.time.Instant;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.knime.core.node.CanceledExecutionException;
import org.knime.core.node.ExecutionMonitor;
import org.knime.core.node.NodeProgressMonitor;
import org.knime.kerberos.KerberosAuthManager;
import org.knime.kerberos.KerberosInternalAPI;
import org.knime.kerberos.KerberosInternalAPITest.TestCallBackHandler;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.logger.KerberosLogger;
import org.knime.kerberos.testing.KrbTicketCacheUtil;
import org.knime.kerberos.testing.TestKDC;
import org.knime.kerberos.testing.Util;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

/**
 * Testcase for {@link KerberosProvider}
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KerberosProviderTest extends KerberosProviderTestBase {

    private static TestKDC testKDC;

    /**
     * Sets up a test KDC.
     *
     * @throws Exception
     */
    @BeforeAll
    public static void setUpBeforeClass() throws Exception {
        testKDC = new TestKDC();
    }

    /**
     * Tears down the test KDC.
     *
     * @throws Exception
     */
    @AfterAll
    public static void tearDownAfterClass() throws Exception {
        testKDC.stop();
    }

    /**
     * Setup for each individual test method.
     */
    @BeforeEach
    public void setupBefore() {
        KerberosPluginConfig.TEST_OVERRIDES = new HashMap<>();

        // deactivates the multiplexing of Kerberos log messages into a KNIME NodeLogger,
        // which requires a fully booted KNIME and OSGI container, which we do not want.
        KerberosLogger.setUseNodeLoggerForwarder(false);
    }

    /**
     * Rolls back to initial state after each test
     *
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @AfterEach
    public void rollBack() throws InterruptedException, ExecutionException {
        try {
            KerberosInternalAPI.logout().get();
        } catch (ExecutionException e) {
            if (!(e.getCause() instanceof IllegalStateException)) {
                throw e;
            }
        }
    }

    /**
     * Test automatic keytab login in KerberosProvider.doWithKerberosAuth().
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuth_keytab() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
            final Subject s = Subject.getSubject(AccessController.getContext());
            assertEquals(testKDC.getKeytabPrincipal(),
                s.getPrincipals(KerberosPrincipal.class).iterator().next().getName());
            return null;
        }));
        assertAuthenticated(testKDC.getKeytabPrincipal());
    }

    /**
     * Test automatic keytab login in KerberosProvider.doWithKerberosAuth().
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuth_userPwd_and_already_logged_in() throws Exception {
        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        config.save();

        Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler(TestKDC.USER, TestKDC.PWD)));

        Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
            final Subject s = Subject.getSubject(AccessController.getContext());
            assertEquals(testKDC.getUserPrincipal(),
                s.getPrincipals(KerberosPrincipal.class).iterator().next().getName());
            return null;
        }));
    }

    /**
     * Assert failure in KerberosProvider.doWithKerberosAuth(), when user/pwd auth is configured but the user has not
     * logged in so far. Throws LoginException("Not logged in. Please login via the preference page first.")
     *
     */
    @Test
    public void test_doWithKerberosAuth_userPwd_but_not_logged_in() {
        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        config.save();

        assertThrows(LoginException.class, () -> Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
            fail("Should never be executed");
            return null;
        })));
    }

    /**
     * Assert failure in KerberosProvider.doWithKerberosAuth(), when TICKET_CACHE auth is configured but there is not
     * ticket cache. Throws LoginException("Unable to obtain Principal Name for authentication")
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuth_with_missing_ticketCache() throws Exception {
        KrbTicketCacheUtil.deleteTicketCache();

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.TICKET_CACHE, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        config.save();

        assertThrows(LoginException.class, () -> Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
            fail("Should never be executed");
            return null;
        })));
    }

    /**
     * Tests lazy login in doWithKerberosAuthBlocking() when using keytab login.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuthBlocking_keytab_lazy_login() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        KerberosProvider.doWithKerberosAuthBlocking(() -> {
            final Subject s = Subject.getSubject(AccessController.getContext());
            assertEquals(testKDC.getKeytabPrincipal(),
                s.getPrincipals(KerberosPrincipal.class).iterator().next().getName());
            return null;
        }, null);
        assertAuthenticated(testKDC.getKeytabPrincipal());
    }

    /**
     * Asserts failure in doWithKerberosAuthBlocking() when using user/password authentication, but not logged in prior
     * to invocation.
     *
     */
    @Test
    public void test_doWithKerberosAuthBlocking_userPwd_but_not_logged_in() {
        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        config.save();

        assertThrows(LoginException.class, () -> KerberosProvider.doWithKerberosAuthBlocking(() -> {
            fail("Should never be executed");
            return null;
        }, null));
    }

    /**
     * Asserts CanceledExecutionException when invoking doWithKerberosAuthBlocking() with a pre-cancelled execution
     * monitor.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuthBlocking_precancelled_via_monitor() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        final ExecutionMonitor exec = mockExecMonitor(0);

        assertThrows(CanceledExecutionException.class, () -> KerberosProvider.doWithKerberosAuthBlocking(() -> {
            fail("Should never be executed");
            return null;
        }, exec));
    }

    private static void testCancellation(final ExecutionMonitor exec, final boolean interruptToCancel,
        final int waitBeforeCancel) throws Exception {
        final AtomicReference<String> failMsg = new AtomicReference<String>(null);

        final Runnable runnable = () -> {
            boolean cancelled = false;
            try {
                KerberosProvider.doWithKerberosAuthBlocking(() -> {
                    Thread.sleep(1000);
                    failMsg.set("Should never be executed");
                    return null;
                }, exec);
            } catch (CanceledExecutionException e) {
                cancelled = true;
            } catch (Throwable e) {
                failMsg.set("Unexpected exception thrown: " + e.getClass().getCanonicalName() + ": " + e.getMessage());
                e.printStackTrace();
                return;
            }

            if (!cancelled) {
                failMsg.set("Was not cancelled");
            }
        };

        final Thread t = new Thread(runnable);
        t.start();

        if (waitBeforeCancel > 0 && interruptToCancel) {
            Thread.sleep(waitBeforeCancel);
            t.interrupt();
        }

        t.join();

        if (failMsg.get() != null) {
            fail(failMsg.get());
        }
    }

    private static ExecutionMonitor mockExecMonitor(final int cancelAfterCheckCancelledInvocations) throws Exception {
        final NodeProgressMonitor monitorMock = mock(NodeProgressMonitor.class);
        doAnswer(new Answer<Object>() {
            private int count = 0;

            @Override
            public Object answer(final InvocationOnMock invocation) throws Throwable {
                if (count++ >= cancelAfterCheckCancelledInvocations) {
                    throw new CanceledExecutionException();
                } else {
                    return null;
                }
            }
        }).when(monitorMock).checkCanceled();

        return new ExecutionMonitor(monitorMock);
    }

    /**
     * Tests that doWithKerberosAuthBlocking can be cancelled using the monitor.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuthBlocking_cancelled_via_monitor() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        for (int i = 0; i < 10; i++) {
            final ExecutionMonitor exec = mockExecMonitor(1 + (i / 5) * 1);
            testCancellation(exec, false, -1);
        }
    }

    /**
     * Tests that doWithKerberosAuthBlocking can be cancelled using Thread.interrupt().
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuthBlocking_cancelled_via_interruption() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        for (int i = 0; i < 10; i++) {
            testCancellation(null, true, Math.max(2, i * 10));
        }
    }

    /**
     * Tests that doWithKerberosAuthBlocking can be cancelled using the execution monitor, directly after invocation.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuthBlocking_immediately_cancelled_via_monitor() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        for (int i = 0; i < 10; i++) {
            final ExecutionMonitor exec = mockExecMonitor(1);
            testCancellation(exec, false, -1);
        }
    }

    /**
     * Tests that doWithKerberosAuthBlocking can be cancelled using Thread.interrupt(), directly after invocation.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuthBlocking_immediately_cancelled_via_interruption() throws Exception {
        KerberosPluginConfig config = createKeytabKerberosConfig();
        config.save();

        for (int i = 0; i < 10; i++) {
            testCancellation(null, true, 1);
        }
    }

    /**
     * Test im logout for background kdestroy.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuth_with_deleted_ticket_cache() throws Exception {

        final var ccFile = KrbTicketCacheUtil.createTicketCacheWithKinit(testKDC);

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "", AuthMethod.TICKET_CACHE, "", "", true,
                PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 115000, true, true, ccFile.toString());

        Util.awaitFuture(KerberosInternalAPI.login(config, null));
        assertTrue(KerberosAuthManager.getKerberosState().isAuthenticated());

        KrbTicketCacheUtil.deleteTicketCache();

        config.save();
        try {
            Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
                fail("Should never be executed");
                return null;
            }));
            fail("Should never be executed");
        } catch (LoginException e) {
            // to be expected
        }
        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
    }

    /**
     * Test a logout for background kdestroy.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithKerberosAuth_with_updated_ticket_cache() throws Exception {

        final var ccFile = KrbTicketCacheUtil.createTicketCacheWithKinit(testKDC);

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "", AuthMethod.TICKET_CACHE, "", "", true,
                PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 115000, true, true, ccFile.toString());

        Util.awaitFuture(KerberosInternalAPI.login(config, null));
        assertTrue(KerberosAuthManager.getKerberosState().isAuthenticated());
        final Instant expiryTime = KerberosAuthManager.getKerberosState().getTicketValidUntil();

        KrbTicketCacheUtil.deleteTicketCache();
        // we need to sleep one second because the expiry timestamp only has second precision
        Thread.sleep(1000);
        KrbTicketCacheUtil.createTicketCacheWithKinit(testKDC);

        config.save();
        Util.awaitFuture(KerberosProvider.doWithKerberosAuth(() -> {
            return null;
        }));
        // assert we are still authenticated but that we have picked up the new ticket
        assertTrue(KerberosAuthManager.getKerberosState().isAuthenticated());
        assertTrue(KerberosAuthManager.getKerberosState().getTicketValidUntil().isAfter(expiryTime));
    }

    private static KerberosPluginConfig createKeytabKerberosConfig() {
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);
        return config;
    }
}
