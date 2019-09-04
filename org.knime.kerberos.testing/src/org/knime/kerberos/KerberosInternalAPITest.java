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
package org.knime.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.stream.Stream;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.logger.KerberosLogger;
import org.knime.kerberos.logger.LogForwarder;
import org.knime.kerberos.testing.KDC;
import org.knime.kerberos.testing.Util;

import sun.security.krb5.KrbException;

/**
 * Test cases for {@link KerberosInternalAPI}.
 *
 * @author Mareike Hoeger, KNIME GmbH
 */
@SuppressWarnings("restriction")
public class KerberosInternalAPITest {

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

    private static void testSuccessfulUserPasswordLogin(final KerberosPluginConfig config, final String username)
        throws Exception {
        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler(username, KDC.PWD)));

        final KerberosState state = KerberosAuthManager.getKerberosState();
        assertTrue(state.isAuthenticated());
        assertEquals(KDC.USER + "@" + testKDC.getRealm(), state.getPrincipal());
        assertTrue(Instant.now().isBefore(state.getTicketValidUntil()));
        assertFalse(KerberosLogger.getCapturedLines().isEmpty());
    }

    /**
     * Test configuration for defaults and keytab
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_defaults_and_keytab() throws Throwable {
        // krb5.conf is set by miniKDC so we should have a defaults environment
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);

        testSuccessfulKeyTabLogin(config);
    }

    /**
     * Test configuration for defaults and keytab with preset sun.security.krb5.principal, which is different from
     * keytab principal.
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_defaults_and_keytab_and_preset_principal() throws Throwable {

        System.setProperty("sun.security.krb5.principal", "wrongprincipal@wrongrealm");
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);

        testSuccessfulKeyTabLogin(config);

    }

    /**
     * Tests configuration with file and keytab
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_file_and_keytab() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            createValidKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        testSuccessfulKeyTabLogin(config);
    }

    /**
     * Tests configuration with Realm & KDC, with unreachable testKDC. Expects "LoginException: ICMP Port Unreachable".
     *
     * @throws Throwable
     */
    @Test(expected = LoginException.class)
    public void test_login_with_RealmKDC_and_unreachable_kdc() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "localhost", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, null));
    }

    /**
     * Tests login with with Realm & KDC, with valid keytab and principal
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_keytab() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        testSuccessfulKeyTabLogin(config);
    }

    /**
     * Tests configuration with Realm & KDC, with username/password
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_UserPwd() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        testSuccessfulUserPasswordLogin(config, KDC.USER);
    }

    /**
     * Tests configuration with Realm & KDC, with principal/password
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_PrincipalPwd() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        testSuccessfulUserPasswordLogin(config, KDC.USER + "@" + testKDC.getRealm());
    }

    /**
     * Tests configuration with Realm & KDC, with username and wrong password. Expects
     * "javax.security.auth.login.LoginException: Checksum failed"
     *
     * FIXME Is that seriously the Exception for a wrong password!?
     *
     * @throws Throwable
     */
    @Test(expected = LoginException.class)
    public void test_login_with_RealmKDC_and_wrong_password() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler(KDC.USER, "wrong")));
    }

    /**
     * Tests configuration with Realm & KDC, with unknown username and wrong password Expects
     * "javax.security.auth.login.LoginException: Client not found [...]"
     *
     * FIXME This is also a really bad error message.
     *
     * @throws Throwable
     */
    @Test(expected = LoginException.class)
    public void test_login_with_RealmKDC_and_wrong_user() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler("unknown", "wrong")));
    }

    /**
     * Tests configuration with Realm & KDC and a callback handler that says the user cancelled the login. Expects
     * UserRequestedCancelException
     *
     * @throws Throwable
     */
    @Test(expected = UserRequestedCancelException.class)
    public void test_login_with_RealmKDC_and_user_cancelled_login() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler()));
    }

    /**
     * Tests configuration with Realm & KDC, without realm specified in keytab principal
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_keytab_without_realm() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, KDC.KEYTAB_USER, testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        testSuccessfulKeyTabLogin(config);
    }

    /**
     * Tests configuration with Realm & KDC, without realm expects "java.lang.IllegalArgumentException: Realm must be
     * specified."
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_missing_realm() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", "",
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, without KDC expects "java.lang.IllegalArgumentException: KDC must be
     * specified."
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_missing_kdc() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, without KDC Expects "java.lang.IllegalArgumentException: KDC [...] is
     * invalid."
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDCinvalidKDC() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "123.232.+.23", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC and keytab. Expects "java.lang.IllegalArgumentException: because keytab file
     * does not contain any keys for given principal [...]".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_keytab_principal_not_in_keytab() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "test@FALSE", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, without keytab specified. Expects "java.lang.IllegalArgumentException:
     * Keytab file must be specified".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_missing_keytab() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), "", true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, with asterisk principal. Expects "java.lang.IllegalArgumentException:
     * Principal '*' is not allowed as keytab principal".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_asterisk_in_keytab_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "*", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid realm in keytab principal. Expects "KrbException: Illegal
     * character in realm name; one of: '/', ':', '".
     *
     * @throws Throwable
     */
    @Test(expected = KrbException.class)
    public void test_validateConfig_with_RealmKDC_and_invalid_keytab_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "test@ab:cde", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, with out principal. Expects "java.lang.IllegalArgumentException: Keytab
     * principal must be specified".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_keytab_but_missing_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, with non existing file. Expects "java.lang.IllegalArgumentException: Keytab
     * file does not exist".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_keytab_but_nonexisting_keytab_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), "somewrongfile", true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, with different realm in config and principal. Expects
     * "java.lang.IllegalArgumentException: The configured realm [...] does not match realm [...] from keytab
     * principal".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_RealmKDC_and_keytab_but_realm_mismatch() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", "HADOOPABC",
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid Realm. Expects "KrbException: Illegal character in realm name;
     * one of: '/', ':', '".
     *
     * @throws Throwable
     */
    @Test(expected = KrbException.class)
    public void test_validateConfig_with_RealmKDC_but_invalid_realm() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", "HADOOP:",
            "localhost", AuthMethod.KEYTAB, "test@HADOOP:", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with file, with malformed file. Expects "KrbException: Unmatched close brace".
     *
     * @throws Throwable
     */
    @Test(expected = KrbException.class)
    public void test_validateConfig_with_malformed_config_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            createInvalidKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with file, with malformed file. Expects "java.lang.KrbException: Illegal config content:-".
     *
     * @throws Throwable
     */
    @Test(expected = KrbException.class)
    public void test_validateConfig_with_malformed_config_file2() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            createInvalidKDCKrb5(testKDC.getRealm()), "", "", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(),
            testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with file, without actually specifying the file. Expects "java.lang.IllegalArgumentException:
     * Kerberos config file must be specified".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_missing_krb_config_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE, "", "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with file, without a KDC for given realm configured. Expects
     * "java.lang.IllegalArgumentException: Kerberos config file does not exist".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_invalid_path_to_krb_config_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE, "--", "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with file and keytab auth, but without a KDC for realm of keytab principal. Expects
     * "java.lang.IllegalArgumentException: Cannot locate KDC for realm of keytab principal [...]".
     *
     * @throws Throwable
     */
    @Test(expected = IllegalArgumentException.class)
    public void test_validateConfig_with_file_and_keytab_but_missing_kdc_for_keytab_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            createNoKDCforRealmKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
    }

    /**
     * Tests configuration with file and keytab, but without default realm in file. Expects
     * "java.lang.IllegalArgumentException: No default realm is set".
     *
     * @throws Throwable
     */
    @Test(expected = KrbException.class)
    public void test_validateConfig_with_missing_default_realm_in_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            createNoDefaultRealmKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false));
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
        Util.awaitFuture(KerberosInternalAPI.logout());
        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
    }

    /**
     * Test a renewal with a renewable ticket from the ticket cache.
     *
     * @throws Exception
     */
    @Test
    public void test_renewal_with_renewable_ticket_from_ticket_cache() throws Exception {
        String kinit = "kinit";
        if (System.getProperty("os.name").startsWith("Windows")) {
            //Windows will try to use the java kinit if we do not point it to MIT specifically
            String mitPath =
                Stream.of(System.getenv("PATH").split(";")).filter(s -> s.contains("MIT")).findFirst().get();
            kinit = mitPath + File.separator + "kinit";
        }
        ProcessBuilder pb = new ProcessBuilder(kinit, "-l", "2m", "-r", "4m", "-c", testKDC.getCcFile(), "-k", "-t",
            testKDC.getKeytabFilePath(), testKDC.getKeytabPrincipal());
        pb.environment().put("KRB5CCNAME", testKDC.getCcFile());
        pb.environment().put("KRB5_CONFIG", testKDC.getKdcConfPath());
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);
        Process proc = pb.start();
        proc.waitFor();
        if (proc.exitValue() != 0) {
            throw new RuntimeException("Could not obtain ticket via kinit");
        }

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "", AuthMethod.TICKET_CACHE, "", "", true,
                PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 115, true, false, testKDC.getCcFile());

        Util.awaitFuture(KerberosInternalAPI.login(config, null));
        Instant prevValidUntil = KerberosAuthManager.getKerberosState().getTicketValidUntil();
        Thread.sleep(7000);

        KerberosState afterState = KerberosAuthManager.getKerberosState();
        assertTrue(afterState.isAuthenticated());
        assertTrue(afterState.getTicketValidUntil().isAfter(prevValidUntil));
    }

    /**
     * Test renewal when doing keytab authentication
     *
     * @throws Exception
     */
    @Test
    public void test_renewal_with_keytab() throws Exception {
        // ticket lifetime is 60 000 seconds (thanks MiniKDC) and renewalSafetyMargin is 59 995 seconds -> renewal should happen after 5s
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            createValidKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 59995,
            true, false, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        KerberosState currentState = Util.awaitFuture(KerberosInternalAPI.login(config, null));
        Instant prevValidUntil = currentState.getTicketValidUntil();
        Thread.sleep(7000);

        currentState = KerberosAuthManager.getKerberosState();
        assertTrue(currentState.isAuthenticated());
        assertTrue(currentState.getTicketValidUntil().isAfter(prevValidUntil));
        prevValidUntil = currentState.getTicketValidUntil();

        Thread.sleep(5000);
        currentState = KerberosAuthManager.getKerberosState();
        assertTrue(currentState.isAuthenticated());
        assertTrue(currentState.getTicketValidUntil().isAfter(prevValidUntil));
    }

    private static String createValidKrb5(final String realm, final String kdc) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tkdc_realm = %s %n", realm));
        sb.append(String.format("\tdefault_realm = %s %n", realm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\tkdc = %s %n\t }", realm, kdc));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();
    }

    private static String createInvalidKrb5(final String realm, final String kdc) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdefault_realm = %s %n", realm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = %n \t\tkdc = %s %n\t }", realm, kdc));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();

    }

    private static String createInvalidKDCKrb5(final String realm) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdefault_realm = %s %n", realm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\t%s %n\t }", realm, "-"));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();

    }

    private static String createNoKDCforRealmKrb5(final String defaultRealm, final String kdc) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdefault_realm = %s %n", defaultRealm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\tkdc = %s %n\t }", "OTHER", kdc));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();

    }

    private static String createNoDefaultRealmKrb5(final String realm, final String kdc) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\tkdc = %s %n\t }", realm, kdc));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();

    }

    /**
     * Callback Handler for user name/password authentication
     *
     * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
     */
    public static class TestCallBackHandler implements KerberosUserPwdAuthCallbackHandler {
        private final boolean m_userCancelled;

        private final String m_user;

        private final String m_pwd;

        /**
         * Creates a Callback handler that says the user cancelled the login.s
         *
         */
        public TestCallBackHandler() {
            m_user = null;
            m_pwd = null;
            m_userCancelled = true;
        }

        /**
         * Creates a Callback handler that answers with the given user and password
         *
         * @param user the user name
         * @param pwd the password
         */
        public TestCallBackHandler(final String user, final String pwd) {
            m_user = user;
            m_pwd = pwd;
            m_userCancelled = false;
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {

            for (int i = 0; i < callbacks.length; i++) {
                if (callbacks[i] instanceof NameCallback) {
                    NameCallback nc = (NameCallback)callbacks[i];
                    nc.setName(m_user);
                } else if (callbacks[i] instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback)callbacks[i];
                    pc.setPassword(m_pwd.toCharArray());
                }
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public boolean promptUser() {
            return !m_userCancelled;
        }
    }
}
