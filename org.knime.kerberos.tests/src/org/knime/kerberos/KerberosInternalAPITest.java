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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Instant;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.logger.KerberosLogger;
import org.knime.kerberos.testing.KrbConfigUtil;
import org.knime.kerberos.testing.KrbTicketCacheUtil;
import org.knime.kerberos.testing.TestKDC;
import org.knime.kerberos.testing.Util;

/**
 * Test cases for {@link KerberosInternalAPI}.
 *
 * @author Mareike Hoeger, KNIME GmbH
 */
public class KerberosInternalAPITest {

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

    private static void testSuccessfulUserPasswordLogin(final KerberosPluginConfig config, final String username)
        throws Exception {
        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler(username, TestKDC.PWD)));

        final KerberosState state = KerberosAuthManager.getKerberosState();
        assertTrue(state.isAuthenticated());
        assertEquals(TestKDC.USER + "@" + testKDC.getRealm(), state.getPrincipal());
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
            KrbConfigUtil.createValidKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        testSuccessfulKeyTabLogin(config);
    }

    /**
     * Tests configuration with Realm & KDC, with unreachable testKDC. Expects "LoginException: ICMP Port Unreachable".
     */
    @Test
    public void test_login_with_RealmKDC_and_unreachable_kdc() {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "localhost", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        assertThrows(LoginException.class, () -> Util.awaitFuture(KerberosInternalAPI.login(config, null)));
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

        testSuccessfulUserPasswordLogin(config, TestKDC.USER);
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

        testSuccessfulUserPasswordLogin(config, TestKDC.USER + "@" + testKDC.getRealm());
    }

    /**
     * Tests configuration with Realm & KDC, with username and wrong password. Expects
     * "javax.security.auth.login.LoginException: Checksum failed"
     *
     * Sadly, this is really the Exception for a wrong password.
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_wrong_password() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        assertThrows(LoginException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler(TestKDC.USER, "wrong"))));
    }

    /**
     * Tests configuration with Realm & KDC, with unknown username and wrong password Expects
     * "javax.security.auth.login.LoginException: Client not found [...]"
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_wrong_user() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        assertThrows(LoginException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler("unknown", "wrong"))));
    }

    /**
     * Tests configuration with Realm & KDC and a callback handler that says the user cancelled the login. Expects
     * UserRequestedCancelException
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_user_cancelled_login() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(), testKDC.getKDCHost(),
                AuthMethod.USER_PWD, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertFalse(KerberosAuthManager.getKerberosState().isAuthenticated());
        assertThrows(LoginException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.login(config, new TestCallBackHandler())));
    }

    /**
     * Tests configuration with Realm & KDC, without realm specified in keytab principal
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_RealmKDC_and_keytab_without_realm() throws Throwable {

        // we need to make sure that we have a proper default realm configured. For this we do a quick login/logout
        // using the full keytab principal
        test_login_with_RealmKDC_and_keytab();
        rollBack();

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, TestKDC.KEYTAB_USER, testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        testSuccessfulKeyTabLogin(config);
    }

    /**
     * Tests configuration with Realm & KDC, without realm expects "java.lang.IllegalArgumentException: Realm must be
     * specified."
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_missing_realm() throws Throwable {
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", "",
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, without KDC expects "java.lang.IllegalArgumentException: KDC must be
     * specified."
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_missing_kdc() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid KDC IP. Expects "java.lang.IllegalArgumentException: KDC [...]
     * is invalid."
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_invalid_KDC_IP() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "123.232.+.23", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with missing KDC host. Expects "java.lang.IllegalArgumentException: KDC
     * [...] is invalid."
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_missing_KDC_host() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            ":123", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid KDC syntax. Expects "java.lang.IllegalArgumentException: KDC
     * [...] is invalid."
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_invalid_KDC_syntax() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "host with spaces", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid KDC IP. Expects "java.lang.IllegalArgumentException: KDC [...]
     * is invalid."
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_unknown_KDC_host() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            "some-unknown-host", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC and keytab. Expects "java.lang.IllegalArgumentException: because keytab file
     * does not contain any keys for given principal [...]".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_keytab_principal_not_in_keytab() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "test@FALSE", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);
        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, without keytab specified. Expects "java.lang.IllegalArgumentException:
     * Keytab file must be specified".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_missing_keytab() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), "", true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with asterisk principal. Expects "java.lang.IllegalArgumentException:
     * Principal '*' is not allowed as keytab principal".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_asterisk_in_keytab_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "*", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid realm in keytab principal. Expects "IllegalArgumentException:
     * Illegal character in realm name; one of: '/', ':', '".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_invalid_keytab_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "test@ab/cde", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with out principal. Expects "java.lang.IllegalArgumentException: Keytab
     * principal must be specified".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_keytab_but_missing_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, "", testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with non existing file. Expects "java.lang.IllegalArgumentException: Keytab
     * file does not exist".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_keytab_but_nonexisting_keytab_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", testKDC.getRealm(),
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), "somewrongfile", true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with different realm in config and principal. Expects
     * "java.lang.IllegalArgumentException: The configured realm [...] does not match realm [...] from keytab
     * principal".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_and_keytab_but_realm_mismatch() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", "HADOOPABC",
            testKDC.getKDCHost(), AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid Realm. Expects "IllegalArgumentException: Realm contains
     * illegal character '/'.
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_but_invalid_slash_in_realm() throws Throwable {

        final String realm = "HADOOP/test";
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", realm, "localhost",
            AuthMethod.KEYTAB, "test@HADOOP", testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with Realm & KDC, with invalid Realm. Expects "IllegalArgumentException: Realm contains
     * illegal character '\0'.
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_RealmKDC_but_invalid_zero_termination_in_realm() throws Throwable {

        final String realm = "HADOOP" + '\0' + "test";
        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.REALM_KDC, "", realm, "localhost",
            AuthMethod.KEYTAB, "test@HADOOP", testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, true, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with file, with malformed file. Expects "LoginException: Unmatched close brace".
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_malformed_config_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            KrbConfigUtil.createInvalidKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        assertThrows(IOException.class, () -> testSuccessfulKeyTabLogin(config));
    }

    /**
     * Tests configuration with file, with malformed file. Expects "LoginException: Illegal config content:-".
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_malformed_config_file2() throws Throwable {

        KerberosPluginConfig config =
            new KerberosPluginConfig(KerberosConfigSource.FILE, KrbConfigUtil.createInvalidKDCKrb5(testKDC.getRealm()),
                "", "", AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
                PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);

        assertThrows(IOException.class, () -> testSuccessfulKeyTabLogin(config));
    }

    /**
     * Tests configuration with file, without actually specifying the file. Expects "java.lang.IllegalArgumentException:
     * Kerberos config file must be specified".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_missing_krb_config_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE, "", "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with file, without a KDC for given realm configured. Expects
     * "java.lang.IllegalArgumentException: Kerberos config file does not exist".
     *
     * @throws Throwable
     */
    @Test
    public void test_validateConfig_with_invalid_path_to_krb_config_file() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE, "--", "", "",
            AuthMethod.KEYTAB, testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true,
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000, true, false, null);

        assertThrows(IllegalArgumentException.class,
            () -> Util.awaitFuture(KerberosInternalAPI.validateConfig(config, false)));
    }

    /**
     * Tests configuration with file and keytab auth, but without a KDC for realm of keytab principal. Expects
     * "LoginException: Cannot locate KDC".
     *
     * @throws Throwable
     */
    @Test
    public void test_login_with_file_and_keytab_but_missing_kdc_for_keytab_principal() throws Throwable {

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.FILE,
            KrbConfigUtil.createNoKDCforRealmKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
            testKDC.getKeytabPrincipal(), testKDC.getKeytabFilePath(), true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 30000,
            true, false, null);

        assertThrows(LoginException.class,
            () -> testSuccessfulKeyTabLogin(config));
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
        final var ccFile = KrbTicketCacheUtil.createTicketCacheWithKinit(testKDC);

        KerberosPluginConfig config = new KerberosPluginConfig(KerberosConfigSource.DEFAULT, "", "", "",
            AuthMethod.TICKET_CACHE, "", "", true, PrefKey.DEBUG_LOG_LEVEL_DEFAULT, 115, true, true, ccFile.toString());

        Util.awaitFuture(KerberosInternalAPI.login(config, null));
        Instant prevValidUntil = KerberosAuthManager.getKerberosState().getTicketValidUntil();
        Thread.sleep(7000);

        KerberosState afterState = KerberosAuthManager.getKerberosState();
        assertTrue(afterState.isAuthenticated());
        assertFalse(afterState.getTicketValidUntil().equals(prevValidUntil));
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
            KrbConfigUtil.createValidKrb5(testKDC.getRealm(), testKDC.getKDCHost()), "", "", AuthMethod.KEYTAB,
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
