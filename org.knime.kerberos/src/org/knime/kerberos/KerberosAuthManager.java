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
 *   Jan 17, 2019 (bjoern): created
 */
package org.knime.kerberos;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.security.auth.RefreshFailedException;
import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.log4j.Logger;
import org.knime.core.node.NodeLogger.LEVEL;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.logger.KerberosLogger;

import sun.security.krb5.Config; // NOSONAR this is intended
import sun.security.krb5.KrbException;

/**
 * Stateful class that holds the current state of the Kerberos login and offers basic operations on top of this state,
 * such as logging in, logging out etc. The state is held in static members and can be modified with static methods.
 *
 * <p>
 * The methods in this class is NOT threadsafe! All method invocations of this class must go through
 * {@link KerberosAuthManager#EXECUTOR}.
 * </p>
 *
 * @author Bjoern Lohrmann, KNIME Gmbh
 */
public class KerberosAuthManager {

    /**
     * Singlethread Executor for the method invocations.
     */
    public static final ScheduledExecutorService EXECUTOR = Executors.newSingleThreadScheduledExecutor((r) -> { Thread t = new Thread(r, "KerberosWorker"); t.setDaemon(true); return t;});

    private static final  Logger LOG = Logger.getLogger(KerberosAuthManager.class);

    private static final String SYSTEM_PROPERTY_KRB5_CONF = "java.security.krb5.conf";

    private static final String SYSTEM_PROPERTY_REALM = "java.security.krb5.realm";

    private static final String SYSTEM_PROPERTY_KDC = "java.security.krb5.kdc";

    private static final String SYSTEM_PROPERTY_PRINCIPAL = "sun.security.krb5.principal";

    private static final  List<String> SYS_PROPS = Collections.unmodifiableList(Arrays.asList(SYSTEM_PROPERTY_KDC,
        SYSTEM_PROPERTY_REALM, SYSTEM_PROPERTY_KRB5_CONF, SYSTEM_PROPERTY_PRINCIPAL));

    // this is volatile because it will be read directly by arbitrary threads via KerberosProvier.getKerberosState()
    private static volatile KerberosState loginState = new KerberosState();

    private static KerberosPluginConfig loginPluginConfig = null;

    private static LoginContext loginContext = null;

    private static ScheduledFuture<?> renewFuture = null;

    private static Path tmpKrb5Conf = null;

    private static final  Map<String, String> systemPropertyBackup = new HashMap<>();

    private static KerberosStateListener stateListener;


    private KerberosAuthManager() {
    }

    /**
     * Sets the system back to the state it was before the kerberos plugin was used.
     * It does a logout if necessary and resets system properties
     */
    public static void rollbackToInitialState() {
        setLoginState(new KerberosState());

        try {
            if (loginContext != null) {
                loginContext.logout();
                if(renewFuture != null) {
                    //Cancel running renewal service
                    renewFuture.cancel(true);
                }
            }
        } catch (LoginException e) {
            // we only log this as debug because we can safely ignore it
            LOG.debug("Failed to logout: " + e.getMessage(), e);
        } finally {
            loginContext = null;
            renewFuture = null;
            loginPluginConfig = null;
        }

        restoreSystemProperties();

        try {
            if (tmpKrb5Conf != null) {
                Files.deleteIfExists(tmpKrb5Conf);
            }
        } catch (IOException e) {
            // we only log this as debug because we can safely ignore it
            LOG.debug("Failed to delete temp file: " + e.getMessage(), e);
        } finally {
            tmpKrb5Conf = null;
        }

        KerberosLogger.stopCapture();

        try {
            Config.refresh();
        } catch (KrbException e) {
            // we only log this as debug because we can safely ignore it
            LOG.debug("Failed refresh Kerberos config: " + e.getMessage(), e);
        }
    }

    private static void restoreSystemProperties() {
        if(!systemPropertyBackup.isEmpty()) {
            for (String sysProperty : SYS_PROPS) {
                final String backupValue = systemPropertyBackup.get(sysProperty);
                if (backupValue == null) {
                    System.clearProperty(sysProperty);
                } else {
                    System.setProperty(sysProperty, backupValue);
                }
            }
        }
        systemPropertyBackup.clear();
    }

    private static void backupSystemProperties() {
        for (String sysProperty : SYS_PROPS) {
            systemPropertyBackup.put(sysProperty, System.getProperty(sysProperty));
        }
    }

    private static void clearSystemProperties() {
        for (String sysProperty : SYS_PROPS) {
            System.clearProperty(sysProperty);
        }
    }

    /**
     * Tries to load Kerberos configuration according to the preferences and validates as much of the preferences and
     * the loaded Kerberos configuration as possible.
     *
     * If this method throws an error, then {@link #rollbackToInitialState()} must be called.
     *
     * @param config
     * @throws IOException
     */
    public static void configure(final KerberosPluginConfig config) throws IOException {
        LOG.debug("Trying to configure Kerberos");

        // starts capturing the stdout until rollback
        if (config.doDebugLogging()) {
            KerberosLogger.startCapture(LEVEL.valueOf(config.getDebugLogLevel()));
        }

        validateConfigShallow(config);
        backupSystemProperties();
        setupSystemProperties(config);

        // ! I/O
        try {
            Config.refresh();
        } catch (KrbException e) {
            throw new IOException("Failed refresh Kerberos config: " + e.getMessage(), e);
        }

        KerberosPluginConfigValidator.postRefreshValidate(config);

        loginPluginConfig = config;
    }

    private static void validateConfigShallow(final KerberosPluginConfig config) {
        final List<String> errorsAndWarnings = new LinkedList<>();
        config.validateShallow(errorsAndWarnings, errorsAndWarnings);
        if (!errorsAndWarnings.isEmpty()) {
            throw new IllegalArgumentException(errorsAndWarnings.get(0));
        }
    }

    private static void setupSystemProperties(final KerberosPluginConfig config) throws IOException {
        switch (config.getKerberosConfSource()) {
            case DEFAULT:
                // do nothing (the point is to use system properties that
                // have been set with knime.ini, or just use Java defaults
                break;
            case FILE:
                clearSystemProperties();
                System.setProperty(SYSTEM_PROPERTY_KRB5_CONF, config.getKerberosConfFile());
                break;
            case REALM_KDC:
                clearSystemProperties();
                if (tmpKrb5Conf != null) {
                    throw new RuntimeException("Exists already");
                }
                tmpKrb5Conf = createRealmKDCKrb5(config);
                System.setProperty(SYSTEM_PROPERTY_KRB5_CONF, tmpKrb5Conf.toString());
        }

        if(config.getAuthMethod().equals(AuthMethod.KEYTAB)){
            System.setProperty(SYSTEM_PROPERTY_PRINCIPAL, config.getKeytabPrincipal());
        }
    }


    private static Path createRealmKDCKrb5(final KerberosPluginConfig config) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("default_realm = %s%n", config.getRealm()));
        //The MiniKDC runs only with TCP. Java sun.security.krb5 does not try TCP if UDP fails. Used for testing only for now
        //We may want to do this configurable in the future.
        if(config.isTestConfiguration()) {
            sb.append(String.format("\tudp_preference_limit = 1%n"));
        }
        sb.append(String.format("dns_lookup_kdc = false%n"));
        sb.append(String.format("dns_lookup_realm = false%n%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("%s = { %n kdc = %s%n ", config.getRealm(), config.getKDC()));
        //Setting the KDC timeout to 5 seconds and retries to 2, to avoid long waits in worker thread
        sb.append(String.format( "max_retries = %d%n", 2));
        sb.append(String.format( "kdc_timeout = %d%n }", 5000));
        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        return configFile;
    }

    /**
     * @return the current loginState
     */
    public static KerberosState getKerberosState() {
        return loginState;
    }

    /**
     * @param loginState the loginState to set
     */
    private static void setLoginState(final KerberosState state) {
        loginState = state;
        if (stateListener != null) {
            stateListener.kerberosStateChanged(state);
        }
    }

    /**
     * Attempts a login with the current configuration.
     *
     * If this method throws an error, then {@link #rollbackToInitialState()} must be called.
     *
     * @throws LoginException if the login fails
     */
    public static void login() throws LoginException {
        login(null);
    }

    /**
     * Attempts a login with the given configuration.
     *
     * If this method throws an error, then {@link #rollbackToInitialState()} must be called.
     *
     * @param handler the callbackHandler to use in case of user/password authentication
     * @throws LoginException if the login fails
     */
    public static void login(final KerberosUserPwdAuthCallbackHandler handler) throws LoginException {
        LOG.info("Doing Kerberos login with config " + loginPluginConfig.getConfigurationSummary());

        final LoginContext tmpLoginContext =
            new LoginContext("KNIMEKerberosLoginContext", null, handler, new KerberosJAASConfiguration(loginPluginConfig));

        if (loginPluginConfig.getAuthMethod() == AuthMethod.USER_PWD) {
            if (!handler.promptUser()) {
                throw new UserRequestedCancelException();
            }
        }
        // try authentication
        tmpLoginContext.login();
        loginContext = tmpLoginContext;
        setLoginState(createAuthenticatedKerberosState());
        scheduleRenewal();
        LOG.info("Logged into Kerberos as " + loginState.toString());
    }

    private static KerberosState createAuthenticatedKerberosState() {
        final Subject subject = loginContext.getSubject();
        final String principal = subject.getPrincipals(KerberosPrincipal.class).iterator().next().getName();

        final KerberosTicket tgt = subject.getPrivateCredentials(KerberosTicket.class).iterator().next();
        final Instant validUntil = tgt.getEndTime().toInstant();
        return new KerberosState(principal, validUntil);
    }

    private static void scheduleRenewal() {
        final KerberosTicket tgt =
            loginContext.getSubject().getPrivateCredentials(KerberosTicket.class).iterator().next();

        long millisUntilRenewal;
        if (tgt.isRenewable() || loginPluginConfig.getAuthMethod() == AuthMethod.KEYTAB) {
            millisUntilRenewal = Math.max(
                tgt.getEndTime().getTime() - Instant.now().toEpochMilli() - (loginPluginConfig.getRenewalSafetyMarginSeconds() * 1000), 5000);
        } else {
            // we can only let the current login expire and update the UI then
            millisUntilRenewal = (int) Math
                    .max(tgt.getEndTime().getTime() - Instant.now().toEpochMilli() + 1000, 1000);
        }

        LOG.debug(String.format("Scheduling login renewal in %d seconds", Duration.ofMillis(millisUntilRenewal).getSeconds()));
        renewFuture = EXECUTOR.schedule(() -> {
            try {
                tryRenewLoginNonInteractively();
            } catch (Exception e) {
                LOG.error("Failed to fetch a new Kerberos ticket: " + ExceptionUtil.getDeepestErrorMessage(e, true), e);
            }
        }, millisUntilRenewal, TimeUnit.MILLISECONDS);

    }

    private static void tryRenewLoginNonInteractively() throws LoginException {
        if (loginContext == null && loginContext.getSubject() == null) {
            throw new IllegalStateException("Login renew failed due to missing LoginContext");
        }

        final KerberosTicket ticket =
            loginContext.getSubject().getPrivateCredentials(KerberosTicket.class).iterator().next();

        if (ticket.isRenewable()) {
            try {
                ticket.refresh();
                setLoginState(createAuthenticatedKerberosState());
                scheduleRenewal();
                LOG.info("Renewed Kerberos ticket for " + loginState.toString());
                return;
            } catch (RefreshFailedException ex) {
                LOG.error(
                    String.format("Could not renew Kerberos ticket (%s), trying to fetch a new ticket if possible",
                        ExceptionUtil.getDeepestErrorMessage(ex, true)));
                // Too bad, but there may be another we when we are using keytabs or a ticket cache
            }
        }

        // ticket is not renewable, or renewal failed
        switch (loginPluginConfig.getAuthMethod()) {
            case KEYTAB:
                // if this fails we throw an exception because there is nothing else we can do
                login();
                LOG.info("Fetched new Kerberos ticket for " + loginState.toString());
                break;
            case TICKET_CACHE:
                if (ticketCacheHasChanged()) {
                    login();
                    LOG.info("Found new Kerberos ticket in ticket cache for " + loginState.toString());
                } else {
                    LOG.info("Kerberos login expired, hence logging out");
                    rollbackToInitialState();
                }
                break;
            case USER_PWD:
                // we can only fetch a new ticket by prompting the user for a password.
                // since this method is supposed to be non-interactive, we cannot do anything
                // but rollback (to update the UI)
                LOG.info("Kerberos login expired, hence logging out");
                rollbackToInitialState();
                break;
        }
    }

    /**
     * @return the Subject of the current loginContext may be null.
     */
    public static Subject getSubject() {
        return loginContext.getSubject();
    }


    /**
     * Registers the state listener and calls it once with the current Kerberos state.
     *
     * @param listener
     */
    public static void registerStateListener(final KerberosStateListener listener) {
        stateListener = listener;
        stateListener.kerberosStateChanged(loginState);
    }


    /**
     * Checks whether the ticket cache outside of KNIME has changed. This method must only be called while we are
     * authenticated based on a ticket cache.
     *
     * @return whether the ticket cache outside of KNIME has changed.
     */
    public static boolean ticketCacheHasChanged() {
        if (!loginState.isAuthenticated() || loginPluginConfig.getAuthMethod() != AuthMethod.TICKET_CACHE) {
            throw new IllegalStateException("Ticket-cache based Kerberos login required");
        }

        boolean toReturn = true;

        try {
            final LoginContext tmpLoginContext =
                new LoginContext("KNIMEKerberosLoginContext", null, TicketCacheChangedCheckCallbackHandler.INSTANCE, new KerberosJAASConfiguration(loginPluginConfig));
            tmpLoginContext.login();
            final KerberosTicket tmpTicket = tmpLoginContext.getSubject().getPrivateCredentials(KerberosTicket.class).iterator().next();
            final KerberosTicket tgt = getSubject().getPrivateCredentials(KerberosTicket.class).iterator().next();
            if (tmpTicket != null && tmpTicket.equals(tgt)) {
                toReturn = false;
            }
        } catch (final LoginException ex) { // NOSONAR
            // failed to get ticket = ticket has changed
        }

        return toReturn;
    }

    /**
     * @param showIcon
     */
    public static void showKerberosStatusIcon(final boolean showIcon) {
        if (stateListener != null) {
            stateListener.showKerberosStatusIcon(showIcon || loginState.isAuthenticated());
        }
    }

}
