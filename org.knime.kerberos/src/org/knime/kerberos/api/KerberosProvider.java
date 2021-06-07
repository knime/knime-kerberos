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
 *   28.01.2019 (Mareike Hoeger, KNIME GmbH, Konstanz, Germany): created
 */
package org.knime.kerberos.api;

import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginException;

import org.eclipse.core.runtime.Plugin;
import org.knime.core.node.CanceledExecutionException;
import org.knime.core.node.ExecutionMonitor;
import org.knime.core.node.NodeLogger.LEVEL;
import org.knime.core.node.workflow.NodeContext;
import org.knime.kerberos.KerberosAuthManager;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.logger.KerberosLogger;

/**
 * Provides Kerberos authentication for KNIME nodes. Nodes can use the {@link #doWithKerberosAuth(KerberosCallback)}
 * method to run code that requires a JAAS {@link Subject} with a Kerberos ticket. The ticket will be acquired
 * automatically based on Eclipse preferences.
 *
 * <p>
 * IMPORTANT: Users of this class should call {@link #ensureInitialized()} *before* performing any operations that could
 * lead to loading classes from Java's Kerberos implementation, otherwise debug logging might not work. The recommended
 * place to call {@link #ensureInitialized()} is in the {@link Plugin#start(org.osgi.framework.BundleContext)} method of
 * the plugin that uses {@link KerberosProvider}.
 * </p>
 *
 * @author Bjoern Lohrmann, KNIME GmbH, Konstanz, Germany
 * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
 * @since 4.0
 */
public class KerberosProvider {

    private KerberosProvider() {
    }

    /**
     * @return a Future that provides the current {@link KerberosState}.
     */
    public static KerberosState getKerberosState() {
        return KerberosAuthManager.getKerberosState();
    }

    /**
     * Ensures that Java's Kerberos implementation is properly initialized, in particular debug logging. Users of
     * {@link KerberosProvider} should call this method *before* performing any operations that load classes from Java's
     * Kerberos stack.
     *
     * <p>
     * Background: Debug logging in Java's Kerberos stack depends on the value of a final variable, which is initialized
     * at class loading time based on the value of a system property. Afterwards, debug logging cannot be changed
     * without JVM restart.
     * </p>
     *
     * @since 4.1.1
     */
    public static void ensureInitialized() {
        final KerberosPluginConfig config = KerberosPluginConfig.load();
        if (config.doDebugLogging()) {
            KerberosLogger.startCapture(LEVEL.valueOf(config.getDebugLogLevel()));
        }
    }

    /**
     * Executes the given callback with an already authenticated Kerberos context. {@link Future#get()} will throw a
     * {@link LoginException}, when authentication is not done with keytab but the user us not already logged in.
     *
     * @param callback A KerberosCallback with the method to execute in a Kerberos-authenticated JAAS context.
     * @return a Future with the return T
     */
    public static <T> Future<T> doWithKerberosAuth(final KerberosCallback<T> callback) {
        final NodeContext nodeContext = NodeContext.getContext();
        return KerberosAuthManager.EXECUTOR.submit(() -> {
            final KerberosPluginConfig config = KerberosPluginConfig.load();

            try {
                if (nodeContext != null) {
                    NodeContext.pushContext(nodeContext);
                }

                KerberosAuthManager.showKerberosStatusIcon(true);
                ensureAuthenticated(config);

                final Subject subject = KerberosAuthManager.getSubject();
                try {
                    return Subject.doAs(subject, (PrivilegedExceptionAction<T>)() -> callback.doAuthenticated());
                } catch (PrivilegedActionException e) {
                    // unpack the exception that was thrown by the callback
                    throw (Exception)e.getCause();
                }
            } finally {
                if (nodeContext != null) {
                    NodeContext.removeLastContext();
                }
            }
        });
    }

    private static void ensureAuthenticated(final KerberosPluginConfig config) throws Exception {
        final boolean authenticated = KerberosAuthManager.getKerberosState().isAuthenticated();

        switch (config.getAuthMethod()) {
            case TICKET_CACHE:
                if (authenticated && KerberosAuthManager.ticketCacheHasChanged()) {
                    KerberosAuthManager.rollbackToInitialState();
                    tryLogin(config);
                } else if (!authenticated) {
                    // throws exception if unsuccessful
                    tryLogin(config);
                }
                break;
            case KEYTAB:
                if (!authenticated) {
                    // throws exception if unsuccessful
                    tryLogin(config);
                }
                break;
            case USER_PWD:
                if (!authenticated) {
                    throw new LoginException("Not logged into Kerberos. Please login first.");
                }
                break;
        }
    }

    private static void tryLogin(final KerberosPluginConfig config) throws Exception {
        try {
            KerberosAuthManager.configure(config);
            KerberosAuthManager.login();
        } catch (Exception e) {
            KerberosAuthManager.rollbackToInitialState();
            throw e;
        }
    }

    /**
     * Blocking method, that executes the given callback using {@link #doWithKerberosAuth(KerberosCallback)}, which
     * returns a future. This method blocks until the future has completed (successfully, or by throwing an exception),
     * or the given {@link ExecutionMonitor} is canceled, or the current thread is interrupted.
     *
     * @param callback A KerberosCallback with the method to execute in a Kerberos-authenticated JAAS context..
     * @param exec An {@link ExecutionMonitor} that can be used to cancel the operation. May be null.
     * @return the value of type T returned by the given callback.
     * @throws CanceledExecutionException If the callback execution has been cancelled using the given
     *             {@link ExecutionMonitor}, or by interrupting the current thread.
     * @throws LoginException, when authentication is not done with keytab but the user is not already logged in.
     * @throws Exception when the given callback threw an exception.
     */
    public static <T> T doWithKerberosAuthBlocking(final KerberosCallback<T> callback, final ExecutionMonitor exec)
        throws Exception {

        if (exec != null) {
            exec.checkCanceled();
        }

        return getFutureResult(doWithKerberosAuth(callback), exec);
    }

    static <T> T getFutureResult(final Future<T> future, final ExecutionMonitor exec)
        throws Exception {

        if (exec != null) {
            exec.checkCanceled();
        }

        while (true) {
            try {
                return future.get(250, TimeUnit.MILLISECONDS);
            } catch (final TimeoutException | InterruptedException e) {
                if (exec != null) {
                    try {
                        exec.checkCanceled();
                    } catch (final CanceledExecutionException canceledInKNIME) {
                        future.cancel(true);
                        throw canceledInKNIME;
                    }
                } else if (e instanceof InterruptedException) {
                    future.cancel(true);
                    throw new CanceledExecutionException();
                }
            } catch (ExecutionException e) {
                // unpack the exception that was thrown by the callback
                throw (Exception)e.getCause();
            }
        }
    }
}
