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
 *   Jun 7, 2021 (bjoern): created
 */
package org.knime.kerberos.api;

import java.security.AccessController;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Future;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.login.LoginException;

import org.eclipse.core.runtime.Plugin;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.knime.core.node.CanceledExecutionException;
import org.knime.core.node.ExecutionMonitor;
import org.knime.core.node.NodeLogger;
import org.knime.core.node.workflow.NodeContext;
import org.knime.core.util.KNIMERuntimeContext;

import com.sun.security.jgss.ExtendedGSSCredential;

/**
 * Provides Kerberos authentication with
 * <a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94">
 * constrained delegation</a> for KNIME nodes. *
 * <p>
 * IMPORTANT: Users of this class should call {@link KerberosProvider#ensureInitialized()} *before* performing any
 * operations that could lead to loading classes from Java's Kerberos implementation, otherwise debug logging might not
 * work. The recommended place to call {@link KerberosProvider#ensureInitialized()} is in the
 * {@link Plugin#start(org.osgi.framework.BundleContext)} method of the plugin that uses
 * {@link KerberosDelegationProvider}.
 * </p>
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 * @since 4.4
 * @noreference non-public API
 */
public final class KerberosDelegationProvider {

    private static final NodeLogger LOG = NodeLogger.getLogger(KerberosDelegationProvider.class);

    private static final String SPNEGO_OID = "1.3.6.1.5.5.2";

    private static final String KERBEROS5_OID = "1.2.840.113554.1.2.2";

    private static final Oid GSS_MECHANISM = pickMech();

    private static Oid pickMech() {
        try {
            final Oid spnego = new Oid(SPNEGO_OID);
            final Oid kerberos5 = new Oid(KERBEROS5_OID);

            final Set<Oid> mechs =
                new HashSet<>(Arrays.asList(GSSManager.getInstance().getMechsForName(GSSName.NT_USER_NAME)));

            if (mechs.contains(kerberos5)) {
                return kerberos5;
            } else if (mechs.contains(spnego)) {
                return spnego;
            } else {
                throw new IllegalArgumentException("No mechanism found");
            }
        } catch (GSSException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
    }

    /**
     * Interface for callback function that is provided with a {@link GSSCredential} for a (possibly impersonated) user.
     *
     * @author Bjoern Lohrmann, KNIME GmbH
     * @param <T> Return type of the callback function
     *
     * @noreference non-public API
     * @since 4.4
     */
    @FunctionalInterface
    public static interface KerberosDelegationCallback<T> {
        /**
         * This function should be implemented by KNIME nodes that need to perform operations which require
         * Kerberos-based impersonation. If this method is invoked, it can be assumed that the Kerberos login was
         * successful, a ticket has been acquired and that the supplied credential can be used to perform operations.
         * The provided credential belongs to the user on behalf of which the operation is supposed to be performed.
         *
         * @param credential A {@link GSSCredential} that can be used perform operations on behalf of an impersonated
         *            user.
         * @return may return an Object
         * @throws Exception When something went wrong while running this callback function.
         */
        T doAuthenticated(GSSCredential credential) throws Exception;
    }

    /**
     * Invokes the given callback with a {@link GSSCredential} that :
     * <ul>
     * <li>in KNIME Analytics Platform: belongs to the currently authenticated Kerberos principal</li>
     * <li>in a KNIME Server Executor: delegates to the current workflow user authenticated Kerberos principal, using
     * Microsoft constrained delegation (S4U2Self, S4U2Proxy) as the underlying delegation mechanism.</li>
     * </ul>
     *
     * @param callback A {@link KerberosDelegationCallback} to which a (possibly delegated) {@link GSSCredential} is
     *            made available.
     * @return a Future with the return T of the callback.
     */
    public static <T> Future<T> doWithConstrainedDelegationIfOnServer(final KerberosDelegationCallback<T> callback) {

        return KerberosProvider.doWithKerberosAuth(() -> {

            // default credential created from the JAAS subject
            final GSSCredential credential = GSSManager.getInstance() //
                .createCredential(GSSCredential.INITIATE_ONLY);

            if (KNIMERuntimeContext.INSTANCE.runningInServerContext()) {
                final GSSName nameToImpersonate = GSSManager.getInstance() //
                    .createName(getUserToImpersonate(), GSSName.NT_USER_NAME, GSS_MECHANISM);

                LOG.debugWithFormat("Impersonating Kerberos principal %s with Kerberos constrained delegation (MS-SFU)",
                    nameToImpersonate.toString());

                final GSSCredential impersonatedCredential =
                    ((ExtendedGSSCredential)credential).impersonate(nameToImpersonate);

                return callback.doAuthenticated(impersonatedCredential);

            } else {
                return callback.doAuthenticated(credential);
            }

        });
    }

    private static String getUserToImpersonate() {
        final KerberosPrincipal krbPrincipal = Subject.getSubject(AccessController.getContext()) //
            .getPrincipals(KerberosPrincipal.class) //
            .iterator() //
            .next();

        final String workflowUser = NodeContext.getWorkflowUser() //
            .orElseThrow(() -> new IllegalStateException("Could not determine workflow user to impersonate"));

        return String.format("%s@%s", workflowUser, krbPrincipal.getRealm());
    }

    /**
     * Invokes the given callback with a {@link GSSCredential} that :
     * <ul>
     * <li>in KNIME Analytics Platform: belongs to the currently authenticated Kerberos principal</li>
     * <li>in a KNIME Server Executor: delegates to the current workflow user authenticated Kerberos principal, using
     * Microsoft constrained delegation (S4U2Self, S4U2Proxy) as the underlying delegation mechanism.</li>
     * </ul>
     *
     * @param callback A {@link KerberosDelegationCallback} to which a (possibly delegated) {@link GSSCredential} is
     *            made available.
     * @param exec An {@link ExecutionMonitor} that can be used to cancel the operation. May be null.
     * @return the value of type T returned by the given callback.
     * @throws CanceledExecutionException If the callback execution has been cancelled using the given
     *             {@link ExecutionMonitor}, or by interrupting the current thread.
     * @throws LoginException, when authentication is not done with keytab but the user is not already logged in.
     * @throws Exception when the given callback threw an exception.
     */
    public static <T> T doWithConstrainedDelegationBlocking(final KerberosDelegationCallback<T> callback,
        final ExecutionMonitor exec) throws Exception {

        if (exec != null) {
            exec.checkCanceled();
        }

        return KerberosProvider.getFutureResult(doWithConstrainedDelegationIfOnServer(callback), exec);
    }
}
