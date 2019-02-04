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
 *   17.01.2019 (Mareike Hoeger, KNIME GmbH, Konstanz, Germany): created
 */
package org.knime.kerberos;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;

import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;

import sun.security.jgss.krb5.Krb5Util;
import sun.security.krb5.Config;
import sun.security.krb5.KrbException;
import sun.security.krb5.PrincipalName;
import sun.security.krb5.Realm;
import sun.security.krb5.RealmException;

/**
 * Provides utility methods that performs deeper validation of a
 * {@link KerberosPluginConfig}.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
@SuppressWarnings("restriction")
public class KerberosPluginConfigValidator {

    /**
     * Validates Kerberos preferences, before we try to actually load any configuration. This method does not change any
     * system state, but may perform file and network I/O.
     *
     * @param config
     *
     * @throws IOException
     * @throws RealmException
     */
    public static void preRefreshValidate(final KerberosPluginConfig config) throws IOException, RealmException {
        switch (config.getKerberosConfSource()) {
            case REALM_KDC:
                preValidateRealmKDC(config);
                break;
            case FILE:
            case DEFAULT:
                // nothing to do here
                break;
        }
    }

    private static void validateKeytabAndPrincipal(final KerberosPluginConfig config) throws RealmException {
        if (config.getKeytabPrincipal().equals("*")) {
            throw new IllegalArgumentException("Principal '*' is not allowed as keytab principal.");
        }
        final PrincipalName principalName =
            new PrincipalName(config.getKeytabPrincipal(), PrincipalName.KRB_NT_PRINCIPAL);
        final KerberosPrincipal kerberosPrincipal = new KerberosPrincipal(principalName.getName());
        final KeyTab keyTab = KeyTab.getInstance(kerberosPrincipal, new File(config.getKeytabFile()));

        if (Krb5Util.keysFromJavaxKeyTab(keyTab, principalName).length == 0) {
            throw new IllegalArgumentException(
                String.format("Keytab file does not contain any keys for principal '%s'", config.getKeytabPrincipal()));
        }
    }

    @SuppressWarnings("unused")
    private static void preValidateRealmKDC(final KerberosPluginConfig config)
        throws RealmException, UnknownHostException {

        //Check if we can create a Realm from the given string

        new Realm(config.getRealm());
        try {
            //Let the URI class do the parsing of the possible host:port string
            URI uri = new URI("test://" + config.getKDC());
            String host = uri.getHost();
            if(host == null) {
                throw new IllegalArgumentException(String.format("KDC %s is invalid.", config.getKDC()));
            }

            // network I/O!
            InetAddress.getByName(host);

        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException(String.format("KDC %s is invalid. %s", config.getKDC(), ex.getMessage()));
        }

    }

    /**
     * Performs further validation of Kerberos preferences and the loaded Kerberos config.
     *
     * @param config
     *
     * @throws KrbException
     */
    public static void postRefreshValidate(final KerberosPluginConfig config) throws KrbException {
        validateDefaultRealm();

        if (config.getAuthMethod() == AuthMethod.KEYTAB) {
            validateKeytabAndPrincipal(config);
            checkKDCForKeytabPrincipal(config);
        }
    }

    private static void validateDefaultRealm() throws KrbException {
        final Config krbConfig = Config.getInstance();
        // this ensures that a default realm is configured somewhere (throws an exception otherwise)
        krbConfig.getDefaultRealm();
    }

    private static void checkKDCForKeytabPrincipal(final KerberosPluginConfig config) throws RealmException {
        final Realm principalRealm =
            new PrincipalName(config.getKeytabPrincipal(), PrincipalName.KRB_NT_PRINCIPAL).getRealm();

        KerberosConfigSource source = config.getKerberosConfSource();
        switch (source) {
            case REALM_KDC:
                if (!principalRealm.toString().equals(config.getRealm())) {
                    throw new IllegalArgumentException(
                        String.format("The configured realm '%s' does not match realm %s from keytab principal",
                            config.getRealm(), principalRealm));
                }
                break;
            case FILE:
            case DEFAULT:
                String kdcs = null;
                try {
                    // this may do I/O (DNS queries)
                    kdcs = Config.getInstance().getKDCList(principalRealm.toString());
                } catch (KrbException e) {
                    // no KDC mapping was found for principal realm
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    throw new IllegalArgumentException(
                        String.format("Cannot locate KDC for realm of keytab principal %s: %s", config.getKeytabPrincipal(),
                            cause.getMessage()),
                        cause);
                } catch (IllegalArgumentException e) {
                    // probably a syntactic problem in the Kerberos config file
                    throw new IllegalArgumentException(
                        String.format("Kerberos config file cannot be parsed (probably): %s", e.getMessage()), e);
                }

                if (kdcs.trim().isEmpty()) {
                    if (source == KerberosConfigSource.FILE) {
                        throw new IllegalArgumentException(String.format(
                            "Kerberos config file does not specify KDC for the realm '%s' of the keytab principal",
                            principalRealm));
                    } else {
                        throw new IllegalArgumentException(String.format(
                            "Could not find any KDC for the realm '%s' of the keytab principal", principalRealm));
                    }
                }
                break;
            default:
                // should never happen
                throw new RuntimeException("Unknown KerberosConfigSource " + source);
        }
    }
}
