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

import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;

import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;

/**
 * Provides utility methods that performs deeper validation of a
 * {@link KerberosPluginConfig}.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KerberosPluginConfigValidator {

    /**
     * Validates Kerberos preferences, before we try to actually load any configuration. This method does not change any
     * system state, but may perform file and network I/O.
     *
     * @param config
     *
     * @throws IOException
     * @throws IllegalArgumentException
     */
    private static void validateKeytabAndPrincipal(final KerberosPluginConfig config) {
        final KerberosPrincipal kerberosPrincipal =
            new KerberosPrincipal(config.getKeytabPrincipal(), KerberosPrincipal.KRB_NT_PRINCIPAL);
        final KeyTab keyTab = KeyTab.getInstance(kerberosPrincipal, new File(config.getKeytabFile()));

        if (keyTab.getKeys(kerberosPrincipal).length == 0) {
            throw new IllegalArgumentException(
                String.format("Keytab file does not contain any keys for principal '%s'", config.getKeytabPrincipal()));
        }
    }

    /**
     * Performs further validation of Kerberos preferences and the loaded Kerberos config.
     *
     * @param config
     *
     * @throws IllegalArgumentException
     */
    public static void postRefreshValidate(final KerberosPluginConfig config) {
        if (config.getAuthMethod() == AuthMethod.KEYTAB) {
            validateKeytabAndPrincipal(config);

            if (config.getKerberosConfSource() == KerberosConfigSource.REALM_KDC) {
                checkRealmForKeytabPrincipal(config);
            }
        }
    }

    private static void checkRealmForKeytabPrincipal(final KerberosPluginConfig config) {
        final KerberosPrincipal kerberosPrincipal =
                new KerberosPrincipal(config.getKeytabPrincipal(), KerberosPrincipal.KRB_NT_PRINCIPAL);
        final String principalRealm = kerberosPrincipal.getRealm();
        if (!principalRealm.equals(config.getRealm())) {
            throw new IllegalArgumentException(
                String.format("The configured realm '%s' does not match realm %s from keytab principal",
                    config.getRealm(), principalRealm));
        }
    }
}
