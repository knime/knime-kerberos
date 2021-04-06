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
 *   Jan 14, 2019 (marrus): created
 */
package org.knime.kerberos;

import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.knime.kerberos.config.KerberosPluginConfig;

/**
 * Kerberos JAAS Configuration.
 *
 * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
 */
public class KerberosJAASConfiguration extends Configuration {

    private final AppConfigurationEntry m_confEntry;

    /**
     * Creates a new JAAS login context configuration for Kerberos that sets up the
     * {@login com.sun.security.auth.module.Krb5LoginModule} according to the given {@link KerberosPluginConfig}.
     *
     * @param config Configuration for the KNIME Kerberos plugin.
     */
    public KerberosJAASConfiguration(final KerberosPluginConfig config) {
        final Map<String, String> krb5LoginModuleParameters = createKrb5LoginModuleParameters(config);
        m_confEntry = new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, krb5LoginModuleParameters);
    }

    /**
     * Creates Krb5 Login Module Parameters based on the given {@link KerberosPluginConfig}.
     *
     * @param config Configuration for the KNIME Kerberos plugin.
     * @return map of options for the login module
     */
    private static Map<String, String> createKrb5LoginModuleParameters(final KerberosPluginConfig config) {
        final Map<String, String> krb5LoginModuleParameters;
        switch (config.getAuthMethod()) {
            case KEYTAB:
                krb5LoginModuleParameters = createParametersForKeytabLogin(config);
                break;
            case TICKET_CACHE:
                krb5LoginModuleParameters = createParametersForTicketCacheLogin(config);
                break;
            case USER_PWD:
                // nothing to do here
                krb5LoginModuleParameters = createParametersForUserPwdLogin(config);
                break;
            default:
                throw new IllegalArgumentException("Unsupport authentication method: " + config.getAuthMethod());
        }
        return krb5LoginModuleParameters;
    }

    private static Map<String, String> createParametersForUserPwdLogin(final KerberosPluginConfig config) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("debug", Boolean.toString(config.doDebugLogging()));
        parameters.put("refreshKrb5Config", "true");
        parameters.put("useTicketCache", "false");
        parameters.put("useKeyTab", "false");
        parameters.put("useFirstPass", "false");
        parameters.put("tryFirstPass", "false");
        parameters.put("doNotPrompt", "false");

        parameters.put("storePass", "false");
        return parameters;
    }

    private static Map<String, String> createParametersForTicketCacheLogin(final KerberosPluginConfig config) {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("debug", Boolean.toString(config.doDebugLogging()));
        parameters.put("refreshKrb5Config", "true");
        parameters.put("useTicketCache", "true");
        if(config.isTestConfiguration()) {
            parameters.put("ticketCache", config.getTicketCache());
        }
        parameters.put("useKeyTab", "false");
        parameters.put("useFirstPass", "false");
        parameters.put("tryFirstPass", "false");
        parameters.put("doNotPrompt", "true");

        return parameters;
    }

    private static Map<String, String> createParametersForKeytabLogin(final KerberosPluginConfig config) {

        Map<String, String> parameters = new HashMap<>();
        parameters.put("debug", Boolean.toString(config.doDebugLogging()));
        parameters.put("refreshKrb5Config", "true");
        parameters.put("useTicketCache", "false");
        parameters.put("useKeyTab", "true");
        parameters.put("useFirstPass", "false");
        parameters.put("tryFirstPass", "false");
        parameters.put("doNotPrompt", "true");

        parameters.put("principal", config.getKeytabPrincipal());
        parameters.put("storeKey", "false");
        parameters.put("keyTab", config.getKeytabFile());
        return parameters;
    }

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry(final String name) {

        return new AppConfigurationEntry[]{m_confEntry};
    }
}
