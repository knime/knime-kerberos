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
 *   Jan 15, 2019 (bjoern): created
 */
package org.knime.kerberos.config;

/**
 * Class for Preference Keys.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class PrefKey {

    /**
     * Enum for authentication methods.
     */
    public enum AuthMethod {
            /**
             * Authentication is handled outside of KNIME, read tickets from ticket cache.
             */
            TICKET_CACHE,
            /**
             * Authentication with username and password.
             */
            USER_PWD,
            /**
             * Authentication with keytab file.
             */
            KEYTAB;

        /**
         * Creates a {@link AuthMethod} from a String
         * @param value the String representing the {@link AuthMethod}
         * @return the {@link AuthMethod} for the String
         * @throws IllegalArgumentException if the String is not a valid {@link AuthMethod}
         */
        public static AuthMethod fromValue(final String value) throws IllegalArgumentException {
            if (value == null || value.isEmpty()) {
                throw new IllegalArgumentException("No Kerberos authenticaton method specified (must be one of TICKET_CACHE, USER_PWD or KEYTAB)");
            }

            if (TICKET_CACHE.toString().equalsIgnoreCase(value)) {
                return TICKET_CACHE;
            } else if (USER_PWD.toString().equalsIgnoreCase(value)) {
                return USER_PWD;
            } else if (KEYTAB.toString().equalsIgnoreCase(value)) {
                return KEYTAB;
            } else {
                throw new IllegalArgumentException(value + " is not a valid Kerberos authentication method ");
            }
        }
    }

    /**
     * Enum for how to get Kerberos client configuration.
     */
    public enum KerberosConfigSource {
        /**
         * Try to look up Kerberos configuration under default locations chosen by Java. See here:
         * https://docs.oracle.com/javase/8/docs/technotes/guides/security/jgss/tutorials/KerberosReq.html
         */
        DEFAULT,
        /**
         * Read Kerberos configuratio form a file (typically called <code>krb5.conf</code>).
         */
        FILE,
        /**
         * Directly use a particular KDC and realm.
         */
        REALM_KDC;

        /**
         * Creates a {@link KerberosConfigSource} from a String
         * @param value the String representing the {@link KerberosConfigSource}
         * @return the {@link KerberosConfigSource} for the String
         * @throws IllegalArgumentException if the String is not a valid {@link KerberosConfigSource}
         */
    public static KerberosConfigSource fromValue(final String value) throws IllegalArgumentException {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("No way of configuring Kerberos is specified (must be one of DEFAULT, FILE or REALM_KDC)");
        }

        if (DEFAULT.toString().equalsIgnoreCase(value)) {
            return DEFAULT;
        } else if (FILE.toString().equalsIgnoreCase(value)) {
            return FILE;
        } else if (REALM_KDC.toString().equalsIgnoreCase(value)) {
            return REALM_KDC;
        } else {
            throw new IllegalArgumentException(value + " is not a valid way to configure Kerberos");
        }
    }
}


    /** Preference key for the Kerberos configuration source. */
    public static final String KERBEROS_CONF_KEY = "org.knime.kerberos.conf";

    /** Default value for the Kerberos configuration source. */
    public static final  String KERBEROS_CONF_DEFAULT = KerberosConfigSource.DEFAULT.toString();

    /** Preference key for the Kerberos configuration file path. */
    public static final  String KERBEROS_CONF_FILE_KEY = "org.knime.kerberos.conf.file";

    /** Default value for the Kerberos configuration file path. */
    public static final  String KERBEROS_CONF_FILE_DEFAULT = "";

    /** Preference key for the Kerberos realm. */
    public static final  String KERBEROS_REALM_KEY = "org.knime.kerberos.realm";

    /** Default value for the Kerberos realm. */
    public static final  String KERBEROS_REALM_DEFAULT = "";

    /** Preference key for the Kerberos KDC. */
    public static final  String KERBEROS_KDC_KEY = "org.knime.kerberos.kdc";

    /** Default value for the Kerberos KDC. */
    public static final  String KERBEROS_KDC_DEFAULT = "";

    /** Preference key for the Kerberos authentication method. */
    public static final  String AUTH_METHOD_KEY = "org.knime.kerberos.authMethod";

    /** Default value for the Kerberos authentication method. */
    public static final  String AUTH_METHOD_DEFAULT = AuthMethod.TICKET_CACHE.toString();

    /** Preference key for the Kerberos keytab principal. */
    public static final  String KEYTAB_PRINCIPAL_KEY = "org.knime.kerberos.keytabPrincipal";

    /** Default value for the Kerberos keytab principal. */
    public static final  String KEYTAB_PRINCIPAL_DEFAULT = "";

    /** Preference key for the Kerberos keytab file path. */
    public static final  String KEYTAB_FILE_KEY = "org.knime.kerberos.keytabFile";

    /** Default value for the Kerberos keytab file path. */
    public static final  String KEYTAB_FILE_DEFAULT = "";

    /** Preference key for the Kerberos debug setting. */
    public static final  String DEBUG_KEY = "org.knime.kerberos.debug";

    /** Default value for the Kerberos debug setting. */
    public static final  boolean DEBUG_DEFAULT = false;

    /** Preference key for the Kerberos debug level. */
    public static final  String DEBUG_LOG_LEVEL_KEY = "org.knime.kerberos.debugLogLevel";

    /** Default value for the Kerberos debug level. */
    public static final  String DEBUG_LOG_LEVEL_DEFAULT = "INFO";

}
