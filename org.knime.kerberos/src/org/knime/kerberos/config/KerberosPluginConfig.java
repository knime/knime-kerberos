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

import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

import org.apache.log4j.lf5.LogLevel;
import org.apache.log4j.lf5.LogLevelFormatException;
import org.eclipse.jface.preference.IPreferenceStore;
import org.knime.kerberos.KerberosPlugin;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;

/**
 * Instances of this class hold a possible configuration for the Kerberos authentication.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KerberosPluginConfig {

    /**
     * Internal map with config overrides for unit-testing If this is non-null, then the various getter methods won't
     * use the Eclipse PreferenceStore, but this map.
     */
    public static Map<String, String> TEST_OVERRIDES = null;

    private static IPreferenceStore m_referenceStore;

    private final KerberosConfigSource m_confSource;

    private final String m_kerberosConfFile;

    private final String m_realm;

    private final String m_kdc;

    private final AuthMethod m_authMethod;

    private final String m_keytabPrincipal;

    private final String m_keytabFile;

    private final boolean m_doDebugLogging;

    private final String m_debugLogLevel;

    private final boolean m_isTestConfiguration;

    private final String m_ticketCache;

    private final long m_renewalSafetyMarginSeconds;

    /**
     * Creates a new instance. All String parameters are sanitized, i.e. empty strings or those only containing
     * whitespaces mapped to null.
     *
     * @param confSource
     * @param kerberosConfFile
     * @param realm
     * @param kdc
     * @param authMethod
     * @param keytabPrincipal
     * @param keytabFile
     * @param doDebugLogging
     * @param debugLogLevel
     * @param renewalSaftyMargin
     */
    public KerberosPluginConfig(final KerberosConfigSource confSource, final String kerberosConfFile,
        final String realm, final String kdc, final AuthMethod authMethod, final String keytabPrincipal,
        final String keytabFile, final boolean doDebugLogging, final String debugLogLevel, final long renewalSaftyMargin) {

        m_confSource = confSource;
        m_kerberosConfFile = cleanUp(kerberosConfFile);
        m_realm = cleanUp(realm);
        m_kdc = cleanUp(kdc);
        m_authMethod = authMethod;
        m_keytabPrincipal = cleanUp(keytabPrincipal);
        m_keytabFile = cleanUp(keytabFile);
        m_doDebugLogging = doDebugLogging;
        m_debugLogLevel = cleanUp(debugLogLevel);
        m_renewalSafetyMarginSeconds = renewalSaftyMargin;
        m_isTestConfiguration = false;
        m_ticketCache = null;
    }

    /**
     * Creates a new instance. All String parameters are sanitized, i.e. empty strings or those only containing
     * whitespaces mapped to null.
     *
     * @param confSource
     * @param kerberosConfFile
     * @param realm
     * @param kdc
     * @param authMethod
     * @param keytabPrincipal
     * @param keytabFile
     * @param doDebugLogging
     * @param debugLogLevel
     * @param renewalSaftyMargin
     * @param isTestConfiguration
     * @param ticketCache Path to ticket cache when using TICKET_CACHE authentication (only for unit-testing)
     */
    public KerberosPluginConfig(final KerberosConfigSource confSource, final String kerberosConfFile,
        final String realm, final String kdc, final AuthMethod authMethod, final String keytabPrincipal,
        final String keytabFile, final boolean doDebugLogging, final String debugLogLevel, final long renewalSaftyMargin,
        final boolean isTestConfiguration, final String ticketCache) {

        m_confSource = confSource;
        m_kerberosConfFile = cleanUp(kerberosConfFile);
        m_realm = cleanUp(realm);
        m_kdc = cleanUp(kdc);
        m_authMethod = authMethod;
        m_keytabPrincipal = cleanUp(keytabPrincipal);
        m_keytabFile = cleanUp(keytabFile);
        m_doDebugLogging = doDebugLogging;
        m_debugLogLevel = cleanUp(debugLogLevel);
        m_renewalSafetyMarginSeconds = renewalSaftyMargin;
        m_isTestConfiguration = isTestConfiguration;
        m_ticketCache = ticketCache;
    }

    /**
     * @return the PreferenceStore
     */
    private static IPreferenceStore getPreferenceStore() {
        if (m_referenceStore == null) {
            m_referenceStore = KerberosPlugin.getDefault().getPreferenceStore();
        }
        return m_referenceStore;
    }

    private static String cleanUp(final String aString) {
        String toReturn = aString;
        if (aString != null) {
            toReturn = aString.trim();
            if (toReturn.isEmpty()) {
                toReturn = null;
            }
        }
        return toReturn;
    }

    /**
     * @return the configuration source for the Kerberos authentication.
     */
    public KerberosConfigSource getKerberosConfSource() {
        return m_confSource;
    }

    /**
     * @return whether this configuration has a path to a configuration file set.
     */
    public boolean hasKerberosConfFile() {
        return getKerberosConfFile() != null;
    }

    /**
     * @return whether this configuration has a realm set.
     */
    public boolean hasRealm() {
        return getRealm() != null;
    }

    /**
     * @return whether this configuration has a KDC set.
     */
    public boolean hasKDC() {
        return getKDC() != null;
    }

    /**
     * @return whether this configuration has a keytab principal set.
     */
    public boolean hasKeytabPrincipal() {
        return getKeytabPrincipal() != null;
    }

    /**
     * @return whether this configuration has a path to a keytab file set.
     */
    public boolean hasKeytabFile() {
        return getKeytabFile() != null;
    }

    /**
     * @return the kerberosConfFile
     */
    public String getKerberosConfFile() {
        return m_kerberosConfFile;
    }

    /**
     * @return the Kerberos realm
     */
    public String getRealm() {
        return m_realm;
    }

    /**
     * @return the kdc
     */
    public String getKDC() {
        return m_kdc;
    }

    /**
     * @return the authMethod
     */
    public AuthMethod getAuthMethod() {
        return m_authMethod;
    }

    /**
     * @return the keytabPrincipaL
     */
    public String getKeytabPrincipal() {
        return m_keytabPrincipal;
    }

    /**
     * @return the keytabFile
     */
    public String getKeytabFile() {
        return m_keytabFile;
    }

    /**
     * @return the doDebugLogging
     */
    public boolean doDebugLogging() {
        return m_doDebugLogging;
    }

    /**
     * @return the debugLogLevel
     */
    public String getDebugLogLevel() {
        return m_debugLogLevel;
    }

    /**
     * @return the ticket cache, when using {@link AuthMethod#TICKET_CACHE} authentication (only for unit-testing).
     */
    public String getTicketCache() {
        return m_ticketCache;
    }

    /**
     * @return the renewalSafetyMargin
     */
    public long getRenewalSafetyMarginSeconds() {
        return m_renewalSafetyMarginSeconds;
    }

    /**
     * @return the isTestConfiguration
     */
    public boolean isTestConfiguration() {
        return m_isTestConfiguration;
    }

    private static String loadString(final String key) {
        if (TEST_OVERRIDES != null) {
            return TEST_OVERRIDES.get(key);
        } else if (getPreferenceStore().isDefault(key)) {
            return getPreferenceStore().getDefaultString(key);
        } else {
            return getPreferenceStore().getString(key);
        }
    }

    private static void saveString(final String key, final String value) {
        if (TEST_OVERRIDES != null) {
            TEST_OVERRIDES.put(key, value);
        } else {
            if (value == null || getPreferenceStore().getDefaultString(key).equals(value)) {
                getPreferenceStore().setToDefault(key);
            } else {
                getPreferenceStore().setValue(key, value);
            }
        }
    }

    private static void saveBoolean(final String key, final boolean value) {
        if (TEST_OVERRIDES != null) {
            TEST_OVERRIDES.put(key, Boolean.toString(value));
        } else {
            if (getPreferenceStore().getDefaultBoolean(key) == value) {
                getPreferenceStore().setToDefault(key);
            } else {
                getPreferenceStore().setValue(key, value);
            }
        }
    }

    private static boolean loadBoolean(final String key) {
        if (TEST_OVERRIDES != null) {
            return Boolean.parseBoolean(TEST_OVERRIDES.get(key));
        } else if (getPreferenceStore().isDefault(key)) {
            return getPreferenceStore().getDefaultBoolean(key);
        } else {
            return getPreferenceStore().getBoolean(key);
        }
    }

    private static long loadLong(final String key) {
        if (TEST_OVERRIDES != null) {
            return Long.parseLong(TEST_OVERRIDES.get(key));
        } else if (getPreferenceStore().isDefault(key)) {
            return getPreferenceStore().getDefaultLong(key);
        } else {
            return getPreferenceStore().getLong(key);
        }
    }

    private static void saveLong(final String key, final long value) {
        if (TEST_OVERRIDES != null) {
            TEST_OVERRIDES.put(key, String.valueOf(value));
        } else {
            if (getPreferenceStore().getDefaultLong(key) == (value)) {
                getPreferenceStore().setToDefault(key);
            } else {
                getPreferenceStore().setValue(key, value);
            }
        }
    }
    /**
     * @return a new {@link KerberosPluginConfig} that containes the currently stored Eclipse preferences.
     */
    public static KerberosPluginConfig load() {
        return new KerberosPluginConfig(KerberosConfigSource.fromValue(loadString(PrefKey.KERBEROS_CONF_KEY)),
            loadString(PrefKey.KERBEROS_CONF_FILE_KEY), loadString(PrefKey.KERBEROS_REALM_KEY),
            loadString(PrefKey.KERBEROS_KDC_KEY), AuthMethod.fromValue(loadString(PrefKey.AUTH_METHOD_KEY)),
            loadString(PrefKey.KEYTAB_PRINCIPAL_KEY), loadString(PrefKey.KEYTAB_FILE_KEY),
            loadBoolean(PrefKey.DEBUG_KEY), loadString(PrefKey.DEBUG_LOG_LEVEL_KEY), loadLong(PrefKey.RENEWAL_SAFETY_MARGIN_SECONDS_KEY));
    }

    /**
     * @return a new {@link KerberosPluginConfig} that contains default values.
     */
    public static KerberosPluginConfig defaults() {
        return new KerberosPluginConfig(KerberosConfigSource.fromValue(PrefKey.KERBEROS_CONF_DEFAULT),
            PrefKey.KERBEROS_CONF_FILE_DEFAULT, PrefKey.KERBEROS_REALM_DEFAULT, PrefKey.KERBEROS_KDC_DEFAULT,
            AuthMethod.fromValue(PrefKey.AUTH_METHOD_DEFAULT), PrefKey.KEYTAB_PRINCIPAL_DEFAULT,
            PrefKey.KEYTAB_FILE_DEFAULT, PrefKey.DEBUG_DEFAULT, PrefKey.DEBUG_LOG_LEVEL_DEFAULT,
            PrefKey.RENEWAL_SAFETY_MARGIN_SECONDS_DEFAULT);
    }

    /**
     * Persists the contents of this {@link KerberosPluginConfig} object to Eclipse preferences.
     */
    public void save() {
        saveString(PrefKey.KERBEROS_CONF_KEY, getKerberosConfSource().toString());
        saveString(PrefKey.KERBEROS_CONF_FILE_KEY, getKerberosConfFile());
        saveString(PrefKey.KERBEROS_REALM_KEY, getRealm());
        saveString(PrefKey.KERBEROS_KDC_KEY, getKDC());
        saveString(PrefKey.AUTH_METHOD_KEY, getAuthMethod().toString());
        saveString(PrefKey.KEYTAB_PRINCIPAL_KEY, getKeytabPrincipal());
        saveString(PrefKey.KEYTAB_FILE_KEY, getKeytabFile());
        saveBoolean(PrefKey.DEBUG_KEY, doDebugLogging());
        saveString(PrefKey.DEBUG_LOG_LEVEL_KEY, getDebugLogLevel());
        saveLong(PrefKey.RENEWAL_SAFETY_MARGIN_SECONDS_KEY, getRenewalSafetyMarginSeconds());
    }

    /**
     * Performs shallow validation of the preferences and collects error/warning messages in the given lists.
     *
     * Shallow validation means that required preferences are set and that preferences have valid values. For
     * preferences that reference a file, this method also performs some basic file checks, and warns if those fail.
     *
     * @param errors List to collect error messages.
     * @param warnings List to collect warning messages.
     */
    public void validateShallow(final List<String> errors, final List<String> warnings) {
        switch (getKerberosConfSource()) {
            case DEFAULT:
                // nothing to do
                break;
            case FILE:
                if (!hasKerberosConfFile()) {
                    errors.add("Kerberos config file must be specified.");
                } else if (!Paths.get(getKerberosConfFile()).toFile().exists()) {
                    warnings.add("Kerberos config file does not exist.");
                } else if (!Paths.get(getKerberosConfFile()).toFile().isFile()) {
                    warnings.add("Kerberos config file must be a file.");
                } else if (!Paths.get(getKerberosConfFile()).toFile().canRead()) {
                    warnings.add("Kerberos config file cannot be read, probably due to missing permissions.");
                }
                break;
            case REALM_KDC:
                if (!hasRealm()) {
                    errors.add("Realm must be specified.");
                }
                if (!hasKDC()) {
                    errors.add("KDC must be specified.");
                }
                break;
        }

        switch (getAuthMethod()) {
            case TICKET_CACHE:
                // nothing to do
                break;
            case USER_PWD:
                // nothing to do
                break;
            case KEYTAB:
                if (!hasKeytabPrincipal()) {
                    errors.add("Keytab principal must be specified.");
                }

                if (!hasKeytabFile()) {
                    errors.add("Keytab file must be specified.");
                } else if (!Paths.get(getKeytabFile()).toFile().exists()) {
                    warnings.add("Keytab file does not exist.");
                } else if (!Paths.get(getKeytabFile()).toFile().isFile()) {
                    warnings.add("Keytab file must be a file.");
                } else if (!Paths.get(getKeytabFile()).toFile().canRead()) {
                    warnings.add("Keytab file cannot be read, probably due to missing permissions.");
                }
                break;
        }

        try {
            LogLevel.valueOf(getDebugLogLevel());
        } catch (LogLevelFormatException ex) {
            errors.add(String.format("Debug log level '%s' is not a valid log level.", getDebugLogLevel()));
        }
    }

    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof KerberosPluginConfig)) {
            return false;
        }
        KerberosPluginConfig other = (KerberosPluginConfig)obj;

        return m_confSource.equals(other.m_confSource) && m_kerberosConfFile.equalsIgnoreCase(other.m_kerberosConfFile)
            && m_realm.equalsIgnoreCase(other.m_realm) && m_kdc.equalsIgnoreCase(other.m_kdc)
            && m_authMethod.equals(other.m_authMethod) && m_keytabPrincipal.equalsIgnoreCase(other.m_keytabPrincipal)
            && m_keytabFile.equalsIgnoreCase(other.m_keytabFile) && m_doDebugLogging == other.m_doDebugLogging
            && m_debugLogLevel.equalsIgnoreCase(m_debugLogLevel) && m_renewalSafetyMarginSeconds == other.m_renewalSafetyMarginSeconds;
    }

    @Override
    public int hashCode() {
        int prime = 31;
        int result = 1;
        result = result * prime + ((m_confSource == null) ? 0 : m_confSource.hashCode());
        result = result * prime + ((m_kerberosConfFile == null) ? 0 : m_kerberosConfFile.hashCode());
        result = result * prime + ((m_realm == null) ? 0 : m_realm.hashCode());
        result = result * prime + ((m_kdc == null) ? 0 : m_kdc.hashCode());
        result = result * prime + ((m_authMethod == null) ? 0 : m_authMethod.hashCode());
        result = result * prime + ((m_keytabPrincipal == null) ? 0 : m_keytabPrincipal.hashCode());
        result = result * prime + ((m_keytabFile == null) ? 0 : m_keytabFile.hashCode());
        result = result * prime + (m_doDebugLogging ? 1 : 0);
        result = result * prime + ((m_debugLogLevel == null) ? 0 : m_debugLogLevel.hashCode());
        result = result * prime + Long.hashCode(m_renewalSafetyMarginSeconds);

        return result;
    }

    /**
     * @return a one-line summary string that describes the current configuration for logging purposes.
     */
    public String getConfigurationSummary() {
        final String configSource;
        switch (getKerberosConfSource()) {
            case DEFAULT:
                configSource = "cfg:DEFAULT";
                break;
            case FILE:
                configSource = "cfg:" + getKerberosConfFile();
                break;
            case REALM_KDC:
                configSource = String.format("cfg:realm=%s|KDC=%s", getRealm(), getKDC());
                break;
            default:
                throw new IllegalStateException("Unknown config source: " + getKerberosConfSource());
        }

        final String auth;
        switch (getAuthMethod()) {
            case TICKET_CACHE:
                auth = "auth:TICKET_CACHE";
                break;
            case KEYTAB:
                auth = String.format("auth:keytab=%s|principal=%s", getKeytabFile(), getKeytabPrincipal());
                break;
            case USER_PWD:
                auth = "auth:USER_PWD";
                break;
            default:
                throw new IllegalStateException("Unknown auth method " + getAuthMethod());
        }

        return String.format("%s / %s / debug=%s", configSource, auth, Boolean.toString(doDebugLogging()));
    }
}
