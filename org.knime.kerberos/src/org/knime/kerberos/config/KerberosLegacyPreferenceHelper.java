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
 *   06.02.2019 (Mareike Hoeger, KNIME GmbH, Konstanz, Germany): created
 */
package org.knime.kerberos.config;

import org.eclipse.core.runtime.preferences.IEclipsePreferences;
import org.eclipse.core.runtime.preferences.InstanceScope;
import org.eclipse.jface.preference.IPreferenceStore;
import org.knime.kerberos.KerberosPlugin;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.osgi.service.prefs.BackingStoreException;

/**
 * Helper to migrate legacy Kerberos preferences into the new KerberosPlugin
 *
 * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
 */
public class KerberosLegacyPreferenceHelper {

    /** Preference key for custom kerberos user. */
    public static final String PREF_KERBEROS_USER = "org.knime.bigdata.config.kerberos.user";

    /** Preference key for custom kerberos keytab file. */
    public static final String PREF_KERBEROS_KEYTAB_FILE = "org.knime.bigdata.config.kerberos.keytab.file";

    /** Kerberos logging flag. */
    public static final String PREF_KERBEROS_LOGGING_ENABLED = "org.knime.bigdata.config.kerberos.logging.enabled";

    /** Kerberos logging level. */
    public static final String PREF_KERBEROS_LOGGING_LEVEL = "org.knime.bigdata.config.kerberos.logging.level";


    /**
     * Saves the Preferences from the legacy Kerberos preferences into the new KerberosPlugin preferences. The old
     * settings are removed from the preferences.
     *
     * @throws BackingStoreException if failure in the backing store occurs
     */
    public static void migrateLegacyKerberosPreferences() throws BackingStoreException {
        IPreferenceStore preferenceStore = KerberosPlugin.getDefault().getPreferenceStore();
        IEclipsePreferences commonsNode = InstanceScope.INSTANCE.getNode("org.knime.bigdata.commons");

        if (commonsNode == null) {
            // nothing to migrate
            return;
        }

        if (commonsNode.get(PREF_KERBEROS_USER, null) != null) {
            String keytabUser = commonsNode.get(PREF_KERBEROS_USER, "");
            if (!keytabUser.isEmpty()) {
                preferenceStore.setValue(PrefKey.KEYTAB_PRINCIPAL_KEY, keytabUser);
                commonsNode.remove(PREF_KERBEROS_USER);
            }
        }

        if (commonsNode.get(PREF_KERBEROS_KEYTAB_FILE, null) != null) {
            String keytabFile = commonsNode.get(PREF_KERBEROS_KEYTAB_FILE, "");
            if (!keytabFile.isEmpty()) {
                preferenceStore.setValue(PrefKey.KEYTAB_FILE_KEY, keytabFile);
                commonsNode.remove(PREF_KERBEROS_KEYTAB_FILE);
                preferenceStore.setValue(PrefKey.AUTH_METHOD_KEY, AuthMethod.KEYTAB.toString());
            }
        }

        if (commonsNode.get(PREF_KERBEROS_LOGGING_ENABLED, null) != null) {
            boolean kerberosLog = commonsNode.getBoolean(PREF_KERBEROS_LOGGING_ENABLED, PrefKey.DEBUG_DEFAULT);
            preferenceStore.setValue(PrefKey.DEBUG_KEY, kerberosLog);
            commonsNode.remove(PREF_KERBEROS_LOGGING_ENABLED);
        }

        if (commonsNode.get(PREF_KERBEROS_LOGGING_LEVEL, null) != null) {
            String logLevel = commonsNode.get(PREF_KERBEROS_LOGGING_LEVEL, "");
            if (!logLevel.isEmpty()) {
                preferenceStore.setValue(PrefKey.DEBUG_LOG_LEVEL_KEY, logLevel);
                commonsNode.remove(PREF_KERBEROS_LOGGING_LEVEL);
            }
        }
    }
}
