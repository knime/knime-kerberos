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

import org.eclipse.core.runtime.preferences.AbstractPreferenceInitializer;
import org.eclipse.jface.preference.IPreferenceStore;
import org.knime.kerberos.KerberosPlugin;

/**
 * Initializes the default values for the kerberos configuration.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class PrefInitializer extends AbstractPreferenceInitializer {

    /**
     * {@inheritDoc}
     */
    @Override
    public void initializeDefaultPreferences() {
        final IPreferenceStore preferenceStore = KerberosPlugin.getDefault().getPreferenceStore();

        preferenceStore.setDefault(PrefKey.KERBEROS_CONF_KEY, PrefKey.KERBEROS_CONF_DEFAULT);
        preferenceStore.setDefault(PrefKey.KERBEROS_CONF_FILE_KEY, PrefKey.KERBEROS_CONF_FILE_DEFAULT);
        preferenceStore.setDefault(PrefKey.KERBEROS_REALM_KEY, PrefKey.KERBEROS_REALM_DEFAULT);
        preferenceStore.setDefault(PrefKey.KERBEROS_KDC_KEY, PrefKey.KERBEROS_KDC_DEFAULT);
        preferenceStore.setDefault(PrefKey.AUTH_METHOD_KEY, PrefKey.AUTH_METHOD_DEFAULT);
        preferenceStore.setDefault(PrefKey.KEYTAB_PRINCIPAL_KEY, PrefKey.KEYTAB_PRINCIPAL_DEFAULT);
        preferenceStore.setDefault(PrefKey.KEYTAB_FILE_KEY, PrefKey.KEYTAB_FILE_DEFAULT);
        preferenceStore.setDefault(PrefKey.DEBUG_KEY, PrefKey.DEBUG_DEFAULT);
        preferenceStore.setDefault(PrefKey.DEBUG_LOG_LEVEL_KEY, PrefKey.DEBUG_LOG_LEVEL_DEFAULT);
        preferenceStore.setDefault(PrefKey.RENEWAL_SAFETY_MARGIN_SECONDS_KEY, PrefKey.RENEWAL_SAFETY_MARGIN_SECONDS_DEFAULT);
        preferenceStore.setDefault(PrefKey.SHOW_ICON_KEY, PrefKey.SHOW_ICON_DEFAULT);
    }
}
