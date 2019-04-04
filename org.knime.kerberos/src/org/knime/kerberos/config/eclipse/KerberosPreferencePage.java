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
 *   Feb 11, 2019 (Sascha Wolke, KNIME GmbH): created
 */
package org.knime.kerberos.config.eclipse;

import java.util.ArrayList;

import org.eclipse.jface.preference.IPreferenceStore;
import org.eclipse.jface.preference.PreferencePage;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Event;
import org.eclipse.swt.widgets.FileDialog;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.IWorkbench;
import org.eclipse.ui.IWorkbenchPreferencePage;
import org.knime.kerberos.KerberosInternalAPI;
import org.knime.kerberos.KerberosPlugin;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;

/**
 * Preferences page for Kerberos related settings.
 *
 * @author Sascha Wolke, KNIME GmbH
 */
public class KerberosPreferencePage extends PreferencePage implements IWorkbenchPreferencePage, Listener {

    private Button m_configDefaultButton;
    private Button m_configFileButton;
    private Text m_configFileInput;
    private Button m_configFileBrowseButton;
    private Button m_configRealmKDCButton;
    private Text m_configRealmInput;
    private Text m_configKDCInput;

    private Button m_authTicketCacheButton;
    private Button m_authUserPwdButton;
    private Button m_authKeytabButton;
    private Text m_authKeytabPrincipalInput;
    private Text m_authKeytabFileInput;
    private Button m_authKeytabFileBrowseButton;

    private Button m_debugEnableButton;
    private Button m_debugDebugButton;
    private Button m_debugInfoButton;
    private Button m_debugWarnButton;
    private Button m_debugErrorButton;

    private KerberosPreferencesStatusWidget m_statusWidget;

    private long m_renewalSafetyMarginSeconds;
    private Button m_loginIconEnableButton;

    @Override
    public void init(final IWorkbench workbench) {
        final IPreferenceStore preferenceStore = KerberosPlugin.getDefault().getPreferenceStore();
        setPreferenceStore(preferenceStore);
    }

    @Override
    protected Control createContents(final Composite parent) {
        Composite mainContainer = new Composite(parent, SWT.NONE);
        GridLayout mainContainerLayout = new GridLayout(1, false);
        mainContainerLayout.marginWidth = mainContainerLayout.marginHeight = 0;
        mainContainer.setLayout(mainContainerLayout);
        mainContainer.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));

        /////////////// Configuration settings ///////////////
        Group configGroup = new Group(mainContainer, SWT.NONE);
        configGroup.setText("Kerberos Configuration");
        configGroup.setLayout(new GridLayout(3, false));
        configGroup.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));

        m_configDefaultButton = createMainRadioButton(configGroup, "Use system defaults (discouraged)");

        m_configFileButton = createMainRadioButton(configGroup, "Use Kerberos client configuration file (krb5.conf)");
        m_configFileInput = createSubRadioTextInput(configGroup, "File:", 1);
        m_configFileBrowseButton = createFileBrowseButton(configGroup, m_configFileInput,
            "Open Kerberos client configuration", new String[]{"*.conf", "*.*"});

        m_configRealmKDCButton = createMainRadioButton(configGroup, "Use realm and KDC");
        m_configRealmInput = createSubRadioTextInput(configGroup, "Realm:", 2);
        m_configKDCInput = createSubRadioTextInput(configGroup, "KDC:", 2);


        /////////////// Authentication settings ///////////////
        Group authGroup = new Group(mainContainer, SWT.NONE);
        authGroup.setText("How to log in");
        authGroup.setLayout(new GridLayout(3, false));
        authGroup.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));

        m_authTicketCacheButton = createMainRadioButton(authGroup, "With system ticket cache (discouraged)");

        m_authUserPwdButton = createMainRadioButton(authGroup, "With username and password");

        m_authKeytabButton = createMainRadioButton(authGroup, "With keytab");
        m_authKeytabPrincipalInput = createSubRadioTextInput(authGroup, "Principal:", 2);
        m_authKeytabFileInput = createSubRadioTextInput(authGroup, "Keytab:", 1);
        m_authKeytabFileBrowseButton =
            createFileBrowseButton(authGroup, m_authKeytabFileInput, "Open keytab", new String[]{"*.keytab", "*.*"});

        /////////////// Debug settings ///////////////
        Group debugGroup = new Group(mainContainer, SWT.NONE);
        debugGroup.setText("Kerberos debug logging to KNIME log and Console");
        debugGroup.setLayout(new GridLayout(5, false));
        debugGroup.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));

        m_debugEnableButton = new Button(debugGroup, SWT.CHECK);
        m_debugEnableButton.setText("Enable:");
        m_debugEnableButton.addListener(SWT.Selection, this);

        m_debugDebugButton = new Button(debugGroup, SWT.RADIO);
        m_debugDebugButton.setText("DEBUG");
        m_debugDebugButton.addListener(SWT.Selection, this);

        m_debugInfoButton = new Button(debugGroup, SWT.RADIO);
        m_debugInfoButton.setText("INFO");
        m_debugInfoButton.addListener(SWT.Selection, this);

        m_debugWarnButton = new Button(debugGroup, SWT.RADIO);
        m_debugWarnButton.setText("WARN");
        m_debugWarnButton.addListener(SWT.Selection, this);

        m_debugErrorButton = new Button(debugGroup, SWT.RADIO);
        m_debugErrorButton.setText("ERROR");
        m_debugErrorButton.addListener(SWT.Selection, this);

        /////////////// Status Bar ///////////////
        Group statusBarGroup = new Group(mainContainer, SWT.NONE);
        statusBarGroup.setText("Status Bar");
        statusBarGroup.setLayout(new GridLayout(1, false));
        statusBarGroup.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));

        m_loginIconEnableButton = new Button(statusBarGroup, SWT.CHECK);
        m_loginIconEnableButton.setText("Permanently enable login status bar");
        m_loginIconEnableButton.addListener(SWT.Selection, this);


        /////////////// Status/Validate/Login/Logout ///////////////
        m_statusWidget = new KerberosPreferencesStatusWidget(mainContainer, this);

        /////////////// load preferences and state ///////////////
        loadConfigIntoFields(KerberosPluginConfig.load());
        m_statusWidget.loadKerberosState();

        return mainContainer;
    }

    private Button createMainRadioButton(final Composite parent, final String label) {
        GridData containerGridData = new GridData(SWT.LEFT, SWT.NONE, true, false, 3, 1);
        Button button = new Button(parent, SWT.RADIO);
        button.setText(label);
        button.setLayoutData(containerGridData);
        button.addListener(SWT.Selection, this);
        return button;
    }

    private Text createSubRadioTextInput(final Composite parent, final String text, final int span) {
        Label label = new Label(parent, SWT.NONE);
        label.setText(text);
        GridData labelGridData = new GridData(SWT.LEFT, SWT.CENTER, false, false);
        labelGridData.horizontalIndent = 20;
        label.setLayoutData(labelGridData);

        Text input = new Text(parent, SWT.BORDER);
        input.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, span, 1));
        input.addListener(SWT.CHANGED, this);

        return input;
    }

    private Button createFileBrowseButton(final Composite parent, final Text input, final String title,
        final String[] extensions) {

        Button button = new Button(parent, SWT.PUSH);
        button.setText("  Browse...  ");
        button.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, false, false));
        button.addListener(SWT.Selection, event -> {
            FileDialog fd = new FileDialog(parent.getShell(), SWT.OPEN);
            fd.setText(title);
            fd.setFilterExtensions(extensions);
            String selected = fd.open();
            if (selected != null) { // check if cancelled
                input.setText(selected);
                validateInputFields(loadFieldsIntoConfig());
            }
        });
        return button;
    }

    /**
     * Load preferences from store into fields.
     */
    private void loadConfigIntoFields(final KerberosPluginConfig config) {
        m_configDefaultButton.setSelection(config.getKerberosConfSource() == KerberosConfigSource.DEFAULT);
        m_configFileButton.setSelection(config.getKerberosConfSource() == KerberosConfigSource.FILE);
        m_configRealmKDCButton.setSelection(config.getKerberosConfSource() == KerberosConfigSource.REALM_KDC);
        m_configFileInput.setText(getString(config.getKerberosConfFile()));
        m_configRealmInput.setText(getString(config.getRealm()));
        m_configKDCInput.setText(getString(config.getKDC()));

        m_authTicketCacheButton.setSelection(config.getAuthMethod() == AuthMethod.TICKET_CACHE);
        m_authUserPwdButton.setSelection(config.getAuthMethod() == AuthMethod.USER_PWD);
        m_authKeytabButton.setSelection(config.getAuthMethod() == AuthMethod.KEYTAB);
        m_authKeytabPrincipalInput.setText(getString(config.getKeytabPrincipal()));
        m_authKeytabFileInput.setText(getString(config.getKeytabFile()));

        m_debugEnableButton.setSelection(config.doDebugLogging());
        m_debugDebugButton.setSelection(config.getDebugLogLevel().equalsIgnoreCase("DEBUG"));
        m_debugInfoButton.setSelection(config.getDebugLogLevel().equalsIgnoreCase("INFO"));
        m_debugWarnButton.setSelection(config.getDebugLogLevel().equalsIgnoreCase("WARN"));
        m_debugErrorButton.setSelection(config.getDebugLogLevel().equalsIgnoreCase("ERROR"));

        m_renewalSafetyMarginSeconds = config.getRenewalSafetyMarginSeconds();
        m_loginIconEnableButton.setSelection(config.showIcon());
        updateInputEnabledState();
        validateInputFields(loadFieldsIntoConfig());
    }

    private static String getString(final String input) {
        return input == null ? "" : input;
    }

    /**
     * @return configuration from input fields as {@link KerberosPluginConfig}
     */
    protected KerberosPluginConfig loadFieldsIntoConfig() {
        return new KerberosPluginConfig(
            getConfigSource(), m_configFileInput.getText(), m_configRealmInput.getText(), m_configKDCInput.getText(),
            getAuthMethod(), m_authKeytabPrincipalInput.getText(), m_authKeytabFileInput.getText(),
            m_debugEnableButton.getSelection(), getDebugLevel(),
            m_renewalSafetyMarginSeconds, m_loginIconEnableButton.getSelection());
    }

    private KerberosConfigSource getConfigSource() {
        if (m_configDefaultButton.getSelection()) {
            return KerberosConfigSource.DEFAULT;
        } else if (m_configFileButton.getSelection()) {
            return KerberosConfigSource.FILE;
        } else if (m_configRealmKDCButton.getSelection()) {
            return KerberosConfigSource.REALM_KDC;
        } else {
            return KerberosConfigSource.fromValue(PrefKey.KERBEROS_CONF_DEFAULT);
        }
    }

    private AuthMethod getAuthMethod() {
        if (m_authTicketCacheButton.getSelection()) {
            return AuthMethod.TICKET_CACHE;
        } else if (m_authUserPwdButton.getSelection()) {
            return AuthMethod.USER_PWD;
        } else if (m_authKeytabButton.getSelection()) {
            return AuthMethod.KEYTAB;
        } else {
            return AuthMethod.fromValue(PrefKey.AUTH_METHOD_DEFAULT);
        }
    }

    private String getDebugLevel() {
        if (m_debugDebugButton.getSelection()) {
            return "DEBUG";
        } else if (m_debugInfoButton.getSelection()) {
            return "INFO";
        } else if (m_debugWarnButton.getSelection()) {
            return "WARN";
        } else if (m_debugErrorButton.getSelection()) {
            return "ERROR";
        } else {
            return PrefKey.DEBUG_LOG_LEVEL_DEFAULT;
        }
    }

    /**
     * Validate given configuration and displays one error or warning message and invalidates the page on errors.
     *
     * @param config configuration to validate
     */
    private void validateInputFields(final KerberosPluginConfig config) {
        final ArrayList<String> errors = new ArrayList<>();
        final ArrayList<String> warnings = new ArrayList<>();
        config.validateShallow(errors, warnings);

        if (!errors.isEmpty()) {
            setMessage(errors.get(0), ERROR);
        } else if (!warnings.isEmpty()) {
            setMessage(warnings.get(0), WARNING);
        } else {
            setMessage(null);
        }

        setValid(errors.isEmpty());
    }

    /**
     * Updates enabled state on all input elements.
     */
    private void updateInputEnabledState() {
        // Configuration file
        if (m_configFileButton.getSelection()) {
            m_configFileInput.setEnabled(true);
            m_configFileBrowseButton.setEnabled(true);
            m_configRealmInput.setEnabled(false);
            m_configKDCInput.setEnabled(false);
        } else if (m_configRealmKDCButton.getSelection()) {
            m_configFileInput.setEnabled(false);
            m_configFileBrowseButton.setEnabled(false);
            m_configRealmInput.setEnabled(true);
            m_configKDCInput.setEnabled(true);
        } else {
            m_configFileInput.setEnabled(false);
            m_configFileBrowseButton.setEnabled(false);
            m_configRealmInput.setEnabled(false);
            m_configKDCInput.setEnabled(false);
        }

        // Authentication settings
        m_authKeytabPrincipalInput.setEnabled(m_authKeytabButton.getSelection());
        m_authKeytabFileInput.setEnabled(m_authKeytabButton.getSelection());
        m_authKeytabFileBrowseButton.setEnabled(m_authKeytabButton.getSelection());

        // Logging level
        m_debugDebugButton.setEnabled(m_debugEnableButton.getSelection());
        m_debugInfoButton.setEnabled(m_debugEnableButton.getSelection());
        m_debugWarnButton.setEnabled(m_debugEnableButton.getSelection());
        m_debugErrorButton.setEnabled(m_debugEnableButton.getSelection());

    }

    @Override
    public void handleEvent(final Event event) {
        updateInputEnabledState();
        validateInputFields(loadFieldsIntoConfig());
    }

    @Override
    protected void performDefaults() {
        loadConfigIntoFields(KerberosPluginConfig.defaults());
        super.performDefaults();
    }

    @Override
    protected void performApply() {
        final KerberosPluginConfig config = loadFieldsIntoConfig();
        config.save();
        KerberosInternalAPI.showKerberosStatusIcon(m_loginIconEnableButton.getSelection());
    }

    @Override
    public boolean performOk() {
        boolean statusWidgetResult = m_statusWidget.performOk();

        if (statusWidgetResult) {
            final KerberosPluginConfig config = loadFieldsIntoConfig();
            config.save();
        }
        KerberosInternalAPI.showKerberosStatusIcon(m_loginIconEnableButton.getSelection());
        return statusWidgetResult;
    }

    @Override
    public boolean performCancel() {
        return m_statusWidget.performCancel();
    }
}
