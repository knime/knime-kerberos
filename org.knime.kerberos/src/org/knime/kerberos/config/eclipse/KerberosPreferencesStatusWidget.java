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
 *   Feb 18, 2019 (Sascha Wolke, KNIME GmbH): created
 */
package org.knime.kerberos.config.eclipse;

import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.TimeZone;
import java.util.concurrent.Future;
import java.util.stream.Collectors;

import org.eclipse.swt.SWT;
import org.eclipse.swt.custom.StyledText;
import org.eclipse.swt.dnd.Clipboard;
import org.eclipse.swt.dnd.TextTransfer;
import org.eclipse.swt.dnd.Transfer;
import org.eclipse.swt.graphics.Color;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Button;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Link;
import org.eclipse.swt.widgets.Listener;
import org.eclipse.swt.widgets.Shell;
import org.knime.kerberos.KerberosInternalAPI;
import org.knime.kerberos.api.KerberosProvider;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.logger.KerberosLogger;

/**
 * Widget that shows current Kerberos status and Validate/Login/Logout buttons.
 *
 * Behavior of the widget:
 *   * If the user is authenticated:
 *     - Current ticket status will be displayed.
 *     - Validate buttons is disabled and logout button enabled.
 *   * If the user is not authenticated:
 *     - Current status is not authenticated.
 *     - Validate and login button is enabled.
 *   * After a click on login, logout or validate:
 *     - Clicked button gets replaced by cancel button.
 *   * After the user presses cancel:
 *     - State becomes XYZ cancelled.
 *   * On pressing cancel on the preference page, all running workers are cancelled.
 *   * On pressing OK on the preferences page:
 *     - If a validate or get current state worker is running, it will be cancelled.
 *     - If a login or logout worker is running, an error will be shown and the preference blocks.
 *
 * @author Sascha Wolke, KNIME GmbH
 */
public class KerberosPreferencesStatusWidget {

    private static final String STATE_RUN_VALIDATION = "Validating configuration...";
    private static final String STATE_VALID = "Valid configuration";
    private static final String STATE_RUN_LOGIN = "Waiting for login to complete...";
    private static final String STATE_RUN_LOGOUT = "Waiting for logout to complete...";

    private static final String KERBEROS_LOG_TITLE = "Kerberos debug log";

    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.RFC_1123_DATE_TIME;

    private KerberosPreferencePage m_preferencePage;

    private Group m_statusGroup;

    private Label m_statusLabel;
    private Label m_statusValue;
    private Label m_statusPrincipalLabel;
    private Label m_statusPrincipalValue;
    private Label m_statusExpiresLabel;
    private Label m_statusExpiresValue;
    private Label m_statusLogLabel;
    private Link m_statusLogLink;
    private Button m_statusValidateButton;
    private Button m_statusLoginLogoutButton;

    private BackgroundWorker m_workerThread;

    private UserPasswordDialogCallbackHandler m_userPassHandler;

    /**
     * A worker that run's fetch current state/validate/login/logout actions in background.
     *
     * @author Sascha Wolke, KNIME GmbH
     */
    private static class BackgroundWorker extends Thread {
        private final boolean m_warnBeforeCancel;
        private final String m_action;

        protected BackgroundWorker(final boolean warnBeforeCancel, final String action, final Runnable runnable) {
            super(runnable);
            m_warnBeforeCancel = warnBeforeCancel;
            m_action = action;
        }

        protected boolean warnBeforeCancel() {
            return m_warnBeforeCancel;
        }

        protected String getAction() {
            return m_action;
        }
    }

    /**
     * Default constructor.
     *
     * @param parent parent composite that contains this widget
     * @param preferencePage preference page that contains this widget
     */
    protected KerberosPreferencesStatusWidget(final Composite parent, final KerberosPreferencePage preferencePage) {
        m_statusGroup = new Group(parent, SWT.NONE);
        m_statusGroup.setText("Status");
        m_statusGroup.setLayout(new GridLayout(4, false));
        m_statusGroup.setLayoutData(new GridData(SWT.FILL, SWT.TOP, true, false));

        m_preferencePage = preferencePage;

        m_statusLabel = new Label(m_statusGroup, SWT.NONE);
        m_statusLabel.setText("Status:");
        m_statusLabel.setLayoutData(new GridData(SWT.LEFT, SWT.CENTER, false, false));
        m_statusValue = new Label(m_statusGroup, SWT.NONE);
        m_statusValue.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));
        m_statusValue.setText("Loading current state...");

        m_statusPrincipalLabel = new Label(m_statusGroup, SWT.NONE);
        m_statusPrincipalLabel.setText("Principal:");
        m_statusPrincipalLabel.setLayoutData(new GridData(SWT.LEFT, SWT.CENTER, false, false));
        m_statusPrincipalLabel.setVisible(false);
        m_statusPrincipalValue = new Label(m_statusGroup, SWT.NONE);
        m_statusPrincipalValue.setText("");
        m_statusPrincipalValue.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));
        m_statusPrincipalValue.setVisible(false);

        m_statusExpiresLabel = new Label(m_statusGroup, SWT.NONE);
        m_statusExpiresLabel.setText("Expires:");
        m_statusExpiresLabel.setLayoutData(new GridData(SWT.LEFT, SWT.CENTER, false, false));
        m_statusExpiresLabel.setVisible(false);
        m_statusExpiresValue = new Label(m_statusGroup, SWT.NONE);
        m_statusExpiresValue.setText("");
        m_statusExpiresValue.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false, 3, 1));
        m_statusExpiresValue.setVisible(false);

        m_statusLogLabel = new Label(m_statusGroup, SWT.NONE);
        m_statusLogLabel.setText("Log:");
        m_statusLogLabel.setLayoutData(new GridData(SWT.LEFT, SWT.TOP, false, false));
        m_statusLogLink = new Link(m_statusGroup, SWT.BORDER);
        m_statusLogLink.setText("<a>View debug log</a>");
        m_statusLogLink.setLayoutData(new GridData(SWT.LEFT, SWT.TOP, true, false, 3, 1));
        m_statusLogLink.addListener(SWT.Selection, event -> openKerberosLog());

        final Label l = new Label(m_statusGroup, SWT.NONE);
        l.setLayoutData(new GridData(SWT.FILL, SWT.NONE, true, false, 2, 1));

        m_statusValidateButton = new Button(m_statusGroup, SWT.PUSH);
        m_statusValidateButton.setText("  Validate  ");
        m_statusValidateButton.setToolTipText("Validate Kerberos configuration");
        m_statusValidateButton.setLayoutData(new GridData(SWT.RIGHT, SWT.BOTTOM, false, false));
        m_statusValidateButton.setVisible(false);

        m_statusLoginLogoutButton = new Button(m_statusGroup, SWT.PUSH);
        m_statusLoginLogoutButton.setText("  Logout  ");
        m_statusLoginLogoutButton.setLayoutData(new GridData(SWT.RIGHT, SWT.BOTTOM, false, false));
        m_statusLoginLogoutButton.setVisible(false);

        m_userPassHandler = new UserPasswordDialogCallbackHandler(parent.getShell());
    }

    /**
     * Load current Kerberos state.
     */
    protected void loadKerberosState() {
        m_workerThread = new BackgroundWorker(false, "Load current state", () -> {
            Future<KerberosState> future = KerberosProvider.getKerberosState();
            handleStateFuture(future, false);
        });
        m_workerThread.start();
    }

    private void validateConfig() {
        showStatusMessage(STATE_RUN_VALIDATION);
        showValidateRunningButtons();
        KerberosPluginConfig config = m_preferencePage.loadFieldsIntoConfig();
        m_workerThread = new BackgroundWorker(false, "Validate configuration", () -> {
            Future<Void> future = KerberosInternalAPI.validateConfig(config, false);

            try {
                future.get();
                getDisplay().asyncExec(() -> {
                    showStatusMessage(STATE_VALID);
                    showNormalStatusButtons(false);
                });
            } catch (InterruptedException e) {
                future.cancel(true);
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                getDisplay().asyncExec(() -> {
                    showStatusError(e);
                    showNormalStatusButtons(false);
                });
            }
        });
        m_workerThread.start();
    }

    private void login() {
        showStatusMessage(STATE_RUN_LOGIN);
        showLoginRunningButtons();
        KerberosPluginConfig config = m_preferencePage.loadFieldsIntoConfig();
        m_workerThread = new BackgroundWorker(true, "login", () -> {
            m_userPassHandler.reset();
            Future<KerberosState> future = KerberosInternalAPI.login(config, m_userPassHandler);
            handleStateFuture(future, false);
        });
        m_workerThread.start();
    }

    private void logout() {
        showStatusMessage(STATE_RUN_LOGOUT);
        showLogoutRunningButtons();
        m_workerThread = new BackgroundWorker(true, "logout", () -> {
            Future<KerberosState> future = KerberosInternalAPI.logout();
            handleStateFuture(future, true);
        });
        m_workerThread.start();
    }

    private void cancel(final String action, final boolean authenticated) {
        m_workerThread.interrupt();
        showStatusMessage(action + " cancelled.");
        showNormalStatusButtons(authenticated);
    }

    private void handleStateFuture(final Future<KerberosState> future, final boolean wasAuthenticated) {
        try {
            KerberosState state = future.get();

            getDisplay().asyncExec(() -> {
                updateStatus(state);
                showNormalStatusButtons(state.isAuthenticated());
            });
        } catch (InterruptedException e) {
            future.cancel(true);
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            getDisplay().asyncExec(() -> {
                showStatusError(e);
                showNormalStatusButtons(wasAuthenticated);
            });
        }
    }

    private static void updateStatusButton(final Button button, final String text, final Listener listener) {
        button.setVisible(true);
        button.setText("  " + text + "  ");
        Arrays.stream(button.getListeners(SWT.Selection)).forEach(l -> button.removeListener(SWT.Selection, l));
        if (listener != null) {
            button.setEnabled(true);
            button.addListener(SWT.Selection, listener);
        } else {
            button.setEnabled(false);
        }
    }

    private void showNormalStatusButtons(final boolean isAuthenticated) {
        if (isAuthenticated) {
            updateStatusButton(m_statusValidateButton, "Validate", null);
            updateStatusButton(m_statusLoginLogoutButton, "Log out", event -> logout());
        } else {
            updateStatusButton(m_statusValidateButton, "Validate", event -> validateConfig());
            updateStatusButton(m_statusLoginLogoutButton, "Log in", event -> login());
        }
    }

    private void showValidateRunningButtons() {
        updateStatusButton(m_statusValidateButton, "Cancel", event -> cancel("Validate", false));
        updateStatusButton(m_statusLoginLogoutButton, "Log in", null);
    }

    private void showLoginRunningButtons() {
        updateStatusButton(m_statusValidateButton, "Validate", null);
        updateStatusButton(m_statusLoginLogoutButton, "Cancel", event -> cancel("Log in", false));
    }

    private void showLogoutRunningButtons() {
        updateStatusButton(m_statusValidateButton, "Validate", null);
        updateStatusButton(m_statusLoginLogoutButton, "Cancel", event -> cancel("Log out", true));
    }

    private void updateStatus(final KerberosState state) {
        if (state.isAuthenticated()) {
            m_statusValue.setText("Authenticated");
            m_statusValue.setForeground(getDisplay().getSystemColor(SWT.COLOR_BLACK));
            m_statusPrincipalLabel.setVisible(true);
            m_statusPrincipalValue.setVisible(true);
            m_statusPrincipalValue.setText(state.getPrincipal());
            m_statusExpiresLabel.setVisible(true);
            m_statusExpiresValue.setVisible(true);
            m_statusExpiresValue.setText(state.getTicketValidUntil().atZone(TimeZone.getDefault().toZoneId()).format(DATE_TIME_FORMATTER));

        } else {
            showStatusMessage("Not authenticated");
        }
    }

    private void showStatusMessage(final String message, final Color foreground) {
        m_statusValue.setText(message);
        m_statusValue.setForeground(foreground);
        m_statusPrincipalLabel.setVisible(false);
        m_statusPrincipalValue.setVisible(false);
        m_statusExpiresLabel.setVisible(false);
        m_statusExpiresValue.setVisible(false);
    }

    private void showStatusMessage(final String message) {
        showStatusMessage(message, getDisplay().getSystemColor(SWT.COLOR_BLACK));
    }

    private void showStatusError(final Exception e) {
        final String error = getDeepestErrorMessage(e, false);
        if (error != null) {
            showStatusMessage(error, getDisplay().getSystemColor(SWT.COLOR_RED));
        } else {
            showStatusMessage("An error occured (see Kerberos log)", getDisplay().getSystemColor(SWT.COLOR_RED));
        }
    }

    /**
     * Returns deepest non empty error message from the given exception and its cause stack.
     *
     * @param t A throwable, possibly with cause chain.
     * @param appendType Whether to append the type of the deepest exception with non-empty error message to the
     *            returned string.
     * @return deepest non empty error message or null.
     */
    private static String getDeepestErrorMessage(final Throwable t, final boolean appendType) {
        String deeperMsg = null;
        if (t.getCause() != null) {
            deeperMsg = getDeepestErrorMessage(t.getCause(), appendType);
        }

        if (deeperMsg != null && deeperMsg.length() > 0) {
            return deeperMsg;
        } else if (t.getMessage() != null && t.getMessage().length() > 0) {
            if (appendType) {
                return String.format("%s (%s)", t.getMessage(), t.getClass().getSimpleName());
            } else {
                return t.getMessage();
            }
        } else {
            return null;
        }
    }

    private void openKerberosLog() {
        final String log = KerberosLogger.getCapturedLines().stream().collect(Collectors.joining("\n"));
        final Clipboard clipboard = new Clipboard(getDisplay());
        final Shell shell = new Shell(getDisplay(), SWT.DIALOG_TRIM | SWT.RESIZE | SWT.APPLICATION_MODAL);
        shell.setText(KERBEROS_LOG_TITLE);
        shell.setLayout(new GridLayout(2, true));

        final StyledText text = new StyledText(shell, SWT.MULTI | SWT.BORDER | SWT.READ_ONLY | SWT.WRAP | SWT.V_SCROLL);
        text.setText(log);
        text.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true, 2, 1));

        final Button clipboardButton = new Button(shell, SWT.PUSH);
        clipboardButton.setText("  Copy to clipboard  ");
        clipboardButton.setLayoutData(new GridData(SWT.LEFT, SWT.CENTER, true, false));
        clipboardButton.addListener(SWT.Selection, event -> {
            TextTransfer textTransfer = TextTransfer.getInstance();
            clipboard.setContents(new Object[]{ log }, new Transfer[]{ textTransfer });
        });

        final Button closeButton = new Button(shell, SWT.PUSH);
        closeButton.setText("  Close  ");
        closeButton.setLayoutData(new GridData(SWT.RIGHT, SWT.CENTER, true, false));
        closeButton.addListener(SWT.Selection, event -> shell.close());

        shell.setSize(800, 400);
        shell.open();
    }

    private Display getDisplay() {
        return m_statusGroup.getDisplay();
    }

    /**
     * Notifies that the OK button of parent container has been pressed.
     *
     * @return <code>false</code> if the container's OK processing should be aborted
     */
    protected boolean performOk() {
        if (m_workerThread.isAlive()) {
            if (m_workerThread.warnBeforeCancel()) {
                m_preferencePage.setErrorMessage("Running " + m_workerThread.getAction() + " detected, must be finished or cancelled first.");
                return false;
            } else {
                m_workerThread.interrupt();
            }
        }

        return true;
    }

    /**
     * Notifies that the parent container has been canceled.
     *
     * @return <code>false</code> if the container's cancel processing should be aborted
     */
    protected boolean performCancel() {
        if (m_workerThread.isAlive()) {
            m_workerThread.interrupt();
        }

        return true;
    }
}
