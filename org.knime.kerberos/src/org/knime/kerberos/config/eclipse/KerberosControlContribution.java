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
 *   11.02.2019 (Mareike Hoeger, KNIME GmbH, Konstanz, Germany): created
 */
package org.knime.kerberos.config.eclipse;

import java.io.File;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.eclipse.core.runtime.FileLocator;
import org.eclipse.jface.dialogs.MessageDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.events.MouseEvent;
import org.eclipse.swt.events.MouseListener;
import org.eclipse.swt.graphics.Image;
import org.eclipse.swt.graphics.ImageData;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Menu;
import org.eclipse.swt.widgets.MenuItem;
import org.eclipse.ui.menus.WorkbenchWindowControlContribution;
import org.knime.kerberos.ExceptionUtil;
import org.knime.kerberos.KerberosAuthManager;
import org.knime.kerberos.KerberosInternalAPI;
import org.knime.kerberos.KerberosPlugin;
import org.knime.kerberos.KerberosStateListener;
import org.knime.kerberos.UserRequestedCancelException;
import org.knime.kerberos.api.KerberosState;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.osgi.framework.FrameworkUtil;

/**
 *
 * @author Mareike Hoeger, KNIME GmbH, Konstanz, Germany
 */
public class KerberosControlContribution extends WorkbenchWindowControlContribution implements KerberosStateListener {

    private static final Logger LOG = Logger.getLogger(KerberosControlContribution.class);

    private UserPasswordDialogCallbackHandler m_userPasswordCallbackHandler;

    private Image m_kerberosIn;

    private Image m_kerberos;

    private Composite m_composite;

    private Label m_icon;

    private Label m_text;

    private Composite m_toolbar;

    private Thread m_loginWorkerThread;

    private boolean m_cancled;

    /**
     * {@inheritDoc}
     */
    @Override
    protected Control createControl(final Composite parent) {
        if (m_composite == null) {
            m_userPasswordCallbackHandler = new UserPasswordDialogCallbackHandler(parent.getShell());
            parent.getParent().setRedraw(true);

            m_toolbar = parent.getParent();
            m_composite = new Composite(parent, SWT.NONE);

            GridLayout layout = new GridLayout(2, false);
            layout.marginHeight = 0;
            layout.marginWidth = 0;
            layout.marginTop = -1;
            m_composite.setLayout(layout);
            m_icon = new Label(m_composite, SWT.CENTER);
            addInteractions(m_icon);

            GridData gdata = new GridData(SWT.FILL, SWT.FILL, false, false, 1, 1);
            gdata.widthHint = 110;
            m_text = new Label(m_composite, SWT.CENTER);
            m_text.setLayoutData(gdata);
            addInteractions(m_text);
            try {
                File bundle = FileLocator.getBundleFile(FrameworkUtil.getBundle(getClass()));
                File kerberos = new File(bundle, "icons/kerberos-login.png");
                m_kerberos = createImage(kerberos.getAbsolutePath(), parent);
                File kerberosIn = new File(bundle, "icons/kerberos-logged-in.png");
                m_kerberosIn = createImage(kerberosIn.getAbsolutePath(), parent);
                m_icon.setImage(m_kerberos);

            } catch (IOException e) {
                LOG.error("Error loading icons", e);
            }

            m_composite.setEnabled(true);

            KerberosAuthManager.registerStateListener(this);
            showKerberosStatusIcon(KerberosPlugin.getDefault().getPreferenceStore().getBoolean(PrefKey.SHOW_ICON_KEY));
        }

        return m_composite;
    }

    private void addInteractions(final Control control) {
        control.addMouseListener(new MouseListener() {
            @Override
            public void mouseUp(final MouseEvent e) {
                // nothing to do
            }

            @Override
            public void mouseDown(final MouseEvent e) {
                // nothing to do
            }

            @Override
            public void mouseDoubleClick(final MouseEvent e) {
                triggerLoginToggle();
            }
        });

        Menu menu = new Menu(control);
        control.setMenu(menu);

        final MenuItem loginLogout = new MenuItem(menu, SWT.PUSH);
        loginLogout.setText("Login");
        loginLogout.addListener(SWT.Selection, (e) -> triggerLoginToggle());
    }

    private void triggerLoginToggle() {

        if (m_icon.getMenu().getItem(0).getText().equals("Login")) {
            m_icon.getMenu().getItem(0).setText("Cancel");
            m_text.getMenu().getItem(0).setText("Cancel");
            KerberosControlContribution.this.m_text.setText("Logging in...");
            startLoginTask();
        } else if(m_icon.getMenu().getItem(0).getText().equals("Cancel")) {
            if (m_loginWorkerThread.isAlive()) {
                m_cancled = true;
                m_loginWorkerThread.interrupt();
            }
        }else {
            m_icon.getMenu().getItem(0).setEnabled(false);
            m_text.getMenu().getItem(0).setEnabled(false);
            KerberosControlContribution.this.m_text.setText("Logging out...");
            startLogoutTask();
        }
    }

    private void startLoginTask() {
        m_loginWorkerThread = new Thread(() -> {
            try {
                KerberosInternalAPI.login(KerberosPluginConfig.load(), m_userPasswordCallbackHandler).get();
            } catch (Exception e) {
                displayLoggedOutState();
                if ((e instanceof InterruptedException) && m_cancled) {
                    m_cancled = false;
                    Display.getDefault().asyncExec(() -> {
                        MessageDialog.openError(Display.getCurrent().getActiveShell(), "Login canceled",
                            "Kerberos login canceled.");
                    });
                }
                // only show an error when the user did not cancel the login in prompt
                else if (!(e.getCause() instanceof UserRequestedCancelException)) {
                    LOG.error("Kerberos login failed: " + e.getMessage(), e);
                    Display.getDefault().asyncExec(() -> {
                        MessageDialog.openError(Display.getCurrent().getActiveShell(), "Login failed",
                            "Kerberos login failed: " + ExceptionUtil.getDeepestErrorMessage(e, true));
                    });
                }
            } finally {
                m_userPasswordCallbackHandler.reset();
            }
        });
         m_loginWorkerThread.start();
    }

    private static void startLogoutTask() {
        new Thread(() -> {
            KerberosInternalAPI.logout();
        }).start();
    }

    private static Image createImage(final String path, final Composite parent) {
        ImageData data = new ImageData(path);
        return new Image(parent.getDisplay(), data);
    }

    /**
     * Called by {@link KerberosAuthManager} when the login status changes.
     */
    @Override
    public void kerberosStateChanged(final KerberosState newState) {
        if (newState.isAuthenticated()) {
            displayLoginState(newState);
        } else {
            displayLoggedOutState();
        }
    }

    private void displayLoggedOutState() {
        Display.getDefault().asyncExec(() -> {
            m_icon.setImage(m_kerberos);
            m_icon.setToolTipText("Double-click to log in");
            m_icon.getMenu().getItem(0).setText("Login");
            m_icon.getMenu().getItem(0).setEnabled(true);

            m_text.setText("Not logged in");
            m_text.setToolTipText("Double-click to log in");
            m_text.getMenu().getItem(0).setText("Login");
            m_text.getMenu().getItem(0).setEnabled(true);
        });
    }

    private void displayLoginState(final KerberosState newState) {
        Display.getDefault().asyncExec(() -> {
            final String tooltip = String.format("Logged in as %s (expires at %s)",
                newState.getPrincipal(),
                newState.getTicketValidUntil().atZone(TimeZone.getDefault().toZoneId()).format(DateTimeFormatter.RFC_1123_DATE_TIME));

            m_icon.setImage(m_kerberosIn);
            m_icon.setToolTipText(tooltip);
            m_icon.getMenu().getItem(0).setText("Logout");
            m_icon.getMenu().getItem(0).setEnabled(true);

            m_text.setText(newState.getPrincipal().split("@")[0]);
            m_text.setToolTipText(tooltip);
            m_text.getMenu().getItem(0).setText("Logout");
            m_text.getMenu().getItem(0).setEnabled(true);
        });
        m_cancled = false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void showKerberosStatusIcon(final boolean showIcon) {
        m_toolbar.setVisible(showIcon);

       getWorkbenchWindow().getShell().layout();

    }

}
