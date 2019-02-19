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
 *   Feb 17, 2019 (Sascha Wolke, KNIME GmbH): created
 */
package org.knime.kerberos.config.eclipse;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.eclipse.jface.dialogs.TitleAreaDialog;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Shell;
import org.eclipse.swt.widgets.Text;

/**
 * {@link CallbackHandler} implementation that asks the user for a name and password in one dialog and remembers the
 * entered name.
 *
 * @author Sascha Wolke, KNIME GmbH
 */
public class UserPasswordDialogCallbackHandler implements CallbackHandler {

    private final UserPasswordDialog m_dialog;

    /**
     * Default constructor.
     *
     * @param parentShell parent shell of the dialog
     */
    protected UserPasswordDialogCallbackHandler(final Shell parentShell) {
        m_dialog = new UserPasswordDialog(parentShell);
    }

    private static class UserPasswordDialog extends TitleAreaDialog {
        private boolean m_userAsked = false;

        private Text m_nameText;
        private Text m_passwordText;

        private String m_name;
        private char[] m_password;

        protected UserPasswordDialog(final Shell parentShell) {
            super(parentShell);
        }

        @Override
        public void create() {
            super.create();
            setTitle("Kerberos Login");
        }

        @Override
        protected Control createDialogArea(final Composite parent) {
            Composite area = (Composite) super.createDialogArea(parent);
            Composite container = new Composite(area, SWT.NONE);
            container.setLayoutData(new GridData(SWT.FILL, SWT.FILL, true, true));
            container.setLayout(new GridLayout(2, false));

            new Label(container, SWT.NONE).setText("Username:");
            m_nameText = new Text(container, SWT.BORDER);
            m_nameText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));

            new Label(container, SWT.NONE).setText("Password:");
            m_passwordText = new Text(container, SWT.BORDER | SWT.PASSWORD);
            m_passwordText.setLayoutData(new GridData(SWT.FILL, SWT.CENTER, true, false));

            // remember name in second run and focus password field
            if (m_name != null && !m_name.isEmpty()) {
                m_nameText.setText(m_name);
                m_passwordText.setFocus();
            }

            return area;
        }

        @Override
        protected void okPressed() {
            m_name = m_nameText.getText();
            m_password = m_passwordText.getText().toCharArray();
            super.okPressed();
        }

        private void askUser() {
            if (!m_userAsked) {
                getParentShell().getDisplay().syncExec(() -> {
                    create();
                    open();
                    m_userAsked = true;
                });
            }
        }

        String getName() {
            askUser();
            return m_name;
        }

        char[] getPassword() {
            askUser();
            return m_password;
        }

        void reset() {
            m_userAsked = false;
        }
    }

    /**
     * Reset the dialog and ask the user again in next callback handle call.
     */
    protected void reset() {
        m_dialog.reset();
    }

    @Override
    public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof NameCallback) {
                ((NameCallback)callback).setName(m_dialog.getName());
            } else if (callback instanceof PasswordCallback) {
                ((PasswordCallback)callback).setPassword(m_dialog.getPassword());
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }
}
