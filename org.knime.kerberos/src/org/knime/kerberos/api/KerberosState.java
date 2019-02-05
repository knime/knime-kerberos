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
 *   Jan 17, 2019 (bjoern): created
 */
package org.knime.kerberos.api;

import java.time.Instant;

/**
 * Holds a Kerberos authentication state.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 * @see KerberosProvider#getKerberosState()
 */
public class KerberosState {

    private final boolean m_isAuthenticated;

    private final String m_principal;

    private final Instant m_ticketValidUntil;

    /**
     * Creates an unauthenticated Kerberos state. Principal and valid time is set to null.
     */
    public KerberosState() {
        m_isAuthenticated = false;
        m_principal = null;
        m_ticketValidUntil = null;
    }

    /**
     * Creates an authenticated Kerberos state.
     *
     * @param principal the authenticated principal
     * @param ticketValidUntil the instant until the ticket is valid
     */
    public KerberosState(final String principal, final Instant ticketValidUntil) {
        m_isAuthenticated = true;
        m_principal = principal;
        m_ticketValidUntil = ticketValidUntil;
    }

    /**
     * @return true, when successfully authenticated, false otherwise.
     */
    public boolean isAuthenticated() {
        return m_isAuthenticated;
    }

    /**
     * @return the Kerberos principal, or null, if we are not authenticated.
     */
    public String getPrincipal() {
        return m_principal;
    }

    /**
     * @return when the Kerberos ticket expires, or null if we are not authenticated.
     */
    public Instant getTicketValidUntil() {
        return m_ticketValidUntil;
    }

    @Override
    public String toString() {
        if (m_isAuthenticated) {
            return String.format("%s (ticket expires %s)", m_principal, m_ticketValidUntil);
        } else {
            return "Not authenticated";
        }
    }
}
