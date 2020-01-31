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
 *   Feb 14, 2019 (bjoern): created
 */
package org.knime.kerberos.logger;

import org.knime.core.node.NodeLogger;
import org.knime.core.node.NodeLogger.LEVEL;

/**
 * {@link LogForwarder} implementation that forwards log messages to a KNIME {@link NodeLogger}.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class NodeLoggerLogForwarder implements LogForwarder {

    private NodeLogger m_nodeLogger;

    private LEVEL m_logLevel;

    /**
     * Creates a new instance.
     *
     * @param logger NodeLogger to forward messages to. May be null if forwardToNodeLogger is false.
     * @param logLevel The log level to use when forwarding messages to the node logger.
     */
    public NodeLoggerLogForwarder(final NodeLogger logger, final LEVEL logLevel) {
        m_nodeLogger = logger;
        m_logLevel = logLevel;
    }

    /**
     * Update which {@link NodeLogger} to forward to, and which log level to use.
     *
     * @param logger The {@link NodeLogger} to forward to.
     * @param logLevel The log level to use.
     */
    public void updateConfiguration(final NodeLogger logger, final LEVEL logLevel) {
        m_nodeLogger = logger;
        m_logLevel = logLevel;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void forwardMessage(final String msg) {
        switch (m_logLevel) {
            case ERROR:
                m_nodeLogger.error(msg);
                break;
            case FATAL:
                m_nodeLogger.fatal(msg);
                break;
            case INFO:
                m_nodeLogger.info(msg);
                break;
            case WARN:
                m_nodeLogger.warn(msg);
                break;
            default:
                m_nodeLogger.debug(msg);
                break;
        }
    }
}
