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
 *   01.02.2017 (koetter): created
 */
package org.knime.kerberos.logger;

import java.io.PrintStream;
import java.util.List;

import org.knime.core.node.NodeLogger;
import org.knime.core.node.NodeLogger.LEVEL;

/**
 * This class captures Kerberos debug output by manipulating system properties and redirecting the System.out to an
 * in-memory buffer (for display purposes), and the KNIME NodeLogger of this class. The { {@link #startCapture(LEVEL)}
 * method starts the redirect, but must be called prior to loading any of Java's Kerberos implementation classes,
 * otherwise we cannot get the full debug log output.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KerberosLogger {

    private static final LogForwarderOutputStream LOG_FORWARDER_OUTPUT_STREAM = new LogForwarderOutputStream();

    private static final MemoryBufferLogFowarder MEMORY_BUFFER_LOG_FORWARDER = new MemoryBufferLogFowarder();

    private static boolean useNodeLoggerForwarder = true;

    private static NodeLoggerLogForwarder nodeLoggerForwarder = null;

    private static PrintStream sysOutReplacement;

    private static PrintStream origSysOut;

    private KerberosLogger() {
        //avoid object creation
    }

    /**
     * Starts capturing the System.out. This method must be called prior to loading any of Java's Kerberos
     * implementation classes, otherwise we cannot get the full debug log output. Every line that gets written to
     * System.out will be written to two places, (1) an in-memory buffer (for display purposes), and (2) the KNIME
     * NodeLogger of this class. It is safe to call this method multiple times, however the in-memory buffer of log
     * messages will be cleared each time.
     *
     * @param nodeLoggerLogLevel the log Level
     */
    public static synchronized void startCapture(final LEVEL nodeLoggerLogLevel) {
        ensureLogForwardersInitialized();
        ensureNodeLoggerForwarderConfig(nodeLoggerLogLevel);
        ensureSystemOutRedirect();
    }

    private static void ensureSystemOutRedirect() {
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.jgss.debug", "true");

        if (sysOutReplacement == null) {
            LOG_FORWARDER_OUTPUT_STREAM.ensureOpen();
            sysOutReplacement = new PrintStream(LOG_FORWARDER_OUTPUT_STREAM, true);

            //save the original output stream in order to reset it if the logging is disabled
            origSysOut = System.out;
            System.setOut(sysOutReplacement);
        }
    }

    /**
     * Ensures that all the log forwarder that forwards to the KerberosLogger NodeLogger
     * is properly configured.
     *
     * @param nodeLoggerLogLevel
     */
    private static void ensureNodeLoggerForwarderConfig(final LEVEL nodeLoggerLogLevel) {
        if (useNodeLoggerForwarder) {
            final NodeLogger logger = NodeLogger.getLogger(KerberosLogger.class);
            nodeLoggerForwarder.updateConfiguration(logger, nodeLoggerLogLevel);
        }
    }

    /**
     * Ensures that all log forwarder instances are initialized and registered.
     */
    private static void ensureLogForwardersInitialized() {
        LOG_FORWARDER_OUTPUT_STREAM.clearLogForwarders();

        MEMORY_BUFFER_LOG_FORWARDER.clearBuffer();
        LOG_FORWARDER_OUTPUT_STREAM.addLogForwarder(MEMORY_BUFFER_LOG_FORWARDER);

        // for unit testing we need to be able to shut off the NodeLoggerLogForwarder because
        // it requires a fully booted KNIME and OSGI container, which we do not want.
        if (useNodeLoggerForwarder) {
            if (nodeLoggerForwarder == null) {
                final NodeLogger logger = NodeLogger.getLogger(KerberosLogger.class);
                nodeLoggerForwarder = new NodeLoggerLogForwarder(logger, LEVEL.DEBUG);
            }
            LOG_FORWARDER_OUTPUT_STREAM.addLogForwarder(nodeLoggerForwarder);
        }
    }

    /**
     * Stops the capturing of the log. This may or may not prevent Java's Kerberos implementation from printing messages
     * to System.out, but it definitely stops the capturing of the messages in KerberosLogger.
     */
    public static synchronized void stopCapture() {
        System.setProperty("sun.security.krb5.debug", "false");
        System.setProperty("sun.security.jgss.debug", "false");

        if (origSysOut != null) {
            System.setOut(origSysOut);
            origSysOut = null;
        }

        if (sysOutReplacement != null) {
            sysOutReplacement.flush();
            // this also closes LOG_FORWARDER_OUTPUT_STREAM
            sysOutReplacement.close();
            sysOutReplacement = null;
        }
    }

    /**
     * @return gets the captured lines as a list of strings
     */
    public static synchronized List<String> getCapturedLines() {
        return MEMORY_BUFFER_LOG_FORWARDER.getCapturedLines();
    }

    /**
     * Clears the in-memory buffer of captured lines.
     */
    public static synchronized void clearCapturedLines() {
        MEMORY_BUFFER_LOG_FORWARDER.clearBuffer();
    }

    /**
     * (Testing code) Method to set whether messages captured from System.out should be forwarded to a KNIME NodeLogger.
     * Being able to switch this off allows unit tests to run without OSGI container.
     *
     * @param shouldUse Whether to forward messages to a KNIME NodeLogger or not.
     */
    public static synchronized void setUseNodeLoggerForwarder(final boolean shouldUse) {
        useNodeLoggerForwarder = shouldUse;
    }
}
