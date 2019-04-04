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
 * This class captures Kerberos debug outut by setting the right system properties and redirecting the System.out to the
 * {@link NodeLoggerOutputStreamBuffer} class.
 *
 * @author Tobias Koetter, KNIME.com
 */
public class KerberosLogger {

    private static final NodeLoggerOutputStreamBuffer BUFFER = new NodeLoggerOutputStreamBuffer();

    private static LogForwarder testingLogForwarder = null;

    private static PrintStream sysOutReplacement;

    private static PrintStream origSysOut;

    private KerberosLogger() {
        //avoid object creation
    }

    /**
     * Enable or disable the Kerberos logging.
     *
     * @param forwardToKNIMELog <code>true</code> if logging should be enabled
     * @param knimeLogLevel the log Level
     */
    public static synchronized void startCapture(final boolean forwardToKNIMELog, final LEVEL knimeLogLevel) {
        if (testingLogForwarder != null) {
            BUFFER.open(testingLogForwarder);
        } else {
            BUFFER.open(newKNIMELogForwarder(forwardToKNIMELog, knimeLogLevel));
        }

        sysOutReplacement = new PrintStream(BUFFER, true);

        //save the original output stream in order to reset it if the logging is disabled
        origSysOut = System.out;
        System.setOut(sysOutReplacement);

        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.jgss.debug", "true");
    }

    /**
     * Stops the capturing of the log
     */
    public static synchronized void stopCapture() {
        System.setProperty("sun.security.krb5.debug", "false");
        System.setProperty("sun.security.jgss.debug", "false");
        if(origSysOut != null) {
            System.setOut(origSysOut);
            origSysOut = null;
        }

        if(sysOutReplacement != null) {
            sysOutReplacement.flush();
            sysOutReplacement.close();
            sysOutReplacement = null;
        }

    }

    /**
     * @return gets the captured lines as a list of strings
     */
    public static synchronized List<String> getCapturedLines() {
        return BUFFER.getBufferedLines();
    }

    /**
     * Sets whether the log should be forwarded for test
     * @param logForwarder the log forwarder to forward to
     */
    public synchronized static void setLogForwarderForTesting(final LogForwarder logForwarder) {
        testingLogForwarder = logForwarder;
    }

    private static LogForwarder newKNIMELogForwarder(final boolean forwardToKNIMELog, final LEVEL knimeLogLevel) {
        final NodeLogger logger = NodeLogger.getLogger(KerberosLogger.class);
        return (line) -> {
            if (forwardToKNIMELog) {
                switch (knimeLogLevel) {
                    case ERROR:
                        logger.error(line);
                        break;
                    case FATAL:
                        logger.fatal(line);
                        break;
                    case INFO:
                        logger.info(line);
                        break;
                    case WARN:
                        logger.warn(line);
                        break;
                    default:
                        logger.debug(line);
                        break;
                }
            }
        };
    }
}
