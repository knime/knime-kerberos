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

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * {@link OutputStream} implementation multiplexes each line of text written to the output stream to to a list of
 * {@link LogForwarder} instances.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class LogForwarderOutputStream extends OutputStream {

    private static final String SEPARATOR = System.getProperty("line.separator");

    private ByteBuffer m_byteBuffer = ByteBuffer.allocate(4096);

    private final StringBuilder m_buf = new StringBuilder();

    private boolean m_closed = false;

    private final List<LogForwarder> m_forwarders = new ArrayList<>();

    /**
     * Registers a log forwarder to receive messages written to this stream.
     *
     * @param logForwarder The forwarder to register.
     */
    public void addLogForwarder(final LogForwarder logForwarder) {
        m_forwarders.add(logForwarder);
    }

    /**
     * Unregisters a log forwarder from receiving messages written to this stream.
     *
     * @param logForwarder The forwarder to unregister.
     * @return True when the log forwarder has previously been registered, false otherwise.
     */
    public boolean removeLogForwarder(final LogForwarder logForwarder) {
        return m_forwarders.remove(logForwarder);
    }

    /**
     * Unregisters all log forwarders from receiving messages written to this stream.
     */
    public void clearLogForwarders() {
        m_forwarders.clear();
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() {
        flush();
        m_closed = true;
    }

    /**
     * Reopens the stream for log message dispatching.
     */
    public void ensureOpen() {
        m_closed = false;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void write(final int b) throws IOException {
        if (m_closed) {
            return;
        }

        // increase internal byte buffer by 4K  if it is exhausted
        if (m_byteBuffer.hasRemaining()) {
            m_byteBuffer.put((byte)b);
        } else if (m_byteBuffer.capacity() < 1000 * 4096) {
            increaseByteBufferSize(m_byteBuffer.capacity() + 4096);

            m_byteBuffer.put((byte)b);
        }
    }

    private void increaseByteBufferSize(final int newSize) {
        // limit the maximum buffer size at 4MiB, dropping bytes if necessary
        final ByteBuffer newBuffer = ByteBuffer.allocate(newSize);
        m_byteBuffer.flip();
        newBuffer.put(m_byteBuffer);
        m_byteBuffer = newBuffer;
    }

    @Override
    public void write(final byte bytes[], final int offset, final int len) throws IOException {
        if (bytes == null) {
            throw new NullPointerException();
        } else if ((offset < 0) || (offset > bytes.length) || (len < 0) ||
                   ((offset + len) > bytes.length) || ((offset + len) < 0)) {
            throw new IndexOutOfBoundsException();
        } else if (len == 0) {
            return;
        }

        if (len > m_byteBuffer.remaining()) {
            // limit the maximum buffer size at 4MiB, dropping bytes if necessary
            increaseByteBufferSize(Math.min(1000 * 4096, m_byteBuffer.capacity() + len));
        }

        m_byteBuffer.put(bytes, offset, Math.min(m_byteBuffer.remaining(), len));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void flush() {

        final String newContent = new String(m_byteBuffer.array(), 0, m_byteBuffer.position());
        m_byteBuffer.clear();
        m_buf.append(newContent);

        int bufferPos = 0;
        while (bufferPos < m_buf.length()) {
            final int nextNewLinePos = m_buf.indexOf(SEPARATOR, bufferPos);
            if (nextNewLinePos == -1) {
                break;
            }
            final String logMessage = m_buf.substring(bufferPos, nextNewLinePos);
            bufferPos += (nextNewLinePos - bufferPos) + SEPARATOR.length();
            logMessage(logMessage);
        }

        m_buf.delete(0, bufferPos);
    }

    /**
     * Hands the given message of to the registered log forwarders.
     */
    private void logMessage(final String msg) {
        final int forwarderCount = m_forwarders.size();
        for (int i = 0; i < forwarderCount; i++) {
            m_forwarders.get(i).forwardMessage(msg);
        }
    }
}