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
 *   Dec 16, 2021 (bjoern): created
 */
package org.knime.kerberos.testing;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Enumeration;
import java.util.function.Supplier;

/**
 * This class loader makes sure that Mockito is correctly configured (by providing this file
 * mockito-extensions/org.mockito.plugins.MockMaker) to support mocking of final classes (e.g. the WorkflowManager).
 *
 * <p>
 * This class has been copied and adapted from knime-gateway
 * </p>
 * .
 *
 * @author Moritz Heine, KNIME GmbH, Konstanz, Germany
 */
public class ClassLoaderFinalClassMock extends ClassLoader {

    private static final String MOCK_MAKER_RESOURCE = "mockito-extensions/org.mockito.plugins.MockMaker";

    private final ClassLoader m_mockitoClassLoader;

    private final ClassLoader m_knimeClassLoader;

    /**
     * Constructor.
     *
     * @param mockitoClassLoader
     */
    public ClassLoaderFinalClassMock(final ClassLoader mockitoClassLoader) {
        m_mockitoClassLoader = mockitoClassLoader;
        m_knimeClassLoader = getClass().getClassLoader();
    }

    @Override
    public void clearAssertionStatus() {
        m_mockitoClassLoader.clearAssertionStatus();
    }

    @Override
    public URL getResource(final String name) {
        if (MOCK_MAKER_RESOURCE.equals(name)) {
            return m_knimeClassLoader.getResource(name);
        }

        return m_mockitoClassLoader.getResource(name);
    }

    @Override
    public InputStream getResourceAsStream(final String name) {
        if (MOCK_MAKER_RESOURCE.equals(name)) {
            return m_knimeClassLoader.getResourceAsStream(name);
        }

        return m_mockitoClassLoader.getResourceAsStream(name);
    }

    @Override
    public Enumeration<URL> getResources(final String name) throws IOException {
        if (MOCK_MAKER_RESOURCE.equals(name)) {
            return m_knimeClassLoader.getResources(name);
        }

        return m_mockitoClassLoader.getResources(name);
    }

    @Override
    public Class<?> loadClass(final String name) throws ClassNotFoundException {
        return org.mockito.Mockito.class.getClassLoader().loadClass(name);
    }

    @Override
    public void setClassAssertionStatus(final String className, final boolean enabled) {
        m_mockitoClassLoader.setClassAssertionStatus(className, enabled);
    }

    @Override
    public void setDefaultAssertionStatus(final boolean enabled) {
        m_mockitoClassLoader.setDefaultAssertionStatus(enabled);
    }

    @Override
    public void setPackageAssertionStatus(final String packageName, final boolean enabled) {
        m_mockitoClassLoader.setPackageAssertionStatus(packageName, enabled);
    }

    @Override
    public String toString() {
        return m_mockitoClassLoader.toString();
    }

    /**
     * Runs the given supplier with class loader manipulation so that Mockito can mock final classes.
     *
     * @param <R> The return type.
     * @param supplier The {@link Supplier} to execute.
     * @return the value returned by the given supplier.
     */
    public static <R> R doWithFinalClassMockingSupport(final Supplier<R> supplier) {
        final ClassLoader contextLoader = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(new ClassLoaderFinalClassMock(contextLoader));

        try {
            return supplier.get();
        } finally {
            Thread.currentThread().setContextClassLoader(contextLoader);
        }
    }
}
