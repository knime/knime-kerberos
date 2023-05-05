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
 *   Jan 31, 2019 (bjoern): created
 */
package org.knime.kerberos.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.util.HashMap;
import java.util.concurrent.ExecutionException;
import java.util.zip.ZipFile;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.knime.core.node.workflow.NodeContext;
import org.knime.core.node.workflow.WorkflowManager;
import org.knime.core.node.workflow.contextv2.ServerJobExecutorInfo;
import org.knime.core.node.workflow.contextv2.WorkflowContextV2;
import org.knime.core.node.workflow.contextv2.WorkflowContextV2.ExecutorType;
import org.knime.kerberos.KerberosInternalAPI;
import org.knime.kerberos.api.KerberosDelegationProvider.KerberosDelegationCallback;
import org.knime.kerberos.config.KerberosPluginConfig;
import org.knime.kerberos.config.PrefKey;
import org.knime.kerberos.config.PrefKey.AuthMethod;
import org.knime.kerberos.config.PrefKey.KerberosConfigSource;
import org.knime.kerberos.logger.KerberosLogger;

/**
 * Testcases for {@link KerberosDelegationProvider}.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KerberosDelegationProviderTest {

    /**
     * Name of an environment variable that specifies a .zip file which contains MIDDLE_SERVICE_KEYTAB and
     * KRB_DELEGATION_TEST_PROPERTIES.
     */
    private static final String CONFIG_ENV_VAR = "KNIME_KERBEROS_TEST_CONF";

    /**
     * Path of a keytab file inside the zip file specified by the CONFIG_ENV_VAR environment variable.
     */
    private static final String MIDDLE_SERVICE_KEYTAB = "krb-delegation-test-config/middle-service.keytab";

    /**
     * Path of a Java properties file inside the zip file specified by the CONFIG_ENV_VAR environment variable. The
     * properties file specifies the Kerberos real, kdc and service/principal names to use for testing.
     */
    private static final String KRB_DELEGATION_TEST_PROPERTIES =
        "krb-delegation-test-config/krb-delegation-test.properties";

    /**
     * Temp folder.
     */
    @TempDir
    Path m_tempFolder;

    private final KrbDelegationTestConfig m_config = new KrbDelegationTestConfig();

    /**
     * Setup for each individual test method.
     *
     * @throws URISyntaxException
     * @throws IOException
     */
    @BeforeEach
    public void setupBefore() throws URISyntaxException, IOException {
        KerberosPluginConfig.TEST_OVERRIDES = new HashMap<>();

        // deactivates the multiplexing of Kerberos log messages into a KNIME NodeLogger,
        // which requires a fully booted KNIME and OSGI container, which we do not want.
        KerberosLogger.setUseNodeLoggerForwarder(false);

        KerberosPluginConfig config = loadAndPrepareConfig();
        config.save();
    }

    private KerberosPluginConfig loadAndPrepareConfig() throws URISyntaxException, IOException {
        if (!System.getenv().containsKey(CONFIG_ENV_VAR)) {
            throw new IllegalArgumentException(String.format(
                "Environment variable %s needs to be set in order to configure Kerberos test environment.",
                CONFIG_ENV_VAR));
        }

        final var krb5ConfFile = m_tempFolder.resolve("krb5.conf");
        final var keytabFile = m_tempFolder.resolve("keytab");

        try (final var configZip = new ZipFile(new File(System.getenv(CONFIG_ENV_VAR)))) {
            try (var in = configZip.getInputStream(configZip.getEntry(KRB_DELEGATION_TEST_PROPERTIES))) {
                m_config.load(in);
            }

            final String krb5Contents;
            try (var in =
                KerberosDelegationProviderTest.class.getClassLoader().getResourceAsStream("/krb5.conf.template")) {
                krb5Contents = IOUtils.toString(in, "UTF8") //
                    .replace("%REALM%", m_config.getRealm()) //
                    .replace("%KDC%", m_config.getKDC());
            }
            Files.writeString(krb5ConfFile, krb5Contents);

            try (var in = configZip.getInputStream(configZip.getEntry(MIDDLE_SERVICE_KEYTAB))) {
                Files.copy(in, keytabFile);
            }
        }

        final var config = new KerberosPluginConfig(KerberosConfigSource.FILE, //
            krb5ConfFile.toAbsolutePath().toString(), //
            "", //
            "", AuthMethod.KEYTAB, //
            String.format("%s@%s", m_config.getMiddleService(), m_config.getRealm()), //
            keytabFile.toAbsolutePath().toString(), //
            true, //
            PrefKey.DEBUG_LOG_LEVEL_DEFAULT, //
            30000, //
            true, //
            false, //
            null);
        return config;
    }

    /**
     * Rolls back to initial state after each test
     *
     * @throws ExecutionException
     * @throws InterruptedException
     */
    @AfterEach
    public void rollBack() throws InterruptedException, ExecutionException {
        m_config.clear();

        if (NodeContext.getContext() != null) {
            NodeContext.removeLastContext();
        }

        try {
            KerberosInternalAPI.logout().get();
        } catch (ExecutionException e) {
            if (!(e.getCause() instanceof IllegalStateException)) {
                throw e;
            }
        }
    }

    /**
     * Tests
     * {@link KerberosDelegationProvider#doWithConstrainedDelegationBlocking(String, String, KerberosCallback, org.knime.core.node.ExecutionMonitor)}
     * without any workflow context, which means no delegation should take place.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithConstrainedDelegationBlocking_servicename_nodelegation() throws Exception {
        final var targetService = m_config.getTargetService().split("/");

        // here we are testing without a workflow context, which means no delegation takes place
        final var returnVal =
            KerberosDelegationProvider.doWithConstrainedDelegationBlocking(targetService[0], targetService[1], () -> {
                final var subject = Subject.getSubject(AccessController.getContext());
                final var principal = subject.getPrincipals(KerberosPrincipal.class).iterator().next();
                assertEquals(String.format("%s@%s", m_config.getMiddleService(), m_config.getRealm()),
                    principal.getName());
                return "test";
            }, null);
        assertEquals("test", returnVal);
    }

    /**
     * Tests
     * {@link KerberosDelegationProvider#doWithConstrainedDelegationBlocking(String, String, KerberosCallback, org.knime.core.node.ExecutionMonitor)}
     * with a Server workflow context, which means delegation should take place.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithConstrainedDelegationBlocking_servicename() throws Exception {
        final var targetService = m_config.getTargetService().split("/");

        NodeContext.pushContext(createServerWorkflowContext());

        // here we are testing without a workflow context, which means no delegation takes place
        final var returnVal =
            KerberosDelegationProvider.doWithConstrainedDelegationBlocking(targetService[0], targetService[1], () -> {
                final var userPrincipal = String.format("%s@%s", m_config.getUserToImpersonate(), m_config.getRealm());
                final var targetServicePrincipal =
                    String.format("%s@%s", m_config.getTargetService(), m_config.getRealm());

                final var subject = Subject.getSubject(AccessController.getContext());
                final var principal = subject.getPrincipals(KerberosPrincipal.class).iterator().next();
                assertEquals(userPrincipal, principal.getName());

                final var serviceTicket = subject.getPrivateCredentials(KerberosTicket.class).iterator().next();
                assertEquals(userPrincipal, serviceTicket.getClient().getName());
                assertEquals(targetServicePrincipal, serviceTicket.getServer().getName());

                return "test";

            }, null);
        assertEquals("test", returnVal);
    }

    private NodeContext createServerWorkflowContext() {
        // we need to be able to mock final classes here because NodeContext is final -> mockito-inline
        final var nodeContextMock = mock(NodeContext.class);

        final var wfmMock = mock(WorkflowManager.class);
        when(nodeContextMock.getWorkflowManager()).thenReturn(wfmMock);

        final var wfContext = mock(WorkflowContextV2.class);
        when(wfContext.getExecutorType()).thenReturn(ExecutorType.SERVER_EXECUTOR);
        when(wfmMock.getContextV2()).thenReturn(wfContext);

        final var executorInfo = mock(ServerJobExecutorInfo.class);
        when(executorInfo.getUserId()).thenReturn(m_config.getUserToImpersonate());
        when(wfContext.getExecutorInfo()).thenReturn(executorInfo);

        return nodeContextMock;
    }

    /**
     * Tests
     * {@link KerberosDelegationProvider#doWithConstrainedDelegationBlocking(KerberosDelegationCallback, org.knime.core.node.ExecutionMonitor)}
     * with a Server workflow context, which means delegation should take place.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithConstrainedDelegationBlocking_gsscredential() throws Exception {
        NodeContext.pushContext(createServerWorkflowContext());

        // here we are testing without a workflow context, which means no delegation takes place
        final var returnVal = KerberosDelegationProvider.doWithConstrainedDelegationBlocking(gssCred -> {
            final var userPrincipal = String.format("%s@%s", m_config.getUserToImpersonate(), m_config.getRealm());
            assertEquals(userPrincipal, gssCred.getName().toString());
            return "test";
        }, null);

        assertEquals("test", returnVal);
    }

    /**
     * Tests
     * {@link KerberosDelegationProvider#doWithConstrainedDelegationBlocking(String, String, KerberosCallback, org.knime.core.node.ExecutionMonitor)}
     * without any workflow context, which means no delegation should take place.
     *
     * @throws Exception
     */
    @Test
    public void test_doWithConstrainedDelegationBlocking_gsscredential_nodelegation() throws Exception {

        // here we are testing without a workflow context, which means no delegation takes place
        final var returnVal =
            KerberosDelegationProvider.doWithConstrainedDelegationBlocking(gssCred -> {
                final var middleServicePrincipal = String.format("%s@%s", m_config.getMiddleService(), m_config.getRealm());
                assertEquals(middleServicePrincipal, gssCred.getName().toString());
                return "test";
            }, null);
        assertEquals("test", returnVal);
    }

}
