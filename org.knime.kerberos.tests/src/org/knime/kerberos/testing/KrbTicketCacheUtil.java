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
 *   Sep 13, 2022 (bjoern): created
 */
package org.knime.kerberos.testing;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.stream.Stream;

/**
 * Utility class to manage the Kerberos ticket cache file for testing purposes.
 *
 * @author Bjoern Lohrmann, KNIME GbmbH
 */
public class KrbTicketCacheUtil {

    /**
     * Try to guess the default credentials cache file name.
     *
     * @return the guessed file path
     * @throws IOException
     */
    public static String getDefaultFileCredentialsCacheName() throws IOException {
        final String stdCacheNameComponent = "krb5cc";

        // 1. KRB5CCNAME (bare file name without FILE:)
        final String cacheEnv = System.getenv("KRB5CCNAME");
        if (cacheEnv != null && !cacheEnv.isEmpty()) {
            if (cacheEnv.toLowerCase().startsWith("file:")) {
                return cacheEnv.substring(5);
            } else {
                return cacheEnv;
            }
        }

        // 2. /tmp/krb5cc_<uid> on unix systems
        if (!System.getProperty("os.name").startsWith("Windows")) {
            final long uid = getUnixUid();
            return File.separator + "tmp" + File.separator + stdCacheNameComponent + "_" + uid;
        }

        final String userName = System.getProperty("user.name");
        String userHome = System.getProperty("user.home");
        if (userHome == null) {
            userHome = System.getProperty("user.dir");
        }

        // 3. <user.home>/krb5cc_<user.name>
        if (userName != null) {
            return userHome + File.separator + stdCacheNameComponent + "_" + userName;

            // 4. <user.home>/krb5cc
        } else {
            return userHome + File.separator + stdCacheNameComponent;
        }
    }

    /**
     * Create a ticket cache file using kinit.
     *
     * @param kdc
     * @throws IOException
     * @throws InterruptedException
     * @return The path to the ticket cache file.
     */
    public static Path createTicketCacheWithKinit(final TestKDC kdc) throws IOException, InterruptedException {
        String kinit = "kinit";
        if (System.getProperty("os.name").startsWith("Windows")) {
            // Windows will try to use the java kinit if we do not point it to MIT specifically
            String mitPath =
                Stream.of(System.getenv("PATH").split(";")).filter(s -> s.contains("MIT")).findFirst().get();
            kinit = mitPath + File.separator + "kinit";
        }

        final var ccFile = Paths.get(getDefaultFileCredentialsCacheName()).toAbsolutePath();

        ProcessBuilder pb = new ProcessBuilder(kinit, "-l", "2m", "-r", "4m", "-c", ccFile.toString(), "-k", "-t",
            kdc.getKeytabFilePath(), kdc.getKeytabPrincipal());
        pb.environment().put("KRB5CCNAME", ccFile.toString());
        if (System.getProperty("os.name").toUpperCase().contains("OS X")) { // Heimdal client
            pb.environment().put("KRB5_CONFIG", writeHeimdalTcpClientConfig(kdc));
        } else { // MIT client
            pb.environment().put("KRB5_CONFIG", kdc.getKrbClientConfig().toAbsolutePath().toString());
        }
        pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);
        Process proc = pb.start();
        proc.waitFor();
        if (proc.exitValue() != 0) {
            throw new RuntimeException("Could not obtain ticket via kinit");
        }

        return ccFile;
    }

    /**
     * Write a krb5.conf client configuration file using "tcp/" as KDC hostname prefix and all other values from the KDC
     * config.
     *
     * Note: The file has to be named "krb5.conf" otherwise Heimdal ignores it...
     *
     * @return path of client configuration
     * @throws IOException
     */
    private static String writeHeimdalTcpClientConfig(final TestKDC kdc) throws IOException {
        final Path tmpDir = Files.createTempDirectory("heimdal-client-config");
        final Path tmpConf = tmpDir.resolve("krb5.conf");
        final String oriConfig = Files.readString(kdc.getKrbClientConfig());
        final String newConfig = oriConfig.replaceAll("kdc = .*\n", "kdc = tcp/" + kdc.getKDCHost() + "\n");
        Files.writeString(tmpConf, newConfig);
        return tmpConf.toString();
    }

    /**
     * Delete ticket cache file if it exists.
     *
     * @throws IOException
     * @throws InterruptedException
     */
    public static void deleteTicketCache() throws IOException, InterruptedException {
        Files.deleteIfExists(Paths.get(getDefaultFileCredentialsCacheName()));
    }

    private static long getUnixUid() throws IOException {
        Process child = Runtime.getRuntime().exec("id -u");
        try (BufferedReader in = new BufferedReader(new InputStreamReader(child.getInputStream()))) {
            return Long.parseLong(in.readLine());
        }
    }
}
