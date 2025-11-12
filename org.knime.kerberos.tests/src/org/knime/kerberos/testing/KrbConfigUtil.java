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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Utility class to help generate krb5.conf files for testing purposes.
 *
 * @author Bjoern Lohrmann, KNIME GmbH
 */
public class KrbConfigUtil {

    /**
     * Creates a valid krb5.conf for the given realm and kdc.
     *
     * @param realm
     * @param kdc
     * @return the path to the file.
     * @throws IOException
     */
    public static String createValidKrb5(final String realm, final String kdc) throws IOException {
        return createValidKrb5(realm, kdc, false);
    }

    /**
     * Creates a valid krb5.conf for the given realm and kdc, with the possibility of using weak crypto schemes
     * (allow_weak_crypto = true).
     *
     * @param realm
     * @param kdc
     * @param allowWeakCrypto
     * @return the path to the file.
     * @throws IOException
     */
    public static String createValidKrb5(final String realm, final String kdc, final boolean allowWeakCrypto)
        throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tkdc_realm = %s %n", realm));
        sb.append(String.format("\tdefault_realm = %s %n", realm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        if (allowWeakCrypto) {
            sb.append(String.format("\tallow_weak_crypto = true%n"));
            sb.append(String.format("\tpermitted_enctypes = arcfour-hmac-md5%n"));
        }
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\tkdc = %s %n\t }", realm, kdc));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();
    }

    /**
     * Creates a syntactically invalid krb5.conf.
     *
     * @param realm
     * @param kdc
     * @return the path to the file.
     * @throws IOException
     */
    public static String createInvalidKrb5(final String realm, final String kdc) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdefault_realm = %s %n", realm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = %n \t\tkdc = %s %n\t }", realm, kdc)); // missing { here -> invalid

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();

    }

    /**
     * Creates a krb5.conf with an invalid kdc address.
     *
     * @param realm
     * @return the path to the file.
     * @throws IOException
     */
    public static String createInvalidKDCKrb5(final String realm) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdefault_realm = %s %n", realm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\t%s %n\t }", realm, "-"));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();

    }

    /**
     * Creates a broken krb5.conf, wher ethe default realm has no realm definition.
     *
     * @param defaultRealm
     * @param kdc
     * @return the path to the file.
     * @throws IOException
     */
    public static String createNoKDCforRealmKrb5(final String defaultRealm, final String kdc) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("[libdefaults]%n"));
        sb.append(String.format("\tdefault_realm = %s %n", defaultRealm));
        sb.append(String.format("\tudp_preference_limit = 1%n"));
        sb.append(String.format("\tdns_lookup_kdc = false%n"));
        sb.append(String.format("[realms]%n"));
        sb.append(String.format("\t%s = { %n \t\tkdc = %s %n\t }", "OTHER", kdc));

        Path configFile = Files.createTempFile("krb", ".conf");
        Files.write(configFile, sb.toString().getBytes(), StandardOpenOption.WRITE);
        configFile.toFile().deleteOnExit();
        return configFile.toString();
    }
}
