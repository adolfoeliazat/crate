/*
 * This file is part of a module with proprietary Enterprise Features.
 *
 * Licensed to Crate.io Inc. ("Crate.io") under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.
 *
 * Unauthorized copying of this file, via any medium is strictly prohibited.
 *
 * To use this file, Crate.io must have given you permission to enable and
 * use such Enterprise Features and you must have a valid Enterprise or
 * Subscription Agreement with Crate.io.  If you enable or use the Enterprise
 * Features, you represent and warrant that you have a valid Enterprise or
 * Subscription Agreement with Crate.io.  Your use of the Enterprise Features
 * if governed by the terms and conditions of your Enterprise or Subscription
 * Agreement with Crate.io.
 */

package io.crate.protocols.postgres;

import io.crate.integrationtests.SQLTransportIntegrationTest;
import io.crate.protocols.postgres.ssl.SslConfigSettings;
import io.crate.settings.SharedSettings;
import io.crate.testing.SQLResponse;
import io.crate.testing.UseJdbc;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.test.ESIntegTestCase;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

import static io.crate.protocols.postgres.ssl.SslConfigurationTest.getAbsoluteFilePathFromClassPath;


@UseJdbc(value = 1)
@ESIntegTestCase.ClusterScope(numDataNodes = 1)
public class SslReqHandlerIntegrationTest extends SQLTransportIntegrationTest {

    private static final String trustStorePathProperty = "javax.net.ssl.trustStore";
    private static final String trustStorePasswordProperty = "javax.net.ssl.trustStorePassword";
    private static final String keyStorePathProperty = "javax.net.ssl.keyStore";
    private static final String keyStorePasswordProperty = "javax.net.ssl.keyStorePassword";
    private static File trustStoreFile;
    private static File keyStoreFile;

    public SslReqHandlerIntegrationTest() {
        super(true);
    }

    @BeforeClass
    public static void beforeIntegrationTest() throws IOException {
        trustStoreFile = getAbsoluteFilePathFromClassPath("truststore.jks");
        keyStoreFile = getAbsoluteFilePathFromClassPath("keystore.jks");
        System.setProperty(trustStorePathProperty, trustStoreFile.getAbsolutePath());
        System.setProperty(trustStorePasswordProperty, "changeit");
        System.setProperty(keyStorePathProperty, keyStoreFile.getAbsolutePath());
        System.setProperty(keyStorePasswordProperty, "changeit");
    }

    @AfterClass
    public static void afterIntegrationTest() {
        System.setProperty(trustStorePathProperty, "");
        System.setProperty(trustStorePasswordProperty, "");
        System.setProperty(keyStorePathProperty, "");
        System.setProperty(keyStorePasswordProperty, "");
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings.builder()
            .put(super.nodeSettings(nodeOrdinal))
            .put(SharedSettings.ENTERPRISE_LICENSE_SETTING.getKey(), true)
            .put(SslConfigSettings.SSL_ENABLED.getKey(), true)
            .put(SslConfigSettings.SSL_TRUSTSTORE_FILEPATH.getKey(), trustStoreFile)
            .put(SslConfigSettings.SSL_TRUSTSTORE_PASSWORD.getKey(), "changeit")
            .put(SslConfigSettings.SSL_KEYSTORE_FILEPATH.getKey(), keyStoreFile)
            .put(SslConfigSettings.SSL_KEYSTORE_PASSWORD.getKey(), "changeit")
            .put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD.getKey(), "changeit")
            .build();
    }

    @Test
    public void testCheckEncryptedConnection() throws Throwable {
        SQLResponse response = execute("select name from sys.nodes");
        System.out.println(response);
        for (Object[] data : response.rows()) {
            System.out.println(data[0]);
        }
        assertEquals(1, response.rowCount());
    }

}
