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

package io.crate.protocols.postgres.ssl;

import io.crate.test.integration.CrateUnitTest;
import org.elasticsearch.common.settings.Settings;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.UnrecoverableKeyException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class SslConfigurationTest extends CrateUnitTest {

    private static File trustStoreFile;
    private static File keyStoreFile;
    private static File keyStoreFileNoKeyPassword;

    @BeforeClass
    public static void beforeTests() throws IOException {
        trustStoreFile = getAbsoluteFilePathFromClassPath("truststore.jks");
        keyStoreFile = getAbsoluteFilePathFromClassPath("keystore.jks");
        keyStoreFileNoKeyPassword = getAbsoluteFilePathFromClassPath("keystore_no_keypasswd.jks");
    }

    @Test
    public void testTrustStoreLoading() throws IOException {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_FILEPATH_SETTING_NAME, trustStoreFile);
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_PASSWORD_SETTING_NAME, "changeit");

        try {
            SslConfiguration.TrustStoreSettings trustStoreSettings = SslConfiguration.loadTrustStore(settingsBuilder.build());
            assertThat(trustStoreSettings.trustManagers.length, is(1));
            assertThat(trustStoreSettings.trustStore.getType(), is("jks"));
        } catch (Exception e) {
            fail("Failed to load trustore");
        }
    }

    @Test
    public void testTrustStoreLoadingFail() throws Exception {
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Keystore was tampered with, or password was incorrect");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_FILEPATH_SETTING_NAME, trustStoreFile);
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_PASSWORD_SETTING_NAME, "wrongpassword");
        SslConfiguration.loadTrustStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoading() throws IOException {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME, keyStoreFile);
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "changeit");

        try {
            SslConfiguration.KeyStoreSettings keyStoreSettings = SslConfiguration.loadKeyStore(settingsBuilder.build());
            assertThat(keyStoreSettings.keyManagers.length, is(1));
            assertThat(keyStoreSettings.keyStore.getType(), is("jks"));
            assertThat(keyStoreSettings.keyStore.getCertificate("root"), notNullValue());
        } catch (Exception e) {
            fail("Failed to load trustore");
        }
    }

    @Test
    public void testKeyStoreLoadingFailWrongPassword() throws Exception {
        expectedException.expect(IOException.class);
        expectedException.expectMessage("Keystore was tampered with, or password was incorrect");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME, keyStoreFile);
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "wrongpassword");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "changeit");

        SslConfiguration.loadKeyStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoadingFailWrongKeyPassword() throws Exception {
        expectedException.expect(UnrecoverableKeyException.class);
        expectedException.expectMessage("Cannot recover key");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME, keyStoreFile);
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "wrongpassword");

        SslConfiguration.KeyStoreSettings ks = SslConfiguration.loadKeyStore(settingsBuilder.build());
        SslCertificateHelper.exportDecryptedKey(ks.keyStore, ks.keyStoreKeyPassword.toCharArray());
    }

    @Test
    public void testKeyStoreLoadingNoKeyPassword() throws IOException {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME, keyStoreFileNoKeyPassword);
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");

        try {
            SslConfiguration.KeyStoreSettings keyStoreSettings = SslConfiguration.loadKeyStore(settingsBuilder.build());
            assertThat(keyStoreSettings.keyManagers.length, is(1));
            assertThat(keyStoreSettings.keyStore.getType(), is("jks"));
            assertThat(keyStoreSettings.keyStore.getCertificate("root"), notNullValue());
        } catch (Exception e) {
            fail();
        }
    }

    @Test
    public void testKeyStoreLoadingNoKeyPasswordFail() throws Exception {
        expectedException.expect(UnrecoverableKeyException.class);
        expectedException.expectMessage("Cannot recover key");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME, keyStoreFileNoKeyPassword);
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "wrongpassword");

        SslConfiguration.KeyStoreSettings ks = SslConfiguration.loadKeyStore(settingsBuilder.build());
        SslCertificateHelper.exportDecryptedKey(ks.keyStore, ks.keyStoreKeyPassword.toCharArray());
    }

    public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) throws IOException {
        final URL fileUrl = SslConfigurationTest.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl == null) {
            throw new FileNotFoundException("Resource was not found: " + fileNameFromClasspath);
        }
        return new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
    }
}
