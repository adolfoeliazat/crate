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
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.UnrecoverableKeyException;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

public class SslConfigurationTest extends CrateUnitTest {

    @Test
    public void testTrustStoreLoading() {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("truststore.jks"));
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
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("truststore.jks"));
        settingsBuilder.put(SslConfigSettings.SSL_TRUSTSTORE_PASSWORD_SETTING_NAME, "wrongpassword");
        SslConfiguration.loadTrustStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoading() {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore.jks"));
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
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore.jks"));
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "wrongpassword");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "changeit");

        SslConfiguration.loadKeyStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoadingFailWrongKeyPassword() throws Exception {
        expectedException.expect(UnrecoverableKeyException.class);
        expectedException.expectMessage("Cannot recover key");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore.jks"));
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "wrongpassword");

        SslConfiguration.loadKeyStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoadingNoKeyPassword() {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore_no_keypasswd.jks"));
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");

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
    public void testKeyStoreLoadingNoKeyPasswordFail() throws Exception {
        expectedException.expect(UnrecoverableKeyException.class);
        expectedException.expectMessage("Cannot recover key");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore_no_keypasswd.jks"));
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "wrongpassword");

        SslConfiguration.loadKeyStore(settingsBuilder.build());
    }

    public static File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file;
        final URL fileUrl = SslConfigurationTest.class.getClassLoader().getResource(fileNameFromClasspath);
        if (fileUrl != null) {
            try {
                file = new File(URLDecoder.decode(fileUrl.getFile(), "UTF-8"));
            } catch (final UnsupportedEncodingException e) {
                return null;
            }

            if (file.exists() && file.canRead()) {
                return file;
            }
        }
        return null;
    }
}
