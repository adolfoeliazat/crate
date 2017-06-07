/*
 * Licensed to Crate under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.  Crate licenses this file
 * to you under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.  You may
 * obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.  See the License for the specific language governing
 * permissions and limitations under the License.
 *
 * However, if you have executed another commercial license agreement
 * with Crate these terms will supersede the license and you may use the
 * software solely pursuant to the terms of the relevant commercial
 * agreement.
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

    private File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
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
