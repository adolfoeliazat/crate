package io.crate.ssl;

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

public class SSLServiceTest extends CrateUnitTest {

    @Test
    public void testTrustStoreLoading() {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SSLConfigSettings.SSL_TRUSTSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("truststore.jks"));
        settingsBuilder.put(SSLConfigSettings.SSL_TRUSTSTORE_PASSWORD_SETTING_NAME, "changeit");

        try {
            SSLService.TrustStoreSettings trustStoreSettings = SSLService.loadTrustStore(settingsBuilder.build());
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
        settingsBuilder.put(SSLConfigSettings.SSL_TRUSTSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("truststore.jks"));
        settingsBuilder.put(SSLConfigSettings.SSL_TRUSTSTORE_PASSWORD_SETTING_NAME, "wrongpassword");
        SSLService.loadTrustStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoading() {
        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore.jks"));
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "changeit");

        try {
            SSLService.KeyStoreSettings keyStoreSettings = SSLService.loadKeyStore(settingsBuilder.build());
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
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore.jks"));
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "wrongpassword");
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "changeit");

        SSLService.loadKeyStore(settingsBuilder.build());
    }

    @Test
    public void testKeyStoreLoadingFailWrongKeyPassword() throws Exception {
        expectedException.expect(UnrecoverableKeyException.class);
        expectedException.expectMessage("Cannot recover key");

        Settings.Builder settingsBuilder = Settings.builder();
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_FILEPATH_SETTING_NAME,
                            getAbsoluteFilePathFromClassPath("keystore.jks"));
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_PASSWORD_SETTING_NAME, "changeit");
        settingsBuilder.put(SSLConfigSettings.SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, "wrongpassword");

        SSLService.loadKeyStore(settingsBuilder.build());
    }

    private File getAbsoluteFilePathFromClassPath(final String fileNameFromClasspath) {
        File file;
        final URL fileUrl = SSLServiceTest.class.getClassLoader().getResource(fileNameFromClasspath);
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
