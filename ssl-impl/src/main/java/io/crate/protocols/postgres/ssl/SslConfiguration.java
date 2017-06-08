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

import com.google.common.annotations.VisibleForTesting;
import io.netty.handler.ssl.*;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.settings.Settings;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Builds a Netty {@link SSLContext} which is passed upon creation of a {@link SslHandler}
 * which is responsible for establishing the SSL connection in a Netty pipeline.
 *
 * http://docs.oracle.com/javase/6/docs/technotes/guides/security/jsse/JSSERefGuide.html
 *
 * TrustManager:
 * Determines whether the remote authentication credentials (and thus the connection) should be trusted.
 * This is where your CA certificates usually go which determine whether to trust the remote.
 *
 * KeyManager:
 * Determines which authentication credentials to send to the remote host.
 * This is where your keys for the authenticating with the remote go.
 *
 * See also {@link SslReqConfiguringHandler}
 */
final class SslConfiguration {

    static SslContext buildSslContext(Settings settings) {
        try {
            TrustStoreSettings trustStoreSettings = loadTrustStore(settings);
            KeyStoreSettings keyStoreSettings = loadKeyStore(settings);
            String keyStorePassword = keyStoreSettings.keyStorePassword;
            String keyStoreKeyPassword = keyStoreSettings.keyStoreKeyPassword;

            // initialize a trust manager factory with the trusted store
            KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyFactory.init(
                keyStoreSettings.keyStore,
                keyStoreKeyPassword == null || keyStoreKeyPassword.isEmpty() ?
                null :
                keyStoreKeyPassword.toCharArray());

            // get the trust managers from the factory
            KeyManager[] keyManagers = keyFactory.getKeyManagers();

            // initialize an ssl context to use these managers and set as default
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(keyManagers, trustStoreSettings.trustManagers, null);
            SSLContext.setDefault(sslContext);
            List<String> supportedCiphers = Arrays.asList(sslContext.createSSLEngine().getSupportedCipherSuites());

            final X509Certificate[] keystoreCert =
                SslCertificateHelper.exportServerCertChain(keyStoreSettings.keyStore);
            final PrivateKey keystoreKey = SslCertificateHelper.exportDecryptedKey(
                keyStoreSettings.keyStore,
                (keyStorePassword == null || keyStorePassword.isEmpty()) ? null : keyStoreKeyPassword.toCharArray());

            if (keystoreKey == null) {
                throw new Exception("No key found in " + keyStoreSettings.keyStorePath);
            }

            X509Certificate[] trustedCertificates =
                SslCertificateHelper.exportRootCertificates(trustStoreSettings.trustStore);
            return buildSSLServerContext(keystoreKey,
                                         keystoreCert,
                                         trustedCertificates,
                                         supportedCiphers,
                                         SslProvider.JDK);
        } catch (SslConfigurationException e) {
            throw e;
        } catch (Exception e) {
            throw new SslConfigurationException("Failed to build SSL configuration", e);
        }
    }

    private static void checkStorePath(String keystoreFilePath, StoreType storeType) throws SslConfigurationException {

        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new SslConfigurationException("Empty file path for " + storeType + "store.");
        }

        Path path = Paths.get(keystoreFilePath);
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new SslConfigurationException("[" + keystoreFilePath + "] is a directory, expected file for " +
                                                storeType + "store.");
        }

        if (!Files.isReadable(path)) {
            throw new SslConfigurationException("Unable to read [" + keystoreFilePath + "] for " + storeType +
                                "store. Please make sure this file exists and has read permissions.");
        }
    }

    private static SslContext buildSSLServerContext(final PrivateKey privateKey,
                                                    final X509Certificate[] cert,
                                                    final X509Certificate[] trustedCerts,
                                                    final Iterable<String> ciphers,
                                                    final SslProvider sslProvider) throws SSLException {
        final SslContextBuilder sslContextBuilder =
            SslContextBuilder
                .forServer(privateKey, cert)
                .ciphers(ciphers)
                .applicationProtocolConfig(ApplicationProtocolConfig.DISABLED)
                .clientAuth(ClientAuth.OPTIONAL)
                .sessionCacheSize(0)
                .sessionTimeout(0)
                .sslProvider(sslProvider);

        if(trustedCerts != null && trustedCerts.length > 0) {
            sslContextBuilder.trustManager(trustedCerts);
        }

        return buildSSLContext(sslContextBuilder);
    }

    private static SslContext buildSSLContext(final SslContextBuilder sslContextBuilder) throws SSLException {

        SslContext sslContext;
        try {
            sslContext = AccessController.doPrivileged(
                (PrivilegedExceptionAction<SslContext>) sslContextBuilder::build);
        } catch (final PrivilegedActionException e) {
            throw (SSLException) e.getCause();
        }

        return sslContext;
    }

    @VisibleForTesting
    static TrustStoreSettings loadTrustStore(Settings settings) throws KeyStoreException,
                                                                       IOException,
                                                                       NoSuchAlgorithmException,
                                                                       CertificateException {
        String trustStorePath = SslConfigSettings.SSL_TRUSTSTORE_FILEPATH.setting().get(settings);
        checkStorePath(trustStorePath, StoreType.TRUST);
        String trustStorePassword = SslConfigSettings.SSL_TRUSTSTORE_PASSWORD.setting().get(settings);

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        trustStore.load(new FileInputStream(new File(trustStorePath)),
                        trustStorePassword.isEmpty() ? null : trustStorePassword.toCharArray());

        TrustManagerFactory trustFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);

        TrustManager[] trustManagers = trustFactory.getTrustManagers();

        return new TrustStoreSettings(trustStore, trustManagers);
    }

    @VisibleForTesting
    static class TrustStoreSettings {

        final KeyStore trustStore;
        final TrustManager[] trustManagers;

        TrustStoreSettings(KeyStore trustStore, TrustManager[] trustManagers) {
            this.trustStore = trustStore;
            this.trustManagers = trustManagers;
        }
    }

    @VisibleForTesting
    static KeyStoreSettings loadKeyStore(Settings settings) throws KeyStoreException,
                                                                   IOException,
                                                                   NoSuchAlgorithmException,
                                                                   CertificateException,
                                                                   UnrecoverableKeyException {
        String keyStorePath = SslConfigSettings.SSL_KEYSTORE_FILEPATH.setting().get(settings);
        checkStorePath(keyStorePath, StoreType.KEY);
        String keyStorePassword = SslConfigSettings.SSL_KEYSTORE_PASSWORD.setting().get(settings);
        String keyStoreKeyPassword = SslConfigSettings.SSL_KEYSTORE_KEY_PASSWORD.setting().get(settings);
        if (keyStoreKeyPassword.isEmpty()) {
            keyStoreKeyPassword = keyStorePassword;
        }

        // load the store
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(new File(keyStorePath)),
                      keyStorePassword.isEmpty() ? null : keyStorePassword.toCharArray());

        // initialize a key manager factory with the key store
        KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyFactory.init(
            keyStore,
            keyStoreKeyPassword.isEmpty() ? null : keyStoreKeyPassword.toCharArray());

        // get the key managers from the factory
        KeyManager[] keyManagers = keyFactory.getKeyManagers();

        return new KeyStoreSettings(keyStore, keyManagers, keyStorePath, keyStorePassword, keyStoreKeyPassword);
    }

    @VisibleForTesting
    static class KeyStoreSettings {

        final KeyStore keyStore;
        final KeyManager[] keyManagers;
        final String keyStorePassword;
        final String keyStoreKeyPassword;
        final String keyStorePath;

        KeyStoreSettings(KeyStore keyStore,
                         KeyManager[] keyManagers,
                         String keyStorePassword,
                         String keyStoreKeyPassword,
                         String keyStorePath) {
            this.keyStore = keyStore;
            this.keyManagers = keyManagers;
            this.keyStorePassword = keyStorePassword;
            this.keyStoreKeyPassword = keyStoreKeyPassword;
            this.keyStorePath = keyStorePath;
        }
    }

    private enum StoreType {
        TRUST,
        KEY;

        @Override
        public String toString() {
            return this.name().toLowerCase();
        }
    }
}
