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

package io.crate.ssl;

import com.google.common.annotations.VisibleForTesting;
import io.netty.handler.ssl.*;
import org.elasticsearch.SpecialPermission;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.inject.Singleton;
import org.elasticsearch.common.settings.Settings;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;


//TODO: remove @Singleton and @Inject and follow the pattern from UserServiceFactoryImpl
@Singleton
public class SSLService {

    private io.netty.handler.ssl.SslContext nettySslContext;

    @Inject
    public SSLService(Settings settings) throws Exception {
        TrustStoreSettings trustStoreSettings = loadTrustStore(settings);
        KeyStoreSettings keyStoreSettings = loadKeyStore(settings);
        String keyStorePassword = keyStoreSettings.keyStorePassword;
        String keyStoreKeyPassword = keyStoreSettings.keyStoreKeyPassword;

        // initialize a trust manager factory with the trusted store
        KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyFactory.init(
            keyStoreSettings.keyStore,
            keyStoreKeyPassword == null || keyStoreKeyPassword.isEmpty() ? null : keyStoreKeyPassword.toCharArray());

        // get the trust managers from the factory
        KeyManager[] keyManagers = keyFactory.getKeyManagers();


        // initialize an ssl context to use these managers and set as default
        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(keyManagers, trustStoreSettings.trustManagers, null);
        SSLContext.setDefault(sslContext);
        List<String> supportedCiphers = Arrays.asList(sslContext.createSSLEngine().getSupportedCipherSuites());


        final X509Certificate[] keystoreCert = SSLCertificateHelper.exportServerCertChain(keyStoreSettings.keyStore);
        final PrivateKey keystoreKey = SSLCertificateHelper.exportDecryptedKey(
            keyStoreSettings.keyStore,
            (keyStorePassword == null || keyStorePassword.isEmpty()) ? null : keyStoreKeyPassword.toCharArray());

        if (keystoreKey == null) {
            throw new Exception("No key found in " + keyStoreSettings.keyStorePath);
        }


        X509Certificate[] trustedCertificates = SSLCertificateHelper.exportRootCertificates(trustStoreSettings.trustStore);
        nettySslContext = buildSSLServerContext(keystoreKey,
                                                keystoreCert,
                                                trustedCertificates,
                                                supportedCiphers,
                                                SslProvider.JDK);
    }

    public SslContext getNettySslContext() {
        return nettySslContext;
    }

    private static void checkStorePath(String keystoreFilePath) throws Exception {

        if (keystoreFilePath == null || keystoreFilePath.length() == 0) {
            throw new Exception("Empty file path!");
        }

        Path path = Paths.get(keystoreFilePath);
        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new Exception("[" + keystoreFilePath + "] is a directory, expected file!");
        }

        if (!Files.isReadable(path)) {
            throw new Exception("Unable to read [" + keystoreFilePath + "] (" + Paths.get(keystoreFilePath) +
                                ") Please make sure this file exists and has read permissions");
        }
    }

    private SslContext buildSSLServerContext(final PrivateKey privateKey,
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

    private SslContext buildSSLContext(final SslContextBuilder sslContextBuilder) throws SSLException {

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

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
    static TrustStoreSettings loadTrustStore(Settings settings) throws Exception {
        String trustStorePath = SSLConfigSettings.SSL_TRUSTSTORE_FILEPATH.setting().get(settings);
        checkStorePath(trustStorePath);
        String trustStorePassword = SSLConfigSettings.SSL_TRUSTSTORE_PASSWORD.setting().get(settings);

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

        // load the store
        trustStore.load(new FileInputStream(new File(trustStorePath)),
                        trustStorePassword.isEmpty() ? null : trustStorePassword.toCharArray());

        // initialize a trust manager factory with the trusted store
        TrustManagerFactory trustFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustFactory.init(trustStore);

        // get the trust managers from the factory
        TrustManager[] trustManagers = trustFactory.getTrustManagers();

        return new TrustStoreSettings(trustStore, trustManagers);
    }

    @VisibleForTesting
    static class TrustStoreSettings {

        KeyStore trustStore;
        TrustManager[] trustManagers;

        TrustStoreSettings(KeyStore trustStore, TrustManager[] trustManagers) {
            this.trustStore = trustStore;
            this.trustManagers = trustManagers;
        }
    }

    @VisibleForTesting
    static KeyStoreSettings loadKeyStore(Settings settings) throws Exception {
        /* Keystore */
        String keyStorePath = SSLConfigSettings.SSL_KEYSTORE_FILEPATH.setting().get(settings);
        checkStorePath(keyStorePath);
        String keyStorePassword = SSLConfigSettings.SSL_KEYSTORE_PASSWORD.setting().get(settings);
        String keyStoreKeyPassword = SSLConfigSettings.SSL_KEYSTORE_KEY_PASSWORD.setting().get(settings);

        // load the store
        final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(new File(keyStorePath)),
                      keyStorePassword.isEmpty() ? null : keyStorePassword.toCharArray());

        // initialize a key manager factory with the key store
        KeyManagerFactory keyFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyFactory.init(
            keyStore,
            keyStoreKeyPassword == null || keyStoreKeyPassword.isEmpty() ? null : keyStoreKeyPassword.toCharArray());

        // get the key managers from the factory
        KeyManager[] keyManagers = keyFactory.getKeyManagers();

        return new KeyStoreSettings(keyStore, keyManagers, keyStorePath, keyStorePassword, keyStoreKeyPassword);
    }

    @VisibleForTesting
    static class KeyStoreSettings {

        KeyStore keyStore;
        KeyManager[] keyManagers;
        String keyStorePassword;
        String keyStoreKeyPassword;
        String keyStorePath;

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
}
