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

import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public class SslCertificateHelper {

    private static final Logger LOGGER = Loggers.getLogger(SslCertificateHelper.class);

    public static X509Certificate[] exportRootCertificates(final KeyStore ks) throws KeyStoreException {
        final Enumeration<String> aliases = ks.aliases();

        final List<X509Certificate> trustedCerts = new ArrayList<X509Certificate>();

        while (aliases.hasMoreElements()) {
            String _alias = aliases.nextElement();

            if (ks.isCertificateEntry(_alias)) {
                final X509Certificate cert = (X509Certificate) ks.getCertificate(_alias);
                if (cert != null) {
                    trustedCerts.add(cert);
                } else {
                    LOGGER.error("Alias {} does not exist", _alias);
                }
            }
        }
        return trustedCerts.toArray(new X509Certificate[0]);
    }

    public static X509Certificate[] exportServerCertChain(final KeyStore ks) throws KeyStoreException {
        final Enumeration<String> aliases = ks.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate[] certs = ks.getCertificateChain(alias);
            if (certs != null && certs.length > 0) {
                return Arrays.copyOf(certs, certs.length, X509Certificate[].class);
            }
        }

        return new X509Certificate[0];
    }

    public static PrivateKey exportDecryptedKey(KeyStore ks, char[] password)
            throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException
    {
        Enumeration<String> aliases = ks.aliases();
        if (!aliases.hasMoreElements()) {
            throw new KeyStoreException("No aliases found in keystore");
        }

        Key key = null;
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            key = ks.getKey(alias, password);
            if (key != null) {
                break;
            }
        }

        if (key == null) {
            throw new KeyStoreException("No key matching the password found in keystore");
        }

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }

        return null;
    }
}
