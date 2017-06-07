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

import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public class SSLCertificateHelper {

    private static final Logger LOGGER = Loggers.getLogger(SSLCertificateHelper.class);
    private static boolean stripRootFromChain = true; //TODO check

    public static X509Certificate[] exportRootCertificates(final KeyStore ks) throws KeyStoreException {
        final List<String> aliases = toList(ks.aliases());

        final List<X509Certificate> trustedCerts = new ArrayList<X509Certificate>();

        if(LOGGER.isDebugEnabled()) {
            LOGGER.debug("No alias given, will trust all of the certificates in the store");
        }

        for (final String _alias : aliases) {

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

    private static List<String> toList(final Enumeration<String> enumeration) {
        final List<String> aliases = new ArrayList<>();

        while (enumeration.hasMoreElements()) {
            aliases.add(enumeration.nextElement());
        }

        return Collections.unmodifiableList(aliases);
    }

    public static X509Certificate[] exportServerCertChain(final KeyStore ks) throws KeyStoreException {
        final List<String> aliases = toList(ks.aliases());
        if (aliases.isEmpty()) {
            String msg = "Keystore does not contain any aliases";
            LOGGER.error(msg);
            throw new KeyStoreException(msg);
        }
        String alias = aliases.get(0);

        final Certificate[] certs = ks.getCertificateChain(alias);
        if (certs != null && certs.length > 0) {
            X509Certificate[] x509Certs = Arrays.copyOf(certs, certs.length, X509Certificate[].class);

            final X509Certificate lastCertificate = x509Certs[x509Certs.length - 1];

            if (lastCertificate.getBasicConstraints() > -1
                && lastCertificate.getSubjectX500Principal().equals(lastCertificate.getIssuerX500Principal())) {
                LOGGER.warn("Certificate chain for alias {} contains a root certificate", alias);

                if(stripRootFromChain ) {
                    x509Certs = Arrays.copyOf(certs, certs.length-1, X509Certificate[].class);
                }
            }

            return x509Certs;
        } else {
            LOGGER.error("Alias {} does not exists or does not contain a certificate chain", alias);
        }

        return new X509Certificate[0];
    }

    public static PrivateKey exportDecryptedKey(KeyStore ks, char[] password) throws KeyStoreException,
                                                                                     UnrecoverableKeyException,
                                                                                     NoSuchAlgorithmException {
        List<String> aliases = toList(ks.aliases());
        if (aliases.isEmpty()) {
            throw new KeyStoreException("No aliases found in keystore");
        }

        String alias = aliases.get(0);
        final Key key = ks.getKey(alias, (password == null || password.length == 0) ? null:password);

        if (key == null) {
            throw new KeyStoreException("No key alias " + alias + " found");
        }

        if (key instanceof PrivateKey) {
            return (PrivateKey) key;
        }

        return null;
    }
}
