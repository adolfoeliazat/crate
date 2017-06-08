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

import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;

import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.*;

public class SslCertificateHelper {

    private static final Logger LOGGER = Loggers.getLogger(SslCertificateHelper.class);
    private static boolean stripRootFromChain = true; //TODO check

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
