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

import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import org.elasticsearch.common.settings.Settings;

import javax.net.ssl.SSLException;
import java.security.cert.CertificateException;

/**
 * SslRequestHandler which uses a simple (and insecure) self-signed certificate.
 */
public class SelfSignedSslReqHandler extends SslReqConfiguringHandler {

    public SelfSignedSslReqHandler(Settings settings) {
        super(settings);
    }

    @Override
    SslHandler buildSSLHandler(ChannelPipeline pipeline) throws SSLException, CertificateException {
        SelfSignedCertificate ssc = new SelfSignedCertificate();
        SslContext sslContext =
            SslContextBuilder
                .forServer(ssc.certificate(), ssc.privateKey())
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .startTls(false)
                .build();
        return sslContext.newHandler(pipeline.channel().alloc());
    }
}
