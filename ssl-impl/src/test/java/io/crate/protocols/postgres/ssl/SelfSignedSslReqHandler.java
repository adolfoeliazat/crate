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
