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

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import org.elasticsearch.common.settings.Settings;

import javax.net.ssl.SSLException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * Handler which configures SSL when it receives an SSLRequest.
 */
public class SslConfiguringHandler implements SslReqHandler {

    private final Settings settings;

    public SslConfiguringHandler(Settings settings) {
        this.settings = settings;
        LOGGER.debug("SSL support is enabled.");
    }

    @Override
    public State process(ChannelPipeline pipeline, ByteBuf buffer) {
        if (buffer.readableBytes() < NUM_BYTES_REQUIRED) {
            return State.WAITING_FOR_INPUT;
        }
        // mark the buffer so we can jump back if we don't handle this startup
        buffer.markReaderIndex();
        // reads the total message length (int) and the SSL request code (int)
        if (buffer.readInt() == 8 && buffer.readInt() == SSL_REQUEST_CODE) {
            LOGGER.trace("Received SSL negotiation pkg");
            buffer.markReaderIndex();
            SslReqHandlerUtils.writeByteAndFlushMessage(pipeline.channel(), 'S');
            try {
                // add the ssl handler which must come first
                pipeline.addFirst(buildSSLHandler(pipeline));
            } catch (NoSuchAlgorithmException | SSLException | CertificateException e) {
                throw new RuntimeException("Couldn't setup SSL.", e);
            }
        } else {
            buffer.resetReaderIndex();
        }
        return State.DONE;
    }

    /**
     * Constructs the Netty SslHandler which should be added as the first element of the pipeline.
     */
    private io.netty.handler.ssl.SslHandler buildSSLHandler(ChannelPipeline pipeline)
        throws NoSuchAlgorithmException, SSLException, CertificateException {
        SelfSignedCertificate ssc = new SelfSignedCertificate();
        SslContext sslContext =
            SslContextBuilder
                // TODO Replace this with correct certificate and private key
                .forServer(ssc.certificate(), ssc.privateKey())
                // TODO Replace this with TrustManager which verifies keys
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .startTls(false)
                .build();
        return sslContext.newHandler(pipeline.channel().alloc());
    }

}
