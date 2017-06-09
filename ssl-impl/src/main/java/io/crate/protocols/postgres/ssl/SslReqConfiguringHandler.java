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
import io.netty.handler.ssl.SslHandler;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import java.util.function.Supplier;

/**
 * Handler which configures SSL when it receives an SSLRequest.
 */
public class SslReqConfiguringHandler implements SslReqHandler {

    private final Logger LOGGER;
    private final SslContext sslContext;

    public SslReqConfiguringHandler(Settings settings) {
        this(settings, new DefaultSslContextSupplier(settings));
    }

    public SslReqConfiguringHandler(Settings settings, Supplier<SslContext> sslContextSupplier) {
        this.LOGGER = Loggers.getLogger(SslReqRejectingHandler.class, settings);
        this.sslContext = sslContextSupplier.get();
        assert this.sslContext != null;
        LOGGER.info("SSL support is enabled.");
    }

    @Override
    public State process(ByteBuf buffer, ChannelPipeline pipeline) {
        if (buffer.readableBytes() < SSL_REQUEST_BYTE_LENGTH) {
            return State.WAITING_FOR_INPUT;
        }
        // mark the buffer so we can jump back if we don't handle this message
        buffer.markReaderIndex();
        // reads the total message length (int) and the SSL request code (int)
        if (buffer.readInt() == 8 && buffer.readInt() == SSL_REQUEST_CODE) {
            LOGGER.trace("Received SSL negotiation pkg");
            buffer.markReaderIndex();
            SslReqHandlerUtils.writeByteAndFlushMessage(pipeline.channel(), 'S');
            // add the ssl handler which must come first in the pipeline
            SslHandler sslHandler = sslContext.newHandler(pipeline.channel().alloc());
            pipeline.addFirst(sslHandler);
        } else {
            // ssl message not available, reset the reader offset
            buffer.resetReaderIndex();
        }
        return State.DONE;
    }

    /**
     * Supplies the SslContext which is the factory for creating Netty SslHandlers.
     */
    private static class DefaultSslContextSupplier implements Supplier<SslContext> {

        private final SslContext sslContext;

        private DefaultSslContextSupplier(Settings settings) {
            this.sslContext = SslConfiguration.buildSslContext(settings);
        }

        @Override
        public SslContext get() {
            return sslContext;
        }
    }
}
