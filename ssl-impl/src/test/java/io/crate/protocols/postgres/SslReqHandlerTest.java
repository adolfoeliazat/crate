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

package io.crate.protocols.postgres;

import io.crate.action.sql.SQLOperations;
import io.crate.operation.auth.AuthenticationProvider;
import io.crate.protocols.postgres.ssl.SelfSignedSslReqHandler;
import io.crate.protocols.postgres.ssl.SslConfigurationException;
import io.crate.protocols.postgres.ssl.SslReqConfiguringHandler;
import io.crate.protocols.postgres.ssl.SslReqHandler;
import io.crate.protocols.postgres.ssl.SslReqHandlerLoader;
import io.crate.protocols.postgres.ssl.SslReqRejectingHandler;
import io.crate.settings.SharedSettings;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SslHandler;
import org.elasticsearch.common.settings.Settings;
import org.junit.After;
import org.junit.Test;

import static io.netty.util.ReferenceCountUtil.releaseLater;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;

public class SslReqHandlerTest {

    private EmbeddedChannel channel;

    @After
    public void dispose() {
        if (channel != null) {
            channel.close().awaitUninterruptibly();
            channel = null;
        }
    }

    @Test
    public void testSslReqConfiguringHandler() {
        ConnectionContext ctx =
            new ConnectionContext(
                new SelfSignedSslReqHandler(Settings.EMPTY),
                mock(SQLOperations.class),
                AuthenticationProvider.NOOP_AUTH);

        channel = new EmbeddedChannel(ctx.decoder, ctx.handler);

        sendSslRequest(channel);

        // We should get back an 'S'...
        ByteBuf responseBuffer = channel.readOutbound();
        byte response = responseBuffer.readByte();
        assertEquals(response, 'S');

        // ...and continue encrypted (ssl handler)
        assertTrue(channel.pipeline().first() instanceof SslHandler);
    }

    @Test
    public void testClassLoading() {
        Settings enterpriseDisabled = Settings.builder()
            .put(SharedSettings.ENTERPRISE_LICENSE_SETTING.setting().getKey(), false)
            .build();
        assertTrue(SslReqHandlerLoader.load(enterpriseDisabled) instanceof SslReqRejectingHandler);
    }

    @Test(expected = SslConfigurationException.class)
    public void testClassLoadingWithInvalidConfiguration() {
        // empty ssl configuration which is invalid
        Settings enterpriseEnabled = Settings.builder()
            .put(SharedSettings.ENTERPRISE_LICENSE_SETTING.getKey(), true)
            .build();
        SslReqHandlerLoader.load(enterpriseEnabled);
    }


    private static void sendSslRequest(EmbeddedChannel channel) {
        ByteBuf buffer = releaseLater(Unpooled.buffer());
        buffer.writeInt(SslReqHandler.SSL_REQUEST_BYTE_LENGTH);
        buffer.writeInt(SslReqHandler.SSL_REQUEST_CODE);
        channel.writeInbound(buffer);
    }
}
