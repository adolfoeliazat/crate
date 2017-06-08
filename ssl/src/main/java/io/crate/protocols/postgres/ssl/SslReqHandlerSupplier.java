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

import io.crate.settings.SharedSettings;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

/**
 * Loads the appropriate implementation of the SslReqHandler.
 */
public class SslReqHandlerSupplier {

    private static final Logger LOGGER = Loggers.getLogger(SslReqHandlerSupplier.class);
    private static final String SSL_IMPL_CLASS = "io.crate.protocols.postgres.ssl.SslReqConfiguringHandler";

    private SslReqHandlerSupplier() {}

    public static SslReqHandler load(Settings settings) {
        SslReqHandler handler = null;
        if (SharedSettings.ENTERPRISE_LICENSE_SETTING.setting().get(settings)) {
            ClassLoader classLoader = ClassLoader.getSystemClassLoader();
            try {
                handler = classLoader
                    .loadClass(SSL_IMPL_CLASS)
                    .asSubclass(SslReqHandler.class)
                    .getDeclaredConstructor(Settings.class)
                    .newInstance(settings);
            } catch (ClassNotFoundException e) {
                // We only ignore ClassNotFoundException when the ssl-impl module is not available.
                // All other errors should be bugs.
                LOGGER.info("SSL support disabled because ssl-impl enterprise module is not available.", e);
            } catch (Exception e) {
                throw new RuntimeException("Loading SslConfiguringHandler failed although enterprise is enabled.", e);
            }
        }
        if (handler == null) {
            handler = new SslReqRejectingHandler(settings);
        }
        return handler;
    }
}
