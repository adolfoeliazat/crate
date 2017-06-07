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

import io.crate.settings.CrateSetting;
import io.crate.types.DataTypes;
import org.elasticsearch.common.settings.Setting;

class SSLConfigSettings {

    static final String SSL_TRUSTSTORE_FILEPATH_SETTING_NAME = "cage.ssl.truststore_filepath";
    static final String SSL_TRUSTSTORE_PASSWORD_SETTING_NAME = "cage.ssl.truststore_password";
    static final String SSL_KEYSTORE_FILEPATH_SETTING_NAME = "cage.ssl.keystore_path";
    static final String SSL_KEYSTORE_PASSWORD_SETTING_NAME = "cage.ssl.keystore_password";
    static final String SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME = "cage.ssl.keystore_key_password";

    static final CrateSetting<String> SSL_TRUSTSTORE_FILEPATH = CrateSetting.of(
        Setting.simpleString(SSL_TRUSTSTORE_FILEPATH_SETTING_NAME, Setting.Property.NodeScope),
        DataTypes.STRING);
    static final CrateSetting<String> SSL_TRUSTSTORE_PASSWORD = CrateSetting.of(
        Setting.simpleString(SSL_TRUSTSTORE_PASSWORD_SETTING_NAME, Setting.Property.NodeScope),
        DataTypes.STRING);

    static final CrateSetting<String> SSL_KEYSTORE_FILEPATH = CrateSetting.of(
        Setting.simpleString(SSL_KEYSTORE_FILEPATH_SETTING_NAME, Setting.Property.NodeScope),
        DataTypes.STRING);
    static final CrateSetting<String> SSL_KEYSTORE_PASSWORD = CrateSetting.of(
        Setting.simpleString(SSL_KEYSTORE_PASSWORD_SETTING_NAME, Setting.Property.NodeScope),
        DataTypes.STRING);
    static final CrateSetting<String> SSL_KEYSTORE_KEY_PASSWORD = CrateSetting.of(
        Setting.simpleString(SSL_KEYSTORE_KEY_PASSWORD_SETTING_NAME, Setting.Property.NodeScope),
        DataTypes.STRING);
}
