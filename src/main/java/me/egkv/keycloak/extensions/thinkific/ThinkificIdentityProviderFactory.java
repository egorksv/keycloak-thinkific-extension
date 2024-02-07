/*
 * Copyright 2018 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package me.egkv.keycloak.extensions.thinkific;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.List;

/**
 */
public class ThinkificIdentityProviderFactory extends AbstractIdentityProviderFactory<ThinkificIdentityProvider>
        implements SocialIdentityProviderFactory<ThinkificIdentityProvider> {

    public static final String PROVIDER_ID = "thinkific";

    @Override
    public String getName() {
        return "Thinkific";
    }

    @Override
    public ThinkificIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new ThinkificIdentityProvider(session, new ThinkificIdentityProviderConfig(model));
    }

    @Override
    public ThinkificIdentityProviderConfig createConfig() {
        return new ThinkificIdentityProviderConfig();
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name("thinkificDomain")
                .type(ProviderConfigProperty.STRING_TYPE)
                .label("Thinkific Domain")
                .helpText("Your thinkific site ID, in for of {your-site-id}.thinkific.com")
                .add()
                .build();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}