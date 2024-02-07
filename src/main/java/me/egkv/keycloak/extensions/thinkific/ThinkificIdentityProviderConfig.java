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

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:wadahiro@gmail.com">Hiroyuki Wada</a>
 */
public class ThinkificIdentityProviderConfig extends OIDCIdentityProviderConfig {

    public ThinkificIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    public ThinkificIdentityProviderConfig() {
    }

    public String getThinkificDomain() {
        return getConfig().get("thinkificDomain");
    }

    public void setThinkificDomain(String thinkificDomain) {
        getConfig().put("thinkificDomain", thinkificDomain);
    }


    public void setPrompt(String prompt) {
        getConfig().put("prompt", prompt);
    }
}