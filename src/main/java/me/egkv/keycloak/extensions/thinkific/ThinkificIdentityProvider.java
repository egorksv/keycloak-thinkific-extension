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

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.events.EventBuilder;
import org.keycloak.jose.JOSE;
import org.keycloak.jose.JOSEParser;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jwe.JWEException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.keycloak.broker.oidc.OIDCIdentityProvider.ACCESS_TOKEN_EXPIRATION;
import static org.keycloak.broker.oidc.OIDCIdentityProvider.FEDERATED_ACCESS_TOKEN_RESPONSE;
import static org.keycloak.broker.oidc.OIDCIdentityProvider.VALIDATED_ACCESS_TOKEN;
import static org.keycloak.broker.oidc.OIDCIdentityProvider.VALIDATED_ID_TOKEN;
import static org.keycloak.utils.MediaType.APPLICATION_JWT_TYPE;

/**
 * @author <a href="mailto:wadahiro@gmail.com">Hiroyuki Wada</a>
 */
public class ThinkificIdentityProvider extends AbstractOAuth2IdentityProvider<ThinkificIdentityProviderConfig>
        implements SocialIdentityProvider<ThinkificIdentityProviderConfig> {

    private static final Logger log = Logger.getLogger(ThinkificIdentityProvider.class);

    public static final String OAUTH2_PARAMETER_RESPONSE_MODE = "response_mode";
    public static final String AUTH_URL = "https://{subdomain}.thinkific.com/oauth2/authorize";
    public static final String TOKEN_URL = "https://{subdomain}.thinkific.com/oauth2/token";
    public static final String PROFILE_URL = "";
    public static final String DEFAULT_SCOPE = "openid email profile";
    public static final String THINKIFIC_USER_ID_API_V_1 = "user_id_api_v1";

    public ThinkificIdentityProvider(KeycloakSession session, ThinkificIdentityProviderConfig config) {
        super(session, config);
        config.setAuthorizationUrl(AUTH_URL.replace("{subdomain}", config.getThinkificDomain()));
        config.setTokenUrl(TOKEN_URL.replace("{subdomain}", config.getThinkificDomain()));
        config.setUserInfoUrl(PROFILE_URL.replace("{subdomain}", config.getThinkificDomain()));
        config.setClientAuthMethod(OIDCLoginProtocol.CLIENT_SECRET_BASIC);
    }

    @Override
    protected boolean supportsExternalExchange() {
        return true;
    }

    @Override
    protected String getProfileEndpointForValidation(EventBuilder event) {
        return PROFILE_URL;
    }

    @Override
    protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
        BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "id"));

        user.setUsername(getJsonProperty(profile, "username") + "#" + getJsonProperty(profile, "discriminator"));
        user.setEmail(getJsonProperty(profile, "email"));
        user.setIdpConfig(getConfig());
        user.setIdp(this);

        AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

        return user;
    }

    private static final String BROKER_NONCE_PARAM = "BROKER_NONCE";

    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        AuthenticationSessionModel authenticationSession = request.getAuthenticationSession();
        UriBuilder uriBuilder = super.createAuthorizationUrl(request);
        uriBuilder.replaceQueryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code id_token")
                .queryParam(OAUTH2_PARAMETER_RESPONSE_MODE, "form_post");
        String nonce = Base64Url.encode(SecretGenerator.getInstance().randomBytes(16));
        authenticationSession.setClientNote(BROKER_NONCE_PARAM, nonce);
        uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);

        return uriBuilder;
    }


    @Override
    protected String getDefaultScopes() {
        return DEFAULT_SCOPE;
    }


    /**
     * Parses a JWT token that can be a JWE, JWS or JWE/JWS. It returns the content
     * as a string. If JWS is involved the signature is also validated. A
     * IdentityBrokerException is thrown on any error.
     *
     * @param encodedToken   The token in the encoded string format.
     * @param shouldBeSigned true if the token should be signed (id token),
     *                       false if the token can be only encrypted and not signed (user info).
     * @return The content in string format.
     */
    protected String parseTokenInput(String encodedToken, boolean shouldBeSigned) {
        if (encodedToken == null) {
            throw new IdentityBrokerException("No token from server.");
        }

        try {
            JWSInput jws;
            JOSE joseToken = JOSEParser.parse(encodedToken);
            if (joseToken instanceof JWE) {
                // encrypted JWE token
                JWE jwe = (JWE) joseToken;

                KeyWrapper key;
                if (jwe.getHeader().getKeyId() == null) {
                    key = session.keys().getActiveKey(session.getContext().getRealm(), KeyUse.ENC, jwe.getHeader().getRawAlgorithm());
                } else {
                    key = session.keys().getKey(session.getContext().getRealm(), jwe.getHeader().getKeyId(), KeyUse.ENC, jwe.getHeader().getRawAlgorithm());
                }
                if (key == null || key.getPrivateKey() == null) {
                    throw new IdentityBrokerException("Private key not found in the realm to decrypt token algorithm " + jwe.getHeader().getRawAlgorithm());
                }

                jwe.getKeyStorage().setDecryptionKey(key.getPrivateKey());
                jwe.verifyAndDecodeJwe();
                String content = new String(jwe.getContent(), StandardCharsets.UTF_8);

                try {
                    // try to decode the token just in case it is a JWS
                    joseToken = JOSEParser.parse(content);
                } catch (Exception e) {
                    if (shouldBeSigned) {
                        throw new IdentityBrokerException("Token is not a signed JWS", e);
                    }
                    // the token is only a encrypted JWE (user-info)
                    return content;
                }

                if (!(joseToken instanceof JWSInput)) {
                    throw new IdentityBrokerException("Invalid token type");
                }

                jws = (JWSInput) joseToken;
            } else if (joseToken instanceof JWSInput) {
                // common signed JWS token
                jws = (JWSInput) joseToken;
            } else {
                throw new IdentityBrokerException("Invalid token type");
            }

            // verify signature of the JWS
//            if (!verify(jws)) {
//                throw new IdentityBrokerException("token signature validation failed");
//            }
            return new String(jws.getContent(), StandardCharsets.UTF_8);
        } catch (JWEException e) {
            throw new IdentityBrokerException("Invalid token", e);
        }
    }
    public JsonWebToken validateToken(String encodedToken) {
        boolean ignoreAudience = false;

        return validateToken(encodedToken, ignoreAudience);
    }


    protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
        JsonWebToken token;
        try {
            token = JsonSerialization.readValue(parseTokenInput(encodedToken, true), JsonWebToken.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Invalid token", e);
        }

        String iss = token.getIssuer();

//        if (!token.isActive(getConfig().getAllowedClockSkew())) {
//            throw new IdentityBrokerException("Token is no longer valid");
//        }

        if (!ignoreAudience && !token.hasAudience(getConfig().getClientId())) {
            throw new IdentityBrokerException("Wrong audience from token.");
        }

        if (!ignoreAudience && (token.getIssuedFor() != null && !getConfig().getClientId().equals(token.getIssuedFor()))) {
            throw new IdentityBrokerException("Token issued for does not match client id");
        }

//        String trustedIssuers = getConfig().getIssuer();
//
//        if (trustedIssuers != null && trustedIssuers.length() > 0) {
//            String[] issuers = trustedIssuers.split(",");
//
//            for (String trustedIssuer : issuers) {
//                if (iss != null && iss.equals(trustedIssuer.trim())) {
//                    return token;
//                }
//            }
//
//            throw new IdentityBrokerException("Wrong issuer from token. Got: " + iss + " expected: " + getConfig().getIssuer());
//        }

        return token;
    }

    private String verifyAccessToken(AccessTokenResponse tokenResponse) {
        String accessToken = tokenResponse.getToken();

        if (accessToken == null) {
            throw new IdentityBrokerException("No access_token from server. error='" + tokenResponse.getError() +
                    "', error_description='" + tokenResponse.getErrorDescription() +
                    "', error_uri='" + tokenResponse.getErrorUri() + "'");
        }
        return accessToken;
    }

    @Override
    public BrokeredIdentityContext getFederatedIdentity(String response) {
        AccessTokenResponse tokenResponse = null;
        try {
            tokenResponse = JsonSerialization.readValue(response, AccessTokenResponse.class);
        } catch (IOException e) {
            throw new IdentityBrokerException("Could not decode access token response.", e);
        }
        String accessToken = verifyAccessToken(tokenResponse);

        String encodedIdToken = session.getAttribute("idToken").toString();

        JsonWebToken idToken = validateToken(encodedIdToken);

        if (getConfig().isPassMaxAge()) {
            AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();

            if (isAuthTimeExpired(idToken, authSession)) {
                throw new IdentityBrokerException("User not re-authenticated by the target OpenID Provider");
            }

            Object authTime = idToken.getOtherClaims().get(IDToken.AUTH_TIME);

            if (authTime != null) {
                authSession.setClientNote(AuthenticationManager.AUTH_TIME_BROKER, authTime.toString());
            }
        }

        try {
            BrokeredIdentityContext identity = extractIdentity(tokenResponse, accessToken, idToken);
            /* https://support.thinkific.dev/hc/en-us/articles/4422685802903-OpenID-Connect
             * IMPORTANT: During a successful response, the sub value currently contains the Thinkific User's ID.
             * However, this User ID will change in the future. To keep consistency and get user's data via API call,
             * you will have to use user_id_api_v1 attribute.
             *
             * Hence, we are storing token subject in legacyId and user_id_api_v1 in id.
             */
            if (!identity.getLegacyId().equals(idToken.getSubject())) {
                throw new IdentityBrokerException("Mismatch between the subject in the id_token and the subject from the user_info endpoint");
            }

            if (getConfig().isFilteredByClaims()) {
                String filterName = getConfig().getClaimFilterName();
                String filterValue = getConfig().getClaimFilterValue();

                logger.tracef("Filtering user %s by %s=%s", idToken.getOtherClaims().get(getusernameClaimNameForIdToken()), filterName, filterValue);
                if (idToken.getOtherClaims().containsKey(filterName)) {
                    Object claimObject = idToken.getOtherClaims().get(filterName);
                    List<String> claimValues = new ArrayList<>();
                    if (claimObject instanceof List) {
                        ((List<?>)claimObject).forEach(v->claimValues.add(Objects.toString(v)));
                    } else {
                        claimValues.add(Objects.toString(claimObject));
                    }
                    logger.tracef("Found claim %s with values %s", filterName, claimValues);
                    if (!claimValues.stream().anyMatch(v->v.matches(filterValue))) {
                        logger.warnf("Claim %s has values \"%s\" that does not match the expected filter \"%s\"", filterName, claimValues, filterValue);
                        throw new IdentityBrokerException(String.format("Unmatched claim value for %s.", filterName)).
                                withMessageCode(Messages.IDENTITY_PROVIDER_UNMATCHED_ESSENTIAL_CLAIM_ERROR);
                    }
                } else {
                    logger.debugf("Claim %s was not found", filterName);
                    throw new IdentityBrokerException(String.format("Claim %s not found", filterName)).
                            withMessageCode(Messages.IDENTITY_PROVIDER_UNMATCHED_ESSENTIAL_CLAIM_ERROR);
                }
            }

            if (!getConfig().isDisableNonce()) {
                identity.getContextData().put(BROKER_NONCE_PARAM, idToken.getOtherClaims().get(OIDCLoginProtocol.NONCE_PARAM));
            }

            if (getConfig().isStoreToken()) {
                if (tokenResponse.getExpiresIn() > 0) {
                    long accessTokenExpiration = Time.currentTime() + tokenResponse.getExpiresIn();
                    tokenResponse.getOtherClaims().put(ACCESS_TOKEN_EXPIRATION, accessTokenExpiration);
                    response = JsonSerialization.writeValueAsString(tokenResponse);
                }
                identity.setToken(response);
            }

            return identity;
        } catch (IdentityBrokerException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not fetch attributes from userinfo endpoint.", e);
        }
    }

    protected boolean isAuthTimeExpired(JsonWebToken idToken, AuthenticationSessionModel authSession) {
        String maxAge = authSession.getClientNote(OIDCLoginProtocol.MAX_AGE_PARAM);

        if (maxAge == null) {
            return false;
        }

        String authTime = idToken.getOtherClaims().getOrDefault(IDToken.AUTH_TIME, "0").toString();
        int authTimeInt = authTime == null ? 0 : Integer.parseInt(authTime);
        int maxAgeInt = Integer.parseInt(maxAge);

        if (authTimeInt + maxAgeInt < Time.currentTime()) {
            logger.debugf("Invalid auth_time claim. User not re-authenticated by the target OP.");
            return true;
        }

        return false;
    }
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) throws IOException {
        String legacyId = idToken.getSubject();
        String id = idToken.getOtherClaims().get(THINKIFIC_USER_ID_API_V_1).toString();
        BrokeredIdentityContext identity = new BrokeredIdentityContext(id);
        String name = (String) idToken.getOtherClaims().get(IDToken.NAME);
        String givenName = (String)idToken.getOtherClaims().get(IDToken.GIVEN_NAME);
        String familyName = (String)idToken.getOtherClaims().get(IDToken.FAMILY_NAME);
        String preferredUsername = (String) idToken.getOtherClaims().get(getusernameClaimNameForIdToken());
        String email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);

        if (!getConfig().isDisableUserInfoService()) {
            String userInfoUrl = getUserInfoUrl();
            if (userInfoUrl != null && !userInfoUrl.isEmpty()) {

                if (accessToken != null) {
                    SimpleHttp.Response response = executeRequest(userInfoUrl, SimpleHttp.doGet(userInfoUrl, session).header("Authorization", "Bearer " + accessToken));
                    String contentType = response.getFirstHeader(HttpHeaders.CONTENT_TYPE);
                    MediaType contentMediaType;
                    try {
                        contentMediaType = MediaType.valueOf(contentType);
                    } catch (IllegalArgumentException ex) {
                        contentMediaType = null;
                    }
                    if (contentMediaType == null || contentMediaType.isWildcardSubtype() || contentMediaType.isWildcardType()) {
                        throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
                    }
                    JsonNode userInfo;

                    if (MediaType.APPLICATION_JSON_TYPE.isCompatible(contentMediaType)) {
                        userInfo = response.asJson();
                    } else if (APPLICATION_JWT_TYPE.isCompatible(contentMediaType)) {
                        userInfo = JsonSerialization.readValue(parseTokenInput(response.asString(), false), JsonNode.class);
                    } else {
                        throw new RuntimeException("Unsupported content-type [" + contentType + "] in response from [" + userInfoUrl + "].");
                    }

                    id = getJsonProperty(userInfo, "sub");
                    name = getJsonProperty(userInfo, "name");
                    givenName = getJsonProperty(userInfo, IDToken.GIVEN_NAME);
                    familyName = getJsonProperty(userInfo, IDToken.FAMILY_NAME);
                    preferredUsername = getUsernameFromUserInfo(userInfo);
                    email = getJsonProperty(userInfo, "email");
                    AbstractJsonUserAttributeMapper.storeUserProfileForMapper(identity, userInfo, getConfig().getAlias());
                }
            }
        }
        identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);

        identity.setId(id);
        identity.setLegacyId(legacyId);

        if (givenName != null) {
            identity.setFirstName(givenName);
        }

        if (familyName != null) {
            identity.setLastName(familyName);
        }

        if (givenName == null && familyName == null) {
            identity.setName(name);
        }

        identity.setEmail(email);

        identity.setBrokerUserId(getConfig().getAlias() + "." + id);

        if (preferredUsername == null) {
            preferredUsername = email;
        }

        if (preferredUsername == null) {
            preferredUsername = id;
        }

        identity.setUsername(preferredUsername);
        if (tokenResponse != null && tokenResponse.getSessionState() != null) {
            identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
        }
        if (tokenResponse != null) identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
        if (tokenResponse != null) processAccessTokenResponse(identity, tokenResponse);

        return identity;
    }
    protected String getUserInfoUrl() {
        return getConfig().getUserInfoUrl();
    }

    protected String getUsernameFromUserInfo(JsonNode userInfo) {
        return getJsonProperty(userInfo, "preferred_username");
    }

    protected void processAccessTokenResponse(BrokeredIdentityContext context, AccessTokenResponse response) {
        // Don't verify audience on accessToken as it may not be there. It was verified on IDToken already
        if (getConfig().isAccessTokenJwt()) {
            JsonWebToken access = validateToken(response.getToken(), true);
            context.getContextData().put(VALIDATED_ACCESS_TOKEN, access);
        }
    }
    protected String getusernameClaimNameForIdToken() {
        return IDToken.PREFERRED_USERNAME;
    }
    private SimpleHttp.Response executeRequest(String url, SimpleHttp request) throws IOException {
        SimpleHttp.Response response = request.asResponse();
        if (response.getStatus() != 200) {
            String msg = "failed to invoke url [" + url + "]";
            try {
                String tmp = response.asString();
                if (tmp != null) msg = tmp;

            } catch (IOException e) {

            }
            throw new IdentityBrokerException("Failed to invoke url [" + url + "]: " + msg);
        }
        return  response;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new ThinkificIdentityProvider.ThinkificEndpoint(callback, realm, event, this);
    }

    protected static class ThinkificEndpoint extends Endpoint {
        private static final String OAUTH2_PARAMETER_IDTOKEN = "id_token";
        private final ThinkificIdentityProvider provider;

        public ThinkificEndpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event, AbstractOAuth2IdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = (ThinkificIdentityProvider) provider;
        }

        @GET
        @Path("/")
        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                                     @QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                                     @QueryParam(OAuth2Constants.ERROR) String error) {
            return null;
        }

        @POST
        public Response doPost(@FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
                               @FormParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
                               @FormParam(OAuth2Constants.ERROR) String error,
                               @FormParam(OAUTH2_PARAMETER_IDTOKEN) String idToken) {
            session.setAttribute("idToken", idToken);
            return super.authResponse(state, authorizationCode, error);
        }


    }
}