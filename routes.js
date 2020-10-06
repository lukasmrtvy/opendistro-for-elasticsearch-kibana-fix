"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.OpenIdAuthRoutes = void 0;
/*
 *   Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License").
 *   You may not use this file except in compliance with the License.
 *   A copy of the License is located at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   or in the "license" file accompanying this file. This file is distributed
 *   on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 *   express or implied. See the License for the specific language governing
 *   permissions and limitations under the License.
 */
const config_schema_1 = require("@kbn/config-schema");
const cryptiles_1 = require("@hapi/cryptiles");
const querystring_1 = require("querystring");
const helper_1 = require("./helper");
class OpenIdAuthRoutes {
    constructor(router, config, sessionStorageFactory, openIdAuthConfig, securityClient, core) {
        this.router = router;
        this.config = config;
        this.sessionStorageFactory = sessionStorageFactory;
        this.openIdAuthConfig = openIdAuthConfig;
        this.securityClient = securityClient;
        this.core = core;
    }
    redirectToLogin(request, response) {
        this.sessionStorageFactory.asScoped(request).clear();
        return response.redirected({
            headers: {
                location: `${this.core.http.basePath.serverBasePath}/auth/openid/login`,
            },
        });
    }
    setupRoutes() {
        this.router.get({
            path: `/auth/openid/login`,
            validate: {
                query: config_schema_1.schema.any(),
            },
            options: {
                authRequired: false,
            },
        }, async (context, request, response) => {
            // implementation refers to https://github.com/hapijs/bell/blob/master/lib/oauth.js
            // Sign-in initialization
            if (!request.query.code) {
                const nonce = cryptiles_1.randomString(OpenIdAuthRoutes.NONCE_LENGTH);
                const query = {
                    client_id: this.config.openid?.client_id,
                    response_type: 'code',
                    redirect_uri: `${helper_1.getBaseRedirectUrl(this.config, this.core)}/auth/openid/login`,
                    state: nonce,
                    scope: this.openIdAuthConfig.scope,
                };
                const queryString = querystring_1.stringify(query);
                const location = `${this.openIdAuthConfig.authorizationEndpoint}?${queryString}`;
                const cookie = {
                    oidc: {
                        state: nonce,
                        nextUrl: request.query.nextUrl || '/',
                    },
                };
                this.sessionStorageFactory.asScoped(request).set(cookie);
                return response.redirected({
                    headers: {
                        location,
                    },
                });
            }
            // Authentication callback
            // validate state first
            let cookie;
            try {
                cookie = await this.sessionStorageFactory.asScoped(request).get();
                if (!cookie ||
                    !cookie.oidc?.state ||
                    cookie.oidc.state !== request.query.state) {
                    return this.redirectToLogin(request, response);
                }
            }
            catch (error) {
                return this.redirectToLogin(request, response);
            }
            const nextUrl = cookie.oidc.nextUrl;
            const clientId = this.config.openid?.client_id;
            const clientSecret = this.config.openid?.client_secret;
            const query = {
                grant_type: 'authorization_code',
                code: request.query.code,
                redirect_uri: `${helper_1.getBaseRedirectUrl(this.config, this.core)}/auth/openid/login`,
                client_id: clientId,
                client_secret: clientSecret,
            };
            try {
                const tokenResponse = await helper_1.callTokenEndpoint(this.openIdAuthConfig.tokenEndpoint, query);
                const user = await this.securityClient.authenticateWithHeader(request, this.openIdAuthConfig.authHeaderName, `Bearer ${tokenResponse.idToken}`);
                // set to cookie
                const sessionStorage = {
                    username: user.username,
                    credentials: {
                        authHeaderValue: `Bearer ${tokenResponse.idToken}`,
                        refresh_token: tokenResponse.refreshToken,
                        expires_at: Date.now() + tokenResponse.expiresIn * 1000,
                    },
                    authType: 'openid',
                    expiryTime: Date.now() + this.config.cookie.ttl,
                };
                this.sessionStorageFactory.asScoped(request).set(sessionStorage);
                return response.redirected({
                    headers: {
                        location: nextUrl,
                    },
                });
            }
            catch (error) {
                context.security_plugin.logger.error(`OpenId authentication failed: ${error}`);
                // redirect to login
                return this.redirectToLogin(request, response);
            }
        });
        this.router.get({
            path: `/auth/logout`,
            validate: false,
        }, async (context, request, response) => {
            const cookie = await this.sessionStorageFactory.asScoped(request).get();
            this.sessionStorageFactory.asScoped(request).clear();
            // authHeaderValue is the bearer header, e.g. "Bearer <auth_token>"
            const token = cookie?.credentials.authHeaderValue.split(' ')[1]; // get auth token
            const logoutQueryParams = {
                post_logout_redirect_uri: helper_1.getBaseRedirectUrl(this.config, this.core),
                id_token_hint: token,
            };
            const logoutBaseUri = this.config.openid?.logout_url || this.openIdAuthConfig.endSessionEndpoint;
            const endSessionUrl = `${logoutBaseUri}?${querystring_1.stringify(logoutQueryParams)}`;
            return response.redirected({
                headers: {
                    location: endSessionUrl,
                },
            });
        });
    }
}
exports.OpenIdAuthRoutes = OpenIdAuthRoutes;
OpenIdAuthRoutes.NONCE_LENGTH = 22;
