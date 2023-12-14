/*
 *   Copyright OpenSearch Contributors
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

import { ParsedUrlQuery } from 'querystring';
import {
  SessionStorageFactory,
  IRouter,
  ILegacyClusterClient,
  CoreSetup,
  OpenSearchDashboardsRequest,
  Logger,
  LifecycleResponseFactory,
  AuthToolkit,
  IOpenSearchDashboardsResponse,
} from 'opensearch-dashboards/server';
import { Server, ServerStateCookieOptions } from '@hapi/hapi';
import { SecurityPluginConfigType } from '../../..';
import { SecuritySessionCookie } from '../../../session/security_cookie';
import { AuthenticationType } from '../authentication_type';
import { JwtAuthRoutes } from './routes';

import {
  setExtraAuthStorage,
  getExtraAuthStorageValue,
  ExtraAuthStorageOptions,
} from '../../../session/cookie_splitter';

export class JwtAuthentication extends AuthenticationType {
  public readonly type: string = 'jwt';

  private authHeaderName: string;

  constructor(
    config: SecurityPluginConfigType,
    sessionStorageFactory: SessionStorageFactory<SecuritySessionCookie>,
    router: IRouter,
    esClient: ILegacyClusterClient,
    coreSetup: CoreSetup,
    logger: Logger
  ) {
    super(config, sessionStorageFactory, router, esClient, coreSetup, logger);
    this.authHeaderName = this.config.jwt?.header.toLowerCase() || 'authorization';
  }

  public async init() {
    this.createExtraStorage();
    const routes = new JwtAuthRoutes(this.router, this.sessionStorageFactory);
    routes.setupRoutes();
  }

  createExtraStorage() {
    // @ts-ignore
    const hapiServer: Server = this.sessionStorageFactory.asScoped({}).server;

    const extraCookiePrefix = this.config.jwt.extra_storage.cookie_prefix;
    const extraCookieSettings: ServerStateCookieOptions = {
      isSecure: this.config.cookie.secure,
      isSameSite: this.config.cookie.isSameSite,
      password: this.config.cookie.password,
      domain: this.config.cookie.domain,
      path: this.coreSetup.http.basePath.serverBasePath || '/',
      clearInvalid: false,
      isHttpOnly: true,
      ignoreErrors: true,
      encoding: 'iron', // Same as hapi auth cookie
    };

    for (let i = 1; i <= this.config.saml.extra_storage.additional_cookies; i++) {
      hapiServer.states.add(extraCookiePrefix + i, extraCookieSettings);
    }
  }

  private getExtraAuthStorageOptions(logger?: Logger): ExtraAuthStorageOptions {
    // If we're here, we will always have the openid configuration
    return {
      cookiePrefix: this.config.jwt.extra_storage.cookie_prefix,
      additionalCookies: this.config.jwt.extra_storage.additional_cookies,
      logger,
    };
  }

  private getTokenFromUrlParam(request: OpenSearchDashboardsRequest): string | undefined {
    const urlParamName = this.config.jwt?.url_param;
    if (urlParamName) {
      const token = request.url.searchParams.get(urlParamName);
      return (token as string) || undefined;
    }
    return undefined;
  }

  private getBearerToken(request: OpenSearchDashboardsRequest): string | undefined {
    const token = this.getTokenFromUrlParam(request);
    if (token) {
      return `Bearer ${token}`;
    }

    // no token in url parameter, try to get token from header
    return (request.headers[this.authHeaderName] as string) || undefined;
  }

  requestIncludesAuthInfo(
    request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>
  ): boolean {
    if (request.headers[this.authHeaderName]) {
      return true;
    }
    const urlParamName = this.config.jwt?.url_param;
    if (urlParamName && request.url.searchParams.get(urlParamName)) {
      return true;
    }

    return false;
  }

  async getAdditionalAuthHeader(
    request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>
  ): Promise<any> {
    const header: any = {};
    const token = this.getTokenFromUrlParam(request);
    if (token) {
      header[this.authHeaderName] = `Bearer ${token}`;
    }
    return header;
  }

  getCookie(
    request: OpenSearchDashboardsRequest<unknown, unknown, unknown, any>,
    authInfo: any
  ): SecuritySessionCookie {
    const authorizationHeaderValue = this.getBearerToken(request) || '';

    setExtraAuthStorage(
      request,
      authorizationHeaderValue,
      this.getExtraAuthStorageOptions(this.logger)
    );
    return {
      username: authInfo.user_name,
      credentials: {
        authHeaderValueExtra: true,
      },
      authType: this.type,
      expiryTime: Date.now() + this.config.session.ttl,
    };
  }

  async isValidCookie(
    cookie: SecuritySessionCookie,
    request: OpenSearchDashboardsRequest
  ): Promise<boolean> {
    return (
      cookie.authType === this.type &&
      cookie.username &&
      cookie.expiryTime &&
      (cookie.credentials?.authHeaderValue || this.getExtraAuthStorageValue(request, cookie))
    );
  }

  getExtraAuthStorageValue(request: OpenSearchDashboardsRequest, cookie: SecuritySessionCookie) {
    let extraValue = '';
    if (!cookie.credentials?.authHeaderValueExtra) {
      return extraValue;
    }

    try {
      extraValue = getExtraAuthStorageValue(request, this.getExtraAuthStorageOptions(this.logger));
    } catch (error) {
      this.logger.info(error);
    }

    return extraValue;
  }

  handleUnauthedRequest(
    request: OpenSearchDashboardsRequest,
    response: LifecycleResponseFactory,
    toolkit: AuthToolkit
  ): IOpenSearchDashboardsResponse {
    return response.unauthorized();
  }

  buildAuthHeaderFromCookie(
    cookie: SecuritySessionCookie,
    request: OpenSearchDashboardsRequest
  ): any {
    const headers: any = {};

    if (cookie.credentials?.authHeaderValueExtra) {
      try {
        const extraAuthStorageValue = this.getExtraAuthStorageValue(request, cookie);
        headers[this.authHeaderName] = extraAuthStorageValue;
      } catch (error) {
        this.logger.error(error);
        // @todo Re-throw?
        // throw error;
      }
    } else {
      headers[this.authHeaderName] = cookie.credentials?.authHeaderValue;
    }

    return headers;
  }
}
