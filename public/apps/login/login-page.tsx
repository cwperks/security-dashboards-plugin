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

import React, { useState } from 'react';
import {
  EuiText,
  EuiCompressedFieldText,
  EuiSpacer,
  EuiButton,
  EuiImage,
  EuiListGroup,
  EuiForm,
  EuiCompressedFormRow,
  EuiHorizontalRule,
  EuiCompressedFieldPassword,
} from '@elastic/eui';
import { CoreStart } from '../../../../../src/core/public';
import { ClientConfigType } from '../../types';
import { validateCurrentPassword } from '../../utils/login-utils';
import {
  ANONYMOUS_AUTH_LOGIN,
  AuthType,
  OPENID_AUTH_LOGIN_WITH_FRAGMENT,
  SAML_AUTH_LOGIN_WITH_FRAGMENT,
} from '../../../common';
import { getDashboardsSignInOptions } from '../../utils/dashboards-info-utils';
import { DashboardSignInOption } from '../configuration/types';
import { getSavedTenant } from '../../utils/storage-utils';

interface LoginPageDeps {
  http: CoreStart['http'];
  chrome: CoreStart['chrome'];
  config: ClientConfigType;
}

interface LoginButtonConfig {
  buttonname: string;
  showbrandimage: boolean;
  brandimage: string;
  buttonstyle: string;
}

export function getNextPath(serverBasePath: string) {
  const urlParams = new URLSearchParams(window.location.search);
  let nextUrl = urlParams.get('nextUrl');
  if (!nextUrl || nextUrl.toLowerCase().includes('//')) {
    // Appending the next url with trailing slash. We do so because in case the serverBasePath is empty, we can simply
    // redirect to '/'.
    nextUrl = serverBasePath + '/';
  }
  const savedTenant = getSavedTenant();
  const url = new URL(
    window.location.protocol + '//' + window.location.host + nextUrl + window.location.hash
  );
  if (
    !!savedTenant &&
    !(
      url.searchParams.has('security_tenant') ||
      url.searchParams.has('securitytenant') ||
      url.searchParams.has('securityTenant_')
    )
  ) {
    url.searchParams.append('security_tenant', savedTenant);
  }
  return url.pathname + url.search + url.hash;
}

function redirect(serverBasePath: string) {
  // navigate to nextUrl
  window.location.href = getNextPath(serverBasePath);
}

export function extractNextUrlFromWindowLocation(): string {
  const urlParams = new URLSearchParams(window.location.search);
  let nextUrl = urlParams.get('nextUrl');
  if (!nextUrl || nextUrl.toLowerCase().includes('//')) {
    return '';
  } else {
    nextUrl = encodeURIComponent(nextUrl);
    const hash = window.location.hash || '';
    nextUrl += hash;
  }
  return `?nextUrl=${nextUrl}`;
}

export function LoginPage(props: LoginPageDeps) {
  const [username, setUsername] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [loginFailed, setloginFailed] = useState(false);
  const [loginError, setloginError] = useState('');
  const [usernameValidationFailed, setUsernameValidationFailed] = useState(false);
  const [passwordValidationFailed, setPasswordValidationFailed] = useState(false);
  const [dynamicSignInOptions, setDynamicSignInOptions] = React.useState<
    DashboardSignInOption[] | null
  >(null);

  React.useEffect(() => {
    const loadDynamicSignInOptions = async () => {
      try {
        setDynamicSignInOptions(await getDashboardsSignInOptions(props.http));
      } catch (error) {
        setDynamicSignInOptions(null);
      }
    };

    loadDynamicSignInOptions();
  }, [props.http]);

  let errorLabel: any = null;
  if (loginFailed) {
    errorLabel = (
      <EuiText id="error" color="danger" textAlign="center">
        <b>{loginError}</b>
      </EuiText>
    );
  }

  // @ts-ignore : Parameter 'e' implicitly has an 'any' type.
  const handleSubmit = async (e) => {
    e.preventDefault();

    // Clear errors
    setloginFailed(false);
    setUsernameValidationFailed(false);
    setPasswordValidationFailed(false);

    // Form validation
    if (username === '') {
      setUsernameValidationFailed(true);
      return;
    }

    if (password === '') {
      setPasswordValidationFailed(true);
      return;
    }

    try {
      const isValid = await reValidateSignInOption(DashboardSignInOption.BASIC);
      if (!isValid) {
        return;
      }
      await validateCurrentPassword(props.http, username, password);
      redirect(props.http.basePath.serverBasePath);
    } catch (error) {
      console.log(error);
      setloginFailed(true);
      setloginError('Invalid username or password. Please try again.');
      return;
    }
  };

  const renderLoginButton = (
    authType: string,
    loginEndPoint: string,
    buttonConfig: LoginButtonConfig
  ) => {
    const buttonId = `${authType}_login_button`;
    const loginEndPointWithPath = `${props.http.basePath.serverBasePath}${loginEndPoint}`;
    return (
      <EuiCompressedFormRow>
        <EuiButton
          data-test-subj="submit"
          aria-label={buttonId}
          size="s"
          type="button"
          className={buttonConfig.buttonstyle || 'btn-login'}
          onClick={async (event) => {
            event.preventDefault();
            if (await reValidateSignInOption(authType as DashboardSignInOption)) {
              window.location.assign(loginEndPointWithPath);
            }
          }}
          iconType={buttonConfig.showbrandimage ? buttonConfig.brandimage : ''}
        >
          {buttonConfig.buttonname}
        </EuiButton>
      </EuiCompressedFormRow>
    );
  };

  const reValidateSignInOption = async (signInOption: DashboardSignInOption) => {
    try {
      const availableSignInOptions = await getDashboardsSignInOptions(props.http);

      if (!availableSignInOptions.includes(signInOption)) {
        window.location.reload();
        return false;
      }
    } catch (error) {
      return true;
    }

    return true;
  };

  const mapDynamicSignInOptionsToAuthTypes = (options: DashboardSignInOption[]) => {
    return options
      .map((option) => {
        switch (option) {
          case DashboardSignInOption.BASIC:
            return AuthType.BASIC;
          case DashboardSignInOption.OPEN_ID:
            return AuthType.OPEN_ID;
          case DashboardSignInOption.SAML:
            return AuthType.SAML;
          case DashboardSignInOption.ANONYMOUS:
            return AuthType.ANONYMOUS;
          default:
            return undefined;
        }
      })
      .filter((option): option is AuthType => Boolean(option));
  };

  const formOptions = (options: string | string[]) => {
    let formBody = [];
    const formBodyOp = [];
    let authOpts: string[] =
      dynamicSignInOptions && dynamicSignInOptions.length > 0
        ? mapDynamicSignInOptionsToAuthTypes(dynamicSignInOptions)
        : [];

    if (authOpts.length === 0) {
      if (typeof options === 'string') {
        if (options !== '') {
          authOpts.push(options.toLowerCase());
        }
      } else if (!(options && options.length === 1 && options[0] === '')) {
        authOpts = [...options];
      }
      if (authOpts.length === 0) {
        authOpts.push(AuthType.BASIC);
      }
      if (props.config.auth.anonymous_auth_enabled && !authOpts.includes(AuthType.ANONYMOUS)) {
        authOpts.push(AuthType.ANONYMOUS);
      }
    }

    // Remove proxy and jwt from the list because they do not have a login button
    // The count of visible options determines if a separator gets added
    authOpts = authOpts.filter((auth) => auth !== AuthType.PROXY && auth !== AuthType.JWT);

    for (let i = 0; i < authOpts.length; i++) {
      switch (authOpts[i].toLowerCase()) {
        case AuthType.BASIC: {
          formBody.push(
            <EuiCompressedFormRow>
              <EuiCompressedFieldText
                data-test-subj="user-name"
                aria-label="username_input"
                placeholder="Username"
                icon="user"
                onChange={(e) => setUsername(e.target.value)}
                value={username}
                isInvalid={usernameValidationFailed}
              />
            </EuiCompressedFormRow>
          );
          formBody.push(
            <EuiCompressedFormRow isInvalid={passwordValidationFailed}>
              <EuiCompressedFieldPassword
                data-test-subj="password"
                aria-label="password_input"
                placeholder="Password"
                type="dual"
                onChange={(e) => setPassword(e.target.value)}
                value={password}
                isInvalid={usernameValidationFailed}
              />
            </EuiCompressedFormRow>
          );
          const buttonId = `${AuthType.BASIC}_login_button`;
          formBody.push(
            <EuiCompressedFormRow>
              <EuiButton
                data-test-subj="submit"
                aria-label={buttonId}
                fill
                size="s"
                type="submit"
                className={props.config.ui.basicauth.login.buttonstyle || 'btn-login'}
                onClick={handleSubmit}
              >
                Log in
              </EuiButton>
            </EuiCompressedFormRow>
          );

          if (authOpts.length > 1) {
            // Add a separator between the username/password form and the other login options
            formBody.push(<EuiSpacer size="xs" />);
            formBody.push(<EuiHorizontalRule size="full" margin="xl" />);
            formBody.push(<EuiSpacer size="xs" />);
          }
          break;
        }
        case AuthType.OPEN_ID: {
          const oidcConfig = props.config.ui[AuthType.OPEN_ID].login;
          const nextUrl = extractNextUrlFromWindowLocation();
          const oidcAuthLoginUrl = OPENID_AUTH_LOGIN_WITH_FRAGMENT + nextUrl;
          formBodyOp.push(renderLoginButton(AuthType.OPEN_ID, oidcAuthLoginUrl, oidcConfig));
          break;
        }
        case AuthType.SAML: {
          const samlConfig = props.config.ui[AuthType.SAML].login;
          const nextUrl = extractNextUrlFromWindowLocation();
          const samlAuthLoginUrl = SAML_AUTH_LOGIN_WITH_FRAGMENT + nextUrl;
          formBodyOp.push(renderLoginButton(AuthType.SAML, samlAuthLoginUrl, samlConfig));
          break;
        }
        case AuthType.ANONYMOUS: {
          const anonymousConfig = props.config.ui[AuthType.ANONYMOUS].login;
          formBody.push(
            renderLoginButton(AuthType.ANONYMOUS, ANONYMOUS_AUTH_LOGIN, anonymousConfig)
          );
          break;
        }
        default: {
          setloginFailed(true);
          setloginError(
            `Authentication Type: ${authOpts[i]} is not supported for multiple authentication.`
          );
          break;
        }
      }
    }

    formBody = formBody.concat(formBodyOp);
    return formBody;
  };

  // TODO: Get brand image from server config
  return (
    <EuiListGroup className="login-wrapper">
      {props.config.ui.basicauth.login.showbrandimage && (
        <EuiImage
          size="fullWidth"
          alt=""
          url={props.config.ui.basicauth.login.brandimage || props.chrome.logos.OpenSearch.url}
        />
      )}
      <EuiSpacer size="s" />
      <EuiText size="m" textAlign="center">
        {props.config.ui.basicauth.login.title || 'Log in to OpenSearch Dashboards'}
      </EuiText>
      <EuiSpacer size="s" />
      <EuiText size="s" textAlign="center">
        {props.config.ui.basicauth.login.subtitle ||
          'If you have forgotten your username or password, contact your system administrator.'}
      </EuiText>
      <EuiSpacer size="s" />
      <EuiForm component="form">
        {formOptions(props.config.auth.type)}
        {errorLabel}
      </EuiForm>
    </EuiListGroup>
  );
}
