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

import { mount, shallow } from 'enzyme';
import React, { act } from 'react';
import { ClientConfigType } from '../../../types';
import { LoginPage, extractNextUrlFromWindowLocation, getNextPath } from '../login-page';
import { validateCurrentPassword } from '../../../utils/login-utils';
import { API_AUTH_LOGOUT } from '../../../../common';
import { chromeServiceMock } from '../../../../../../src/core/public/mocks';
import { AuthType } from '../../../../common';
import { setSavedTenant } from '../../../utils/storage-utils';
import { getDashboardsSignInOptions } from '../../../utils/dashboards-info-utils';

jest.mock('../../../utils/login-utils', () => ({
  validateCurrentPassword: jest.fn(),
}));

jest.mock('../../../utils/dashboards-info-utils', () => ({
  getDashboardsSignInOptions: jest.fn(),
}));

const configUI = {
  basicauth: {
    login: {
      title: 'Title1',
      subtitle: 'SubTitle1',
      showbrandimage: true,
      brandimage: 'http://localhost:5601/images/test.png',
      buttonstyle: 'test-btn-style',
    },
  },
  anonymous: {
    login: {
      title: 'Anony1',
      subtitle: 'AnonySub1',
      showbrandimage: true,
      brandimage: 'http://localhost:5601/images/test.png',
      buttonstyle: 'test-btn-style',
    },
  },
  openid: {
    login: {
      buttonname: 'Button1',
      showbrandimage: true,
      brandimage: 'http://localhost:5601/images/test.png',
      buttonstyle: 'test-btn-style',
    },
  },
  saml: {
    login: {
      buttonname: 'Button2',
      showbrandimage: true,
      brandimage: 'http://localhost:5601/images/test.png',
      buttonstyle: 'test-btn-style',
    },
  },
  autologout: true,
  backend_configurable: true,
};

const configUiDefault = {
  basicauth: {
    login: {
      showbrandimage: true,
    },
  },
};

describe('test extractNextUrlFromWindowLocation', () => {
  test('extract next url from window with nextUrl', () => {
    // Trick to mock window.location
    const originalLocation = window.location;
    delete window.location;
    window.location = new URL(
      "http://localhost:5601/app/login?nextUrl=%2Fapp%2Fdashboards#/view/7adfa750-4c81-11e8-b3d7-01146121b73d?_g=(filters:!(),refreshInterval:(pause:!f,value:900000),time:(from:now-24h,to:now))&_a=(description:'Analyze%20mock%20flight%20data%20for%20OpenSearch-Air,%20Logstash%20Airways,%20OpenSearch%20Dashboards%20Airlines%20and%20BeatsWest',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:''),timeRestore:!t,title:'%5BFlights%5D%20Global%20Flight%20Dashboard',viewMode:view)"
    ) as any;
    expect(extractNextUrlFromWindowLocation()).toEqual(
      "?nextUrl=%2Fapp%2Fdashboards#/view/7adfa750-4c81-11e8-b3d7-01146121b73d?_g=(filters:!(),refreshInterval:(pause:!f,value:900000),time:(from:now-24h,to:now))&_a=(description:'Analyze%20mock%20flight%20data%20for%20OpenSearch-Air,%20Logstash%20Airways,%20OpenSearch%20Dashboards%20Airlines%20and%20BeatsWest',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:''),timeRestore:!t,title:'%5BFlights%5D%20Global%20Flight%20Dashboard',viewMode:view)"
    );
  });

  test('extract next url from window without nextUrl', () => {
    const originalLocation = window.location;
    delete window.location;
    window.location = new URL('http://localhost:5601/app/home');
    expect(extractNextUrlFromWindowLocation()).toEqual('');
  });
});

describe('test redirect', () => {
  test('extract redirect excludes security_tenant when no tenant in local storage', () => {
    // Trick to mock window.location
    const originalLocation = window.location;
    delete window.location;
    window.location = new URL('http://localhost:5601/app/login?nextUrl=%2Fapp%2Fdashboards') as any;
    setSavedTenant(null);
    const nextPath = getNextPath('');
    expect(nextPath).toEqual('/app/dashboards');
    window.location = originalLocation;
  });

  test('extract redirect includes security_tenant when tenant in local storage', () => {
    const originalLocation = window.location;
    delete window.location;
    window.location = new URL('http://localhost:5601/app/login?nextUrl=%2Fapp%2Fdashboards');
    setSavedTenant('custom');
    const nextPath = getNextPath('');
    expect(nextPath).toEqual('/app/dashboards?security_tenant=custom');
    setSavedTenant(null);
    window.location = originalLocation;
  });

  test('extract redirect includes security_tenant when tenant in local storage, existing url params and hash', () => {
    const originalLocation = window.location;
    delete window.location;
    window.location = new URL(
      "http://localhost:5601/app/login?nextUrl=%2Fapp%2Fdashboards?param1=value1#/view/7adfa750-4c81-11e8-b3d7-01146121b73d?_g=(filters:!(),refreshInterval:(pause:!f,value:900000),time:(from:now-24h,to:now))&_a=(description:'Analyze%20mock%20flight%20data%20for%20OpenSearch-Air,%20Logstash%20Airways,%20OpenSearch%20Dashboards%20Airlines%20and%20BeatsWest',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:''),timeRestore:!t,title:'%5BFlights%5D%20Global%20Flight%20Dashboard',viewMode:view)"
    );
    setSavedTenant('custom');
    const nextPath = getNextPath('');
    expect(nextPath).toEqual(
      "/app/dashboards?param1=value1&security_tenant=custom#/view/7adfa750-4c81-11e8-b3d7-01146121b73d?_g=(filters:!(),refreshInterval:(pause:!f,value:900000),time:(from:now-24h,to:now))&_a=(description:'Analyze%20mock%20flight%20data%20for%20OpenSearch-Air,%20Logstash%20Airways,%20OpenSearch%20Dashboards%20Airlines%20and%20BeatsWest',filters:!(),fullScreenMode:!f,options:(hidePanelTitles:!f,useMargins:!t),query:(language:kuery,query:''),timeRestore:!t,title:'%5BFlights%5D%20Global%20Flight%20Dashboard',viewMode:view)"
    );
    setSavedTenant(null);
    window.location = originalLocation;
  });
});

describe('Login page', () => {
  let chrome: ReturnType<typeof chromeServiceMock.createStartContract>;
  const mockHttpStart = {
    basePath: {
      serverBasePath: '/app/opensearch-dashboards',
    },
  };

  beforeEach(() => {
    chrome = chromeServiceMock.createStartContract();
    (getDashboardsSignInOptions as jest.Mock).mockRejectedValue(new Error('not configured'));
  });

  describe('renders', () => {
    it('renders with config value: string array', () => {
      const config: ClientConfigType = {
        ui: configUI,
        auth: {
          type: [AuthType.BASIC],
          logout_url: API_AUTH_LOGOUT,
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with config value with anonymous auth enabled: string array', () => {
      const config: ClientConfigType = {
        ui: configUI,
        auth: {
          type: [AuthType.BASIC],
          logout_url: API_AUTH_LOGOUT,
          anonymous_auth_enabled: true,
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with config value: string', () => {
      const config: ClientConfigType = {
        ui: configUI,
        auth: {
          type: AuthType.BASIC,
          logout_url: API_AUTH_LOGOUT,
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with config value with anonymous auth enabled: string', () => {
      const config: ClientConfigType = {
        ui: configUI,
        auth: {
          type: AuthType.BASIC,
          logout_url: API_AUTH_LOGOUT,
          anonymous_auth_enabled: true,
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with config value for multiauth', () => {
      const config: ClientConfigType = {
        ui: configUI,
        auth: {
          type: [AuthType.BASIC, AuthType.OPEN_ID, AuthType.SAML],
          logout_url: API_AUTH_LOGOUT,
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with config value for multiauth with anonymous auth enabled', () => {
      const config: ClientConfigType = {
        ui: configUI,
        auth: {
          type: [AuthType.BASIC, AuthType.OPEN_ID, AuthType.SAML],
          logout_url: API_AUTH_LOGOUT,
          anonymous_auth_enabled: true,
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with default value: string array', () => {
      const config: ClientConfigType = {
        ui: configUiDefault,
        auth: {
          type: [''],
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });

    it('renders with default value: string', () => {
      const config: ClientConfigType = {
        ui: configUiDefault,
        auth: {
          type: '',
        },
      };
      const component = shallow(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
      expect(component).toMatchSnapshot();
    });
  });

  describe('event trigger testing', () => {
    let component;
    const config: ClientConfigType = {
      ui: configUiDefault,
      auth: {
        type: AuthType.BASIC,
      },
    };
    beforeEach(() => {
      component = mount(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
    });

    it('should update user name field on change event', () => {
      const event = {
        target: { value: 'dummy' },
      } as React.ChangeEvent<HTMLInputElement>;
      component.find('input[data-test-subj="user-name"]').simulate('change', event);
      component.update();
      expect(component.find('input[data-test-subj="user-name"]').prop('value')).toBe('dummy');
    });

    it('should update password field on change event', () => {
      const event = {
        target: { value: 'dummy' },
      } as React.ChangeEvent<HTMLInputElement>;
      component.find('input[data-test-subj="password"]').simulate('change', event);
      component.update();
      expect(component.find('input[data-test-subj="password"]').prop('value')).toBe('dummy');
    });
  });

  describe('handle submit event', () => {
    let component;
    const config: ClientConfigType = {
      ui: configUiDefault,
      auth: {
        type: AuthType.BASIC,
      },
    };
    beforeEach(() => {
      (validateCurrentPassword as jest.Mock).mockResolvedValue(undefined);
      component = mount(
        <LoginPage http={mockHttpStart as any} chrome={chrome} config={config as any} />
      );
    });

    it('submit click event', async () => {
      window = Object.create(window);
      const url = 'http://dummy.com';
      Object.defineProperty(window, 'location', {
        value: {
          href: url,
          protocol: 'http:',
          host: 'dummy.com',
          search: '',
          hash: '',
        },
      });
      component.find('input[data-test-subj="user-name"]').simulate('change', {
        target: { value: 'user1' },
      });
      component.find('input[data-test-subj="password"]').simulate('change', {
        target: { value: 'password1' },
      });

      await act(async () => {
        component.find('button[aria-label="basicauth_login_button"]').simulate('click', {
          preventDefault: () => {},
        });
      });
      component.update();

      expect(validateCurrentPassword).toHaveBeenCalledTimes(1);
      expect(validateCurrentPassword).toHaveBeenCalledWith(mockHttpStart, 'user1', 'password1');
    });
  });
});
