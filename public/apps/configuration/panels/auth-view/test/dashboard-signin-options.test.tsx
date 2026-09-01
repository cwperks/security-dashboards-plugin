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

import { shallow } from 'enzyme';
import React from 'react';
import { EuiCallOut } from '@elastic/eui';
import { SignInOptionsPanel } from '../dashboard-signin-options';
import { SignInOptionsModal } from '../signin-options-modal';
import { DashboardSignInOption } from '../../../types';
import { updateDashboardSignInOptions } from '../../../../../utils/dashboards-info-utils';

jest.mock('../../../../../utils/dashboards-info-utils', () => ({
  updateDashboardSignInOptions: jest.fn(),
}));

describe('SignInOptionsPanel', () => {
  const authc = {
    basic_auth_domain: {
      http_authenticator: {
        type: 'basic',
      },
    },
    saml_auth_domain: {
      http_authenticator: {
        type: 'saml',
      },
    },
  };

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('builds table items from auth domains and enabled options', () => {
    const component = shallow(
      <SignInOptionsPanel
        authc={authc as any}
        signInEnabledOptions={[DashboardSignInOption.BASIC]}
        http={{} as any}
        isAnonymousAuthEnabled={true}
      />
    );

    const items = component.find('EuiInMemoryTable').prop('items') as Array<{ name: string }>;
    expect(items.map((item) => item.name)).toEqual([
      DashboardSignInOption.ANONYMOUS,
      DashboardSignInOption.BASIC,
      DashboardSignInOption.SAML,
    ]);
  });

  it('updates selected sign-in options', async () => {
    (updateDashboardSignInOptions as jest.Mock).mockResolvedValue({ message: 'ok' });

    const component = shallow(
      <SignInOptionsPanel
        authc={authc as any}
        signInEnabledOptions={[DashboardSignInOption.BASIC]}
        http={{} as any}
        isAnonymousAuthEnabled={false}
      />
    );

    const handleUpdate = component.find(SignInOptionsModal).prop('handleUpdate') as (
      selectedOptions: Array<{ name: DashboardSignInOption; displayName: string; status: boolean }>
    ) => Promise<void>;

    await handleUpdate([
      {
        name: DashboardSignInOption.SAML,
        displayName: 'SAML',
        status: false,
      },
    ]);

    expect(updateDashboardSignInOptions).toHaveBeenCalledWith({}, [DashboardSignInOption.SAML]);
  });
});

describe('SignInOptionsModal', () => {
  const dashboardOptions = [
    {
      name: DashboardSignInOption.BASIC,
      displayName: 'Basic authentication',
      status: true,
    },
    {
      name: DashboardSignInOption.SAML,
      displayName: 'SAML',
      status: false,
    },
  ];

  it('shows a warning and disables update when no options are selected', () => {
    const component = shallow(
      <SignInOptionsModal
        dashboardOptions={dashboardOptions}
        handleUpdate={jest.fn().mockResolvedValue(undefined)}
      />
    );

    component.find('EuiButton[data-test-subj="editDashboardSigninOptions"]').simulate('click');

    const selectionConfig = component.find('EuiInMemoryTable').prop('selection') as {
      onSelectionChange: (selectedOptions: typeof dashboardOptions) => void;
    };

    selectionConfig.onSelectionChange([]);
    component.update();

    expect(component.find(EuiCallOut).prop('title')).toBe('Select at least one sign-in option.');
    expect(
      component.find('EuiButton[data-test-subj="updateDashboardSigninOptions"]').prop('disabled')
    ).toBe(true);
  });
});
