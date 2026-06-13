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

import {
  EuiBasicTableColumn,
  EuiFlexGroup,
  EuiGlobalToastList,
  EuiHealth,
  EuiHorizontalRule,
  EuiInMemoryTable,
  EuiPageContentHeader,
  EuiPageContentHeaderSection,
  EuiPanel,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { get, keys } from 'lodash';
import { HttpStart } from 'opensearch-dashboards/public';
import React from 'react';
import { updateDashboardSignInOptions } from '../../../../utils/dashboards-info-utils';
import { DashboardOption, DashboardSignInOption } from '../../types';
import { createErrorToast, createSuccessToast, useToastState } from '../../utils/toast-utils';
import { SignInOptionsModal } from './signin-options-modal';

interface SignInOptionsPanelProps {
  authc: [];
  signInEnabledOptions: DashboardSignInOption[];
  http: HttpStart;
  isAnonymousAuthEnabled: boolean;
}

const OPTION_LABELS: Record<DashboardSignInOption, string> = {
  [DashboardSignInOption.BASIC]: 'Basic authentication',
  [DashboardSignInOption.OPEN_ID]: 'OpenID Connect',
  [DashboardSignInOption.SAML]: 'SAML',
  [DashboardSignInOption.ANONYMOUS]: 'Anonymous',
};

export const columns: Array<EuiBasicTableColumn<DashboardOption>> = [
  {
    field: 'displayName',
    name: 'Name',
    dataType: 'string',
    sortable: true,
  },
  {
    field: 'status',
    name: 'Status',
    render: (enabled: DashboardOption['status']) => (
      <EuiHealth color={enabled ? 'success' : 'subdued'}>
        {enabled ? 'Enabled' : 'Disabled'}
      </EuiHealth>
    ),
  },
];

function getDashboardOptions(
  authc: [],
  enabledOptions: DashboardSignInOption[],
  isAnonymousAuthEnabled: boolean
) {
  const options = keys(authc)
    .map((domain) => get(authc, [domain, 'http_authenticator', 'type']))
    .filter((option): option is string => Boolean(option))
    .map((option) => {
      switch (option.toLowerCase()) {
        case 'basic':
        case DashboardSignInOption.BASIC:
          return DashboardSignInOption.BASIC;
        case DashboardSignInOption.OPEN_ID:
          return DashboardSignInOption.OPEN_ID;
        case DashboardSignInOption.SAML:
          return DashboardSignInOption.SAML;
        default:
          return undefined;
      }
    })
    .filter((option): option is DashboardSignInOption => Boolean(option))
    .filter((option): option is DashboardSignInOption =>
      [
        DashboardSignInOption.BASIC,
        DashboardSignInOption.OPEN_ID,
        DashboardSignInOption.SAML,
      ].includes(option as DashboardSignInOption)
    )
    .filter((option, index, arr) => arr.indexOf(option) === index)
    .map((option) => ({
      name: option,
      displayName: OPTION_LABELS[option],
      status: enabledOptions.includes(option),
    }));

  if (isAnonymousAuthEnabled) {
    options.push({
      name: DashboardSignInOption.ANONYMOUS,
      displayName: OPTION_LABELS[DashboardSignInOption.ANONYMOUS],
      status: enabledOptions.includes(DashboardSignInOption.ANONYMOUS),
    });
  }

  return options.sort((a, b) => a.displayName.localeCompare(b.displayName));
}

export function SignInOptionsPanel(props: SignInOptionsPanelProps) {
  const [toasts, addToast, removeToast] = useToastState();
  const [dashboardOptions, setDashboardOptions] = React.useState<DashboardOption[]>(() =>
    getDashboardOptions(props.authc, props.signInEnabledOptions, props.isAnonymousAuthEnabled)
  );

  React.useEffect(() => {
    setDashboardOptions(
      getDashboardOptions(props.authc, props.signInEnabledOptions, props.isAnonymousAuthEnabled)
    );
  }, [props.authc, props.signInEnabledOptions, props.isAnonymousAuthEnabled]);

  const handleUpdate = async (selectedOptions: DashboardOption[]) => {
    const selectedNames = selectedOptions.map((option) => option.name);

    try {
      await updateDashboardSignInOptions(props.http, selectedNames);
      setDashboardOptions((currentOptions) =>
        currentOptions.map((option) => ({
          ...option,
          status: selectedNames.includes(option.name),
        }))
      );
      addToast(
        createSuccessToast(
          'dashboard-signin-options-success',
          'Dashboards sign-in options updated',
          'Changes applied.'
        )
      );
    } catch (error) {
      addToast(
        createErrorToast(
          'dashboard-signin-options-error',
          'Dashboards sign-in options not updated',
          error instanceof Error ? error.message : 'Error updating values.'
        )
      );
    }
  };

  return (
    <EuiPanel>
      <EuiPageContentHeader>
        <EuiPageContentHeaderSection>
          <EuiTitle size="s">
            <h3>Dashboards sign-in options</h3>
          </EuiTitle>
          <EuiText size="xs" color="subdued">
            <p>
              Choose which configured authentication methods appear on the Dashboards login page.
            </p>
          </EuiText>
        </EuiPageContentHeaderSection>
        <EuiPageContentHeaderSection>
          <EuiFlexGroup responsive={false}>
            <SignInOptionsModal dashboardOptions={dashboardOptions} handleUpdate={handleUpdate} />
          </EuiFlexGroup>
        </EuiPageContentHeaderSection>
      </EuiPageContentHeader>
      <EuiHorizontalRule margin="m" />
      <EuiInMemoryTable
        tableLayout="auto"
        columns={columns}
        items={dashboardOptions}
        itemId="name"
        pagination={false}
        sorting={{ sort: { field: 'displayName', direction: 'asc' } }}
      />
      <EuiGlobalToastList toasts={toasts} toastLifeTimeMs={3000} dismissToast={removeToast} />
    </EuiPanel>
  );
}
