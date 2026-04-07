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
  EuiButton,
  EuiCallOut,
  EuiInMemoryTable,
  EuiModal,
  EuiModalBody,
  EuiModalFooter,
  EuiModalHeader,
  EuiModalHeaderTitle,
  EuiSpacer,
} from '@elastic/eui';
import React from 'react';
import { DashboardOption } from '../../types';
import { columns } from './dashboard-signin-options';

interface SignInOptionsModalProps {
  dashboardOptions: DashboardOption[];
  handleUpdate: (selectedOptions: DashboardOption[]) => Promise<void>;
}

function haveSameSelection(left: DashboardOption[], right: DashboardOption[]) {
  if (left.length !== right.length) {
    return false;
  }

  return left.every((option) =>
    right.some((selectedOption) => selectedOption.name === option.name)
  );
}

export function SignInOptionsModal(props: SignInOptionsModalProps) {
  const selectedOptions = React.useMemo(
    () => props.dashboardOptions.filter((option) => option.status),
    [props.dashboardOptions]
  );
  const [isModalVisible, setIsModalVisible] = React.useState(false);
  const [newSignInOptions, setNewSignInOptions] = React.useState<DashboardOption[]>(
    selectedOptions
  );

  React.useEffect(() => {
    if (!isModalVisible) {
      setNewSignInOptions(selectedOptions);
    }
  }, [isModalVisible, selectedOptions]);

  const disableUpdate = haveSameSelection(
    newSignInOptions,
    props.dashboardOptions.filter((option) => option.status)
  );

  return (
    <>
      <EuiButton
        data-test-subj="editDashboardSigninOptions"
        onClick={() => setIsModalVisible(true)}
      >
        Edit
      </EuiButton>
      {isModalVisible && (
        <EuiModal onClose={() => setIsModalVisible(false)}>
          <EuiModalHeader>
            <EuiModalHeaderTitle>Dashboards sign-in options</EuiModalHeaderTitle>
          </EuiModalHeader>
          <EuiModalBody>
            Select which configured authentication methods appear on the Dashboards login page.
            <EuiSpacer />
            {newSignInOptions.length === 0 && (
              <>
                <EuiCallOut
                  color="warning"
                  iconType="alert"
                  title="Select at least one sign-in option."
                />
                <EuiSpacer />
              </>
            )}
            <EuiInMemoryTable
              tableLayout="auto"
              columns={columns.slice(0, 1)}
              items={props.dashboardOptions}
              itemId="name"
              pagination={false}
              selection={{
                onSelectionChange: setNewSignInOptions,
                initialSelected: selectedOptions,
              }}
              sorting={{ sort: { field: 'displayName', direction: 'asc' } }}
            />
          </EuiModalBody>
          <EuiModalFooter>
            <EuiButton onClick={() => setIsModalVisible(false)}>Cancel</EuiButton>
            <EuiButton
              fill
              data-test-subj="updateDashboardSigninOptions"
              disabled={disableUpdate || newSignInOptions.length === 0}
              onClick={async () => {
                await props.handleUpdate(newSignInOptions);
                setIsModalVisible(false);
              }}
            >
              Update
            </EuiButton>
          </EuiModalFooter>
        </EuiModal>
      )}
    </>
  );
}
