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

import React from 'react';
import { CoreStart } from 'opensearch-dashboards/public';
import { NavigationPublicPluginStart } from 'src/plugins/navigation/public/types';
import { ClientConfigType } from '../../types';
import { PLUGIN_NAME } from '../../../common';
import { AppDependencies } from '../types';
import { Cluster } from '../../types';
import { DataSourceOption } from 'src/plugins/data_source_management/public/components/data_source_selector/data_source_selector';

export interface TopNavMenuProps extends AppDependencies {
  dataSourcePickerReadOnly: boolean;
  setDatasourceId: (dataSource: DataSourceOption) => void;
}

export const SecurityPluginTopNavMenu = (props: TopNavMenuProps) => {
  const { coreStart, depsStart, params, dataSourceManagement, setDatasourceId } = props;
  const { setHeaderActionMenu } = params;
  const DataSourceMenu = dataSourceManagement?.ui.DataSourceMenu;
  const dataSourceEnabled = !!depsStart.dataSource?.dataSourceEnabled;

  return dataSourceEnabled ? (
    <DataSourceMenu
      showDataSourceSelectable={dataSourceEnabled}
      appName={PLUGIN_NAME}
      savedObjects={coreStart.savedObjects.client}
      setMenuMountPoint={setHeaderActionMenu}
      notifications={coreStart.notifications}
      dataSourceCallBackFunc={setDatasourceId}
      hideLocalCluster={false}
      fullWidth={false}
    />
  ) : null;
};
