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

import { parse } from 'url';
import { ParsedUrlQuery } from 'querystring';
import { OpenSearchDashboardsRequest } from 'opensearch-dashboards/server';
import { encodeUriQuery } from '../../../../src/plugins/opensearch_dashboards_utils/common/url/encode_uri_query';

export function composeNextUrlQueryParam(
  request: OpenSearchDashboardsRequest,
  basePath: string
): string {
  try {
    const currentUrl = request.url.toString();
    const parsedUrl = parse(currentUrl, true);
    const nextUrl = parsedUrl?.path;

    if (!!nextUrl && nextUrl !== '/') {
      return `nextUrl=${encodeUriQuery(basePath + nextUrl)}`;
    }
  } catch (error) {
    /* Ignore errors from parsing */
  }
  return '';
}

export interface ParsedUrlQueryParams extends ParsedUrlQuery {
  nextUrl: string;
}

export const INVALID_NEXT_URL_PARAMETER_MESSAGE = 'Invalid nextUrl parameter.';

/**
 * We require the nextUrl parameter to be an relative url.
 *
 * Here we validate the nextUrl parameter by checking if it meets the following criteria:
 *   - nextUrl is the basePath /
 *   - If nextUrl is longer than 2 chars then the second character must be alphabetical or underscore
 *   - The following characters must be alphanumeric, dash or underscore
 * Note: url has been decoded by OpenSearchDashboards.
 *
 * @param url url string.
 * @returns error message if nextUrl is invalid, otherwise void.
 */
export const validateNextUrl = (url: string | undefined): string | void => {
  if (url) {
    const path = url.split(/\?|#/)[0];
    if (
      !path.startsWith('/') ||
      (path.length >= 2 && !/^\/[a-zA-Z_][\/a-zA-Z0-9-_]+$/.test(path))
    ) {
      return INVALID_NEXT_URL_PARAMETER_MESSAGE;
    }
  }
};
