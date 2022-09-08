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
import { interceptError } from '../plugin';
import { setShouldShowTenantPopup } from '../utils/storage-utils';

jest.mock('../utils/storage-utils', () => ({
  setShouldShowTenantPopup: jest.fn(),
}));

describe('Session timeout', () => {
  const mockCoreStart = {
    http: 1,
  };

  const fakeError = {
    response: {
      status: undefined,
    },
  };

  let setShouldShowTenantPopupSpy;

  let windowSpy;

  beforeEach(() => {
    windowSpy = jest.spyOn(window, "window", "get");
    setShouldShowTenantPopupSpy = jest.spyOn(setShouldShowTenantPopup);
    // useStateSpy.mockImplementation((init) => [init, setState]);
  });

  afterEach(() => {
    windowSpy.mockRestore();
    jest.clearAllMocks();
  });

  it('should not set modal when show popup is true', () => {
    fakeError.response.status = 401;
    windowSpy.mockImplementation(() => ({
      location: {
        origin: "https://example.com",
        pathname: "/"
      }
    }));

    let sessionTimeoutFn = interceptError("http://localhost:5601/app/logout", windowSpy)
    sessionTimeoutFn(fakeError, null);
    expect(setShouldShowTenantPopup).toBeCalledTimes(1);
  });
});
