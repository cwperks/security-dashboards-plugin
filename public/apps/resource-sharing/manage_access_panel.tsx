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

/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiComboBox,
  EuiComboBoxOptionOption,
  EuiFormRow,
  EuiHorizontalRule,
  EuiLoadingSpinner,
  EuiSelect,
  EuiSpacer,
  EuiText,
  EuiTitle,
} from '@elastic/eui';
import { HttpStart } from '../../../../../src/core/public';

const RESOURCE_API_BASE = '/api/resource';

interface AccessLevelEntry {
  accessLevel: string;
  users: string[];
  roles: string[];
}

function normalizeList(values?: string[]): string[] {
  return [...new Set(values ?? [])].filter(Boolean).sort();
}

function formatAccessLevel(al: string): string {
  // Strip resource type prefix (e.g. "visualization_view" → "View", "dashboard_full_access" → "Full access")
  const stripped = al.replace(/^(dashboard|visualization|report[_-]?\w*)_/i, '');
  return stripped.charAt(0).toUpperCase() + stripped.slice(1).replace(/_/g, ' ');
}

function toOptions(values: string[]): Array<EuiComboBoxOptionOption<string>> {
  return values.map((v) => ({ label: v }));
}

function fromOptions(options: Array<EuiComboBoxOptionOption<string>>): string[] {
  return normalizeList(options.map((o) => o.label));
}

interface Props {
  http: HttpStart;
  objectId: string;
  objectType: string;
  currentUsername?: string;
}

export function ManageAccessPanel({ http, objectId, objectType, currentUsername }: Props) {
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [supported, setSupported] = useState(false);
  const [accessLevels, setAccessLevels] = useState<string[]>([]);
  const [generalAccess, setGeneralAccess] = useState<string | null>(null);
  const [entries, setEntries] = useState<AccessLevelEntry[]>([]);
  const [initialSignature, setInitialSignature] = useState('');
  const [saveSuccess, setSaveSuccess] = useState(false);
  const [canShare, setCanShare] = useState(true);

  const qualifiedId = `${objectType}:${objectId}`;

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [typesResp, sharingResp] = await Promise.all([
          http.get(`${RESOURCE_API_BASE}/types`).catch(() => ({ types: [] })),
          http
            .get(`${RESOURCE_API_BASE}/view`, {
              query: { resourceId: qualifiedId, resourceType: objectType },
            })
            .catch(() => null),
        ]);
        if (cancelled) return;

        const typeConfig = (typesResp as any).types?.find((t: any) => t.type === objectType);
        if (!typeConfig) {
          setSupported(false);
          setIsLoading(false);
          return;
        }

        setSupported(true);
        setAccessLevels(typeConfig.access_levels ?? []);

        const shareWith = (sharingResp as any)?.sharing_info?.share_with;
        const owner = (sharingResp as any)?.sharing_info?.created_by?.user;
        setCanShare(!currentUsername || owner === currentUsername);
        console.log('[ManageAccess] objectId:', objectId, 'objectType:', objectType);
        console.log('[ManageAccess] sharingResp:', JSON.stringify(sharingResp));
        console.log('[ManageAccess] shareWith:', JSON.stringify(shareWith));
        const ga =
          shareWith && typeof shareWith.general_access === 'string'
            ? shareWith.general_access
            : null;
        const parsed = Object.entries(shareWith ?? {})
          .filter(([k]) => k !== 'general_access')
          .map(([al, r]: [string, any]) => ({
            accessLevel: al,
            users: normalizeList(r?.users),
            roles: normalizeList(r?.roles),
          }))
          .filter((e) => e.users.length > 0 || e.roles.length > 0);

        setGeneralAccess(ga);
        setEntries(parsed);
        setInitialSignature(JSON.stringify({ generalAccess: ga, entries: parsed }));
      } catch (e: any) {
        if (!cancelled) setError(e?.body?.message ?? e?.message ?? 'Failed to load sharing info');
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [http, objectId, objectType]);

  const currentSignature = JSON.stringify({ generalAccess, entries });
  const hasChanges = currentSignature !== initialSignature;
  console.log(
    '[ManageAccess] hasChanges:',
    hasChanges,
    'current:',
    currentSignature,
    'initial:',
    initialSignature
  );

  async function handleSave() {
    setIsSaving(true);
    setError(null);
    setSaveSuccess(false);
    try {
      await http.post(`${RESOURCE_API_BASE}/patch_sharing`, {
        body: JSON.stringify({
          resource_id: qualifiedId,
          resource_type: objectType,
          general_access: generalAccess,
        }),
      });
      setInitialSignature(currentSignature);
      setSaveSuccess(true);
    } catch (e: any) {
      setError(e?.body?.message ?? e?.message ?? 'Failed to save');
    } finally {
      setIsSaving(false);
    }
  }

  if (isLoading) {
    return (
      <div style={{ padding: 16, textAlign: 'center' }}>
        <EuiLoadingSpinner size="l" />
      </div>
    );
  }

  if (!supported) {
    return (
      <div style={{ padding: 16 }}>
        <EuiText size="s" color="subdued">
          Access management is not available for this {objectType}.
        </EuiText>
      </div>
    );
  }

  return (
    <div style={{ padding: 16, maxHeight: 500, overflowY: 'auto' }}>
      {error && (
        <>
          <EuiCallOut color="danger" iconType="alert" title={error} size="s" />
          <EuiSpacer size="s" />
        </>
      )}
      {saveSuccess && (
        <>
          <EuiCallOut color="success" iconType="check" title="Sharing updated" size="s" />
          <EuiSpacer size="s" />
        </>
      )}

      <EuiFormRow label="General access" compressed>
        <EuiSelect
          compressed
          disabled={!canShare}
          value={generalAccess ?? ''}
          options={[
            { value: '', text: 'Private (only owner)' },
            ...accessLevels
              .filter((al) => !al.includes('full_access'))
              .map((al) => ({ value: al, text: 'Anyone can ' + formatAccessLevel(al).toLowerCase() })),
          ]}
          onChange={(e) => setGeneralAccess(e.target.value || null)}
        />
      </EuiFormRow>

      {accessLevels.length > 0 && (
        <>
          <EuiSpacer size="m" />
          <EuiHorizontalRule margin="s" />
          <EuiTitle size="xxs">
            <h4>Share with specific users or roles</h4>
          </EuiTitle>
          <EuiSpacer size="s" />

          {entries.map((entry, idx) => (
            <React.Fragment key={idx}>
              <EuiFormRow label="Access level" compressed>
                <EuiSelect
                  compressed
                  value={entry.accessLevel}
                  options={accessLevels.map((al) => ({
                    value: al,
                    text: formatAccessLevel(al),
                  }))}
                  onChange={(e) => {
                    const next = [...entries];
                    next[idx] = { ...entry, accessLevel: e.target.value };
                    setEntries(next);
                  }}
                />
              </EuiFormRow>
              <EuiFormRow label="Users" compressed>
                <EuiComboBox
                  compressed
                  noSuggestions
                  selectedOptions={toOptions(entry.users)}
                  onCreateOption={(v) => {
                    const next = [...entries];
                    next[idx] = { ...entry, users: normalizeList([...entry.users, v]) };
                    setEntries(next);
                  }}
                  onChange={(opts) => {
                    const next = [...entries];
                    next[idx] = { ...entry, users: fromOptions(opts) };
                    setEntries(next);
                  }}
                />
              </EuiFormRow>
              <EuiFormRow label="Roles" compressed>
                <EuiComboBox
                  compressed
                  noSuggestions
                  selectedOptions={toOptions(entry.roles)}
                  onCreateOption={(v) => {
                    const next = [...entries];
                    next[idx] = { ...entry, roles: normalizeList([...entry.roles, v]) };
                    setEntries(next);
                  }}
                  onChange={(opts) => {
                    const next = [...entries];
                    next[idx] = { ...entry, roles: fromOptions(opts) };
                    setEntries(next);
                  }}
                />
              </EuiFormRow>
              <EuiButtonEmpty
                color="danger"
                size="s"
                iconType="trash"
                onClick={() => setEntries(entries.filter((_, i) => i !== idx))}
              >
                Remove
              </EuiButtonEmpty>
              <EuiSpacer size="s" />
            </React.Fragment>
          ))}

          {canShare && accessLevels.length > entries.length && (
            <EuiButtonEmpty
              size="s"
              iconType="plusInCircle"
              onClick={() => {
                const next = accessLevels.find((al) => !entries.some((e) => e.accessLevel === al));
                if (next) setEntries([...entries, { accessLevel: next, users: [], roles: [] }]);
              }}
            >
              Add access level
            </EuiButtonEmpty>
          )}
        </>
      )}

      <EuiSpacer size="m" />
      {!canShare && (
        <EuiText size="s" color="subdued">
          You do not have permission to modify sharing for this resource.
        </EuiText>
      )}
      {canShare && (
        <EuiButton
          fill
          size="s"
          fullWidth
          isLoading={isSaving}
          isDisabled={!hasChanges}
          onClick={handleSave}
        >
          Save
        </EuiButton>
      )}
    </div>
  );
}
