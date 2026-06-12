const BASE_URL = '/api';

async function request(url, options = {}) {
  const res = await fetch(`${BASE_URL}${url}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `HTTP ${res.status}`);
  }

  return res.json();
}

export const api = {
  getZones: () => request('/zones'),
  getZone: (zoneId) => request(`/zones/${zoneId}`),
  getZoneRecords: (zoneId) => request(`/zones/${zoneId}/records`),
  getZoneSoa: (zoneId) => request(`/zones/${zoneId}/soa`),
  addRecord: (zoneId, data) =>
    request(`/zones/${zoneId}/records`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  resolve: (name, type) =>
    request('/resolve', {
      method: 'POST',
      body: JSON.stringify({ name, type }),
    }),
  getStats: () => request('/stats'),

  getDrafts: () => request('/preview/drafts'),
  getDraft: (id) => request(`/preview/drafts/${id}`),
  createDraft: (data) =>
    request('/preview/drafts', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateDraft: (id, data) =>
    request(`/preview/drafts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  addDraftChange: (draftId, data) =>
    request(`/preview/drafts/${draftId}/changes`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  deleteDraftChange: (draftId, changeId) =>
    request(`/preview/drafts/${draftId}/changes/${changeId}`, {
      method: 'DELETE',
    }),
  runPlayback: (draftId, sampleSetId) =>
    request(`/preview/drafts/${draftId}/playback`, {
      method: 'POST',
      body: JSON.stringify({ sampleSetId }),
    }),
  checkConflict: (draftId) => request(`/preview/drafts/${draftId}/conflict`),
  publishDraft: (draftId, force = false) =>
    request(`/preview/drafts/${draftId}/publish`, {
      method: 'POST',
      body: JSON.stringify({ force }),
    }),
  abandonDraft: (draftId) =>
    request(`/preview/drafts/${draftId}/abandon`, {
      method: 'POST',
    }),
  getDraftReports: (draftId) => request(`/preview/drafts/${draftId}/reports`),

  getSampleSets: () => request('/preview/sample-sets'),
  getSampleSet: (id) => request(`/preview/sample-sets/${id}`),
  createSampleSet: (data) =>
    request('/preview/sample-sets', {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateSampleSet: (id, data) =>
    request(`/preview/sample-sets/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  deleteSampleSet: (id) =>
    request(`/preview/sample-sets/${id}`, {
      method: 'DELETE',
    }),
  addSample: (sampleSetId, data) =>
    request(`/preview/sample-sets/${sampleSetId}/samples`, {
      method: 'POST',
      body: JSON.stringify(data),
    }),
  updateSample: (id, data) =>
    request(`/preview/samples/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    }),
  deleteSample: (id) =>
    request(`/preview/samples/${id}`, {
      method: 'DELETE',
    }),

  getReport: (id) => request(`/preview/reports/${id}`),
  getReportResults: (id, filters = {}) => {
    const params = new URLSearchParams(filters).toString();
    return request(`/preview/reports/${id}/results${params ? `?${params}` : ''}`);
  },

  getPreviewZones: () => request('/preview/zones'),
  getPreviewPolicies: () => request('/preview/policies'),
  getPreviewEnforcement: () => request('/preview/enforcement'),
};
