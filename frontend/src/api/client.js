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
};
