import React, { useState, useEffect, useCallback } from 'react';
import { api } from '../api/client.js';

const CHANGE_TYPE_LABELS = {
  record_add: '新增记录',
  record_modify: '修改记录',
  record_delete: '删除记录',
  policy_add: '新增策略',
  policy_modify: '修改策略',
  policy_delete: '删除策略',
  blocklist_add: '新增黑名单',
  blocklist_delete: '删除黑名单',
  allowlist_add: '新增白名单',
  allowlist_delete: '删除白名单',
  ratelimit_add: '新增限流',
  ratelimit_modify: '修改限流',
  ratelimit_delete: '删除限流',
};

const CHANGE_TYPE_OPTIONS = [
  { value: 'record_add', label: '新增记录' },
  { value: 'record_modify', label: '修改记录' },
  { value: 'record_delete', label: '删除记录' },
  { value: 'policy_add', label: '新增策略' },
  { value: 'policy_modify', label: '修改策略' },
  { value: 'policy_delete', label: '删除策略' },
  { value: 'blocklist_add', label: '新增黑名单' },
  { value: 'blocklist_delete', label: '删除黑名单' },
  { value: 'allowlist_add', label: '新增白名单' },
  { value: 'allowlist_delete', label: '删除白名单' },
  { value: 'ratelimit_add', label: '新增限流' },
  { value: 'ratelimit_modify', label: '修改限流' },
  { value: 'ratelimit_delete', label: '删除限流' },
];

const STATUS_LABELS = {
  SUCCESS: '成功',
  NXDOMAIN: '不存在',
  REFUSED: '拒绝',
  RATE_LIMITED: '限流',
  SERVFAIL: '服务错误',
};

const STATUS_COLORS = {
  SUCCESS: '#10b981',
  NXDOMAIN: '#f59e0b',
  REFUSED: '#ef4444',
  RATE_LIMITED: '#f59e0b',
  SERVFAIL: '#ef4444',
};

const CHANGE_TYPE_LABELS_RESULT = {
  none: '无变化',
  status_change: '状态变化',
  content_change: '内容变化',
  to_nxdomain: '变为不存在',
  to_refused: '被拒绝',
  to_ratelimited: '被限流',
  to_success: '变为成功',
  policy_rewritten: '策略改写',
  policy_match_change: '命中策略变化',
  enforcement_change: '执行规则变化',
};

const CHANGE_TYPE_COLORS = {
  none: '#6b7280',
  status_change: '#f59e0b',
  content_change: '#3b82f6',
  to_nxdomain: '#ef4444',
  to_refused: '#ef4444',
  to_ratelimited: '#ef4444',
  to_success: '#10b981',
  policy_rewritten: '#8b5cf6',
  policy_match_change: '#f59e0b',
  enforcement_change: '#f59e0b',
};

function formatTime(ts) {
  if (!ts) return '-';
  return new Date(ts).toLocaleString('zh-CN');
}

function ResultDetailModal({ result, onClose }) {
  if (!result) return null;

  const renderResult = (r, label) => (
    <div style={{ flex: 1, padding: '16px', background: '#f8fafc', borderRadius: '8px' }}>
      <h4 style={{ margin: '0 0 12px 0', color: '#1e293b' }}>{label}</h4>
      <div style={{ marginBottom: '12px' }}>
        <span style={{ fontWeight: 600, color: '#64748b' }}>状态: </span>
        <span style={{ color: STATUS_COLORS[r.status] || '#64748b', fontWeight: 600 }}>
          {STATUS_LABELS[r.status] || r.status}
        </span>
      </div>
      {r.reason && (
        <div style={{ marginBottom: '12px', color: '#ef4444' }}>
          <span style={{ fontWeight: 600, color: '#64748b' }}>原因: </span>
          {r.reason}
        </div>
      )}
      {r.matchedPattern && (
        <div style={{ marginBottom: '12px' }}>
          <span style={{ fontWeight: 600, color: '#64748b' }}>匹配规则: </span>
          <code style={{ background: '#e2e8f0', padding: '2px 6px', borderRadius: '4px' }}>
            {r.matchedPattern}
          </code>
        </div>
      )}
      {r.matchedPolicyName && (
        <div style={{ marginBottom: '12px' }}>
          <span style={{ fontWeight: 600, color: '#64748b' }}>命中策略: </span>
          <code style={{ background: '#ede9fe', padding: '2px 6px', borderRadius: '4px', color: '#7c3aed' }}>
            {r.matchedPolicyName}
          </code>
        </div>
      )}
      <div style={{ marginTop: '16px' }}>
        <div style={{ fontWeight: 600, color: '#64748b', marginBottom: '8px' }}>解析结果:</div>
        <pre style={{
          background: '#1e293b',
          color: '#e2e8f0',
          padding: '12px',
          borderRadius: '8px',
          fontSize: '12px',
          overflowX: 'auto',
          maxHeight: '300px',
        }}>
          {JSON.stringify(r, null, 2)}
        </pre>
      </div>
    </div>
  );

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center',
      justifyContent: 'center', zIndex: 1000,
    }} onClick={onClose}>
      <div style={{
        background: 'white', borderRadius: '12px', padding: '24px',
        maxWidth: '1000px', width: '90%', maxHeight: '90vh', overflow: 'auto',
      }} onClick={(e) => e.stopPropagation()}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3 style={{ margin: 0 }}>
            {result.queryName} {result.queryType}
          </h3>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', fontSize: '24px', cursor: 'pointer', color: '#64748b',
          }}>&times;</button>
        </div>
        <div style={{ display: 'flex', gap: '16px' }}>
          {renderResult(result.onlineResult, '线上结果')}
          {renderResult(result.draftResult, '草稿结果')}
        </div>
        {result.rulesHitOnline?.length > 0 && (
          <div style={{ marginTop: '16px' }}>
            <h4 style={{ margin: '0 0 8px 0' }}>线上命中规则:</h4>
            {result.rulesHitOnline.map((r, i) => (
              <div key={i} style={{ background: '#fef3c7', padding: '8px 12px', borderRadius: '6px', marginBottom: '4px' }}>
                {r.type}: {r.name || r.pattern}
              </div>
            ))}
          </div>
        )}
        {result.rulesHitDraft?.length > 0 && (
          <div style={{ marginTop: '16px' }}>
            <h4 style={{ margin: '0 0 8px 0' }}>草稿命中规则:</h4>
            {result.rulesHitDraft.map((r, i) => (
              <div key={i} style={{ background: '#dbeafe', padding: '8px 12px', borderRadius: '6px', marginBottom: '4px' }}>
                {r.type}: {r.name || r.pattern}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default function PreviewWorkbench() {
  const [activeTab, setActiveTab] = useState('drafts');
  const [drafts, setDrafts] = useState([]);
  const [sampleSets, setSampleSets] = useState([]);
  const [selectedDraft, setSelectedDraft] = useState(null);
  const [selectedSampleSet, setSelectedSampleSet] = useState(null);
  const [zones, setZones] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [enforcement, setEnforcement] = useState(null);

  const [showNewDraft, setShowNewDraft] = useState(false);
  const [newDraftName, setNewDraftName] = useState('');
  const [newDraftDesc, setNewDraftDesc] = useState('');

  const [showNewSampleSet, setShowNewSampleSet] = useState(false);
  const [newSampleSetName, setNewSampleSetName] = useState('');
  const [newSampleSetDesc, setNewSampleSetDesc] = useState('');

  const [showAddChange, setShowAddChange] = useState(false);
  const [newChangeType, setNewChangeType] = useState('record_add');
  const [newChangeZoneId, setNewChangeZoneId] = useState('');
  const [newChangeTargetId, setNewChangeTargetId] = useState('');
  const [newChangeData, setNewChangeData] = useState('{}');

  const [showAddSample, setShowAddSample] = useState(false);
  const [newSampleName, setNewSampleName] = useState('');
  const [newSampleType, setNewSampleType] = useState('A');
  const [newSampleRemark, setNewSampleRemark] = useState('');

  const [latestReport, setLatestReport] = useState(null);
  const [reportResults, setReportResults] = useState([]);
  const [filterChangedOnly, setFilterChangedOnly] = useState(false);
  const [filterFailedOnly, setFilterFailedOnly] = useState(false);
  const [filterBlockedOnly, setFilterBlockedOnly] = useState(false);
  const [selectedResult, setSelectedResult] = useState(null);
  const [isRunning, setIsRunning] = useState(false);
  const [loading, setLoading] = useState({ drafts: false, samples: false, report: false });

  const loadData = useCallback(async () => {
    try {
      setLoading((l) => ({ ...l, drafts: true, samples: true }));
      const [draftsData, sampleSetsData, zonesData, policiesData, enforcementData] = await Promise.all([
        api.getDrafts(),
        api.getSampleSets(),
        api.getPreviewZones(),
        api.getPreviewPolicies(),
        api.getPreviewEnforcement(),
      ]);
      setDrafts(draftsData);
      setSampleSets(sampleSetsData);
      setZones(zonesData);
      setPolicies(policiesData);
      setEnforcement(enforcementData);
    } catch (e) {
      console.error('Failed to load data:', e);
    } finally {
      setLoading((l) => ({ ...l, drafts: false, samples: false }));
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const selectDraft = async (draft) => {
    setSelectedDraft(draft);
    if (draft) {
      try {
        const detailed = await api.getDraft(draft.id);
        setSelectedDraft(detailed);
        const reports = await api.getDraftReports(draft.id);
        if (reports.length > 0) {
          await loadReport(reports[0].id);
        } else {
          setLatestReport(null);
          setReportResults([]);
        }
      } catch (e) {
        console.error('Failed to load draft details:', e);
      }
    }
  };

  const selectSampleSet = async (set) => {
    setSelectedSampleSet(set);
    if (set) {
      try {
        const detailed = await api.getSampleSet(set.id);
        setSelectedSampleSet(detailed);
      } catch (e) {
        console.error('Failed to load sample set details:', e);
      }
    }
  };

  const loadReport = async (reportId) => {
    try {
      setLoading((l) => ({ ...l, report: true }));
      const [report, results] = await Promise.all([
        api.getReport(reportId),
        api.getReportResults(reportId),
      ]);
      setLatestReport(report);
      setReportResults(results);
    } catch (e) {
      console.error('Failed to load report:', e);
    } finally {
      setLoading((l) => ({ ...l, report: false }));
    }
  };

  const createDraft = async () => {
    if (!newDraftName.trim()) return;
    try {
      const draft = await api.createDraft({ name: newDraftName, description: newDraftDesc });
      setDrafts((prev) => [draft, ...prev]);
      setShowNewDraft(false);
      setNewDraftName('');
      setNewDraftDesc('');
      await selectDraft(draft);
    } catch (e) {
      alert('创建草稿失败: ' + e.message);
    }
  };

  const createSampleSet = async () => {
    if (!newSampleSetName.trim()) return;
    try {
      const set = await api.createSampleSet({ name: newSampleSetName, description: newSampleSetDesc });
      setSampleSets((prev) => [set, ...prev]);
      setShowNewSampleSet(false);
      setNewSampleSetName('');
      setNewSampleSetDesc('');
      await selectSampleSet(set);
    } catch (e) {
      alert('创建样本集失败: ' + e.message);
    }
  };

  const addChange = async () => {
    if (!selectedDraft) return;
    try {
      let newData = null;
      let oldData = null;
      try {
        newData = JSON.parse(newChangeData);
      } catch (e) {
        alert('JSON格式错误');
        return;
      }

      if (newChangeType.includes('_modify') || newChangeType.includes('_delete')) {
        if (!newChangeTargetId) {
          alert('请选择目标ID');
          return;
        }
        if (newChangeType.includes('_modify')) {
          const zone = zones.find((z) => z.id === newChangeZoneId);
          if (zone) {
            const rec = zone.records.find((r) => r.id === newChangeTargetId);
            if (rec) {
              oldData = { name: rec.name, type: rec.type, value: rec.value, ttl: rec.ttl };
            }
          }
        }
      }

      const change = await api.addDraftChange(selectedDraft.id, {
        changeType: newChangeType,
        targetId: newChangeTargetId || null,
        zoneId: newChangeZoneId || null,
        oldData,
        newData,
      });

      const detailed = await api.getDraft(selectedDraft.id);
      setSelectedDraft(detailed);
      setShowAddChange(false);
      setNewChangeType('record_add');
      setNewChangeZoneId('');
      setNewChangeTargetId('');
      setNewChangeData('{}');
    } catch (e) {
      alert('添加变更失败: ' + e.message);
    }
  };

  const removeChange = async (changeId) => {
    if (!selectedDraft) return;
    if (!confirm('确定删除此变更？')) return;
    try {
      await api.deleteDraftChange(selectedDraft.id, changeId);
      const detailed = await api.getDraft(selectedDraft.id);
      setSelectedDraft(detailed);
    } catch (e) {
      alert('删除变更失败: ' + e.message);
    }
  };

  const addSample = async () => {
    if (!selectedSampleSet || !newSampleName.trim()) return;
    try {
      await api.addSample(selectedSampleSet.id, {
        name: newSampleName,
        type: newSampleType,
        remark: newSampleRemark,
      });
      const detailed = await api.getSampleSet(selectedSampleSet.id);
      setSelectedSampleSet(detailed);
      const sets = await api.getSampleSets();
      setSampleSets(sets);
      setShowAddSample(false);
      setNewSampleName('');
      setNewSampleType('A');
      setNewSampleRemark('');
    } catch (e) {
      alert('添加样本失败: ' + e.message);
    }
  };

  const removeSample = async (sampleId) => {
    if (!selectedSampleSet) return;
    if (!confirm('确定删除此样本？')) return;
    try {
      await api.deleteSample(sampleId);
      const detailed = await api.getSampleSet(selectedSampleSet.id);
      setSelectedSampleSet(detailed);
      const sets = await api.getSampleSets();
      setSampleSets(sets);
    } catch (e) {
      alert('删除样本失败: ' + e.message);
    }
  };

  const runPlayback = async () => {
    if (!selectedDraft || !selectedSampleSet) {
      alert('请先选择草稿和样本集');
      return;
    }
    try {
      setIsRunning(true);
      const result = await api.runPlayback(selectedDraft.id, selectedSampleSet.id);
      setLatestReport(result.report);
      setReportResults(result.results);
      const draft = await api.getDraft(selectedDraft.id);
      setSelectedDraft(draft);
    } catch (e) {
      alert('回放失败: ' + e.message);
    } finally {
      setIsRunning(false);
    }
  };

  const publishDraft = async () => {
    if (!selectedDraft) return;
    try {
      const conflict = await api.checkConflict(selectedDraft.id);
      if (conflict.conflict) {
        if (!confirm(`检测到冲突: ${conflict.reason}\n\n是否强制发布？`)) {
          return;
        }
        await api.publishDraft(selectedDraft.id, true);
      } else {
        await api.publishDraft(selectedDraft.id, false);
      }
      alert('发布成功！');
      await loadData();
      const detailed = await api.getDraft(selectedDraft.id);
      setSelectedDraft(detailed);
    } catch (e) {
      alert('发布失败: ' + e.message);
    }
  };

  const abandonDraft = async () => {
    if (!selectedDraft) return;
    if (!confirm('确定放弃此草稿？此操作不可撤销。')) return;
    try {
      await api.abandonDraft(selectedDraft.id);
      await loadData();
      const detailed = await api.getDraft(selectedDraft.id);
      setSelectedDraft(detailed);
    } catch (e) {
      alert('放弃失败: ' + e.message);
    }
  };

  const filteredResults = reportResults.filter((r) => {
    if (filterChangedOnly && !r.statusChanged && !r.contentChanged) return false;
    if (filterFailedOnly && r.draftResult.status !== 'NXDOMAIN' && r.draftResult.status !== 'REFUSED' && r.draftResult.status !== 'SERVFAIL') return false;
    if (filterBlockedOnly && r.draftResult.status !== 'REFUSED' && r.draftResult.status !== 'RATE_LIMITED') return false;
    return true;
  });

  const summary = latestReport?.summary || {};

  const availableRecords = zones.find((z) => z.id === newChangeZoneId)?.records || [];
  const availablePolicies = policies;
  const availableBlocklist = enforcement?.blocklist || [];
  const availableAllowlist = enforcement?.allowlist || [];
  const availableRatelimit = enforcement?.ratelimit || [];

  return (
    <div className="preview-workbench" style={{ display: 'flex', flexDirection: 'column', height: '100%', background: '#f1f5f9' }}>
      <div style={{ padding: '16px 24px', background: 'white', borderBottom: '1px solid #e2e8f0', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0, color: '#1e293b' }}>变更预演与回放工作台</h2>
        <div style={{ fontSize: '14px', color: '#64748b' }}>
          安全地预览配置变更的影响，避免线上风险
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div style={{ width: '420px', background: 'white', borderRight: '1px solid #e2e8f0', display: 'flex', flexDirection: 'column' }}>
          <div style={{ borderBottom: '1px solid #e2e8f0', display: 'flex' }}>
            <button
              onClick={() => setActiveTab('drafts')}
              style={{
                flex: 1, padding: '12px', border: 'none', background: activeTab === 'drafts' ? '#eff6ff' : 'transparent',
                cursor: 'pointer', fontWeight: activeTab === 'drafts' ? 600 : 400,
                color: activeTab === 'drafts' ? '#2563eb' : '#64748b',
                borderBottom: activeTab === 'drafts' ? '2px solid #2563eb' : '2px solid transparent',
              }}
            >
              草稿变更集 ({drafts.length})
            </button>
            <button
              onClick={() => setActiveTab('samples')}
              style={{
                flex: 1, padding: '12px', border: 'none', background: activeTab === 'samples' ? '#eff6ff' : 'transparent',
                cursor: 'pointer', fontWeight: activeTab === 'samples' ? 600 : 400,
                color: activeTab === 'samples' ? '#2563eb' : '#64748b',
                borderBottom: activeTab === 'samples' ? '2px solid #2563eb' : '2px solid transparent',
              }}
            >
              查询样本集 ({sampleSets.length})
            </button>
          </div>

          <div style={{ flex: 1, overflow: 'auto', padding: '12px' }}>
            {activeTab === 'drafts' && (
              <div>
                <div style={{ marginBottom: '12px', display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => setShowNewDraft(true)}
                    style={{
                      flex: 1, padding: '10px', background: '#2563eb', color: 'white',
                      border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 500,
                    }}
                  >
                    + 新建草稿
                  </button>
                </div>

                {showNewDraft && (
                  <div style={{
                    background: '#f8fafc', padding: '12px', borderRadius: '8px',
                    marginBottom: '12px', border: '1px solid #e2e8f0',
                  }}>
                    <input
                      placeholder="草稿名称"
                      value={newDraftName}
                      onChange={(e) => setNewDraftName(e.target.value)}
                      style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box' }}
                    />
                    <textarea
                      placeholder="描述（可选）"
                      value={newDraftDesc}
                      onChange={(e) => setNewDraftDesc(e.target.value)}
                      style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box', minHeight: '60px' }}
                    />
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={createDraft}
                        style={{ flex: 1, padding: '8px', background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                      >
                        创建
                      </button>
                      <button
                        onClick={() => setShowNewDraft(false)}
                        style={{ flex: 1, padding: '8px', background: '#e2e8f0', color: '#475569', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                      >
                        取消
                      </button>
                    </div>
                  </div>
                )}

                {loading.drafts ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#64748b' }}>加载中...</div>
                ) : drafts.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#64748b' }}>暂无草稿</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {drafts.map((draft) => (
                      <div
                        key={draft.id}
                        onClick={() => selectDraft(draft)}
                        style={{
                          padding: '12px', borderRadius: '8px', cursor: 'pointer',
                          background: selectedDraft?.id === draft.id ? '#dbeafe' : 'white',
                          border: `1px solid ${selectedDraft?.id === draft.id ? '#3b82f6' : '#e2e8f0'}`,
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span style={{ fontWeight: 600, color: '#1e293b' }}>{draft.name}</span>
                          <span style={{
                            fontSize: '11px', padding: '2px 8px', borderRadius: '10px',
                            background: draft.status === 'draft' ? '#dcfce7' : draft.status === 'published' ? '#dbeafe' : '#fee2e2',
                            color: draft.status === 'draft' ? '#166534' : draft.status === 'published' ? '#1e40af' : '#991b1b',
                          }}>
                            {draft.status === 'draft' ? '草稿' : draft.status === 'published' ? '已发布' : '已放弃'}
                          </span>
                        </div>
                        <div style={{ fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>
                          快照版本: v{draft.snapshotVersion}
                        </div>
                        <div style={{ fontSize: '11px', color: '#94a3b8' }}>
                          最近回放: {formatTime(draft.lastPlaybackAt)}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {selectedDraft && (
                  <div style={{ marginTop: '16px', borderTop: '1px solid #e2e8f0', paddingTop: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                      <h4 style={{ margin: 0, color: '#1e293b' }}>变更列表</h4>
                      {selectedDraft.status === 'draft' && (
                        <button
                          onClick={() => setShowAddChange(true)}
                          style={{
                            padding: '6px 12px', background: '#10b981', color: 'white',
                            border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px',
                          }}
                        >
                          + 添加变更
                        </button>
                      )}
                    </div>

                    {showAddChange && (
                      <div style={{
                        background: '#f8fafc', padding: '12px', borderRadius: '8px',
                        marginBottom: '12px', border: '1px solid #e2e8f0',
                      }}>
                        <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>变更类型</label>
                        <select
                          value={newChangeType}
                          onChange={(e) => setNewChangeType(e.target.value)}
                          style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px' }}
                        >
                          {CHANGE_TYPE_OPTIONS.map((opt) => (
                            <option key={opt.value} value={opt.value}>{opt.label}</option>
                          ))}
                        </select>

                        {(newChangeType.startsWith('record_')) && (
                          <>
                            <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>所属Zone</label>
                            <select
                              value={newChangeZoneId}
                              onChange={(e) => { setNewChangeZoneId(e.target.value); setNewChangeTargetId(''); }}
                              style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px' }}
                            >
                              <option value="">请选择Zone</option>
                              {zones.map((z) => (
                                <option key={z.id} value={z.id}>{z.name}</option>
                              ))}
                            </select>
                          </>
                        )}

                        {(newChangeType.includes('_modify') || newChangeType.includes('_delete')) && (
                          <>
                            <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>目标ID</label>
                            <select
                              value={newChangeTargetId}
                              onChange={(e) => setNewChangeTargetId(e.target.value)}
                              style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px' }}
                            >
                              <option value="">请选择目标</option>
                              {newChangeType.startsWith('record_') && availableRecords.map((r) => (
                                <option key={r.id} value={r.id}>{r.name} {r.type} - {r.value}</option>
                              ))}
                              {newChangeType.startsWith('policy_') && availablePolicies.map((p) => (
                                <option key={p.id} value={p.id}>{p.name}</option>
                              ))}
                              {newChangeType.startsWith('blocklist_') && availableBlocklist.map((b) => (
                                <option key={b.id} value={b.id}>{b.pattern}</option>
                              ))}
                              {newChangeType.startsWith('allowlist_') && availableAllowlist.map((a) => (
                                <option key={a.id} value={a.id}>{a.pattern}</option>
                              ))}
                              {newChangeType.startsWith('ratelimit_') && availableRatelimit.map((r) => (
                                <option key={r.id} value={r.id}>{r.pattern}</option>
                              ))}
                            </select>
                          </>
                        )}

                        {!newChangeType.includes('_delete') && (
                          <>
                            <label style={{ display: 'block', fontSize: '12px', color: '#64748b', marginBottom: '4px' }}>数据 (JSON)</label>
                            <textarea
                              value={newChangeData}
                              onChange={(e) => setNewChangeData(e.target.value)}
                              style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', minHeight: '80px', fontFamily: 'monospace', fontSize: '12px', boxSizing: 'border-box' }}
                            />
                          </>
                        )}

                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            onClick={addChange}
                            style={{ flex: 1, padding: '8px', background: '#10b981', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                          >
                            添加
                          </button>
                          <button
                            onClick={() => setShowAddChange(false)}
                            style={{ flex: 1, padding: '8px', background: '#e2e8f0', color: '#475569', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                          >
                            取消
                          </button>
                        </div>
                      </div>
                    )}

                    {selectedDraft.changes?.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '20px', color: '#94a3b8', fontSize: '13px' }}>
                        暂无变更，点击上方按钮添加
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {selectedDraft.changes?.map((change) => (
                          <div key={change.id} style={{
                            background: '#f8fafc', padding: '10px', borderRadius: '6px',
                            border: '1px solid #e2e8f0', fontSize: '13px',
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                              <span style={{
                                padding: '2px 8px', borderRadius: '4px', fontSize: '11px',
                                background: '#fee2e2', color: '#991b1b',
                              }}>
                                {CHANGE_TYPE_LABELS[change.changeType] || change.changeType}
                              </span>
                              {selectedDraft.status === 'draft' && (
                                <button
                                  onClick={() => removeChange(change.id)}
                                  style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: '12px' }}
                                >
                                  删除
                                </button>
                              )}
                            </div>
                            {change.oldData && (
                              <div style={{ marginTop: '6px', fontSize: '11px', color: '#64748b' }}>
                                <div style={{ color: '#94a3b8' }}>旧值:</div>
                                <pre style={{ margin: '2px 0', padding: '4px', background: '#fef2f2', borderRadius: '4px', overflow: 'auto', fontSize: '10px' }}>
                                  {JSON.stringify(change.oldData)}
                                </pre>
                              </div>
                            )}
                            {change.newData && (
                              <div style={{ marginTop: '6px', fontSize: '11px', color: '#64748b' }}>
                                <div style={{ color: '#94a3b8' }}>新值:</div>
                                <pre style={{ margin: '2px 0', padding: '4px', background: '#f0fdf4', borderRadius: '4px', overflow: 'auto', fontSize: '10px' }}>
                                  {JSON.stringify(change.newData)}
                                </pre>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {selectedDraft.status === 'draft' && (
                      <div style={{ marginTop: '16px', display: 'flex', gap: '8px' }}>
                        <button
                          onClick={publishDraft}
                          style={{
                            flex: 1, padding: '10px', background: '#10b981', color: 'white',
                            border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 500,
                          }}
                        >
                          发布
                        </button>
                        <button
                          onClick={abandonDraft}
                          style={{
                            flex: 1, padding: '10px', background: '#ef4444', color: 'white',
                            border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 500,
                          }}
                        >
                          放弃
                        </button>
                      </div>
                    )}

                    {selectedDraft.operations?.length > 0 && (
                      <div style={{ marginTop: '16px', borderTop: '1px solid #e2e8f0', paddingTop: '16px' }}>
                        <h4 style={{ margin: '0 0 8px 0', color: '#1e293b', fontSize: '13px' }}>操作日志</h4>
                        <div style={{ maxHeight: '150px', overflow: 'auto' }}>
                          {selectedDraft.operations.map((op) => (
                            <div key={op.id} style={{
                              padding: '6px 8px', fontSize: '11px', color: '#64748b',
                              borderBottom: '1px solid #f1f5f9',
                            }}>
                              <span style={{ color: '#3b82f6' }}>[{op.operation}]</span>
                              {' '}{op.detail}
                              <div style={{ color: '#94a3b8', fontSize: '10px' }}>{formatTime(op.createdAt)}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {activeTab === 'samples' && (
              <div>
                <div style={{ marginBottom: '12px', display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => setShowNewSampleSet(true)}
                    style={{
                      flex: 1, padding: '10px', background: '#8b5cf6', color: 'white',
                      border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 500,
                    }}
                  >
                    + 新建样本集
                  </button>
                </div>

                {showNewSampleSet && (
                  <div style={{
                    background: '#f8fafc', padding: '12px', borderRadius: '8px',
                    marginBottom: '12px', border: '1px solid #e2e8f0',
                  }}>
                    <input
                      placeholder="样本集名称"
                      value={newSampleSetName}
                      onChange={(e) => setNewSampleSetName(e.target.value)}
                      style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box' }}
                    />
                    <textarea
                      placeholder="描述（可选）"
                      value={newSampleSetDesc}
                      onChange={(e) => setNewSampleSetDesc(e.target.value)}
                      style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box', minHeight: '60px' }}
                    />
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={createSampleSet}
                        style={{ flex: 1, padding: '8px', background: '#8b5cf6', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                      >
                        创建
                      </button>
                      <button
                        onClick={() => setShowNewSampleSet(false)}
                        style={{ flex: 1, padding: '8px', background: '#e2e8f0', color: '#475569', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                      >
                        取消
                      </button>
                    </div>
                  </div>
                )}

                {loading.samples ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#64748b' }}>加载中...</div>
                ) : sampleSets.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '20px', color: '#64748b' }}>暂无样本集</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {sampleSets.map((set) => (
                      <div
                        key={set.id}
                        onClick={() => selectSampleSet(set)}
                        style={{
                          padding: '12px', borderRadius: '8px', cursor: 'pointer',
                          background: selectedSampleSet?.id === set.id ? '#ede9fe' : 'white',
                          border: `1px solid ${selectedSampleSet?.id === set.id ? '#8b5cf6' : '#e2e8f0'}`,
                        }}
                      >
                        <div style={{ fontWeight: 600, color: '#1e293b', marginBottom: '4px' }}>
                          {set.name}
                        </div>
                        <div style={{ fontSize: '12px', color: '#64748b' }}>
                          {set.sampleCount || 0} 条查询样本
                        </div>
                        {set.description && (
                          <div style={{ fontSize: '11px', color: '#94a3b8', marginTop: '4px' }}>
                            {set.description}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}

                {selectedSampleSet && (
                  <div style={{ marginTop: '16px', borderTop: '1px solid #e2e8f0', paddingTop: '16px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                      <h4 style={{ margin: 0, color: '#1e293b' }}>查询样本</h4>
                      <button
                        onClick={() => setShowAddSample(true)}
                        style={{
                          padding: '6px 12px', background: '#8b5cf6', color: 'white',
                          border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '12px',
                        }}
                      >
                        + 添加样本
                      </button>
                    </div>

                    {showAddSample && (
                      <div style={{
                        background: '#f8fafc', padding: '12px', borderRadius: '8px',
                        marginBottom: '12px', border: '1px solid #e2e8f0',
                      }}>
                        <input
                          placeholder="域名"
                          value={newSampleName}
                          onChange={(e) => setNewSampleName(e.target.value)}
                          style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box' }}
                        />
                        <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
                          <select
                            value={newSampleType}
                            onChange={(e) => setNewSampleType(e.target.value)}
                            style={{ flex: 1, padding: '8px', border: '1px solid #cbd5e1', borderRadius: '6px' }}
                          >
                            {['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR'].map((t) => (
                              <option key={t} value={t}>{t}</option>
                            ))}
                          </select>
                        </div>
                        <input
                          placeholder="备注（可选）"
                          value={newSampleRemark}
                          onChange={(e) => setNewSampleRemark(e.target.value)}
                          style={{ width: '100%', padding: '8px', marginBottom: '8px', border: '1px solid #cbd5e1', borderRadius: '6px', boxSizing: 'border-box' }}
                        />
                        <div style={{ display: 'flex', gap: '8px' }}>
                          <button
                            onClick={addSample}
                            style={{ flex: 1, padding: '8px', background: '#8b5cf6', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                          >
                            添加
                          </button>
                          <button
                            onClick={() => setShowAddSample(false)}
                            style={{ flex: 1, padding: '8px', background: '#e2e8f0', color: '#475569', border: 'none', borderRadius: '6px', cursor: 'pointer' }}
                          >
                            取消
                          </button>
                        </div>
                      </div>
                    )}

                    {selectedSampleSet.samples?.length === 0 ? (
                      <div style={{ textAlign: 'center', padding: '20px', color: '#94a3b8', fontSize: '13px' }}>
                        暂无样本，点击上方按钮添加
                      </div>
                    ) : (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {selectedSampleSet.samples?.map((sample) => (
                          <div key={sample.id} style={{
                            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                            padding: '8px 10px', background: '#f8fafc', borderRadius: '6px',
                            border: '1px solid #e2e8f0', fontSize: '13px',
                          }}>
                            <div>
                              <span style={{ fontFamily: 'monospace' }}>{sample.name}</span>
                              <span style={{ color: '#8b5cf6', marginLeft: '8px', fontSize: '11px' }}>{sample.type}</span>
                              {sample.remark && (
                                <div style={{ fontSize: '11px', color: '#94a3b8' }}>{sample.remark}</div>
                              )}
                            </div>
                            <button
                              onClick={() => removeSample(sample.id)}
                              style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: '12px' }}
                            >
                              删除
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>

          <div style={{ padding: '12px', borderTop: '1px solid #e2e8f0', background: '#f8fafc' }}>
            <div style={{ marginBottom: '8px', fontSize: '12px', color: '#64748b' }}>
              <div>当前草稿: <strong>{selectedDraft?.name || '未选择'}</strong></div>
              <div>当前样本集: <strong>{selectedSampleSet?.name || '未选择'}</strong></div>
            </div>
            <button
              onClick={runPlayback}
              disabled={!selectedDraft || !selectedSampleSet || isRunning || selectedDraft?.status !== 'draft'}
              style={{
                width: '100%', padding: '12px',
                background: !selectedDraft || !selectedSampleSet || isRunning || selectedDraft?.status !== 'draft' ? '#94a3b8' : '#f59e0b',
                color: 'white', border: 'none', borderRadius: '8px', cursor: 'pointer',
                fontWeight: 600, fontSize: '14px',
              }}
            >
              {isRunning ? '回放中...' : '▶ 开始回放'}
            </button>
          </div>
        </div>

        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {!latestReport ? (
            <div style={{
              flex: 1, display: 'flex', flexDirection: 'column',
              alignItems: 'center', justifyContent: 'center', color: '#64748b',
            }}>
              <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔬</div>
              <h3 style={{ margin: '0 0 8px 0' }}>还没有回放报告</h3>
              <p style={{ margin: 0 }}>选择左侧的草稿和样本集，然后点击"开始回放"按钮</p>
            </div>
          ) : (
            <>
              <div style={{ padding: '16px', background: 'white', borderBottom: '1px solid #e2e8f0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                  <div>
                    <h3 style={{ margin: '0 0 4px 0' }}>回放报告</h3>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>
                      生成时间: {formatTime(latestReport.createdAt)}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '12px', marginBottom: '16px' }}>
                  <div style={{ background: '#eff6ff', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#2563eb' }}>{latestReport.totalSamples}</div>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>总样本数</div>
                  </div>
                  <div style={{ background: '#fef3c7', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#d97706' }}>{latestReport.changedCount}</div>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>有变化</div>
                  </div>
                  <div style={{ background: '#fee2e2', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#dc2626' }}>{latestReport.failedCount}</div>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>失败/拒绝</div>
                  </div>
                  <div style={{ background: '#fef2f2', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#b91c1c' }}>{latestReport.blockedCount}</div>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>被拦截</div>
                  </div>
                  <div style={{ background: '#f0fdf4', padding: '12px', borderRadius: '8px', textAlign: 'center' }}>
                    <div style={{ fontSize: '24px', fontWeight: 700, color: '#059669' }}>
                      {latestReport.totalSamples - latestReport.changedCount}
                    </div>
                    <div style={{ fontSize: '12px', color: '#64748b' }}>无变化</div>
                  </div>
                </div>

                {Object.keys(summary).length > 0 && (
                  <div style={{ marginBottom: '12px', padding: '12px', background: '#f8fafc', borderRadius: '8px' }}>
                    <div style={{ fontSize: '13px', fontWeight: 600, color: '#475569', marginBottom: '8px' }}>影响类型分布:</div>
                    <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                      {Object.entries(summary).map(([type, count]) => (
                        <span key={type} style={{
                          padding: '4px 10px', borderRadius: '12px', fontSize: '12px',
                          background: CHANGE_TYPE_COLORS[type] ? `${CHANGE_TYPE_COLORS[type]}20` : '#e2e8f0',
                          color: CHANGE_TYPE_COLORS[type] || '#64748b', fontWeight: 500,
                        }}>
                          {CHANGE_TYPE_LABELS_RESULT[type] || type}: {count}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <span style={{ fontSize: '13px', color: '#64748b' }}>筛选:</span>
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer',
                    padding: '4px 8px', background: filterChangedOnly ? '#dbeafe' : '#f1f5f9',
                    borderRadius: '6px', fontSize: '12px',
                  }}>
                    <input type="checkbox" checked={filterChangedOnly} onChange={(e) => setFilterChangedOnly(e.target.checked)} />
                    只看变化
                  </label>
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer',
                    padding: '4px 8px', background: filterFailedOnly ? '#fee2e2' : '#f1f5f9',
                    borderRadius: '6px', fontSize: '12px',
                  }}>
                    <input type="checkbox" checked={filterFailedOnly} onChange={(e) => setFilterFailedOnly(e.target.checked)} />
                    只看失败
                  </label>
                  <label style={{
                    display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer',
                    padding: '4px 8px', background: filterBlockedOnly ? '#fecaca' : '#f1f5f9',
                    borderRadius: '6px', fontSize: '12px',
                  }}>
                    <input type="checkbox" checked={filterBlockedOnly} onChange={(e) => setFilterBlockedOnly(e.target.checked)} />
                    只看拦截
                  </label>
                  <span style={{ marginLeft: 'auto', fontSize: '12px', color: '#64748b' }}>
                    显示 {filteredResults.length}/{reportResults.length} 条结果
                  </span>
                </div>
              </div>

              <div style={{ flex: 1, overflow: 'auto', padding: '16px' }}>
                {loading.report ? (
                  <div style={{ textAlign: 'center', padding: '40px', color: '#64748b' }}>加载报告中...</div>
                ) : filteredResults.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '40px', color: '#94a3b8' }}>没有符合条件的结果</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {filteredResults.map((result) => (
                      <div
                        key={result.id}
                        onClick={() => setSelectedResult(result)}
                        style={{
                          padding: '12px', background: 'white', borderRadius: '8px',
                          border: `1px solid ${result.statusChanged || result.contentChanged ? '#fbbf24' : '#e2e8f0'}`,
                          cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '12px',
                        }}
                      >
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                            <span style={{ fontFamily: 'monospace', fontWeight: 600 }}>{result.queryName}</span>
                            <span style={{ color: '#8b5cf6', fontSize: '12px' }}>{result.queryType}</span>
                            <span style={{
                              padding: '2px 8px', borderRadius: '10px', fontSize: '11px',
                              background: CHANGE_TYPE_COLORS[result.changeType] ? `${CHANGE_TYPE_COLORS[result.changeType]}20` : '#e2e8f0',
                              color: CHANGE_TYPE_COLORS[result.changeType] || '#64748b', fontWeight: 500,
                            }}>
                              {CHANGE_TYPE_LABELS_RESULT[result.changeType] || result.changeType}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: '24px', fontSize: '12px', color: '#64748b' }}>
                            <div>
                              线上: <span style={{ color: STATUS_COLORS[result.onlineResult?.status] || '#64748b', fontWeight: 500 }}>
                                {STATUS_LABELS[result.onlineResult?.status] || result.onlineResult?.status}
                              </span>
                              {result.onlineResult?.answer?.length > 0 && (
                                <span style={{ marginLeft: '6px' }}>
                                  {result.onlineResult.answer.map((a) => a.value).join(', ')}
                                </span>
                              )}
                            </div>
                            <div>
                              草稿: <span style={{ color: STATUS_COLORS[result.draftResult?.status] || '#64748b', fontWeight: 500 }}>
                                {STATUS_LABELS[result.draftResult?.status] || result.draftResult?.status}
                              </span>
                              {result.draftResult?.answer?.length > 0 && (
                                <span style={{ marginLeft: '6px' }}>
                                  {result.draftResult.answer.map((a) => a.value).join(', ')}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>
                        <span style={{ color: '#94a3b8', fontSize: '12px' }}>详情 →</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>

      {selectedResult && (
        <ResultDetailModal result={selectedResult} onClose={() => setSelectedResult(null)} />
      )}
    </div>
  );
}
