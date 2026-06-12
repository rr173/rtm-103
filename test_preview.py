#!/usr/bin/env python3
import requests
import json

BASE = "http://localhost:3000/api"

def p(data):
    print(json.dumps(data, indent=2, ensure_ascii=False))

print("=" * 60)
print("1. 获取草稿列表")
print("=" * 60)
drafts = requests.get(f"{BASE}/preview/drafts").json()
draft_id = drafts[0]["id"]
print(f"草稿: {drafts[0]['name']} (id: {draft_id})")
print(f"状态: {drafts[0]['status']}")
print(f"快照版本: v{drafts[0]['snapshotVersion']}")

print("\n" + "=" * 60)
print("2. 获取草稿详情（含变更列表）")
print("=" * 60)
draft_detail = requests.get(f"{BASE}/preview/drafts/{draft_id}").json()
print(f"变更数量: {len(draft_detail['changes'])}")
for i, c in enumerate(draft_detail['changes']):
    print(f"  {i+1}. {c['changeType']}")
    if c.get('newData'):
        print(f"     新值: {json.dumps(c['newData'], ensure_ascii=False)}")

print("\n" + "=" * 60)
print("3. 获取样本集列表")
print("=" * 60)
sample_sets = requests.get(f"{BASE}/preview/sample-sets").json()
sample_set_id = sample_sets[0]["id"]
print(f"样本集: {sample_sets[0]['name']} (id: {sample_set_id})")
print(f"样本数量: {sample_sets[0]['sampleCount']}")

print("\n" + "=" * 60)
print("4. 获取样本集详情")
print("=" * 60)
sample_detail = requests.get(f"{BASE}/preview/sample-sets/{sample_set_id}").json()
for s in sample_detail['samples']:
    print(f"  - {s['name']} {s['type']} ({s.get('remark', '')})")

print("\n" + "=" * 60)
print("5. 执行回放")
print("=" * 60)
result = requests.post(
    f"{BASE}/preview/drafts/{draft_id}/playback",
    json={"sampleSetId": sample_set_id}
).json()
print(f"报告ID: {result['report']['id']}")
print(f"总样本: {result['report']['totalSamples']}")
print(f"有变化: {result['report']['changedCount']}")
print(f"失败/拒绝: {result['report']['failedCount']}")
print(f"被拦截: {result['report']['blockedCount']}")

print("\n" + "=" * 60)
print("6. 影响类型分布")
print("=" * 60)
summary = result.get('summary', {})
change_labels = {
    'none': '无变化',
    'status_change': '状态变化',
    'content_change': '内容变化',
    'to_nxdomain': '变为不存在',
    'to_refused': '被拒绝',
    'to_ratelimited': '被限流',
    'to_success': '变为成功',
    'policy_rewritten': '策略改写',
    'policy_match_change': '命中策略变化',
    'enforcement_change': '执行规则变化',
}
for k, v in summary.items():
    print(f"  {change_labels.get(k, k)}: {v}")

print("\n" + "=" * 60)
print("7. 有变化的样本详情")
print("=" * 60)
for r in result['results']:
    if r['changeType'] != 'none':
        online_val = ','.join([a['value'] for a in r['onlineResult'].get('answer',[])]) or '-'
        draft_val = ','.join([a['value'] for a in r['draftResult'].get('answer',[])]) or '-'
        print(f"\n{r['queryName']} {r['queryType']}: {change_labels.get(r['changeType'], r['changeType'])}")
        print(f"  线上: {r['onlineResult']['status']} -> {online_val}")
        print(f"  草稿: {r['draftResult']['status']} -> {draft_val}")
        if r.get('rulesHitOnline'):
            print(f"  线上命中规则: {[x.get('name') or x.get('pattern') for x in r['rulesHitOnline']]}")
        if r.get('rulesHitDraft'):
            print(f"  草稿命中规则: {[x.get('name') or x.get('pattern') for x in r['rulesHitDraft']]}")

print("\n" + "=" * 60)
print("8. 检查发布冲突")
print("=" * 60)
conflict = requests.get(f"{BASE}/preview/drafts/{draft_id}/conflict").json()
print(f"是否冲突: {conflict['conflict']}")
if conflict['conflict']:
    print(f"原因: {conflict['reason']}")

print("\n" + "=" * 60)
print("✓ 预演功能测试完成！所有API正常工作。")
print("=" * 60)
