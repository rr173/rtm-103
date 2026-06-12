const db = require('../db/database');
const ip = require('ip');

const MAX_REDIRECT_DEPTH = 3;
const MAX_POLICY_LOGS = 10000;

function normalizeName(name) {
  let n = name.toLowerCase();
  if (n !== '.' && n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

function parseCronField(field, min, max) {
  if (!field || field === '*') return null;
  const values = new Set();
  const parts = field.split(',');
  for (const part of parts) {
    if (part.includes('-')) {
      const [start, end] = part.split('-').map(Number);
      for (let i = start; i <= end; i++) {
        if (i >= min && i <= max) values.add(i);
      }
    } else if (part.includes('/')) {
      const [range, step] = part.split('/');
      const stepNum = parseInt(step, 10);
      let start = 0;
      let end = max;
      if (range !== '*') {
        [start, end] = range.split('-').map(Number);
      }
      for (let i = start; i <= end; i += stepNum) {
        if (i >= min && i <= max) values.add(i);
      }
    } else {
      const val = parseInt(part, 10);
      if (val >= min && val <= max) values.add(val);
    }
  }
  return values;
}

function matchTimeWindow(timeWindow) {
  if (!timeWindow) return true;
  const parts = timeWindow.trim().split(/\s+/);
  const hourField = parts[0] || '*';
  const minuteField = parts[1] || '*';
  const dowField = parts[2] || '*';

  const now = new Date();
  const currentHour = now.getHours();
  const currentMinute = now.getMinutes();
  const currentDow = now.getDay();

  const hours = parseCronField(hourField, 0, 23);
  const minutes = parseCronField(minuteField, 0, 59);
  const dows = parseCronField(dowField, 0, 6);

  if (hours && !hours.has(currentHour)) return false;
  if (minutes && !minutes.has(currentMinute)) return false;
  if (dows && !dows.has(currentDow)) return false;

  return true;
}

function matchDomainPattern(domain, pattern) {
  if (!pattern) return true;
  const d = normalizeName(domain);
  const p = pattern.toLowerCase();

  if (p === d) return true;

  if (p.startsWith('*.')) {
    const suffix = p.slice(2);
    return d.endsWith('.' + suffix) || d === suffix;
  }

  if (p.startsWith('/') && p.endsWith('/')) {
    try {
      const regex = new RegExp(p.slice(1, -1), 'i');
      return regex.test(d);
    } catch (e) {
      return false;
    }
  }

  return false;
}

function matchRecordType(queryType, ruleType) {
  if (!ruleType) return true;
  return queryType.toUpperCase() === ruleType.toUpperCase();
}

function matchResponseRegex(answers, regexPattern) {
  if (!regexPattern) return true;
  if (!answers || answers.length === 0) return false;

  let regex;
  try {
    regex = new RegExp(regexPattern, 'i');
  } catch (e) {
    return false;
  }

  for (const answer of answers) {
    if (answer.value && regex.test(answer.value)) {
      return true;
    }
  }
  return false;
}

function matchPolicy(policy, queryName, queryType, answers) {
  if (!policy.enabled) return false;

  if (!matchDomainPattern(queryName, policy.domainPattern)) return false;
  if (!matchRecordType(queryType, policy.recordType)) return false;
  if (!matchTimeWindow(policy.timeWindow)) return false;
  if (!matchResponseRegex(answers, policy.responseRegex)) return false;

  return true;
}

function executeRewrite(answers, policy) {
  const params = policy.actionParams || {};
  const template = params.template || '';
  const regexPattern = policy.responseRegex;

  let regex;
  if (regexPattern) {
    try {
      regex = new RegExp(regexPattern, 'i');
    } catch (e) {
      return answers;
    }
  }

  return answers.map((answer) => {
    if (!answer.value) return answer;

    if (regex) {
      const match = answer.value.match(regex);
      if (match) {
        let newValue = template;
        for (let i = 0; i < match.length; i++) {
          newValue = newValue.replace(new RegExp(`\\$${i}`, 'g'), match[i] || '');
        }
        return { ...answer, value: newValue };
      }
    } else {
      return { ...answer, value: template };
    }
    return answer;
  });
}

function executeNxdomain() {
  return {
    status: 'NXDOMAIN',
    answer: [],
    authority: [],
  };
}

function executePassthrough() {
  return null;
}

function isIpInCidr(ipStr, cidr) {
  try {
    return ip.cidrSubnet(cidr).contains(ipStr);
  } catch (e) {
    return false;
  }
}

function matchIpRange(answers, cidr) {
  if (!answers || answers.length === 0) return false;
  for (const answer of answers) {
    if (answer.type === 'A' || answer.type === 'AAAA') {
      if (isIpInCidr(answer.value, cidr)) {
        return true;
      }
    }
  }
  return false;
}

class PolicyEngine {
  constructor(resolver) {
    this.resolver = resolver;
  }

  async applyPolicies(queryName, queryType, result, _redirectDepth = 0) {
    const originalAnswer = result.answer ? [...result.answer] : [];
    const originalStatus = result.status;
    const policies = db.listPolicies();
    const enabledPolicies = policies.filter((p) => p.enabled);

    let matchedPolicyId = null;
    let executedAction = 'none';
    let modifiedAnswer = originalAnswer;
    let modifiedStatus = originalStatus;
    let modifiedAuthority = result.authority ? [...result.authority] : [];
    let passthrough = false;
    let redirectChain = [];

    for (const policy of enabledPolicies) {
      if (passthrough) break;

      const matches = matchPolicy(policy, queryName, queryType, modifiedAnswer);

      if (!matches) continue;

      matchedPolicyId = policy.id;
      executedAction = policy.action;
      db.incrementPolicyHit(policy.id);

      switch (policy.action) {
        case 'rewrite':
          modifiedAnswer = executeRewrite(modifiedAnswer, policy);
          break;

        case 'redirect':
          if (_redirectDepth >= MAX_REDIRECT_DEPTH) {
            executedAction = 'redirect_limit_exceeded';
            break;
          }
          const params = policy.actionParams || {};
          const targetDomain = params.targetDomain;
          if (targetDomain) {
            const redirectResolveResult = await this.resolver.resolve(
              targetDomain,
              queryType,
              false
            );
            const policyAppliedResult = await this.applyPolicies(
              targetDomain,
              queryType,
              redirectResolveResult,
              _redirectDepth + 1
            );
            modifiedAnswer = policyAppliedResult.answer || [];
            modifiedAuthority = policyAppliedResult.authority || [];
            modifiedStatus = policyAppliedResult.status;
            redirectChain = [policy.id, ...(policyAppliedResult.redirectChain || [])];
            if (policyAppliedResult.executedAction) {
              executedAction = `redirect->${policyAppliedResult.executedAction}`;
            }
          }
          break;

        case 'nxdomain':
          const nxResult = executeNxdomain();
          modifiedAnswer = nxResult.answer;
          modifiedAuthority = nxResult.authority;
          modifiedStatus = nxResult.status;
          break;

        case 'passthrough':
          passthrough = true;
          break;
      }

      break;
    }

    const logEntry = {
      queryName,
      queryType,
      policyId: matchedPolicyId,
      action: executedAction,
      originalAnswer,
      modifiedAnswer: modifiedAnswer !== originalAnswer ? modifiedAnswer : null,
    };
    db.addPolicyLog(logEntry);
    this.trimPolicyLogs();

    return {
      ...result,
      status: modifiedStatus,
      answer: modifiedAnswer,
      authority: modifiedAuthority,
      policyApplied: matchedPolicyId !== null,
      matchedPolicyId,
      executedAction,
      redirectChain,
    };
  }

  trimPolicyLogs() {
    db.trimPolicyLogs(MAX_POLICY_LOGS);
  }

  matchTimeWindow(timeWindow) {
    return matchTimeWindow(timeWindow);
  }

  matchDomainPattern(domain, pattern) {
    return matchDomainPattern(domain, pattern);
  }
}

module.exports = {
  PolicyEngine,
  matchTimeWindow,
  matchDomainPattern,
  matchRecordType,
  matchResponseRegex,
  matchPolicy,
  isIpInCidr,
  matchIpRange,
};
