const DEFAULT_NEGATIVE_TTL = 300;
const CLEANUP_INTERVAL = 10000;

class CacheManager {
  constructor() {
    this.cache = new Map();
    this._startCleanup();
  }

  _key(name, type) {
    return `${name.toLowerCase()}:${type.toUpperCase()}`;
  }

  _startCleanup() {
    setInterval(() => {
      const now = Date.now();
      for (const [key, entry] of this.cache.entries()) {
        if (entry.ttl > 0 && now - entry.insertTime > entry.ttl * 1000) {
          this.cache.delete(key);
        }
      }
    }, CLEANUP_INTERVAL);
  }

  set(name, type, value, ttl) {
    const key = this._key(name, type);
    this.cache.set(key, {
      name,
      type,
      value,
      ttl,
      insertTime: Date.now(),
      hitCount: 0,
    });
  }

  setNegative(name, type, ttl) {
    const actualTtl = ttl || DEFAULT_NEGATIVE_TTL;
    this.set(name, type, { nxdomain: true }, actualTtl);
  }

  get(name, type) {
    const key = this._key(name, type);
    const entry = this.cache.get(key);
    if (!entry) return null;

    const elapsed = (Date.now() - entry.insertTime) / 1000;
    if (entry.ttl > 0 && elapsed >= entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    entry.hitCount += 1;
    return {
      ...entry,
      remainingTTL: Math.max(0, Math.floor(entry.ttl - elapsed)),
    };
  }

  getAll() {
    const now = Date.now();
    const results = [];
    for (const entry of this.cache.values()) {
      const elapsed = (now - entry.insertTime) / 100;
      const remainingTTL = Math.max(0, Math.floor(entry.ttl - elapsed));
      results.push({
        name: entry.name,
        type: entry.type,
        value: entry.value,
        remainingTTL,
        hitCount: entry.hitCount,
      });
    }
    return results;
  }

  clearAll() {
    this.cache.clear();
  }

  clearByName(name) {
    const target = name.toLowerCase();
    for (const [key, entry] of this.cache.entries()) {
      if (entry.name.toLowerCase() === target) {
        this.cache.delete(key);
      }
    }
  }
}

module.exports = { CacheManager, DEFAULT_NEGATIVE_TTL };
