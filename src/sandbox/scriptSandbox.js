const vm = require('vm');

const DEFAULT_TIMEOUT_MS = 5000;
const DEFAULT_MAX_CONCURRENT = 5;
const VALID_DNS_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR', 'ANY'];

class PermissionError extends Error {
  constructor(message) {
    super(message);
    this.name = 'PermissionError';
    this.code = 'ERR_PERMISSION_DENIED';
  }
}

function createDeniedHandler(objectName, propertyName) {
  return function denied() {
    throw new PermissionError(
      `Permission denied: access to '${objectName}.${propertyName}' is not allowed in sandbox. ` +
      `File I/O, network requests, and process operations are restricted.`
    );
  };
}

function createDeniedObject(objectName, propertyNames) {
  const obj = {};
  for (const prop of propertyNames) {
    Object.defineProperty(obj, prop, {
      get: createDeniedHandler(objectName, prop),
      set: createDeniedHandler(objectName, prop),
      enumerable: false,
      configurable: false,
    });
  }
  return new Proxy(obj, {
    get(_target, prop) {
      if (typeof prop === 'symbol') return undefined;
      throw new PermissionError(
        `Permission denied: access to '${objectName}.${String(prop)}' is not allowed in sandbox. ` +
        `File I/O, network requests, and process operations are restricted.`
      );
    },
    set(_target, prop) {
      if (typeof prop === 'symbol') return false;
      throw new PermissionError(
        `Permission denied: access to '${objectName}.${String(prop)}' is not allowed in sandbox. ` +
        `File I/O, network requests, and process operations are restricted.`
      );
    },
  });
}

function createSafeConsole() {
  const safeLog = (level, args) => {
    const serialized = args.map((a) => {
      try {
        if (typeof a === 'object') {
          return JSON.stringify(a, null, 2);
        }
        return String(a);
      } catch (e) {
        return String(a);
      }
    }).join(' ');
    return `[${level}] ${serialized}`;
  };

  const logLines = [];

  const push = (line) => {
    logLines.push(line);
    if (logLines.length > 1000) {
      logLines.shift();
    }
  };

  return {
    _logs: logLines,
    log: (...args) => push(safeLog('log', args)),
    info: (...args) => push(safeLog('info', args)),
    warn: (...args) => push(safeLog('warn', args)),
    error: (...args) => push(safeLog('error', args)),
    debug: (...args) => push(safeLog('debug', args)),
  };
}

class ScriptSandbox {
  constructor(resolver, options = {}) {
    this.resolver = resolver;
    this.timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;
    this.maxConcurrent = options.maxConcurrent || DEFAULT_MAX_CONCURRENT;
    this._runningCount = 0;
  }

  getStats() {
    return {
      running: this._runningCount,
      maxConcurrent: this.maxConcurrent,
      timeoutMs: this.timeoutMs,
    };
  }

  _createDnsApi() {
    const resolve = async (name, type = 'A') => {
      const queryType = String(type).toUpperCase();
      if (!VALID_DNS_TYPES.includes(queryType)) {
        throw new Error(`Invalid DNS type. Must be one of: ${VALID_DNS_TYPES.join(', ')}`);
      }
      if (!name || typeof name !== 'string') {
        throw new Error('Domain name must be a non-empty string');
      }
      return this.resolver.resolve(name, queryType, false);
    };

    const resolveBatch = async (queries) => {
      if (!Array.isArray(queries)) {
        throw new Error('resolveBatch expects an array of queries');
      }
      if (queries.length > 100) {
        throw new Error('Maximum 100 queries per batch');
      }
      const results = [];
      for (const q of queries) {
        try {
          if (typeof q === 'string') {
            results.push({ query: { name: q, type: 'A' }, result: await resolve(q, 'A') });
          } else if (q && typeof q === 'object') {
            results.push({ query: q, result: await resolve(q.name, q.type) });
          } else {
            results.push({ query: q, error: 'Invalid query format' });
          }
        } catch (err) {
          results.push({ query: q, error: err.message });
        }
      }
      return results;
    };

    return {
      resolve,
      resolveBatch,
      VALID_TYPES: [...VALID_DNS_TYPES],
    };
  }

  _createSandboxContext(safeConsole) {
    const deniedProcess = createDeniedObject('process', [
      'exit', 'kill', 'env', 'argv', 'cwd', 'chdir',
      'stdin', 'stdout', 'stderr', 'pid', 'ppid',
    ]);

    const deniedBuffer = createDeniedObject('Buffer', [
      'from', 'alloc', 'allocUnsafe', 'concat',
    ]);

    const context = {
      console: safeConsole,
      setTimeout,
      setInterval,
      clearTimeout,
      clearInterval,
      Promise,
      Map,
      Set,
      Array,
      Object,
      String,
      Number,
      Boolean,
      Date,
      Math,
      JSON,
      parseInt,
      parseFloat,
      isNaN,
      isFinite,
      RegExp,
      Error,
      TypeError,
      RangeError,
      SyntaxError,
      ReferenceError,
      dns: this._createDnsApi(),
      process: deniedProcess,
      require: () => {
        throw new PermissionError(
          "Permission denied: 'require()' is not allowed in sandbox. " +
          'Loading external modules is restricted.'
        );
      },
      global: undefined,
      globalThis: undefined,
      Buffer: deniedBuffer,
    };

    return context;
  }

  async execute(code, options = {}) {
    if (this._runningCount >= this.maxConcurrent) {
      const err = new Error(
        `Too many concurrent scripts running (${this._runningCount}/${this.maxConcurrent}). Try again later.`
      );
      err.code = 'ERR_CONCURRENCY_LIMIT';
      throw err;
    }

    this._runningCount += 1;
    const startTime = Date.now();
    const safeConsole = createSafeConsole();
    const timeoutMs = options.timeoutMs || this.timeoutMs;

    try {
      const context = this._createSandboxContext(safeConsole);
      vm.createContext(context);

      const wrappedCode = `
        (async function() {
          ${code}
        })()
      `;

      const script = new vm.Script(wrappedCode, {
        timeout: timeoutMs,
        displayErrors: true,
      });

      const result = await script.runInContext(context, {
        timeout: timeoutMs,
        displayErrors: true,
      });

      return {
        success: true,
        result: result !== undefined ? JSON.parse(JSON.stringify(result)) : null,
        logs: safeConsole._logs,
        startedAt: startTime,
        finishedAt: Date.now(),
        durationMs: Date.now() - startTime,
      };
    } catch (err) {
      let errorType = 'ExecutionError';
      let errorMessage = err.message;

      if (err instanceof PermissionError) {
        errorType = 'PermissionError';
        errorMessage = err.message;
      } else if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
        errorType = 'TimeoutError';
        errorMessage = `Script execution timed out after ${timeoutMs}ms`;
      } else if (err instanceof SyntaxError) {
        errorType = 'SyntaxError';
        errorMessage = err.message;
      }

      return {
        success: false,
        error: {
          type: errorType,
          message: errorMessage,
          stack: err.stack ? err.stack.split('\n').slice(0, 10).join('\n') : undefined,
        },
        logs: safeConsole._logs,
        startedAt: startTime,
        finishedAt: Date.now(),
        durationMs: Date.now() - startTime,
      };
    } finally {
      this._runningCount -= 1;
    }
  }
}

module.exports = {
  ScriptSandbox,
  PermissionError,
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_CONCURRENT,
};
