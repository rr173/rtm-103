const dgram = require('dgram');
const {
  parseDnsMessage,
  buildResponse,
  buildFormerrResponse,
  DnsParseError,
  RCODE_MAP,
  TYPE_MAP,
} = require('./dnsProtocol');

class DnsUdpServer {
  constructor(resolver, enforcementManager) {
    this.resolver = resolver;
    this.enforcementManager = enforcementManager;
    this.socket = null;
    this.port = parseInt(process.env.DNS_PORT, 10) || 5353;
    this.stats = {
      totalPackets: 0,
      successResponses: 0,
      formerrCount: 0,
      rcodeCounts: {
        0: 0,
        1: 0,
        2: 0,
        3: 0,
        5: 0,
      },
    };
  }

  setPort(port) {
    this.port = port;
  }

  getStats() {
    return {
      port: this.port,
      totalPackets: this.stats.totalPackets,
      successResponses: this.stats.successResponses,
      formerrCount: this.stats.formerrCount,
      rcodeCounts: { ...this.stats.rcodeCounts },
    };
  }

  getConfig() {
    return {
      port: this.port,
    };
  }

  async setPortAndRestart(newPort) {
    const oldPort = this.port;
    this.port = newPort;
    try {
      await this.stop();
    } catch (e) {}
    await this.start();
    return { oldPort, newPort: this.port };
  }

  start() {
    return new Promise((resolve, reject) => {
      this.socket = dgram.createSocket('udp4');

      this.socket.on('error', (err) => {
        console.error(`[DNS-UDP] Socket error: ${err.message}`);
        reject(err);
      });

      this.socket.on('message', (msg, rinfo) => {
        this.handleMessage(msg, rinfo).catch((err) => {
          console.error(`[DNS-UDP] Error handling message: ${err.message}`);
        });
      });

      this.socket.on('listening', () => {
        const addr = this.socket.address();
        console.log(`[DNS-UDP] Listening on ${addr.address}:${addr.port}`);
        resolve();
      });

      this.socket.bind(this.port, '0.0.0.0');
    });
  }

  stop() {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        resolve();
        return;
      }
      this.socket.close((err) => {
        if (err) reject(err);
        else resolve();
      });
      this.socket = null;
    });
  }

  async handleMessage(msg, rinfo) {
    this.stats.totalPackets += 1;

    let parsedId = 0;
    try {
      if (msg.length >= 2) {
        parsedId = msg.readUInt16BE(0);
      }

      const parsed = parseDnsMessage(msg);

      if (parsed.qdcount === 0 || !parsed.questions || parsed.questions.length === 0) {
        throw new DnsParseError('No question in query');
      }

      const question = parsed.questions[0];
      const queryName = question.name;
      const queryType = question.type;
      const queryQtype = question.qtype;

      let enforcement = { action: 'pass' };
      if (this.enforcementManager) {
        enforcement = this.enforcementManager.checkQuery(queryName);
      }

      if (enforcement.action === 'block') {
        this.sendResponse(parsed.id, parsed.rd, question, 5, [], [], [], rinfo);
        return;
      }

      if (enforcement.action === 'ratelimit') {
        const retryAfter = enforcement.retryAfter || 60;
        const additional = [{
          name: queryName,
          type: 'TXT',
          ttl: 0,
          value: `rate-limited, retry after ${retryAfter}s`,
        }];
        this.sendResponse(parsed.id, parsed.rd, question, 5, [], [], additional, rinfo);
        return;
      }

      const result = await this.resolver.resolve(queryName, queryType, false);

      const mappedRcode = RCODE_MAP[result.status];
      let rcode;
      if (mappedRcode !== undefined) {
        rcode = mappedRcode;
      } else if (result.status === 'RATE_LIMITED' || result.status === 'REFUSED') {
        rcode = 5;
      } else {
        rcode = 2;
      }

      const answers = (result.answer || []).map((r) => ({
        name: r.name,
        type: r.type,
        ttl: r.ttl || 3600,
        value: r.value,
      }));

      const authority = (result.authority || []).map((r) => ({
        name: r.name,
        type: r.type,
        ttl: r.ttl || 3600,
        value: r.value,
      }));

      this.sendResponse(parsed.id, parsed.rd, {
        name: question.name,
        type: question.type,
        qtype: queryQtype,
      }, rcode, answers, authority, [], rinfo);
    } catch (err) {
      if (err instanceof DnsParseError) {
        this.stats.formerrCount += 1;
        this.stats.rcodeCounts[1] = (this.stats.rcodeCounts[1] || 0) + 1;
        const resp = buildFormerrResponse(parsedId);
        this.socket.send(resp, rinfo.port, rinfo.address);
        console.log(`[DNS-UDP] FORMERR from ${rinfo.address}:${rinfo.port} - ${err.message}`);
      } else {
        this.stats.rcodeCounts[2] = (this.stats.rcodeCounts[2] || 0) + 1;
        const resp = buildFormerrResponse(parsedId);
        try {
          this.socket.send(resp, rinfo.port, rinfo.address);
        } catch (e) {}
        console.error(`[DNS-UDP] SERVFAIL handling query from ${rinfo.address}:${rinfo.port}: ${err.message}`);
      }
    }
  }

  sendResponse(id, rd, question, rcode, answers, authority, additional, rinfo) {
    this.stats.rcodeCounts[rcode] = (this.stats.rcodeCounts[rcode] || 0) + 1;
    if (rcode === 0) {
      this.stats.successResponses += 1;
    }
    const resp = buildResponse({
      id,
      rd,
      question,
      rcode,
      answers,
      authority,
      additional,
    });
    this.socket.send(resp, rinfo.port, rinfo.address);
  }
}

module.exports = { DnsUdpServer };
