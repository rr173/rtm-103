const dgram = require('dgram');
const net = require('net');
const {
  parseDnsMessage,
  buildResponse,
  buildFormerrResponse,
  buildServfailResponse,
  DnsParseError,
  RCODE_MAP,
  TYPE_MAP,
} = require('./dnsProtocol');

const MAX_TCP_CONNECTIONS = 20;
const TCP_IDLE_TIMEOUT_MS = 60000;

class DnsMessageHandler {
  constructor(resolver, enforcementManager, stats) {
    this.resolver = resolver;
    this.enforcementManager = enforcementManager;
    this.stats = stats;
  }

  async handleDnsQuery(msg, sendResponse) {
    let parsedId = 0;
    let parsedRd = 0;
    let parsedQuestion = null;
    try {
      if (msg.length >= 2) {
        parsedId = msg.readUInt16BE(0);
      }
      if (msg.length >= 4) {
        parsedRd = (msg.readUInt16BE(2) >> 8) & 0x1;
      }

      const parsed = parseDnsMessage(msg);

      if (parsed.qdcount === 0 || !parsed.questions || parsed.questions.length === 0) {
        throw new DnsParseError('No question in query');
      }

      const question = parsed.questions[0];
      parsedQuestion = question;
      const queryName = question.name;
      const queryType = question.type;
      const queryQtype = question.qtype;

      let enforcement = { action: 'pass' };
      if (this.enforcementManager) {
        enforcement = this.enforcementManager.checkQuery(queryName);
      }

      if (enforcement.action === 'block') {
        this.sendDnsResponse(sendResponse, parsed.id, parsed.rd, question, 5, [], [], []);
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
        this.sendDnsResponse(sendResponse, parsed.id, parsed.rd, question, 5, [], [], additional);
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

      this.sendDnsResponse(sendResponse, parsed.id, parsed.rd, {
        name: question.name,
        type: question.type,
        qtype: queryQtype,
      }, rcode, answers, authority, []);
    } catch (err) {
      if (err instanceof DnsParseError) {
        this.stats.formerrCount += 1;
        this.stats.rcodeCounts[1] = (this.stats.rcodeCounts[1] || 0) + 1;
        const resp = buildFormerrResponse(parsedId);
        try {
          sendResponse(resp);
        } catch (e) {}
        console.log(`[DNS] FORMERR - ${err.message}`);
      } else {
        this.stats.rcodeCounts[2] = (this.stats.rcodeCounts[2] || 0) + 1;
        const resp = buildServfailResponse(parsedId, parsedRd, parsedQuestion);
        try {
          sendResponse(resp);
        } catch (e) {}
        console.error(`[DNS] SERVFAIL handling query: ${err.message}`);
      }
    }
  }

  sendDnsResponse(sendResponse, id, rd, question, rcode, answers, authority, additional) {
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
    sendResponse(resp);
  }
}

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
    this.handler = new DnsMessageHandler(resolver, enforcementManager, this.stats);
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
    const oldSocket = this.socket;
    this.port = newPort;
    try {
      await this.stop();
    } catch (e) {}
    try {
      await this.start();
      return { oldPort, newPort: this.port, restarted: true };
    } catch (err) {
      this.port = oldPort;
      this.socket = oldSocket;
      if (this.socket) {
        try {
          await this.start();
        } catch (e2) {}
      }
      throw err;
    }
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

    const sendResponse = (respBuffer) => {
      this.socket.send(respBuffer, rinfo.port, rinfo.address);
    };

    await this.handler.handleDnsQuery(msg, sendResponse);
  }
}

class DnsTcpServer {
  constructor(resolver, enforcementManager) {
    this.resolver = resolver;
    this.enforcementManager = enforcementManager;
    this.server = null;
    this.port = parseInt(process.env.DNS_PORT, 10) || 5353;
    this.connections = new Set();
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
      tcpConnections: 0,
      tcpTotalQueries: 0,
      tcpTotalConnections: 0,
    };
    this.handler = new DnsMessageHandler(resolver, enforcementManager, this.stats);
  }

  setPort(port) {
    this.port = port;
  }

  getStats() {
    return {
      tcpConnections: this.stats.tcpConnections,
      tcpTotalQueries: this.stats.tcpTotalQueries,
      tcpTotalConnections: this.stats.tcpTotalConnections,
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
    try {
      await this.start();
      return { oldPort, newPort: this.port, restarted: true };
    } catch (err) {
      this.port = oldPort;
      throw err;
    }
  }

  start() {
    return new Promise((resolve, reject) => {
      this.server = net.createServer();
      this.server.maxConnections = MAX_TCP_CONNECTIONS;

      this.server.on('error', (err) => {
        console.error(`[DNS-TCP] Server error: ${err.message}`);
        reject(err);
      });

      this.server.on('connection', (socket) => {
        this.handleConnection(socket);
      });

      this.server.listen(this.port, '0.0.0.0', () => {
        const addr = this.server.address();
        console.log(`[DNS-TCP] Listening on ${addr.address}:${addr.port} (maxConnections=${MAX_TCP_CONNECTIONS})`);
        resolve();
      });
    });
  }

  stop() {
    return new Promise((resolve, reject) => {
      if (!this.server) {
        resolve();
        return;
      }
      for (const socket of this.connections) {
        try {
          socket.destroy();
        } catch (e) {}
      }
      this.connections.clear();
      this.stats.tcpConnections = 0;
      this.server.close((err) => {
        if (err) reject(err);
        else resolve();
      });
      this.server = null;
    });
  }

  handleConnection(socket) {
    const remoteAddr = `${socket.remoteAddress}:${socket.remotePort}`;

    if (this.connections.size >= MAX_TCP_CONNECTIONS) {
      console.log(`[DNS-TCP] Connection limit exceeded (${this.connections.size}/${MAX_TCP_CONNECTIONS}), rejecting ${remoteAddr} with RST`);
      try {
        socket.setTimeout(0);
        socket.setKeepAlive(false);
        if (typeof socket.resetAndDestroy === 'function') {
          socket.resetAndDestroy();
        } else {
          socket.once('error', () => {});
          try { socket.setLinger(true, 0); } catch (e) {}
          socket.destroy();
        }
      } catch (e) {}
      return;
    }

    this.connections.add(socket);
    this.stats.tcpConnections = this.connections.size;
    this.stats.tcpTotalConnections += 1;
    console.log(`[DNS-TCP] New connection from ${remoteAddr} (active: ${this.stats.tcpConnections}/${MAX_TCP_CONNECTIONS})`);

    let idleTimer = null;
    const resetIdleTimer = () => {
      if (idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        console.log(`[DNS-TCP] Connection idle timeout from ${remoteAddr}`);
        try {
          socket.destroy();
        } catch (e) {}
      }, TCP_IDLE_TIMEOUT_MS);
    };
    resetIdleTimer();

    let receiveBuffer = Buffer.alloc(0);

    const processBuffer = () => {
      while (receiveBuffer.length >= 2) {
        const msgLength = receiveBuffer.readUInt16BE(0);
        if (receiveBuffer.length < 2 + msgLength) {
          break;
        }
        const dnsMsg = receiveBuffer.slice(2, 2 + msgLength);
        receiveBuffer = receiveBuffer.slice(2 + msgLength);
        this.stats.tcpTotalQueries += 1;
        this.stats.totalPackets += 1;
        this.processDnsMessage(socket, dnsMsg, remoteAddr);
      }
    };

    socket.on('data', (data) => {
      resetIdleTimer();
      receiveBuffer = Buffer.concat([receiveBuffer, data]);
      try {
        processBuffer();
      } catch (err) {
        console.error(`[DNS-TCP] Error processing data from ${remoteAddr}: ${err.message}`);
        try { socket.destroy(); } catch (e) {}
      }
    });

    socket.on('error', (err) => {
      console.error(`[DNS-TCP] Socket error from ${remoteAddr}: ${err.message}`);
    });

    socket.on('close', () => {
      if (idleTimer) clearTimeout(idleTimer);
      this.connections.delete(socket);
      this.stats.tcpConnections = this.connections.size;
      console.log(`[DNS-TCP] Connection closed from ${remoteAddr} (active: ${this.stats.tcpConnections})`);
    });
  }

  async processDnsMessage(socket, msg, remoteAddr) {
    const sendResponse = (respBuffer) => {
      const lengthPrefix = Buffer.alloc(2);
      lengthPrefix.writeUInt16BE(respBuffer.length, 0);
      const framedResp = Buffer.concat([lengthPrefix, respBuffer]);
      try {
        socket.write(framedResp);
      } catch (e) {
        console.error(`[DNS-TCP] Failed to send response to ${remoteAddr}: ${e.message}`);
      }
    };

    await this.handler.handleDnsQuery(msg, sendResponse);
  }
}

class DnsServer {
  constructor(resolver, enforcementManager) {
    this.udpServer = new DnsUdpServer(resolver, enforcementManager);
    this.tcpServer = new DnsTcpServer(resolver, enforcementManager);
  }

  get port() {
    return this.udpServer.port;
  }

  setPort(port) {
    this.udpServer.setPort(port);
    this.tcpServer.setPort(port);
  }

  getStats() {
    const udpStats = this.udpServer.getStats();
    const tcpStats = this.tcpServer.getStats();
    return {
      port: udpStats.port,
      udp: {
        totalPackets: udpStats.totalPackets,
        successResponses: udpStats.successResponses,
        formerrCount: udpStats.formerrCount,
        rcodeCounts: udpStats.rcodeCounts,
      },
      tcp: {
        tcpConnections: tcpStats.tcpConnections,
        tcpTotalQueries: tcpStats.tcpTotalQueries,
        tcpTotalConnections: tcpStats.tcpTotalConnections,
        totalPackets: tcpStats.totalPackets,
        successResponses: tcpStats.successResponses,
        formerrCount: tcpStats.formerrCount,
        rcodeCounts: tcpStats.rcodeCounts,
      },
      tcpConnections: tcpStats.tcpConnections,
      tcpTotalQueries: tcpStats.tcpTotalQueries,
      tcpTotalConnections: tcpStats.tcpTotalConnections,
    };
  }

  getConfig() {
    return this.udpServer.getConfig();
  }

  async setPortAndRestart(newPort) {
    const oldPort = this.udpServer.port;
    try {
      await this.udpServer.setPortAndRestart(newPort);
    } catch (err) {
      throw err;
    }
    try {
      await this.tcpServer.setPortAndRestart(newPort);
    } catch (tcpErr) {
      try {
        await this.udpServer.setPortAndRestart(oldPort);
      } catch (e) {}
      throw tcpErr;
    }
    return { oldPort, newPort, restarted: true };
  }

  async start() {
    await this.udpServer.start();
    await this.tcpServer.start();
  }

  async stop() {
    await this.udpServer.stop();
    await this.tcpServer.stop();
  }
}

module.exports = { DnsUdpServer, DnsTcpServer, DnsServer };
