const TYPE_MAP = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  255: 'ANY',
};

const TYPE_TO_NUM = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  ANY: 255,
};

const RCODE_MAP = {
  SUCCESS: 0,
  NXDOMAIN: 3,
  SERVFAIL: 2,
  REFUSED: 5,
};

class DnsParseError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DnsParseError';
  }
}

function parseDnsMessage(buffer) {
  if (buffer.length < 12) {
    throw new DnsParseError('Message too short');
  }

  let offset = 0;

  const id = buffer.readUInt16BE(offset);
  offset += 2;

  const flags = buffer.readUInt16BE(offset);
  offset += 2;

  const qr = (flags >> 15) & 0x1;
  const opcode = (flags >> 11) & 0xf;
  const aa = (flags >> 10) & 0x1;
  const tc = (flags >> 9) & 0x1;
  const rd = (flags >> 8) & 0x1;
  const ra = (flags >> 7) & 0x1;
  const z = (flags >> 4) & 0x7;
  const rcode = flags & 0xf;

  const qdcount = buffer.readUInt16BE(offset);
  offset += 2;
  const ancount = buffer.readUInt16BE(offset);
  offset += 2;
  const nscount = buffer.readUInt16BE(offset);
  offset += 2;
  const arcount = buffer.readUInt16BE(offset);
  offset += 2;

  const questions = [];
  for (let i = 0; i < qdcount; i++) {
    const { name, newOffset } = parseDomainName(buffer, offset);
    offset = newOffset;

    if (offset + 4 > buffer.length) {
      throw new DnsParseError('Truncated question section');
    }
    const qtype = buffer.readUInt16BE(offset);
    offset += 2;
    const qclass = buffer.readUInt16BE(offset);
    offset += 2;

    questions.push({
      name,
      type: TYPE_MAP[qtype] || String(qtype),
      qtype,
      qclass,
    });
  }

  return {
    id,
    flags,
    qr,
    opcode,
    aa,
    tc,
    rd,
    ra,
    z,
    rcode,
    qdcount,
    ancount,
    nscount,
    arcount,
    questions,
    rawBuffer: buffer,
  };
}

function parseDomainName(buffer, startOffset) {
  const labels = [];
  let offset = startOffset;
  let totalLength = 0;

  while (true) {
    if (offset >= buffer.length) {
      throw new DnsParseError('Truncated domain name');
    }

    const length = buffer[offset];
    offset += 1;

    if (length === 0) {
      break;
    }

    if ((length & 0xc0) === 0xc0) {
      throw new DnsParseError('Compression pointers not supported in queries');
    }

    if (length > 63) {
      throw new DnsParseError('Label exceeds 63 bytes');
    }

    if (offset + length > buffer.length) {
      throw new DnsParseError('Truncated label');
    }

    const label = buffer.toString('ascii', offset, offset + length);
    labels.push(label);
    totalLength += length + 1;
    offset += length;
  }

  if (totalLength > 253) {
    throw new DnsParseError('Domain name exceeds 253 characters');
  }

  return {
    name: labels.join('.'),
    newOffset: offset,
  };
}

function encodeDomainName(name) {
  const labels = name.split('.').filter((l) => l.length > 0);
  const parts = [];
  for (const label of labels) {
    const buf = Buffer.from(label, 'ascii');
    parts.push(Buffer.from([buf.length]));
    parts.push(buf);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function encodeCompressedPointer(offset) {
  const buf = Buffer.alloc(2);
  buf.writeUInt16BE(0xc000 | offset, 0);
  return buf;
}

function encodeIpv4(ip) {
  const parts = ip.split('.');
  const buf = Buffer.alloc(4);
  for (let i = 0; i < 4; i++) {
    buf[i] = parseInt(parts[i], 10) & 0xff;
  }
  return buf;
}

function encodeIpv6(ip) {
  const groups = ip.split(':');
  const expanded = [];
  let emptyIndex = -1;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === '') {
      emptyIndex = i;
    }
  }
  if (emptyIndex >= 0) {
    const before = groups.slice(0, emptyIndex);
    const after = groups.slice(emptyIndex + 1).filter((g) => g !== '');
    const missing = 8 - before.length - after.length;
    for (let i = 0; i < missing; i++) before.push('0');
    groups.splice(emptyIndex, groups.length - emptyIndex, ...before, ...after.slice(before.length - emptyIndex));
  }
  const finalGroups = groups.filter((g) => g !== '');
  const buf = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(finalGroups[i] || '0', 16);
    buf.writeUInt16BE(val & 0xffff, i * 2);
  }
  return buf;
}

function encodeRdata(type, value) {
  switch (type.toUpperCase()) {
    case 'A':
      return encodeIpv4(value);
    case 'AAAA':
      return encodeIpv6(value);
    case 'CNAME':
    case 'NS':
      return encodeDomainName(value);
    case 'MX': {
      const parts = value.split(/\s+/);
      const preference = parseInt(parts[0], 10) || 0;
      const exchange = parts.slice(1).join(' ');
      const prefBuf = Buffer.alloc(2);
      prefBuf.writeUInt16BE(preference, 0);
      return Buffer.concat([prefBuf, encodeDomainName(exchange)]);
    }
    case 'TXT': {
      const strBuf = Buffer.from(value, 'utf8');
      const lenBuf = Buffer.from([strBuf.length]);
      return Buffer.concat([lenBuf, strBuf]);
    }
    default:
      return Buffer.alloc(0);
  }
}

function normalizeNameForCompare(name) {
  let n = (name || '').toLowerCase();
  if (n !== '.' && n.endsWith('.')) n = n.slice(0, -1);
  return n;
}

function buildResponse({
  id,
  rd,
  question,
  rcode,
  answers = [],
  authority = [],
  additional = [],
  aa = true,
}) {
  const parts = [];

  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);

  let flags = 0x8000;
  if (rd) flags |= 0x0100;
  if (aa) flags |= 0x0400;
  flags |= (rcode & 0xf);
  header.writeUInt16BE(flags, 2);

  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(authority.length, 8);
  header.writeUInt16BE(additional.length, 10);
  parts.push(header);

  const qdBuf = Buffer.concat([
    encodeDomainName(question.name),
    (() => {
      const b = Buffer.alloc(4);
      b.writeUInt16BE(question.qtype || TYPE_TO_NUM[question.type] || 1, 0);
      b.writeUInt16BE(1, 2);
      return b;
    })(),
  ]);
  parts.push(qdBuf);

  const questionOffset = 12;
  const qnameNormalized = normalizeNameForCompare(question.name);

  for (const rr of [...answers, ...authority, ...additional]) {
    const rrNameNormalized = normalizeNameForCompare(rr.name);
    if (rrNameNormalized === qnameNormalized) {
      parts.push(encodeCompressedPointer(questionOffset));
    } else {
      parts.push(encodeDomainName(rr.name));
    }

    const rrMeta = Buffer.alloc(8);
    rrMeta.writeUInt16BE(TYPE_TO_NUM[rr.type] || 1, 0);
    rrMeta.writeUInt16BE(1, 2);
    rrMeta.writeUInt32BE(rr.ttl || 3600, 4);
    parts.push(rrMeta);

    const rdata = encodeRdata(rr.type, rr.value);
    const rdlenBuf = Buffer.alloc(2);
    rdlenBuf.writeUInt16BE(rdata.length, 0);
    parts.push(rdlenBuf);
    parts.push(rdata);
  }

  return Buffer.concat(parts);
}

function buildFormerrResponse(id) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x8000 | 0x0001, 2);
  header.writeUInt16BE(0, 4);
  header.writeUInt16BE(0, 6);
  header.writeUInt16BE(0, 8);
  header.writeUInt16BE(0, 10);
  return header;
}

function buildServfailResponse(id, rd, question) {
  if (!question) {
    const header = Buffer.alloc(12);
    header.writeUInt16BE(id, 0);
    header.writeUInt16BE(0x8000 | 0x0002, 2);
    header.writeUInt16BE(0, 4);
    header.writeUInt16BE(0, 6);
    header.writeUInt16BE(0, 8);
    header.writeUInt16BE(0, 10);
    return header;
  }
  return buildResponse({
    id,
    rd,
    question,
    rcode: 2,
    answers: [],
    authority: [],
    additional: [],
  });
}

module.exports = {
  TYPE_MAP,
  TYPE_TO_NUM,
  RCODE_MAP,
  DnsParseError,
  parseDnsMessage,
  parseDomainName,
  encodeDomainName,
  encodeCompressedPointer,
  encodeIpv4,
  encodeIpv6,
  encodeRdata,
  buildResponse,
  buildFormerrResponse,
  buildServfailResponse,
};
