import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";
import dns from "dns";
import { promisify } from "util";
import tls from "tls";
import whois from "whois-json";
import axios from "axios";
import { parsePhoneNumberFromString, isValidPhoneNumber } from 'libphonenumber-js';
import { GoogleGenAI } from "@google/genai";
import { createClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.VITE_SUPABASE_URL || 'https://tkdbonrhwhimcdrsfpnz.supabase.co';
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY || 'sb_secret_QUgpiQAOz-HD8M5BQ8Zdhg_Rfe2xaJg';
const supabase = createClient(supabaseUrl, supabaseServiceKey);

const resolveAny = promisify(dns.resolveAny);
const resolveMx = promisify(dns.resolveMx);
const resolveNs = promisify(dns.resolveNs);
const resolveTxt = promisify(dns.resolveTxt);
const resolveA = promisify(dns.resolve4);
const resolveAAAA = promisify(dns.resolve6);
const resolveSoa = promisify(dns.resolveSoa);
const reverseDns = promisify(dns.reverse);
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY || "" });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- DISPOSABLE EMAIL DOMAINS ---
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com','throwaway.email',
  'yopmail.com','sharklasers.com','guerrillamail.info','spam4.me','trashmail.com',
  'trashmail.me','dispostable.com','mailnull.com','tempr.email','temp-mail.org',
  'emailondeck.com','fakemail.net','maildrop.cc','spamgourmet.com','filzmail.com',
  'getairmail.com','mohmal.com','tempmailaddress.com','spamex.com','mintemail.com',
  'throwam.com','fakeinbox.com','mailexpire.com','mailseal.de','meltmail.com',
  'mytrashmail.com','trashmail.at','trashmail.io','discard.email','tempinbox.com',
  'toss.pw','tmail.com','0-mail.com','10mail.org','spamevader.net','inboxkitten.com',
  'mailtemp.net','temp-mail.io','guerrillamailblock.com','grr.la','jetable.fr.nf'
]);

// --- SSL Certificate via TLS ---
function getSSLCertificate(hostname: string, port = 443): Promise<any> {
  return new Promise((resolve) => {
    const socket = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false, timeout: 10000 }, () => {
      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      socket.end();
      if (!cert || Object.keys(cert).length === 0) { resolve(null); return; }
      const validTo = new Date(cert.valid_to);
      const validFrom = new Date(cert.valid_from);
      const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / 86400000);
      const selfSigned = cert.issuer?.CN === cert.subject?.CN && cert.issuer?.O === cert.subject?.O;
      const san = cert.subjectaltname ? cert.subjectaltname.split(', ').map((s: string) => s.replace('DNS:', '').replace('IP Address:', '').trim()) : [];
      resolve({ subject: cert.subject, issuer: cert.issuer, valid_from: validFrom.toISOString(), valid_to: validTo.toISOString(), days_remaining: daysRemaining, expired: daysRemaining < 0, self_signed: selfSigned, fingerprint: cert.fingerprint, fingerprint256: cert.fingerprint256, san, protocol, cipher: { name: cipher?.name, bits: (cipher as any)?.secretKeySize }, serial_number: cert.serialNumber });
    });
    socket.on('error', () => resolve(null));
    socket.setTimeout(10000, () => { socket.destroy(); resolve(null); });
  });
}

// --- Security Headers Analysis ---
async function analyzeSecurityHeaders(domain: string): Promise<any> {
  try {
    const url = domain.startsWith('http') ? domain : `https://${domain}`;
    const response = await axios.get(url, { timeout: 8000, maxRedirects: 5, validateStatus: () => true, headers: { 'User-Agent': 'Mozilla/5.0 CybercordBot/2.0 (Security Scanner)' } });
    const h = response.headers;
    const securityHeaders: Record<string, any> = {
      'Content-Security-Policy': { present: !!h['content-security-policy'], value: h['content-security-policy'] || null },
      'Strict-Transport-Security': { present: !!h['strict-transport-security'], value: h['strict-transport-security'] || null },
      'X-Frame-Options': { present: !!h['x-frame-options'], value: h['x-frame-options'] || null },
      'X-Content-Type-Options': { present: !!h['x-content-type-options'], value: h['x-content-type-options'] || null },
      'X-XSS-Protection': { present: !!h['x-xss-protection'], value: h['x-xss-protection'] || null },
      'Referrer-Policy': { present: !!h['referrer-policy'], value: h['referrer-policy'] || null },
      'Permissions-Policy': { present: !!h['permissions-policy'], value: h['permissions-policy'] || null },
      'Cache-Control': { present: !!h['cache-control'], value: h['cache-control'] || null },
    };
    const presentCount = Object.values(securityHeaders).filter(v => v.present).length;
    return { status: response.status, statusText: response.statusText, server: h['server'] || h['x-powered-by'] || 'Unknown', security_headers: securityHeaders, headers_score: Math.round((presentCount / Object.keys(securityHeaders).length) * 100), all_headers: response.headers };
  } catch (e: any) { return { error: e.message, security_headers: {}, headers_score: 0 }; }
}

// --- Full DNS Analysis ---
async function analyzeDNS(domain: string): Promise<any> {
  const results: any = { domain };
  const safe = async (fn: () => Promise<any>, key: string) => { try { results[key] = await fn(); } catch { results[key] = null; } };
  await Promise.all([
    safe(() => resolveA(domain), 'a_records'),
    safe(() => resolveAAAA(domain), 'aaaa_records'),
    safe(() => resolveMx(domain), 'mx_records'),
    safe(() => resolveNs(domain), 'ns_records'),
    safe(() => resolveTxt(domain).then(recs => recs.map((r: string[]) => r.join(''))), 'txt_records'),
    safe(() => resolveSoa(domain), 'soa_record'),
  ]);
  const spfRec = (results.txt_records || []).find((t: string) => t.startsWith('v=spf1'));
  results.spf = spfRec || null; results.spf_valid = !!spfRec;
  try { const dt = await resolveTxt(`_dmarc.${domain}`); const dr = dt.map((r: string[]) => r.join('')).find((t: string) => t.startsWith('v=DMARC1')); results.dmarc = dr || null; results.dmarc_valid = !!dr; } catch { results.dmarc = null; results.dmarc_valid = false; }
  const dkimSelectors = ['default','google','k1','selector1','selector2','mail','dkim','key1'];
  const dkimResults: any[] = [];
  for (const sel of dkimSelectors) { try { const t = await resolveTxt(`${sel}._domainkey.${domain}`); if (t.length > 0) dkimResults.push({ selector: sel, record: t.map((r: string[]) => r.join('')).join('') }); } catch { } }
  results.dkim = dkimResults; results.dkim_valid = dkimResults.length > 0;
  try { const anyRecs = await resolveAny(domain); results.ds_records = anyRecs.filter((x: any) => x.type === 'DS'); } catch { results.ds_records = []; }
  results.dnssec = results.ds_records && results.ds_records.length > 0;
  return results;
}

// --- DNS Blacklist Check ---
async function checkBlacklists(target: string): Promise<any[]> {
  const isIP = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(target);
  const results: any[] = [];
  if (isIP) {
    const rev = target.split('.').reverse().join('.');
    for (const bl of [{ name: 'Spamhaus ZEN', host: `${rev}.zen.spamhaus.org` }, { name: 'SpamCop', host: `${rev}.bl.spamcop.net` }, { name: 'Barracuda', host: `${rev}.b.barracudacentral.org` }, { name: 'SORBS', host: `${rev}.dnsbl.sorbs.net` }]) {
      try { await resolveA(bl.host); results.push({ name: bl.name, status: 'LISTED' }); } catch { results.push({ name: bl.name, status: 'CLEAN' }); }
    }
  } else {
    for (const bl of [{ name: 'Spamhaus DBL', host: `${target}.dbl.spamhaus.org` }, { name: 'SURBL', host: `${target}.multi.surbl.org` }, { name: 'URIBL', host: `${target}.uribl.com` }]) {
      try { await resolveA(bl.host); results.push({ name: bl.name, status: 'LISTED' }); } catch { results.push({ name: bl.name, status: 'CLEAN' }); }
    }
  }
  return results;
}

// --- Risk Scoring Engine ---
function calculateRiskScore(data: { ssl?: any; dns?: any; headers?: any; whoisData?: any; blacklists?: any[]; }): any {
  let score = 0;
  const breakdown: any = { ssl: { score: 0, issues: [] }, dns: { score: 0, issues: [] }, headers: { score: 0, issues: [] }, reputation: { score: 0, issues: [] }, domain_age: { score: 0, issues: [] } };
  const recommendations: string[] = [];
  if (data.ssl) {
    if (data.ssl.expired) { breakdown.ssl.score += 25; breakdown.ssl.issues.push('SSL certificate expired'); recommendations.push('Renew SSL certificate immediately'); }
    else if (data.ssl.days_remaining < 30) { breakdown.ssl.score += 15; breakdown.ssl.issues.push(`SSL expires in ${data.ssl.days_remaining} days`); recommendations.push('Renew SSL certificate within 30 days'); }
    if (data.ssl.self_signed) { breakdown.ssl.score += 20; breakdown.ssl.issues.push('Self-signed certificate'); recommendations.push('Replace self-signed cert with CA-issued one'); }
    if (data.ssl.protocol === 'TLSv1' || data.ssl.protocol === 'TLSv1.1') { breakdown.ssl.score += 10; breakdown.ssl.issues.push(`Outdated TLS: ${data.ssl.protocol}`); recommendations.push('Upgrade to TLS 1.2 or 1.3'); }
  } else { breakdown.ssl.score += 10; breakdown.ssl.issues.push('SSL could not be retrieved'); }
  if (data.dns) {
    if (!data.dns.spf_valid) { breakdown.dns.score += 10; breakdown.dns.issues.push('Missing SPF record'); recommendations.push('Add SPF record to prevent email spoofing'); }
    if (!data.dns.dmarc_valid) { breakdown.dns.score += 15; breakdown.dns.issues.push('Missing DMARC policy'); recommendations.push('Implement DMARC with p=reject'); }
    if (!data.dns.dkim_valid) { breakdown.dns.score += 10; breakdown.dns.issues.push('No DKIM records found'); recommendations.push('Configure DKIM email signing'); }
    if (!data.dns.dnssec) { breakdown.dns.score += 5; breakdown.dns.issues.push('DNSSEC not enabled'); recommendations.push('Enable DNSSEC to prevent DNS spoofing'); }
  }
  if (data.headers?.security_headers) {
    const sh = data.headers.security_headers;
    if (!sh['Content-Security-Policy']?.present) { breakdown.headers.score += 8; breakdown.headers.issues.push('Missing CSP'); recommendations.push('Implement Content-Security-Policy header'); }
    if (!sh['Strict-Transport-Security']?.present) { breakdown.headers.score += 8; breakdown.headers.issues.push('Missing HSTS'); recommendations.push('Enable HSTS with min 1 year max-age'); }
    if (!sh['X-Frame-Options']?.present) { breakdown.headers.score += 5; breakdown.headers.issues.push('Missing X-Frame-Options'); recommendations.push('Add X-Frame-Options: DENY'); }
    if (!sh['X-Content-Type-Options']?.present) { breakdown.headers.score += 4; breakdown.headers.issues.push('Missing X-Content-Type-Options'); recommendations.push('Add X-Content-Type-Options: nosniff'); }
    if (!sh['Referrer-Policy']?.present) { breakdown.headers.score += 3; breakdown.headers.issues.push('Missing Referrer-Policy'); recommendations.push('Add Referrer-Policy header'); }
  }
  if (data.blacklists) { const listed = data.blacklists.filter((b: any) => b.status === 'LISTED'); if (listed.length > 0) { breakdown.reputation.score += listed.length * 10; listed.forEach((b: any) => { breakdown.reputation.issues.push(`Listed on ${b.name}`); recommendations.push(`Request delisting from ${b.name}`); }); } }
  if (data.whoisData?.creationDate) { try { const age = Math.floor((Date.now() - new Date(data.whoisData.creationDate).getTime()) / 86400000); if (age < 30) { breakdown.domain_age.score += 25; breakdown.domain_age.issues.push(`Domain only ${age} days old`); recommendations.push('Exercise caution - very new domain'); } else if (age < 365) { breakdown.domain_age.score += 10; breakdown.domain_age.issues.push(`Domain is ${Math.floor(age / 30)} months old`); } } catch { } }
  score = Math.min(100, breakdown.ssl.score + breakdown.dns.score + breakdown.headers.score + breakdown.reputation.score + breakdown.domain_age.score);
  const riskLevel = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Low';
  const complianceSignals = {
    gdpr: { score: Math.max(0, 100 - score), status: score < 30 ? 'Good' : score < 60 ? 'Needs Improvement' : 'Poor', indicators: [{ check: 'HTTPS enforced (HSTS)', status: data.headers?.security_headers?.['Strict-Transport-Security']?.present ? 'PASS' : 'FAIL' }, { check: 'Privacy headers (Referrer-Policy)', status: data.headers?.security_headers?.['Referrer-Policy']?.present ? 'PASS' : 'FAIL' }, { check: 'DMARC anti-spoofing', status: data.dns?.dmarc_valid ? 'PASS' : 'FAIL' }, { check: 'Valid SSL certificate', status: data.ssl && !data.ssl.expired ? 'PASS' : 'FAIL' }] },
    soc2: { score: Math.max(0, 100 - score), status: score < 30 ? 'Good' : score < 60 ? 'Needs Improvement' : 'Poor', indicators: [{ check: 'SSL/TLS properly configured', status: data.ssl && !data.ssl.expired && !data.ssl.self_signed ? 'PASS' : 'FAIL' }, { check: 'Security headers (>50%)', status: (data.headers?.headers_score || 0) > 50 ? 'PASS' : 'FAIL' }, { check: 'SPF email authentication', status: data.dns?.spf_valid ? 'PASS' : 'FAIL' }, { check: 'DMARC anti-spoofing', status: data.dns?.dmarc_valid ? 'PASS' : 'FAIL' }, { check: 'Not on abuse blacklists', status: (data.blacklists || []).every((b: any) => b.status === 'CLEAN') ? 'PASS' : 'FAIL' }] },
    iso27001: { score: Math.max(0, 100 - score), status: score < 30 ? 'Good' : score < 60 ? 'Needs Improvement' : 'Poor', indicators: [{ check: 'Clickjacking protection (X-Frame-Options)', status: data.headers?.security_headers?.['X-Frame-Options']?.present ? 'PASS' : 'FAIL' }, { check: 'CSP information security', status: data.headers?.security_headers?.['Content-Security-Policy']?.present ? 'PASS' : 'FAIL' }, { check: 'Cryptography (TLS 1.2+)', status: data.ssl?.protocol === 'TLSv1.3' || data.ssl?.protocol === 'TLSv1.2' ? 'PASS' : 'FAIL' }, { check: 'DNSSEC enabled', status: data.dns?.dnssec ? 'PASS' : 'FAIL' }] },
    pci_dss: { score: Math.max(0, 100 - score), status: score < 30 ? 'Good' : score < 60 ? 'Needs Improvement' : 'Poor', indicators: [{ check: 'Strong TLS (v1.2+)', status: data.ssl?.protocol === 'TLSv1.3' || data.ssl?.protocol === 'TLSv1.2' ? 'PASS' : 'FAIL' }, { check: 'Valid SSL certificate', status: data.ssl && !data.ssl.expired ? 'PASS' : 'FAIL' }, { check: 'HSTS enabled', status: data.headers?.security_headers?.['Strict-Transport-Security']?.present ? 'PASS' : 'FAIL' }, { check: 'XSS protection header', status: data.headers?.security_headers?.['X-XSS-Protection']?.present ? 'PASS' : 'FAIL' }, { check: 'Content type sniffing disabled', status: data.headers?.security_headers?.['X-Content-Type-Options']?.present ? 'PASS' : 'FAIL' }] }
  };
  return { overall_score: score, risk_level: riskLevel, breakdown, recommendations: [...new Set(recommendations)], compliance_signals: complianceSignals };
}

// Middleware
const authenticate = async (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = authHeader.split('Bearer ')[1];
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) throw new Error('Invalid token');
    req.user = user; next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
};

async function startServer() {
  const app = express();
  const PORT = 3000;
  app.use(express.json());

  app.get("/api/health", (req, res) => res.json({ status: "ok", timestamp: new Date().toISOString(), version: "2.0.0" }));

  // --- DOMAIN FULL ANALYSIS ---
  app.post("/api/domain-full", authenticate, async (req: any, res: any) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: "Target domain is required" });
    try {
      const [dnsR, whoisR, sslR, headersR, blacklistR] = await Promise.allSettled([
        analyzeDNS(target), whois(target).catch(() => null), getSSLCertificate(target), analyzeSecurityHeaders(target), checkBlacklists(target)
      ]);
      const dns_result = dnsR.status === 'fulfilled' ? dnsR.value : {};
      const whois_result = whoisR.status === 'fulfilled' ? whoisR.value : null;
      const ssl_result = sslR.status === 'fulfilled' ? sslR.value : null;
      const headers_result = headersR.status === 'fulfilled' ? headersR.value : {};
      const blacklist_result = blacklistR.status === 'fulfilled' ? blacklistR.value : [];
      let subdomains: string[] = [];
      try {
        const crtRes = await axios.get(`https://crt.sh/?q=%.${target}&output=json`, { timeout: 10000 });
        const names = new Set<string>();
        (Array.isArray(crtRes.data) ? crtRes.data : []).forEach((e: any) => { if (e.name_value) e.name_value.split('\n').forEach((n: string) => { const c = n.replace('*.','').trim(); if (c && c !== target && c.endsWith(target)) names.add(c); }); });
        subdomains = [...names].slice(0, 50);
      } catch { }
      const riskScore = calculateRiskScore({ ssl: ssl_result, dns: dns_result, headers: headers_result, whoisData: whois_result, blacklists: blacklist_result });
      res.json({ target, dns: dns_result, whois: whois_result, ssl: ssl_result, headers: headers_result, blacklists: blacklist_result, subdomains, risk_score: riskScore });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- SSL ANALYSIS ---
  app.post("/api/ssl-analysis", authenticate, async (req: any, res: any) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: "Target is required" });
    try {
      const domain = target.replace(/^https?:\/\//, '').split('/')[0];
      const cert = await getSSLCertificate(domain);
      if (!cert) return res.status(404).json({ error: "Could not retrieve SSL certificate" });
      res.json({ target: domain, ...cert });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- EMAIL ANALYSIS ---
  app.post("/api/email-analysis", authenticate, async (req: any, res: any) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: "Email required" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) return res.status(400).json({ error: "Invalid email format" });
    try {
      const domain = target.split('@')[1];
      const [mxR, spfR, dmarcR] = await Promise.allSettled([
        resolveMx(domain),
        resolveTxt(domain).then(recs => recs.map((r: string[]) => r.join('')).find((t: string) => t.startsWith('v=spf1')) || null),
        resolveTxt(`_dmarc.${domain}`).then(recs => recs.map((r: string[]) => r.join('')).find((t: string) => t.startsWith('v=DMARC1')) || null),
      ]);
      const mx = mxR.status === 'fulfilled' ? mxR.value : [];
      const spf = spfR.status === 'fulfilled' ? spfR.value : null;
      const dmarc = dmarcR.status === 'fulfilled' ? dmarcR.value : null;
      const isDisposable = DISPOSABLE_DOMAINS.has(domain.toLowerCase());
      const isFree = ['gmail.com','yahoo.com','hotmail.com','outlook.com','icloud.com','protonmail.com','live.com','aol.com'].includes(domain.toLowerCase());
      const breach_risk_score = isDisposable ? 80 : isFree ? 35 : (mx as any[]).length === 0 ? 20 : 25;
      res.json({ email: target, domain, format_valid: true, mx_records: mx, mx_valid: (mx as any[]).length > 0, spf_record: spf, spf_valid: !!spf, dmarc_record: dmarc, dmarc_valid: !!dmarc, disposable: isDisposable, free_provider: isFree, breach_risk_score, risk_level: breach_risk_score >= 60 ? 'High' : breach_risk_score >= 35 ? 'Medium' : 'Low' });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- IP FULL ANALYSIS ---
  app.post("/api/ip-full", authenticate, async (req: any, res: any) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: "IP required" });
    try {
      const [geoR, ptrR, blR] = await Promise.allSettled([
        axios.get(`http://ip-api.com/json/${target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`, { timeout: 8000 }),
        reverseDns(target),
        checkBlacklists(target),
      ]);
      const geo = geoR.status === 'fulfilled' ? geoR.value.data : {};
      const ptr = ptrR.status === 'fulfilled' ? ptrR.value : [];
      const blacklists = blR.status === 'fulfilled' ? blR.value : [];
      let abuseData = null;
      const abuseKey = process.env.ABUSEIPDB_API_KEY;
      if (abuseKey) { try { const ar = await axios.get(`https://api.abuseipdb.com/api/v2/check?ipAddress=${target}&maxAgeInDays=90`, { headers: { 'Key': abuseKey, 'Accept': 'application/json' }, timeout: 8000 }); abuseData = ar.data?.data; } catch { } }
      const listedCount = (blacklists as any[]).filter(b => b.status === 'LISTED').length;
      const risk_score = Math.min(100, (geo.proxy || geo.hosting ? 20 : 0) + listedCount * 15 + (abuseData?.abuseConfidenceScore || 0) * 0.5);
      const isPrivate = /^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|127\.|::1)/.test(target);
      res.json({ ip: target, is_private: isPrivate, geolocation: geo, ptr_records: ptr, blacklists, abuse_data: abuseData, risk_score: Math.round(risk_score) });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- BLACKLIST CHECK ---
  app.post("/api/blacklist-check", authenticate, async (req: any, res: any) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: "Target required" });
    try {
      const results = await checkBlacklists(target);
      const lc = results.filter(r => r.status === 'LISTED').length;
      res.json({ target, blacklists: results, listed_count: lc, risk_level: lc > 2 ? 'High' : lc > 0 ? 'Medium' : 'Low' });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- SUBDOMAIN DISCOVERY ---
  app.post("/api/subdomain-discovery", authenticate, async (req: any, res: any) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ error: "Domain required" });
    try {
      const subdomains = new Map<string, string[]>();
      try {
        const crtRes = await axios.get(`https://crt.sh/?q=%.${target}&output=json`, { timeout: 12000 });
        if (Array.isArray(crtRes.data)) {
          crtRes.data.forEach((e: any) => { if (e.name_value) e.name_value.split('\n').forEach((n: string) => { const c = n.replace('*.','').trim().toLowerCase(); if (c && c.endsWith(target) && c !== target) { if (!subdomains.has(c)) subdomains.set(c, ['crt.sh']); }; }); });
        }
      } catch { }
      try {
        const htRes = await axios.get(`https://api.hackertarget.com/hostsearch/?q=${target}`, { timeout: 8000 });
        if (typeof htRes.data === 'string' && !htRes.data.includes('error')) {
          htRes.data.split('\n').forEach((line: string) => { const [sub] = line.split(','); if (sub && sub.endsWith(target) && sub !== target) { if (!subdomains.has(sub)) subdomains.set(sub, ['hackertarget']); else subdomains.get(sub)?.push('hackertarget'); } });
        }
      } catch { }
      const result = Array.from(subdomains.entries()).map(([subdomain, sources]) => ({ subdomain, sources: [...new Set(sources)] }));
      res.json({ target, count: result.length, subdomains: result.slice(0, 100) });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- RISK SCORE ---
  app.post("/api/risk-score", authenticate, async (req: any, res: any) => {
    const { domainData, ipData } = req.body;
    try {
      const score = calculateRiskScore({ ssl: domainData?.ssl, dns: domainData?.dns, headers: domainData?.headers, whoisData: domainData?.whois, blacklists: domainData?.blacklists || ipData?.blacklists });
      res.json(score);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- EXPORT REPORT ---
  app.get("/api/export-report/:investigationId", authenticate, async (req: any, res: any) => {
    const { investigationId } = req.params;
    const format = req.query.format || 'json';
    const userId = req.user.id;
    try {
      const { data: inv, error } = await supabase.from('investigations').select('*').eq('id', investigationId).eq('user_id', userId).single();
      if (error || !inv) return res.status(404).json({ error: 'Investigation not found' });
      if (format === 'csv') {
        const rows = [['Field','Value'],['Query',inv.query],['Type',inv.type],['Status',inv.status],['Risk Score',inv.risk_score],['Created At',inv.created_at],['Summary',(inv.summary||'').replace(/,/g,';').replace(/\n/g,' ')]];
        res.setHeader('Content-Type','text/csv'); res.setHeader('Content-Disposition',`attachment; filename="cybercord-${investigationId}.csv"`);
        return res.send(rows.map(r => r.join(',')).join('\n'));
      }
      if (format === 'html') {
        const rc = (inv.risk_score||0) > 70 ? '#ef4444' : (inv.risk_score||0) > 30 ? '#f59e0b' : '#10b981';
        const html = `<!DOCTYPE html><html><head><title>Cybercord Report: ${inv.query}</title><style>body{font-family:monospace;background:#000;color:#e5e7eb;padding:40px}h1{color:#06b6d4}table{width:100%;border-collapse:collapse}td,th{border:1px solid #374151;padding:8px}th{background:#111}.risk{color:${rc};font-weight:bold}</style></head><body><h1>&#x1F6E1; Cybercord Enterprise Report</h1><p>Generated: ${new Date().toISOString()}</p><h2>${inv.query}</h2><table><tr><th>Field</th><th>Value</th></tr><tr><td>Type</td><td>${inv.type}</td></tr><tr><td>Status</td><td>${inv.status}</td></tr><tr><td>Risk Score</td><td class="risk">${inv.risk_score||'N/A'}/100</td></tr><tr><td>Created</td><td>${inv.created_at}</td></tr></table><h3>Summary</h3><pre>${inv.summary||'No summary'}</pre></body></html>`;
        res.setHeader('Content-Type','text/html'); return res.send(html);
      }
      res.json(inv);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
  });

  // --- RUN-TOOL (expanded) ---
  app.post("/api/run-tool", authenticate, async (req: any, res: any) => {
    const { toolId, target } = req.body;
    const userId = req.user.id;
    if (!target) return res.status(400).json({ error: "Target is required" });
    try {
      const { data: userDoc } = await supabase.from('users').select('settings').eq('id', userId).single();
      const userSettings = userDoc?.settings?.apiKeys || {};
      const { data: globalConfigDoc } = await supabase.from('system_configs').select('keys').eq('id', 'api_keys').single();
      const globalKeys = globalConfigDoc?.keys || {};
      const getApiKey = (service: string, envVar: string) => userSettings?.[service] || globalKeys?.[service]?.value || process.env[envVar];
      let data: any = {}; let reportType = "";
      switch (toolId) {
        case 'sherlock': case 'social-analyzer':
          reportType = "SOCIAL_INTELLIGENCE";
          const platforms = [
            { name: 'GitHub', url: `https://github.com/${target}` }, { name: 'Twitter/X', url: `https://twitter.com/${target}` },
            { name: 'Instagram', url: `https://instagram.com/${target}` }, { name: 'Reddit', url: `https://reddit.com/user/${target}` },
            { name: 'YouTube', url: `https://youtube.com/@${target}` }, { name: 'LinkedIn', url: `https://linkedin.com/in/${target}` },
            { name: 'TikTok', url: `https://tiktok.com/@${target}` }, { name: 'Steam', url: `https://steamcommunity.com/id/${target}` },
            { name: 'Twitch', url: `https://twitch.tv/${target}` }, { name: 'SoundCloud', url: `https://soundcloud.com/${target}` },
            { name: 'Medium', url: `https://medium.com/@${target}` }, { name: 'Dev.to', url: `https://dev.to/${target}` },
            { name: 'GitLab', url: `https://gitlab.com/${target}` }, { name: 'Bitbucket', url: `https://bitbucket.org/${target}` },
            { name: 'Keybase', url: `https://keybase.io/${target}` }, { name: 'Behance', url: `https://behance.net/${target}` },
            { name: 'Dribbble', url: `https://dribbble.com/${target}` }, { name: 'HackerNews', url: `https://news.ycombinator.com/user?id=${target}` },
            { name: 'StackOverflow', url: `https://stackoverflow.com/users/${target}` }, { name: 'Kaggle', url: `https://kaggle.com/${target}` },
            { name: 'DockerHub', url: `https://hub.docker.com/u/${target}` }, { name: 'ProductHunt', url: `https://producthunt.com/@${target}` },
            { name: 'CodePen', url: `https://codepen.io/${target}` }, { name: 'Replit', url: `https://replit.com/@${target}` },
            { name: 'Last.fm', url: `https://last.fm/user/${target}` }, { name: 'Letterboxd', url: `https://letterboxd.com/${target}` },
            { name: 'Chess.com', url: `https://chess.com/member/${target}` }, { name: 'Strava', url: `https://strava.com/athletes/${target}` },
            { name: 'Duolingo', url: `https://duolingo.com/profile/${target}` }, { name: 'Goodreads', url: `https://goodreads.com/${target}` },
          ];
          const results = await Promise.all(platforms.map(async (p) => {
            try {
              const r = await axios.get(p.url, { timeout: 6000, maxRedirects: 3, validateStatus: (s) => s < 500, headers: { 'User-Agent': 'Mozilla/5.0 (compatible; CybercordBot/2.0)' } });
              const body = (r.data?.toString() || '').toLowerCase();
              const notFoundPatterns: Record<string, string[]> = { 'GitHub': ['not found'], 'Twitter/X': ["this account doesn", 'page not found'], 'Reddit': ["nobody on reddit goes by that name"], 'Steam': ['the specified profile could not be found'], 'HackerNews': ['no such user'], 'Dev.to': ['not found'] };
              const patterns = notFoundPatterns[p.name] || ['not found', 'page not found', 'user not found'];
              if (r.status === 404 || patterns.some(pat => body.includes(pat))) return { platform: p.name, status: 'NOT_FOUND' };
              return { platform: p.name, status: 'FOUND', url: p.url };
            } catch (err: any) { return { platform: p.name, status: err.response?.status === 404 ? 'NOT_FOUND' : 'NOT_FOUND' }; }
          }));
          data = { username: target, results };
          break;
        case 'threat-intel':
          reportType = "THREAT_INTELLIGENCE";
          const blResults = await checkBlacklists(target);
          const lc = blResults.filter((b: any) => b.status === 'LISTED').length;
          data = { target, score: Math.min(100, lc * 25), level: lc > 2 ? 'High' : lc > 0 ? 'Medium' : 'Low', category: lc > 0 ? 'Blacklisted' : 'Clean', blacklists: blResults, lastSeen: lc > 0 ? 'Recently' : 'N/A' };
          break;
        case 'numverify': case 'truecaller': case 'eyecon': case 'phoneinfoga':
          reportType = "PHONE_INTELLIGENCE";
          if (!isValidPhoneNumber(target)) throw new Error("Invalid phone number format.");
          const phoneNumber = parsePhoneNumberFromString(target);
          data = { valid: true, number: phoneNumber?.number, country: phoneNumber?.country, type: phoneNumber?.getType() || 'N/A', location: phoneNumber?.country || 'N/A', carrier: 'Unknown', line_type: phoneNumber?.getType() || 'N/A', caller_id: 'Private', spam_score: 0 };
          const numKey = getApiKey('numverify', 'NUMVERIFY_API_KEY');
          if (numKey && toolId === 'numverify') { try { const nvR = await axios.get(`http://apilayer.net/api/validate?access_key=${numKey}&number=${target.replace(/\+/g, '')}`, { timeout: 5000 }); if (nvR.data.valid) data = { ...data, ...nvR.data }; } catch { } }
          break;
        case 'dnsdumpster': case 'subfinder': case 'dns-full':
          reportType = "DNS_RECONNAISSANCE";
          data = await analyzeDNS(target);
          break;
        case 'whois':
          reportType = "WHOIS_LOOKUP";
          data = await whois(target);
          break;
        case 'ssl-checker':
          reportType = "SSL_ANALYSIS";
          const sslD = await getSSLCertificate(target.replace(/^https?:\/\//, '').split('/')[0]);
          data = sslD || { error: 'Could not retrieve SSL certificate' };
          break;
        case 'headers': case 'builtwith':
          reportType = "HTTP_HEADERS_ANALYSIS";
          data = await analyzeSecurityHeaders(target);
          break;
        case 'blacklist':
          reportType = "BLACKLIST_CHECK";
          const blR2 = await checkBlacklists(target);
          data = { target, blacklists: blR2, listed_count: blR2.filter((b: any) => b.status === 'LISTED').length };
          break;
        case 'subdomain-finder': case 'subdomains':
          reportType = "SUBDOMAIN_DISCOVERY";
          const crtR = await axios.get(`https://crt.sh/?q=%.${target}&output=json`, { timeout: 12000 }).catch(() => ({ data: [] }));
          const subs = new Set<string>();
          (Array.isArray(crtR.data) ? crtR.data : []).forEach((e: any) => { if (e.name_value) e.name_value.split('\n').forEach((n: string) => { const c = n.replace('*.','').trim(); if (c && c !== target) subs.add(c); }); });
          data = { target, subdomains: [...subs].slice(0, 100), count: subs.size };
          break;
        case 'shodan': case 'censys': case 'ip-lookup':
          reportType = "IP_INTELLIGENCE";
          const geoR2 = await axios.get(`http://ip-api.com/json/${target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`, { timeout: 8000 });
          data = geoR2.data;
          break;
        case 'email-analysis':
          reportType = "EMAIL_ANALYSIS";
          const eDomain = target.includes('@') ? target.split('@')[1] : target;
          const eMx = await resolveMx(eDomain).catch(() => []);
          data = { email: target, domain: eDomain, mx_records: eMx, mx_valid: (eMx as any[]).length > 0, disposable: DISPOSABLE_DOMAINS.has(eDomain.toLowerCase()), breach_risk_score: DISPOSABLE_DOMAINS.has(eDomain.toLowerCase()) ? 80 : 30 };
          break;
        case 'hibp':
          reportType = "BREACH_CHECK";
          const hibpKey = getApiKey('hibp', 'HIBP_API_KEY');
          if (!hibpKey) { data = { message: 'HIBP API key required. Configure in Admin > API Keys.', email: target, breaches: [] }; break; }
          try {
            const hibpR = await axios.get(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(target)}`, { headers: { 'hibp-api-key': hibpKey, 'user-agent': 'Cybercord-Enterprise/2.0' }, timeout: 8000 });
            data = { email: target, breaches: hibpR.data || [], breach_count: hibpR.data?.length || 0 };
          } catch (err: any) {
            if (err.response?.status === 404) data = { email: target, breaches: [], breach_count: 0, message: 'No breaches found' };
            else data = { email: target, breaches: [], message: err.response?.status === 401 ? 'Invalid HIBP API key' : 'HIBP lookup failed' };
          }
          break;
        case 'domain-full':
          reportType = "DOMAIN_INTELLIGENCE";
          const [dfDns, dfWhois, dfSsl, dfHeaders, dfBl] = await Promise.allSettled([analyzeDNS(target), whois(target).catch(() => null), getSSLCertificate(target), analyzeSecurityHeaders(target), checkBlacklists(target)]);
          const dfRisk = calculateRiskScore({ ssl: dfSsl.status === 'fulfilled' ? dfSsl.value : null, dns: dfDns.status === 'fulfilled' ? dfDns.value : {}, headers: dfHeaders.status === 'fulfilled' ? dfHeaders.value : {}, whoisData: dfWhois.status === 'fulfilled' ? dfWhois.value : null, blacklists: dfBl.status === 'fulfilled' ? dfBl.value : [] });
          data = { target, dns: dfDns.status === 'fulfilled' ? dfDns.value : {}, whois: dfWhois.status === 'fulfilled' ? dfWhois.value : null, ssl: dfSsl.status === 'fulfilled' ? dfSsl.value : null, headers: dfHeaders.status === 'fulfilled' ? dfHeaders.value : {}, blacklists: dfBl.status === 'fulfilled' ? dfBl.value : [], risk_score: dfRisk };
          break;
        default:
          reportType = "SYSTEM_NOTICE";
          data = { message: `Tool '${toolId}' routed via cloud engine.`, status: "PENDING", target };
      }
      res.json({ reportType, data });
    } catch (error: any) { res.status(500).json({ error: error.message || "Tool execution failed" }); }
  });

  app.post("/api/analyze-intelligence", authenticate, async (req: any, res: any) => {
    const { toolData, toolId, target } = req.body;
    if (!toolData) return res.status(400).json({ error: "Tool data required" });
    try {
      const prompt = `You are a Senior Cyber Intelligence Analyst. Analyze the following OSINT data for target: "${target}" using tool: "${toolId}".\n\nDATA:\n${JSON.stringify(toolData, null, 2)}\n\nProvide a concise professional intelligence assessment:\n1. Key Findings\n2. Risk Assessment\n3. Recommendations\n\nFormat in Markdown with **bold** for emphasis.`;
      const response = await ai.models.generateContent({ model: "gemini-2.0-flash", contents: [{ parts: [{ text: prompt }] }] });
      res.json({ analysis: response.text });
    } catch (error: any) { res.status(500).json({ error: "AI Analysis failed. Ensure GEMINI_API_KEY is configured." }); }
  });

  app.post("/api/investigate", authenticate, async (req: any, res: any) => {
    const { type, query } = req.body;
    await new Promise(resolve => setTimeout(resolve, 1000));
    res.json({ success: true, data: { input: query, type, timestamp: new Date().toISOString(), raw_results: [] } });
  });

  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({ server: { middlewareMode: true }, appType: "spa" });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => { res.sendFile(path.join(distPath, "index.html")); });
  }
  app.listen(PORT, "0.0.0.0", () => { console.log(`Cybercord Enterprise v2.0 running on http://localhost:${PORT}`); });
}
startServer();
