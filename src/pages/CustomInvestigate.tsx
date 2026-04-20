import React, { useState, useMemo, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import ReactMarkdown from 'react-markdown';
import { 
  Search, Shield, Globe, Mail, User, Smartphone, Zap, 
  Loader2, Filter, Terminal, Cpu, Lock, Eye, 
  Database, Network, Share2, Play, Info, Users, History, AlertCircle,
  MapPin, Server, Activity, FileText, ExternalLink, Copy, Check, X, ChevronRight,
  Sparkles, BrainCircuit, ShieldAlert
} from 'lucide-react';
import { cn } from '../lib/utils';
import { supabase } from '../supabase';

interface Tool {
  id: string;
  name: string;
  category: 'Identity' | 'Infrastructure' | 'Network' | 'Social' | 'Media' | 'Code' | 'Security' | 'Document';
  description: string;
  icon: any;
  risk: 'Low' | 'Medium' | 'High';
  status: 'Working' | 'Not Working';
}

interface ToolResult {
  reportType: string;
  data: any;
}

const ToolResultRenderer = ({ result, target }: { result: ToolResult; target: string }) => {
  const { reportType, data } = result;

  const renderSection = (title: string, icon: any, children: React.ReactNode) => (
    <div className="mb-8 last:mb-0">
      <div className="flex items-center gap-2 mb-4">
        <div className="p-1.5 bg-cyan-500/10 rounded-lg">
          {React.createElement(icon, { className: "w-4 h-4 text-cyan-500" })}
        </div>
        <h4 className="text-sm font-bold text-gray-300 uppercase tracking-wider">{title}</h4>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {children}
      </div>
    </div>
  );

  const renderItem = (label: string, value: any) => (
    <div className="p-3 rounded-xl bg-white/5 border border-white/5 flex flex-col gap-1">
      <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">{label}</span>
      <span className="text-sm text-gray-200 font-medium truncate">{value?.toString() || 'N/A'}</span>
    </div>
  );

  if (reportType === 'IP_INTELLIGENCE') {
    const geo = data.geolocation || data;
    return (
      <div className="space-y-8">
        {renderSection("Geographic Data", MapPin, (
          <>
            {renderItem("City", geo.city)}
            {renderItem("Region", geo.regionName || geo.region)}
            {renderItem("Country", geo.country ? `${geo.country} (${geo.countryCode})` : 'N/A')}
            {renderItem("Coordinates", geo.lat != null ? `${geo.lat}, ${geo.lon}` : 'N/A')}
            {renderItem("Timezone", geo.timezone)}
            {renderItem("ZIP", geo.zip)}
          </>
        ))}

        {renderSection("Network Intelligence", Server, (
          <>
            {renderItem("ISP", geo.isp)}
            {renderItem("Organization", geo.org)}
            {renderItem("ASN", geo.as || geo.asname)}
            {renderItem("Reverse DNS", geo.reverse || (data.ptr_records && data.ptr_records[0]) || 'N/A')}
          </>
        ))}

        {renderSection("Security Audit", Shield, (
          <>
            {renderItem("Proxy / Hosting", geo.proxy || geo.hosting ? 'YES — Elevated Risk' : 'NO')}
            {renderItem("Mobile Network", geo.mobile ? 'YES' : 'NO')}
            {renderItem("Risk Score", data.risk_score != null ? `${data.risk_score}/100` : 'N/A')}
            {renderItem("Status", geo.status || 'success')}
          </>
        ))}

        {data.blacklists && data.blacklists.length > 0 && renderSection("Blacklist Status", ShieldAlert, (
          <>
            {data.blacklists.map((bl: any, idx: number) => (
              <div key={idx} className="p-3 rounded-xl bg-white/5 border border-white/5 flex items-center justify-between">
                <span className="text-xs font-medium text-gray-400">{bl.name}</span>
                <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-widest", bl.status === 'CLEAN' ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500")}>{bl.status}</span>
              </div>
            ))}
          </>
        ))}
      </div>
    );
  }

  if (reportType === 'PHONE_INTELLIGENCE') {
    return (
      <div className="space-y-8">
        <div className="flex items-center justify-between p-6 rounded-3xl bg-white/5 border border-white/10">
          <div className="flex items-center gap-4">
            <div className={cn(
              "p-3 rounded-2xl",
              data.spam_score > 30 ? "bg-red-500/10 text-red-500" : "bg-emerald-500/10 text-emerald-500"
            )}>
              <Smartphone className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-xl font-bold">{data.caller_id || 'Unknown Caller'}</h3>
              <p className="text-sm text-gray-500">{data.number}</p>
            </div>
          </div>
          {data.spam_score > 0 && (
            <div className="text-right">
              <p className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1">Spam Score</p>
              <p className={cn(
                "text-2xl font-black",
                data.spam_score > 30 ? "text-red-500" : "text-emerald-500"
              )}>{data.spam_score}%</p>
            </div>
          )}
        </div>

        {renderSection("Network & Carrier", Server, (
          <>
            {renderItem("Carrier", data.carrier || data.carrier_name)}
            {renderItem("Line Type", data.line_type || data.type)}
            {renderItem("Reputation", data.reputation || (data.spam_score > 30 ? 'Suspicious' : 'Clean'))}
          </>
        ))}

        {renderSection("Geographic Intelligence", MapPin, (
          <>
            {renderItem("Country", data.country_name || data.country)}
            {renderItem("Location", data.location)}
            {renderItem("Timezone", data.timezone || 'N/A')}
          </>
        ))}

        {data.social_links && data.social_links.length > 0 && (
          renderSection("Social Footprint", Share2, (
            <div className="flex flex-wrap gap-2">
              {data.social_links.map((link: string, idx: number) => (
                <span key={idx} className="px-3 py-1 bg-cyan-500/10 text-cyan-500 text-[10px] font-bold rounded-lg border border-cyan-500/20 uppercase tracking-widest">
                  {link}
                </span>
              ))}
            </div>
          ))
        )}
      </div>
    );
  }

  if (reportType === 'SOCIAL_INTELLIGENCE') {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20">
          <div className="flex items-center gap-3">
            <Users className="w-6 h-6 text-cyan-500" />
            <div>
              <h4 className="font-bold">Social Footprint: {data.username}</h4>
              <p className="text-xs text-gray-400">Scanning major platforms for matching profiles...</p>
            </div>
          </div>
          <div className="flex gap-2">
            <a 
              href={`https://www.google.com/search?q="${data.username}"+social+media+profiles`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-3 py-1.5 bg-white/5 hover:bg-white/10 rounded-xl text-[10px] font-bold uppercase tracking-widest transition-all border border-white/10"
            >
              <Search className="w-3 h-3" />
              Google Search
            </a>
          </div>
        </div>
        
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {data.results.map((res: any, idx: number) => (
            <div key={idx} className={cn(
              "p-4 rounded-xl border flex items-center justify-between transition-all",
              res.status === 'FOUND' ? "bg-emerald-500/5 border-emerald-500/20" : 
              res.status === 'ERROR' ? "bg-amber-500/5 border-amber-500/20" :
              "bg-white/5 border-white/5 opacity-40"
            )}>
              <div className="flex items-center gap-3">
                <div className={cn(
                  "w-2 h-2 rounded-full",
                  res.status === 'FOUND' ? "bg-emerald-500" : 
                  res.status === 'ERROR' ? "bg-amber-500" : "bg-gray-700"
                )} />
                <span className="text-sm font-medium">{res.platform}</span>
              </div>
              
              {res.status === 'FOUND' ? (
                <div className="flex items-center gap-2">
                  <a 
                    href={res.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="p-1.5 hover:bg-emerald-500/20 rounded-lg text-emerald-500 transition-colors"
                    title="View Profile"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              ) : (
                <span className="text-[10px] font-bold text-gray-600 uppercase tracking-widest">
                  {res.status.replace('_', ' ')}
                </span>
              )}
            </div>
          ))}
        </div>

        {data.results.filter((r: any) => r.status === 'FOUND').length === 0 && (
          <div className="p-8 text-center rounded-2xl bg-white/5 border border-dashed border-white/10">
            <User className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-sm text-gray-500">No active profiles found in the primary scan.</p>
            <p className="text-xs text-gray-600 mt-1">Try the Google Search link above for a broader discovery.</p>
          </div>
        )}
      </div>
    );
  }

  if (reportType === 'THREAT_INTELLIGENCE') {
    return (
      <div className="space-y-8">
        <div className="flex flex-col items-center justify-center p-8 rounded-3xl bg-white/5 border border-white/10 relative overflow-hidden">
          <div className={cn(
            "absolute inset-0 opacity-10 blur-3xl",
            data.level === 'High' ? "bg-red-500" : data.level === 'Medium' ? "bg-amber-500" : "bg-emerald-500"
          )} />
          
          <div className={cn(
            "w-24 h-24 rounded-full border-4 flex items-center justify-center mb-4 relative z-10",
            data.level === 'High' ? "border-red-500/50 text-red-500" : 
            data.level === 'Medium' ? "border-amber-500/50 text-amber-500" : 
            "border-emerald-500/50 text-emerald-500"
          )}>
            <span className="text-3xl font-black">{data.score}</span>
          </div>
          <h3 className="text-xl font-bold mb-1 relative z-10">Threat Score: {data.level}</h3>
          <p className="text-gray-500 text-sm relative z-10">{data.category}</p>
        </div>

        {renderSection("Blacklist Status", ShieldAlert, (
          <>
            {data.blacklists.map((bl: any, idx: number) => (
              <div key={idx} className="p-3 rounded-xl bg-white/5 border border-white/5 flex items-center justify-between">
                <span className="text-xs font-medium text-gray-400">{bl.name}</span>
                <span className={cn(
                  "text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-widest",
                  bl.status === 'CLEAN' ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500"
                )}>
                  {bl.status}
                </span>
              </div>
            ))}
          </>
        ))}

        {data.lastSeen !== 'N/A' && (
          <div className="p-4 rounded-2xl bg-white/5 border border-white/10 flex items-center gap-3">
            <Activity className="w-4 h-4 text-cyan-500" />
            <span className="text-xs text-gray-400">Last malicious activity detected: <b className="text-gray-200">{data.lastSeen}</b></span>
          </div>
        )}
      </div>
    );
  }

  if (reportType === 'DNS_RECONNAISSANCE') {
    const recordSections = [
      { key: 'a_records', label: 'A Records (IPv4)' },
      { key: 'aaaa_records', label: 'AAAA Records (IPv6)' },
      { key: 'mx_records', label: 'MX Records (Mail)' },
      { key: 'ns_records', label: 'NS Records (Nameserver)' },
      { key: 'txt_records', label: 'TXT Records' },
    ];
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {renderItem("SPF", data.spf_valid ? '✓ Valid' : '✗ Missing')}
          {renderItem("DMARC", data.dmarc_valid ? '✓ Valid' : '✗ Missing')}
          {renderItem("DKIM", data.dkim_valid ? '✓ Valid' : '✗ Missing')}
          {renderItem("DNSSEC", data.dnssec ? '✓ Enabled' : '✗ Disabled')}
        </div>
        {recordSections.map(({ key, label }) => {
          const recs = data[key];
          if (!recs || (Array.isArray(recs) && recs.length === 0)) return null;
          return (
            <div key={key}>
              <div className="flex items-center gap-2 mb-2">
                <Activity className="w-4 h-4 text-cyan-500" />
                <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">{label}</span>
              </div>
              <div className="space-y-1">
                {(Array.isArray(recs) ? recs : [recs]).map((rec: any, idx: number) => (
                  <div key={idx} className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-cyan-500/80">
                    {typeof rec === 'object' ? JSON.stringify(rec) : String(rec)}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
        {data.spf && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-cyan-500" />
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">SPF Record</span>
            </div>
            <div className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-cyan-500/80 break-all">{data.spf}</div>
          </div>
        )}
        {data.dmarc && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-4 h-4 text-cyan-500" />
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">DMARC Record</span>
            </div>
            <div className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-cyan-500/80 break-all">{data.dmarc}</div>
          </div>
        )}
        {data.dkim && data.dkim.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-2">
              <Lock className="w-4 h-4 text-cyan-500" />
              <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">DKIM Selectors Found</span>
            </div>
            <div className="space-y-1">
              {data.dkim.map((d: any, idx: number) => (
                <div key={idx} className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-cyan-500/80 break-all">
                  [{d.selector}] {d.record}
                </div>
              ))}
            </div>
          </div>
        )}
        {!data.a_records?.length && !data.ns_records?.length && (
          <div className="p-8 text-center text-gray-500 italic">No public DNS records found for this target.</div>
        )}
      </div>
    );
  }

  if (reportType === 'HTTP_HEADERS_ANALYSIS') {
    const sh = data.security_headers || {};
    const securityHeaderKeys = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy', 'Cache-Control'];
    return (
      <div className="space-y-8">
        {renderSection("Response Status", Activity, (
          <>
            {renderItem("Status Code", data.status)}
            {renderItem("Status Text", data.statusText)}
            {renderItem("Server", data.server || 'Unknown')}
            {renderItem("Security Score", data.headers_score != null ? `${data.headers_score}%` : 'N/A')}
          </>
        ))}

        {renderSection("Security Headers", Shield, (
          <>
            {securityHeaderKeys.map(k => (
              <div key={k} className="p-3 rounded-xl bg-white/5 border border-white/5 flex items-center justify-between gap-2">
                <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest truncate">{k.replace(/-/g,' ')}</span>
                <span className={cn("text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-widest shrink-0", sh[k]?.present ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500")}>
                  {sh[k]?.present ? 'SET' : 'MISSING'}
                </span>
              </div>
            ))}
          </>
        ))}

        <div className="space-y-2">
          <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2">Security Header Values</label>
          <div className="p-4 rounded-2xl bg-black border border-white/10 font-mono text-xs text-cyan-500/60 max-h-60 overflow-y-auto custom-scrollbar">
            <pre>{JSON.stringify(sh, null, 2)}</pre>
          </div>
        </div>
      </div>
    );
  }

  if (reportType === 'WHOIS_LOOKUP') {
    return (
      <div className="space-y-8">
        {renderSection("Registration Details", User, (
          <>
            {renderItem("Registrar", data.registrar)}
            {renderItem("Creation Date", data.creationDate || data.createdDate || data.registrationDate)}
            {renderItem("Expiration Date", data.expirationDate || data.expiryDate || data.registryExpiryDate)}
            {renderItem("Updated Date", data.updatedDate || data.updatedAt)}
          </>
        ))}

        {renderSection("Registrant Info", Shield, (
          <>
            {renderItem("Organization", data.registrantOrganization || data.org)}
            {renderItem("Country", data.registrantCountry || data.country)}
            {renderItem("State", data.registrantState || data.registrantStateProvince)}
            {renderItem("City", data.registrantCity)}
          </>
        ))}

        <div className="space-y-2">
          <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2">Raw WHOIS Data</label>
          <div className="p-4 rounded-2xl bg-black border border-white/10 font-mono text-xs text-cyan-500/60 max-h-60 overflow-y-auto custom-scrollbar">
            <pre>{JSON.stringify(data, null, 2)}</pre>
          </div>
        </div>
      </div>
    );
  }

  if (reportType === 'SSL_ANALYSIS') {
    return (
      <div className="space-y-8">
        <div className={cn(
          "p-6 rounded-3xl border flex items-center gap-4",
          data.expired ? "bg-red-500/10 border-red-500/30" : data.days_remaining < 30 ? "bg-amber-500/10 border-amber-500/30" : "bg-emerald-500/10 border-emerald-500/30"
        )}>
          <Shield className={cn("w-8 h-8", data.expired ? "text-red-500" : data.days_remaining < 30 ? "text-amber-500" : "text-emerald-500")} />
          <div>
            <h4 className="font-bold text-white">{data.expired ? 'Certificate EXPIRED' : `Valid for ${data.days_remaining} more days`}</h4>
            <p className="text-sm text-gray-400">{data.issuer?.O || 'Unknown Issuer'}</p>
          </div>
        </div>
        {renderSection("Certificate Details", Lock, (
          <>
            {renderItem("Issued To", data.subject?.CN)}
            {renderItem("Issued By", data.issuer?.CN)}
            {renderItem("Valid From", data.valid_from)}
            {renderItem("Valid To", data.valid_to)}
            {renderItem("Days Remaining", data.days_remaining)}
            {renderItem("Self-Signed", data.self_signed ? 'YES — Not Trusted' : 'NO')}
            {renderItem("Protocol", data.protocol)}
            {renderItem("Cipher", data.cipher?.name)}
          </>
        ))}
        {data.san && data.san.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3"><Globe className="w-4 h-4 text-cyan-500" /><span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Subject Alt Names ({data.san.length})</span></div>
            <div className="flex flex-wrap gap-2">
              {data.san.slice(0, 20).map((n: string, i: number) => <span key={i} className="px-2 py-1 bg-cyan-500/10 text-cyan-500 text-[10px] font-mono rounded border border-cyan-500/20">{n}</span>)}
              {data.san.length > 20 && <span className="px-2 py-1 text-gray-500 text-[10px] font-bold">+{data.san.length - 20} more</span>}
            </div>
          </div>
        )}
        {data.fingerprint256 && (
          <div>
            <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2">SHA-256 Fingerprint</label>
            <div className="mt-2 p-3 rounded-xl bg-black border border-white/10 font-mono text-[10px] text-cyan-500/60 break-all">{data.fingerprint256}</div>
          </div>
        )}
      </div>
    );
  }

  if (reportType === 'EMAIL_ANALYSIS') {
    return (
      <div className="space-y-8">
        <div className={cn(
          "p-6 rounded-3xl border flex items-center gap-4",
          data.disposable ? "bg-red-500/10 border-red-500/30" : "bg-emerald-500/10 border-emerald-500/30"
        )}>
          <Mail className={cn("w-8 h-8", data.disposable ? "text-red-500" : "text-emerald-500")} />
          <div>
            <h4 className="font-bold text-white">{data.disposable ? 'Disposable / Throwaway Email' : data.free_provider ? 'Free Email Provider' : 'Corporate / Custom Domain'}</h4>
            <p className="text-sm text-gray-400">{data.email || data.domain}</p>
          </div>
        </div>
        {renderSection("Validation", Shield, (
          <>
            {renderItem("Format Valid", data.format_valid !== false ? 'YES' : 'NO')}
            {renderItem("MX Records", data.mx_valid ? 'VALID — Can Receive Mail' : 'INVALID — Cannot Receive Mail')}
            {renderItem("Disposable Domain", data.disposable ? 'YES — Suspicious' : 'NO')}
            {renderItem("Free Provider", data.free_provider ? 'YES' : 'NO')}
            {renderItem("Risk Level", data.risk_level || (data.disposable ? 'High' : 'Low'))}
            {renderItem("Breach Risk Score", data.breach_risk_score != null ? `${data.breach_risk_score}/100` : 'N/A')}
          </>
        ))}
        {renderSection("Email Authentication", Globe, (
          <>
            {renderItem("SPF Record", data.spf_valid ? 'VALID' : 'MISSING')}
            {renderItem("DMARC Policy", data.dmarc_valid ? 'VALID' : 'MISSING')}
            {renderItem("SPF Value", data.spf_record || 'N/A')}
          </>
        ))}
        {data.mx_records && data.mx_records.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3"><Server className="w-4 h-4 text-cyan-500" /><span className="text-xs font-bold text-gray-400 uppercase tracking-wider">MX Records</span></div>
            <div className="space-y-1">
              {(data.mx_records as any[]).map((mx: any, i: number) => (
                <div key={i} className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-cyan-500/80">
                  Priority {mx.priority}: {mx.exchange}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  }

  if (reportType === 'SUBDOMAIN_DISCOVERY') {
    return (
      <div className="space-y-6">
        <div className="p-4 rounded-2xl bg-cyan-500/5 border border-cyan-500/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Globe className="w-5 h-5 text-cyan-500" />
            <span className="font-bold text-white">Found {data.count || data.subdomains?.length || 0} Subdomains</span>
          </div>
          <span className="text-xs text-gray-500">Target: {data.target}</span>
        </div>
        {data.subdomains && data.subdomains.length > 0 ? (
          <div className="space-y-1 max-h-96 overflow-y-auto custom-scrollbar pr-1">
            {data.subdomains.map((sub: any, idx: number) => {
              const name = typeof sub === 'string' ? sub : sub.subdomain;
              const sources = typeof sub === 'object' && sub.sources ? sub.sources : [];
              return (
                <div key={idx} className="p-3 rounded-xl bg-white/5 border border-white/5 flex items-center justify-between">
                  <span className="font-mono text-xs text-cyan-400">{name}</span>
                  {sources.length > 0 && <span className="text-[10px] text-gray-600 uppercase tracking-widest">{sources.join(', ')}</span>}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="p-8 text-center text-gray-500 italic">No subdomains discovered for this target.</div>
        )}
      </div>
    );
  }

  if (reportType === 'DOMAIN_INTELLIGENCE') {
    const risk = data.risk_score;
    return (
      <div className="space-y-8">
        {risk && (
          <div className={cn(
            "p-6 rounded-3xl border flex items-center gap-4",
            risk.overall_score > 60 ? "bg-red-500/10 border-red-500/30" : risk.overall_score > 30 ? "bg-amber-500/10 border-amber-500/30" : "bg-emerald-500/10 border-emerald-500/30"
          )}>
            <ShieldAlert className={cn("w-8 h-8", risk.overall_score > 60 ? "text-red-500" : risk.overall_score > 30 ? "text-amber-500" : "text-emerald-500")} />
            <div>
              <h4 className="font-bold text-white">Risk Score: {risk.overall_score}/100 — {risk.risk_level}</h4>
              <p className="text-sm text-gray-400">{risk.recommendations?.length ? `${risk.recommendations.length} recommendations` : 'No critical issues'}</p>
            </div>
          </div>
        )}
        {data.dns && renderSection("DNS Summary", Globe, (
          <>
            {renderItem("A Records", data.dns.a_records?.join(', ') || 'None')}
            {renderItem("NS Records", data.dns.ns_records?.join(', ') || 'None')}
            {renderItem("SPF", data.dns.spf_valid ? '✓ Valid' : '✗ Missing')}
            {renderItem("DMARC", data.dns.dmarc_valid ? '✓ Valid' : '✗ Missing')}
          </>
        ))}
        {data.ssl && renderSection("SSL Certificate", Lock, (
          <>
            {renderItem("Status", data.ssl.expired ? 'EXPIRED' : `Valid (${data.ssl.days_remaining}d remaining)`)}
            {renderItem("Issuer", data.ssl.issuer?.O)}
            {renderItem("Protocol", data.ssl.protocol)}
            {renderItem("Self-Signed", data.ssl.self_signed ? 'YES' : 'NO')}
          </>
        ))}
        {risk?.recommendations?.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3"><ShieldAlert className="w-4 h-4 text-amber-500" /><span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Recommendations</span></div>
            <div className="space-y-1">
              {risk.recommendations.map((r: string, i: number) => (
                <div key={i} className="p-3 rounded-xl bg-amber-500/5 border border-amber-500/10 text-xs text-gray-300 flex items-start gap-2">
                  <span className="text-amber-500 mt-0.5">→</span>{r}
                </div>
              ))}
            </div>
          </div>
        )}
        <div className="space-y-2">
          <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2">Raw Report</label>
          <div className="p-4 rounded-2xl bg-black border border-white/10 font-mono text-xs text-cyan-500/60 max-h-60 overflow-y-auto custom-scrollbar">
            <pre>{JSON.stringify(data, null, 2)}</pre>
          </div>
        </div>
      </div>
    );
  }

  if (reportType === 'BREACH_CHECK') {    return (
      <div className="space-y-6">
        {data.message && (
          <div className="p-4 rounded-2xl bg-amber-500/5 border border-amber-500/20 flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-amber-500 shrink-0" />
            <p className="text-sm text-gray-300">{data.message}</p>
          </div>
        )}
        {data.breaches && data.breaches.length > 0 ? (
          <>
            <div className="p-4 rounded-2xl bg-red-500/10 border border-red-500/30 flex items-center gap-3">
              <Shield className="w-5 h-5 text-red-500" />
              <span className="font-bold text-red-400">{data.breach_count} breach{data.breach_count !== 1 ? 'es' : ''} found for {data.email}</span>
            </div>
            <div className="space-y-3">
              {data.breaches.map((b: any, i: number) => (
                <div key={i} className="p-4 rounded-xl bg-white/5 border border-red-500/10">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-bold text-red-400">{b.Name || b.name}</h4>
                    <span className="text-[10px] text-gray-500">{b.BreachDate || b.date}</span>
                  </div>
                  <p className="text-xs text-gray-400">{(b.Description || '').replace(/<[^>]+>/g, ' ').replace(/&[a-z]+;/gi, ' ').trim()}</p>
                  {b.DataClasses && <div className="mt-2 flex flex-wrap gap-1">{(Array.isArray(b.DataClasses) ? b.DataClasses : []).map((d: string, di: number) => <span key={di} className="px-2 py-0.5 bg-red-500/10 text-red-400 text-[9px] font-bold rounded uppercase">{d}</span>)}</div>}
                </div>
              ))}
            </div>
          </>
        ) : !data.message && (
          <div className="p-8 text-center rounded-2xl bg-emerald-500/5 border border-emerald-500/20">
            <Shield className="w-10 h-10 text-emerald-500 mx-auto mb-3" />
            <h4 className="font-bold text-emerald-400">No Breaches Found</h4>
            <p className="text-sm text-gray-500 mt-1">{data.email} was not found in any known data breaches.</p>
          </div>
        )}
      </div>
    );
  }

  if (reportType === 'WAYBACK_ARCHIVE') {
    return (
      <div className="space-y-6">
        <div className="p-4 rounded-2xl bg-cyan-500/5 border border-cyan-500/10 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <History className="w-5 h-5 text-cyan-500" />
            <span className="font-bold text-white">{data.total_snapshots || 0} Snapshots Found</span>
          </div>
          <a href={`https://web.archive.org/web/*/${encodeURIComponent(target)}`} target="_blank" rel="noopener noreferrer" className="text-xs text-cyan-500 hover:underline flex items-center gap-1">View All <ExternalLink className="w-3 h-3" /></a>
        </div>
        {data.closest && (
          <div className="p-4 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-between">
            <div>
              <p className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-1">Most Recent Snapshot</p>
              <p className="text-sm font-mono text-cyan-400">{data.closest.timestamp}</p>
            </div>
            <a href={data.closest.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 px-3 py-1.5 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-500 text-[10px] font-bold rounded-xl transition-all border border-cyan-500/20">
              <ExternalLink className="w-3 h-3" /> Open
            </a>
          </div>
        )}
        {data.snapshots && data.snapshots.length > 0 && (
          <div className="space-y-1 max-h-96 overflow-y-auto custom-scrollbar pr-1">
            {data.snapshots.map((snap: any, idx: number) => (
              <a key={idx} href={snap.archive_url} target="_blank" rel="noopener noreferrer" className="flex items-center justify-between p-3 rounded-xl bg-white/5 border border-white/5 hover:border-cyan-500/30 transition-all group">
                <span className="font-mono text-xs text-gray-400 group-hover:text-cyan-400">{snap.timestamp}</span>
                <div className="flex items-center gap-3">
                  <span className={cn("text-[10px] font-bold px-1.5 py-0.5 rounded", snap.status === '200' ? "bg-emerald-500/10 text-emerald-500" : "bg-gray-500/10 text-gray-500")}>{snap.status}</span>
                  <ExternalLink className="w-3 h-3 text-gray-600 group-hover:text-cyan-500" />
                </div>
              </a>
            ))}
          </div>
        )}
        {data.error && <div className="p-4 text-center text-gray-500 italic">{data.error}</div>}
      </div>
    );
  }

  if (reportType === 'SECRET_SCAN') {
    return (
      <div className="space-y-6">
        <div className="p-4 rounded-2xl bg-amber-500/5 border border-amber-500/20 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-amber-500 shrink-0" />
          <p className="text-sm text-gray-300">{data.note}</p>
        </div>
        {data.error && (
          <div className="p-4 rounded-2xl bg-red-500/5 border border-red-500/20 text-sm text-red-400">{data.error}</div>
        )}
        {data.repos && data.repos.length > 0 && (
          <div>
            <div className="flex items-center gap-2 mb-3"><Database className="w-4 h-4 text-cyan-500" /><span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Public Repositories ({data.repos.length})</span></div>
            <div className="space-y-2">
              {data.repos.map((r: any, i: number) => (
                <a key={i} href={r.url} target="_blank" rel="noopener noreferrer" className="flex items-center justify-between p-3 rounded-xl bg-white/5 border border-white/5 hover:border-cyan-500/30 transition-all group">
                  <span className="text-sm font-medium text-gray-300 group-hover:text-cyan-400">{r.name}</span>
                  <div className="flex items-center gap-2">
                    {r.language && <span className="text-[10px] text-gray-500">{r.language}</span>}
                    <ExternalLink className="w-3 h-3 text-gray-600 group-hover:text-cyan-500" />
                  </div>
                </a>
              ))}
            </div>
          </div>
        )}
        {data.patterns_checked && (
          <div>
            <div className="flex items-center gap-2 mb-3"><Lock className="w-4 h-4 text-cyan-500" /><span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Patterns Checked</span></div>
            <div className="flex flex-wrap gap-2">{data.patterns_checked.map((p: string, i: number) => <span key={i} className="px-2 py-1 bg-white/5 text-gray-400 text-[10px] font-mono rounded border border-white/5">{p}</span>)}</div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="p-4 rounded-2xl bg-cyan-500/5 border border-cyan-500/10">
        <div className="flex items-center gap-3 mb-2">
          <Info className="w-5 h-5 text-cyan-500" />
          <h4 className="font-bold text-cyan-500">{reportType.replace(/_/g, ' ')}</h4>
        </div>
        <p className="text-sm text-gray-400">{data.message || 'Analysis complete. See raw metadata below.'}</p>
      </div>
      
      <div className="space-y-2">
        <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2">Raw Metadata</label>
        <div className="p-4 rounded-2xl bg-black border border-white/10 font-mono text-xs text-cyan-500/60 max-h-60 overflow-y-auto custom-scrollbar">
          <pre>{JSON.stringify(data, null, 2)}</pre>
        </div>
      </div>
    </div>
  );
};

const TOOLS: Tool[] = ([
  { id: 'threat-intel', name: 'Threat Intelligence', category: 'Security', description: 'Real-time threat assessment and blacklist monitoring for IPs.', icon: ShieldAlert, risk: 'Medium', status: 'Working' },
  { id: 'sherlock', name: 'Sherlock', category: 'Identity', description: 'Hunt down social media accounts by username across 300+ sites.', icon: User, risk: 'Low', status: 'Working' },
  { id: 'dnsdumpster', name: 'DNSDumpster', category: 'Infrastructure', description: 'Interactive DNS reconnaissance and mapping.', icon: Globe, risk: 'Low', status: 'Working' },
  { id: 'subfinder', name: 'Subfinder', category: 'Infrastructure', description: 'Fast passive subdomain enumeration tool.', icon: Search, risk: 'Low', status: 'Working' },
  { id: 'whois', name: 'Whois Lookup', category: 'Infrastructure', description: 'Domain ownership and registration details.', icon: User, risk: 'Low', status: 'Working' },
  { id: 'builtwith', name: 'BuiltWith', category: 'Infrastructure', description: 'Web technology profiler and lookup.', icon: Cpu, risk: 'Low', status: 'Working' },
  { id: 'headers', name: 'HTTP Headers', category: 'Infrastructure', description: 'Analyze security headers and server technology.', icon: Shield, risk: 'Low', status: 'Working' },
  { id: 'ssl-checker', name: 'SSL Checker', category: 'Infrastructure', description: 'Analyze SSL/TLS certificate details and validity.', icon: Lock, risk: 'Low', status: 'Working' },
  { id: 'shodan', name: 'Shodan', category: 'Network', description: 'Search for internet-connected devices and vulnerabilities.', icon: Network, risk: 'Medium', status: 'Working' },
  { id: 'censys', name: 'Censys', category: 'Network', description: 'Search engine for internet-connected hosts and certificates.', icon: Eye, risk: 'Medium', status: 'Working' },
  { id: 'ip-lookup', name: 'IP Intelligence', category: 'Network', description: 'Real-time IP geolocation and network data.', icon: Globe, risk: 'Low', status: 'Working' },
  { id: 'blacklist', name: 'Blacklist Check', category: 'Security', description: 'Check if IP or domain is listed on spam blacklists.', icon: ShieldAlert, risk: 'Low', status: 'Working' },
  { id: 'email-analysis', name: 'Email Analysis', category: 'Identity', description: 'Validate email address and analyze domain reputation.', icon: Mail, risk: 'Low', status: 'Working' },
  { id: 'subdomain-finder', name: 'Subdomain Finder', category: 'Infrastructure', description: 'Discover subdomains using certificate transparency logs.', icon: Search, risk: 'Low', status: 'Working' },
  { id: 'domain-full', name: 'Domain Full Scan', category: 'Infrastructure', description: 'Comprehensive domain analysis: DNS, SSL, WHOIS, headers, blacklists.', icon: Globe, risk: 'Medium', status: 'Working' },
  { id: 'numverify', name: 'NumVerify', category: 'Identity', description: 'Global phone number validation and lookup.', icon: Smartphone, risk: 'Low', status: 'Working' },
  { id: 'truecaller', name: 'Truecaller OSINT', category: 'Identity', description: 'Search caller ID and spam protection data.', icon: Smartphone, risk: 'Medium', status: 'Working' },
  { id: 'eyecon', name: 'Eyecon Lookup', category: 'Identity', description: 'Identify unknown callers and social profiles.', icon: Eye, risk: 'Medium', status: 'Working' },
  { id: 'phoneinfoga', name: 'PhoneInfoga', category: 'Identity', description: 'Advanced information gathering for phone numbers.', icon: Smartphone, risk: 'Medium', status: 'Working' },
  { id: 'wayback', name: 'Wayback Machine', category: 'Media', description: 'Explore archived versions of websites via CDX API.', icon: History, risk: 'Low', status: 'Working' },
  { id: 'amass', name: 'OWASP Amass', category: 'Infrastructure', description: 'In-depth attack surface mapping and asset discovery.', icon: Database, risk: 'Medium', status: 'Working' },
  { id: 'social-analyzer', name: 'Social Analyzer', category: 'Social', description: 'Analyze profiles across 1000+ social media sites.', icon: Users, risk: 'Medium', status: 'Working' },
  { id: 'hibp', name: 'Have I Been Pwned', category: 'Security', description: 'Check if email is in a data breach (requires HIBP API key).', icon: Shield, risk: 'Low', status: 'Working' },
  { id: 'trufflehog', name: 'TruffleHog', category: 'Code', description: 'Find leaked secrets and credentials in git repositories.', icon: Lock, risk: 'High', status: 'Working' },
  { id: 'exiftool', name: 'ExifTool', category: 'Media', description: 'Read, write and edit meta information in files.', icon: FileText, risk: 'Low', status: 'Not Working' },
] as Tool[]).sort((a, b) => {
  if (a.status === 'Working' && b.status === 'Not Working') return -1;
  if (a.status === 'Not Working' && b.status === 'Working') return 1;
  return 0;
});

const VALIDATION_PATTERNS = {
  domain: /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i,
  ip: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  email: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  phone: /^\+?[1-9]\d{1,14}$/,
  username: /^[a-zA-Z0-9._-]{3,30}$/
};

const CustomInvestigate = () => {
  const [searchQuery, setSearchQuery] = useState('');
  const [targetInput, setTargetInput] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);
  const [runningTool, setRunningTool] = useState<string | null>(null);
  const [toolResult, setToolResult] = useState<ToolResult | null>(null);
  const [aiAnalysis, setAiAnalysis] = useState<string | null>(null);
  const [analyzingAi, setAnalyzingAi] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const categories = useMemo(() => Array.from(new Set(TOOLS.map(t => t.category))), []);

  const detectedType = useMemo(() => {
    if (!targetInput) return null;
    if (VALIDATION_PATTERNS.ip.test(targetInput)) return 'IP Address';
    if (VALIDATION_PATTERNS.email.test(targetInput)) return 'Email';
    if (VALIDATION_PATTERNS.phone.test(targetInput)) return 'Phone Number';
    if (VALIDATION_PATTERNS.domain.test(targetInput)) return 'Domain/Subdomain';
    if (VALIDATION_PATTERNS.username.test(targetInput)) return 'Username';
    return 'Unknown';
  }, [targetInput]);

  const filteredTools = useMemo(() => {
    return TOOLS.filter(tool => {
      const matchesSearch = tool.name.toLowerCase().includes(searchQuery.toLowerCase()) || 
                           tool.description.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesCategory = !selectedCategory || tool.category === selectedCategory;
      return matchesSearch && matchesCategory;
    });
  }, [searchQuery, selectedCategory]);

  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => subscription.unsubscribe();
  }, []);

  const handleRunTool = async (tool: Tool) => {
    if (!targetInput) {
      setError("Please enter a target first.");
      return;
    }

    if (detectedType === 'Unknown') {
      setError("Invalid target format. Please enter a valid Domain, IP, Email, Phone, or Username.");
      return;
    }

    setRunningTool(tool.id);
    setToolResult(null);
    setAiAnalysis(null);
    setError(null);
    
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const idToken = session?.access_token;
      const response = await fetch('/api/run-tool', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ toolId: tool.id, target: targetInput, type: detectedType }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Execution failed");
      
      setToolResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setRunningTool(null);
    }
  };

  const handleAiAnalysis = async () => {
    if (!toolResult || !selectedTool) return;

    setAnalyzingAi(true);
    try {
      const { data: { session } } = await supabase.auth.getSession();
      const idToken = session?.access_token;
      const response = await fetch('/api/analyze-intelligence', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ 
          toolData: toolResult.data, 
          toolId: selectedTool.id, 
          target: targetInput 
        }),
      });

      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "AI Analysis failed");
      
      setAiAnalysis(data.analysis);
    } catch (err: any) {
      setError(`AI Analysis Error: ${err.message}`);
    } finally {
      setAnalyzingAi(false);
    }
  };

  if (selectedTool) {
    return (
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <motion.button
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          onClick={() => {
            setSelectedTool(null);
            setToolResult(null);
            setTargetInput('');
            setError(null);
          }}
          className="flex items-center gap-2 text-gray-500 hover:text-cyan-500 transition-colors mb-8 group"
        >
          <ChevronRight className="w-4 h-4 rotate-180 group-hover:-translate-x-1 transition-transform" />
          Back to Workspace
        </motion.button>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
          <div className="lg:col-span-1 space-y-8">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-8 rounded-3xl bg-white/5 border border-white/10"
            >
              <div className="p-4 bg-cyan-500/10 rounded-2xl w-fit mb-6">
                <selectedTool.icon className="w-8 h-8 text-cyan-500" />
              </div>
              <h1 className="text-3xl font-bold mb-4">{selectedTool.name}</h1>
              <p className="text-gray-400 leading-relaxed mb-6">{selectedTool.description}</p>
              
              <div className="flex flex-wrap gap-3">
                <span className={cn(
                  "text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-widest",
                  selectedTool.status === 'Working' ? "bg-emerald-500/10 text-emerald-500" : "bg-red-500/10 text-red-500"
                )}>
                  {selectedTool.status}
                </span>
                <span className={cn(
                  "text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-widest bg-white/5 text-gray-400"
                )}>
                  {selectedTool.category}
                </span>
                <span className={cn(
                  "text-[10px] font-bold px-3 py-1 rounded-full uppercase tracking-widest",
                  selectedTool.risk === 'High' ? "bg-red-500/10 text-red-500" : 
                  selectedTool.risk === 'Medium' ? "bg-amber-500/10 text-amber-500" : 
                  "bg-emerald-500/10 text-emerald-500"
                )}>
                  {selectedTool.risk} Risk
                </span>
              </div>
            </motion.div>

            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="p-8 rounded-3xl bg-white/5 border border-white/10"
            >
              <div className="flex items-center justify-between mb-6">
                <label className="text-xs font-bold text-gray-500 uppercase tracking-widest">Target Input</label>
                {detectedType && detectedType !== 'Unknown' && (
                  <span className="text-[10px] font-bold text-cyan-500 uppercase bg-cyan-500/10 px-2 py-0.5 rounded">
                    {detectedType}
                  </span>
                )}
              </div>
              
              <div className="space-y-4">
                <div className="relative">
                  <Terminal className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-cyan-500" />
                  <input
                    type="text"
                    value={targetInput}
                    onChange={(e) => {
                      setTargetInput(e.target.value);
                      setError(null);
                    }}
                    placeholder="Enter target..."
                    className={cn(
                      "w-full bg-black/40 border rounded-xl py-3 pl-10 pr-4 text-sm focus:outline-none transition-all",
                      error ? "border-red-500/50 focus:ring-red-500/20" : "border-white/10 focus:ring-cyan-500/50 focus:border-cyan-500/30"
                    )}
                  />
                </div>
                {error && <p className="text-red-500 text-xs flex items-center gap-1"><AlertCircle className="w-3 h-3" /> {error}</p>}
                
                <button
                  onClick={() => handleRunTool(selectedTool)}
                  disabled={!!runningTool || selectedTool.status === 'Not Working'}
                  className="w-full py-4 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold rounded-xl transition-all shadow-lg shadow-cyan-500/20 flex items-center justify-center gap-2"
                >
                  {runningTool === selectedTool.id ? (
                    <>
                      <Loader2 className="w-5 h-5 animate-spin" />
                      Executing Scanner...
                    </>
                  ) : (
                    <>
                      <Play className="w-5 h-5" />
                      Run Analysis
                    </>
                  )}
                </button>
                {selectedTool.status === 'Not Working' && (
                  <p className="text-center text-xs text-red-500/60">This tool is currently under maintenance.</p>
                )}
              </div>
            </motion.div>
          </div>

          <div className="lg:col-span-2 space-y-8">
            <AnimatePresence mode="wait">
              {toolResult ? (
                <motion.div
                  key="result"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="space-y-8"
                >
                  <div className="p-8 rounded-3xl bg-black/40 border border-white/10 min-h-[400px]">
                    <div className="flex items-center justify-between mb-8 pb-6 border-b border-white/5">
                      <div className="flex items-center gap-3">
                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                        <h2 className="text-xl font-bold">Analysis Results</h2>
                      </div>
                      <div className="flex items-center gap-2">
                        <button 
                          onClick={handleAiAnalysis}
                          disabled={analyzingAi}
                          className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-500 text-xs font-bold rounded-xl transition-all border border-cyan-500/20 disabled:opacity-50"
                        >
                          {analyzingAi ? <Loader2 className="w-4 h-4 animate-spin" /> : <Sparkles className="w-4 h-4" />}
                          AI Insights
                        </button>
                        <button 
                          onClick={() => {
                            navigator.clipboard.writeText(JSON.stringify(toolResult.data, null, 2));
                          }}
                          className="flex items-center gap-2 px-4 py-2 text-xs font-bold text-gray-500 hover:text-white transition-colors uppercase tracking-widest"
                        >
                          <Copy className="w-4 h-4" />
                          Copy JSON
                        </button>
                      </div>
                    </div>
                    <ToolResultRenderer result={toolResult} target={targetInput} />
                  </div>

                  {aiAnalysis && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="p-8 rounded-3xl bg-cyan-500/5 border border-cyan-500/20 relative overflow-hidden group"
                    >
                      <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:opacity-10 transition-opacity">
                        <BrainCircuit className="w-32 h-32 text-cyan-500" />
                      </div>
                      
                      <div className="flex items-center gap-3 mb-6">
                        <div className="p-2 bg-cyan-500/20 rounded-lg">
                          <Sparkles className="w-5 h-5 text-cyan-500" />
                        </div>
                        <h3 className="text-xl font-bold text-cyan-400">AI Intelligence Assessment</h3>
                      </div>

                      <div className="prose prose-invert prose-cyan max-w-none text-gray-300 text-sm leading-relaxed">
                        <ReactMarkdown>{aiAnalysis}</ReactMarkdown>
                      </div>
                    </motion.div>
                  )}
                </motion.div>
              ) : runningTool ? (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center p-20 rounded-3xl bg-white/5 border border-white/10 border-dashed min-h-[400px]"
                >
                  <div className="relative mb-8">
                    <div className="absolute inset-0 bg-cyan-500/20 blur-2xl rounded-full animate-pulse" />
                    <Loader2 className="w-16 h-16 text-cyan-500 animate-spin relative z-10" />
                  </div>
                  <h3 className="text-xl font-bold mb-2">Scanning Target</h3>
                  <p className="text-gray-500 text-center max-w-xs">
                    Our cloud-native engine is executing {selectedTool.name} protocols. This may take a few seconds.
                  </p>
                </motion.div>
              ) : (
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center p-20 rounded-3xl bg-white/5 border border-white/10 border-dashed min-h-[400px]"
                >
                  <Terminal className="w-16 h-16 text-gray-800 mb-6" />
                  <h3 className="text-xl font-bold text-gray-600 mb-2">Ready for Execution</h3>
                  <p className="text-gray-700 text-center max-w-xs text-sm">
                    Enter a target on the left and click "Run Analysis" to begin gathering intelligence.
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="mb-12">
        <h1 className="text-3xl font-bold tracking-tight mb-4">Custom Tool Workspace</h1>
        <p className="text-gray-500 max-w-2xl">
          Select a specialized intelligence scanner from our ecosystem to begin your investigation.
        </p>
      </div>

      <div className="flex flex-col lg:flex-row gap-8">
        {/* Sidebar Filters */}
        <div className="w-full lg:w-64 space-y-8">
          <div className="p-6 rounded-3xl bg-white/5 border border-white/10">
            <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4 px-1">Search Tools</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter by name..."
                className="w-full bg-black/40 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500/50 transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-4 px-1">Categories</label>
            <div className="flex lg:flex-col gap-2 overflow-x-auto lg:overflow-x-visible pb-4 lg:pb-0 scrollbar-hide">
              <button
                onClick={() => setSelectedCategory(null)}
                className={cn(
                  "whitespace-nowrap lg:whitespace-normal text-left px-4 py-2.5 rounded-xl text-sm font-bold transition-all border shrink-0 lg:shrink",
                  !selectedCategory 
                    ? "bg-cyan-500/10 text-cyan-500 border-cyan-500/20 shadow-[0_0_15px_rgba(8,145,178,0.1)]" 
                    : "text-gray-500 border-transparent hover:bg-white/5 hover:text-gray-300"
                )}
              >
                All Tools
              </button>
              {categories.map(cat => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={cn(
                    "whitespace-nowrap lg:whitespace-normal text-left px-4 py-2.5 rounded-xl text-sm font-bold transition-all border shrink-0 lg:shrink",
                    selectedCategory === cat 
                      ? "bg-cyan-500/10 text-cyan-500 border-cyan-500/20 shadow-[0_0_15px_rgba(8,145,178,0.1)]" 
                      : "text-gray-500 border-transparent hover:bg-white/5 hover:text-gray-300"
                  )}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-grow">
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6">
            {filteredTools.map((tool) => (
              <motion.div
                layout
                key={tool.id}
                className={cn(
                  "p-6 rounded-3xl bg-white/5 border border-white/10 hover:border-cyan-500/30 transition-all group flex flex-col relative overflow-hidden",
                  tool.status === 'Not Working' && "opacity-60 grayscale-[0.5]"
                )}
              >
                <div className="absolute top-0 right-0 p-6 opacity-[0.03] group-hover:opacity-[0.07] transition-opacity">
                  <tool.icon className="w-24 h-24" />
                </div>

                <div className="flex items-start justify-between mb-6 relative z-10">
                  <div className="p-3 bg-white/5 rounded-2xl group-hover:bg-cyan-500/10 transition-colors border border-white/5">
                    <tool.icon className="w-6 h-6 text-gray-400 group-hover:text-cyan-500" />
                  </div>
                  <div className="flex flex-col items-end gap-1.5">
                    <span className={cn(
                      "text-[9px] font-black px-2 py-0.5 rounded-md uppercase tracking-[0.2em] border",
                      tool.status === 'Working' 
                        ? "bg-emerald-500/5 text-emerald-500 border-emerald-500/20" 
                        : "bg-red-500/5 text-red-500 border-red-500/20"
                    )}>
                      {tool.status}
                    </span>
                    <span className={cn(
                      "text-[9px] font-black px-2 py-0.5 rounded-md uppercase tracking-[0.2em] border",
                      tool.risk === 'High' ? "bg-red-500/5 text-red-500 border-red-500/20" : 
                      tool.risk === 'Medium' ? "bg-amber-500/5 text-amber-500 border-amber-500/20" : 
                      "bg-emerald-500/5 text-emerald-500 border-emerald-500/20"
                    )}>
                      {tool.risk} Risk
                    </span>
                  </div>
                </div>
                
                <div className="relative z-10 flex-grow">
                  <h3 className="text-lg font-bold mb-2 group-hover:text-cyan-400 transition-colors">{tool.name}</h3>
                  <p className="text-sm text-gray-500 leading-relaxed mb-8">
                    {tool.description}
                  </p>
                </div>

                <div className="flex items-center justify-between mt-auto pt-6 border-t border-white/5 relative z-10">
                  <span className="text-[10px] text-gray-600 font-bold uppercase tracking-widest">{tool.category}</span>
                  <button
                    onClick={() => setSelectedTool(tool)}
                    className="px-5 py-2.5 bg-cyan-500/10 hover:bg-cyan-500 text-cyan-500 hover:text-white text-[10px] font-black uppercase tracking-widest rounded-xl transition-all border border-cyan-500/20 hover:shadow-[0_0_20px_rgba(8,145,178,0.4)]"
                  >
                    Configure
                  </button>
                </div>
              </motion.div>
            ))}
          </div>

          {filteredTools.length === 0 && (
            <div className="text-center py-20">
              <Search className="w-12 h-12 text-gray-700 mx-auto mb-4" />
              <h3 className="text-xl font-bold text-gray-400">No tools found</h3>
              <p className="text-gray-600">Try adjusting your search or category filter.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const XIcon = ({ className }: { className?: string }) => (
  <X className={className} />
);

export default CustomInvestigate;
