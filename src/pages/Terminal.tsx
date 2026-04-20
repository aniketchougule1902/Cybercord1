import React, { useState, useRef, useEffect } from 'react';
import { motion } from 'motion/react';
import { Terminal as TerminalIcon, ChevronRight, Zap, Shield, Globe, Lock } from 'lucide-react';
import { cn } from '../lib/utils';
import { supabase } from '../supabase';

const Terminal = () => {
  const [history, setHistory] = useState<string[]>([
    'CyberCord OS v2.0.0 - Initializing...',
    'Secure connection established to node_0x4f2...',
    'Type "help" for a list of available commands.',
  ]);
  const [input, setInput] = useState('');
  const [running, setRunning] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history]);

  const addLines = (...lines: string[]) => setHistory(prev => [...prev, ...lines]);

  const handleCommand = async (cmd: string) => {
    const c = cmd.trim();
    const lower = c.toLowerCase();

    if (!c) return;
    addLines(`> ${c}`);

    if (lower === 'clear') { setHistory([]); return; }
    if (lower === 'help') {
      addLines(
        'Available commands:',
        '  help                   Show this help message',
        '  clear                  Clear the terminal',
        '  status                 Show system status',
        '  version                Show version info',
        '  scan <target>          Run full domain/IP analysis',
        '  whois <domain>         WHOIS lookup for a domain',
        '  dns <domain>           DNS records lookup',
        '  ssl <domain>           SSL certificate check',
        '  headers <domain>       Analyze HTTP security headers',
        '  blacklist <ip/domain>  Check blacklist status',
        '  ip <address>           IP geolocation lookup',
      );
      return;
    }
    if (lower === 'status') { addLines('SYSTEM: ONLINE | NODES: 102 | LATENCY: 24ms | AUTH: VERIFIED'); return; }
    if (lower === 'version') { addLines('CyberCord Enterprise v2.0.0 (Build 2026.04.02)'); return; }

    const parts = c.split(/\s+/);
    const command = parts[0].toLowerCase();
    const target = parts.slice(1).join(' ');

    const TOOL_COMMANDS: Record<string, string> = {
      scan: 'domain-full', whois: 'whois', dns: 'dnsdumpster',
      ssl: 'ssl-checker', headers: 'headers', blacklist: 'blacklist', ip: 'ip-lookup',
    };

    if (TOOL_COMMANDS[command]) {
      if (!target) { addLines(`Usage: ${command} <target>`); return; }
      setRunning(true);
      addLines(`[*] Running ${command.toUpperCase()} analysis for ${target}...`);
      try {
        const { data: { session } } = await supabase.auth.getSession();
        const idToken = session?.access_token;
        if (!idToken) { addLines('[!] Not authenticated. Please log in first.'); setRunning(false); return; }

        const res = await fetch('/api/run-tool', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${idToken}` },
          body: JSON.stringify({ toolId: TOOL_COMMANDS[command], target }),
        });
        const result = await res.json();
        if (!res.ok) { addLines(`[!] Error: ${result.error}`); setRunning(false); return; }

        const d = result.data;
        addLines(`[+] ${result.reportType} completed for: ${target}`);

        if (command === 'whois') {
          if (d.registrar) addLines(`    Registrar: ${d.registrar}`);
          if (d.creationDate || d.createdDate) addLines(`    Created: ${d.creationDate || d.createdDate}`);
          if (d.expirationDate || d.expiryDate) addLines(`    Expires: ${d.expirationDate || d.expiryDate}`);
          if (d.registrantCountry) addLines(`    Country: ${d.registrantCountry}`);
        } else if (command === 'dns') {
          if (d.a_records?.length) addLines(`    A:   ${d.a_records.join(', ')}`);
          if (d.ns_records?.length) addLines(`    NS:  ${d.ns_records.join(', ')}`);
          if (d.mx_records?.length) addLines(`    MX:  ${d.mx_records.map((m: any) => m.exchange).join(', ')}`);
          addLines(`    SPF: ${d.spf_valid ? 'VALID' : 'MISSING'} | DMARC: ${d.dmarc_valid ? 'VALID' : 'MISSING'}`);
        } else if (command === 'ssl') {
          if (d.error) { addLines(`    [!] ${d.error}`); }
          else {
            addLines(`    Status: ${d.expired ? 'EXPIRED!' : `Valid (${d.days_remaining} days remaining)`}`);
            addLines(`    Issuer: ${d.issuer?.O || 'Unknown'}`);
            addLines(`    Protocol: ${d.protocol || 'Unknown'}`);
          }
        } else if (command === 'headers') {
          const sh = d.security_headers || {};
          addLines(`    Server: ${d.server || 'Unknown'} | Security Score: ${d.headers_score || 0}%`);
          const checks = ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options'];
          checks.forEach(h => addLines(`    ${h.padEnd(32)}: ${sh[h]?.present ? 'SET' : 'MISSING'}`));
        } else if (command === 'blacklist') {
          const bl = d.blacklists || [];
          const listed = bl.filter((b: any) => b.status === 'LISTED');
          addLines(`    Listed: ${listed.length}/${bl.length} blacklists`);
          if (listed.length > 0) listed.forEach((b: any) => addLines(`    [!] LISTED on ${b.name}`));
          else addLines('    [+] Clean on all blacklists');
        } else if (command === 'ip') {
          const g = d.geolocation || d;
          addLines(`    IP: ${g.query || target}`);
          addLines(`    Location: ${[g.city, g.regionName, g.country].filter(Boolean).join(', ')}`);
          addLines(`    ISP: ${g.isp || 'Unknown'}`);
          addLines(`    Proxy/Hosting: ${g.proxy || g.hosting ? 'YES' : 'NO'}`);
        } else if (command === 'scan') {
          const rsk = d.risk_score;
          if (rsk) addLines(`    Risk Score: ${rsk.overall_score}/100 (${rsk.risk_level})`);
          if (d.dns?.a_records?.length) addLines(`    A Records: ${d.dns.a_records.join(', ')}`);
          if (d.ssl) addLines(`    SSL: ${d.ssl.expired ? 'EXPIRED' : `Valid (${d.ssl.days_remaining}d)`}`);
          if (rsk?.recommendations?.length) addLines(`    Recommendations: ${rsk.recommendations.length} issues found`);
        }
        addLines('[✓] Analysis complete. Results synced to dashboard.');
      } catch (e: any) {
        addLines(`[!] Error: ${e.message}`);
      } finally {
        setRunning(false);
      }
      return;
    }

    addLines(`Command not found: ${c}. Type "help" for assistance.`);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-12">
      <div className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-cyan-500/10 rounded-lg">
            <TerminalIcon className="w-6 h-6 text-cyan-500" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">System Terminal</h1>
        </div>
        <div className="flex gap-2">
          <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50" />
          <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50" />
          <div className="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50" />
        </div>
      </div>

      <div className="bg-black border border-white/10 rounded-2xl overflow-hidden shadow-2xl font-mono">
        <div className="bg-white/5 px-4 py-2 border-b border-white/10 flex items-center justify-between text-[10px] text-gray-500 uppercase tracking-widest">
          <span>root@cybercord:~</span>
          <span>SSH: AES-256-GCM</span>
        </div>
        
        <div 
          ref={scrollRef}
          className="h-[500px] overflow-y-auto p-6 space-y-2 text-sm text-cyan-500/80 scrollbar-hide"
        >
          {history.map((line, idx) => (
            <div key={idx} className={cn(
              line.startsWith('>') ? "text-white font-bold" : "",
              line.includes('[✓]') || line.includes('[+]') ? "text-emerald-500" : "",
              line.includes('[!]') ? "text-red-400" : "",
              line.includes('[*]') ? "text-cyan-400" : "",
              line.includes('SYSTEM:') ? "text-cyan-400" : ""
            )}>
              {line}
            </div>
          ))}
          <div className="flex items-center gap-2 text-white">
            <ChevronRight className="w-4 h-4 text-cyan-500" />
            <input
              type="text"
              autoFocus
              value={input}
              disabled={running}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  handleCommand(input);
                  setInput('');
                }
              }}
              className="flex-grow bg-transparent border-none outline-none focus:ring-0 p-0 text-sm disabled:opacity-50"
              placeholder={running ? 'Running...' : ''}
            />
          </div>
        </div>
      </div>

      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
        {[{ label: "Active Nodes", value: "102", icon: Globe },
          { label: "Encrypted Traffic", value: "1.2 TB", icon: Lock },
          { label: "Threats Blocked", value: "4,291", icon: Shield },
        ].map((stat, idx) => {
          const Icon = stat.icon;
          return (
            <div key={idx} className="p-4 rounded-xl bg-white/5 border border-white/10 flex items-center gap-4">
              <Icon className="w-5 h-5 text-gray-500" />
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-widest">{stat.label}</p>
                <p className="text-lg font-bold">{stat.value}</p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default Terminal;
