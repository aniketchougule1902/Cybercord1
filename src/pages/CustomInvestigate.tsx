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
    return (
      <div className="space-y-8">
        {renderSection("Geographic Data", MapPin, (
          <>
            {renderItem("City", data.city)}
            {renderItem("Region", data.region_name)}
            {renderItem("Country", `${data.country_name} (${data.country_code})`)}
            {renderItem("Coordinates", `${data.latitude}, ${data.longitude}`)}
            {data.location?.country_flag && (
              <div className="col-span-full flex items-center gap-3 p-3 rounded-xl bg-white/5 border border-white/5">
                <img src={data.location.country_flag} alt="Flag" className="w-8 h-6 rounded shadow-sm" referrerPolicy="no-referrer" />
                <span className="text-sm font-medium">{data.location.capital} (Capital)</span>
              </div>
            )}
          </>
        ))}

        {renderSection("Network Intelligence", Server, (
          <>
            {renderItem("IP Type", data.type)}
            {renderItem("ISP", data.connection?.isp)}
            {renderItem("ASN", data.connection?.asn)}
            {renderItem("Routing", data.ip_routing_type)}
          </>
        ))}

        {renderSection("Security Audit", Shield, (
          <>
            {renderItem("Proxy", data.security?.is_proxy ? 'YES' : 'NO')}
            {renderItem("VPN", data.security?.is_vpn ? 'YES' : 'NO')}
            {renderItem("TOR", data.security?.is_tor ? 'YES' : 'NO')}
            {renderItem("Threat Level", data.security?.threat_level || 'Low')}
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
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-5 h-5 text-cyan-500" />
          <h4 className="font-bold">DNS Records Found</h4>
        </div>
        <div className="space-y-2">
          {data.records?.map((record: any, idx: number) => (
            <div key={idx} className="p-3 rounded-xl bg-white/5 border border-white/5 font-mono text-xs text-cyan-500/80">
              {JSON.stringify(record)}
            </div>
          ))}
          {(!data.records || data.records.length === 0) && (
            <div className="p-8 text-center text-gray-500 italic">No public records found for this target.</div>
          )}
        </div>
      </div>
    );
  }

  if (reportType === 'HTTP_HEADERS_ANALYSIS') {
    return (
      <div className="space-y-8">
        {renderSection("Response Status", Activity, (
          <>
            {renderItem("Status Code", data.status)}
            {renderItem("Status Text", data.statusText)}
          </>
        ))}

        {renderSection("Security Headers", Shield, (
          <>
            {renderItem("Content-Security-Policy", data.headers?.['content-security-policy'] ? 'SET' : 'MISSING')}
            {renderItem("Strict-Transport-Security", data.headers?.['strict-transport-security'] ? 'SET' : 'MISSING')}
            {renderItem("X-Frame-Options", data.headers?.['x-frame-options'] ? 'SET' : 'MISSING')}
            {renderItem("X-Content-Type-Options", data.headers?.['x-content-type-options'] ? 'SET' : 'MISSING')}
          </>
        ))}

        <div className="space-y-2">
          <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest px-2">All Headers</label>
          <div className="p-4 rounded-2xl bg-black border border-white/10 font-mono text-xs text-cyan-500/60 max-h-60 overflow-y-auto custom-scrollbar">
            <pre>{JSON.stringify(data.headers, null, 2)}</pre>
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
            {renderItem("Creation Date", data.creationDate)}
            {renderItem("Expiration Date", data.expirationDate)}
            {renderItem("Updated Date", data.updatedDate)}
          </>
        ))}

        {renderSection("Registrant Info", Shield, (
          <>
            {renderItem("Organization", data.registrantOrganization)}
            {renderItem("Country", data.registrantCountry)}
            {renderItem("State", data.registrantState)}
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
  { id: 'shodan', name: 'Shodan', category: 'Network', description: 'Search for internet-connected devices and vulnerabilities.', icon: Network, risk: 'Medium', status: 'Working' },
  { id: 'censys', name: 'Censys', category: 'Network', description: 'Search engine for internet-connected hosts and certificates.', icon: Eye, risk: 'Medium', status: 'Working' },
  { id: 'ip-lookup', name: 'IPStack Intelligence', category: 'Network', description: 'Real-time IP geolocation and security data.', icon: Globe, risk: 'Low', status: 'Working' },
  { id: 'numverify', name: 'NumVerify', category: 'Identity', description: 'Global phone number validation and lookup.', icon: Smartphone, risk: 'Low', status: 'Working' },
  { id: 'truecaller', name: 'Truecaller OSINT', category: 'Identity', description: 'Search caller ID and spam protection data.', icon: Smartphone, risk: 'Medium', status: 'Working' },
  { id: 'eyecon', name: 'Eyecon Lookup', category: 'Identity', description: 'Identify unknown callers and social profiles.', icon: Eye, risk: 'Medium', status: 'Working' },
  { id: 'phoneinfoga', name: 'PhoneInfoga', category: 'Identity', description: 'Advanced information gathering for phone numbers.', icon: Smartphone, risk: 'Medium', status: 'Working' },
  { id: 'hibp', name: 'Have I Been Pwned', category: 'Security', description: 'Check if email or phone is in a data breach.', icon: Shield, risk: 'Low', status: 'Not Working' },
  { id: 'amass', name: 'OWASP Amass', category: 'Infrastructure', description: 'In-depth attack surface mapping and asset discovery.', icon: Database, risk: 'Medium', status: 'Not Working' },
  { id: 'trufflehog', name: 'TruffleHog', category: 'Code', description: 'Find leaked secrets and credentials in git repositories.', icon: Lock, risk: 'High', status: 'Not Working' },
  { id: 'exiftool', name: 'ExifTool', category: 'Media', description: 'Read, write and edit meta information in files.', icon: FileText, risk: 'Low', status: 'Not Working' },
  { id: 'wayback', name: 'Wayback Machine', category: 'Media', description: 'Explore archived versions of websites.', icon: History, risk: 'Low', status: 'Not Working' },
  { id: 'social-analyzer', name: 'Social Analyzer', category: 'Social', description: 'Analyze profiles across 1000+ social media sites.', icon: Users, risk: 'Medium', status: 'Working' },
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
