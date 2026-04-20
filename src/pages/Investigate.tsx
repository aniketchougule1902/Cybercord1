import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Search, Shield, Globe, Mail, User, Smartphone, Zap, Loader2, AlertCircle, CheckCircle2, ChevronRight, BarChart3, Clock, Share2, Download } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { cn } from '../lib/utils';
import { EntityType, InvestigationResult, InvestigationEvent } from '../types';
import { format } from 'date-fns';
import InvestigationFlow from '../components/InvestigationFlow';
import { supabase } from '../supabase';

const Investigate = () => {
  const [query, setQuery] = useState('');
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'timeline' | 'raw'>('overview');

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

  const handleInvestigate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!query || !user) return;

    setIsInvestigating(true);
    setResult(null);

    try {
      const type = detectType(query);
      
      // 1. Create Investigation in Supabase
      const initialData = {
        user_id: user.id,
        query: query,
        type: type,
        status: 'running',
      };
      
      const { data: invData, error: invError } = await supabase
        .from('investigations')
        .insert([initialData])
        .select()
        .single();
        
      if (invError) throw invError;
      const investigationId = invData.id;

      // 2. Call Backend API
      const { data: { session } } = await supabase.auth.getSession();
      const idToken = session?.access_token;
      
      const response = await fetch('/api/investigate', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${idToken}`
        },
        body: JSON.stringify({ query, type }),
      });
      
      if (!response.ok) {
        const errData = await response.json();
        throw new Error(errData.error || 'Investigation failed');
      }

      const apiData = await response.json();

      const finalResult: InvestigationResult = {
        id: investigationId,
        query: query,
        type: type,
        status: 'completed',
        riskScore: apiData.riskScore ?? 0,
        entities: apiData.entities ?? [],
        relationships: apiData.relationships ?? [],
        timeline: (apiData.timeline ?? []) as InvestigationEvent[],
        summary: apiData.summary ?? 'Investigation complete.',
        createdAt: new Date().toISOString(),
      };

      // 3. Update Supabase
      await supabase
        .from('investigations')
        .update({
          status: 'completed',
          risk_score: finalResult.riskScore,
          summary: finalResult.summary,
          entities: finalResult.entities,
          relationships: finalResult.relationships,
          timeline: finalResult.timeline
        })
        .eq('id', investigationId);

      setResult(finalResult);
    } catch (error) {
      console.error(error);
    } finally {
      setIsInvestigating(false);
    }
  };

  const detectType = (q: string): EntityType => {
    if (q.includes('@')) return EntityType.EMAIL;
    if (q.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) return EntityType.IP;
    if (q.includes('.')) return EntityType.DOMAIN;
    if (q.match(/^\+?[\d\s-]{10,}$/)) return EntityType.PHONE;
    return EntityType.USERNAME;
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      {/* Search Header */}
      <div className="text-center mb-12">
        <h1 className="text-4xl font-bold tracking-tight mb-4">Universal Intelligence Search</h1>
        <p className="text-gray-400 max-w-xl mx-auto">
          Enter a domain, IP, email, phone, or username to begin a deep-dive investigation.
        </p>
      </div>

      <div className="max-w-3xl mx-auto mb-16 px-2">
        <form onSubmit={handleInvestigate} className="relative group">
          <div className="absolute inset-0 bg-cyan-500/20 blur-3xl opacity-0 group-focus-within:opacity-100 transition-opacity" />
          <div className="relative flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <div className="relative flex-grow">
              <div className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400">
                <Search className="w-5 h-5" />
              </div>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="e.g. example.com, 8.8.8.8..."
                className="w-full bg-white/5 border border-white/10 rounded-2xl py-4 sm:py-5 pl-12 pr-4 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 focus:border-cyan-500/50 transition-all text-base sm:text-lg"
              />
            </div>
            <button
              type="submit"
              disabled={isInvestigating || !query}
              className="px-8 py-4 sm:py-5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-bold rounded-2xl transition-all flex items-center justify-center gap-2 shadow-[0_0_20px_rgba(8,145,178,0.3)] border border-cyan-400/20"
            >
              {isInvestigating ? (
                <>
                  <Loader2 className="w-5 h-5 animate-spin" />
                  <span className="sm:inline">Running...</span>
                </>
              ) : (
                <>
                  Investigate <Zap className="w-4 h-4" />
                </>
              )}
            </button>
          </div>
        </form>
        
        <div className="mt-6 flex flex-wrap justify-center gap-x-6 gap-y-3 text-[10px] font-bold uppercase tracking-widest text-gray-500">
          <span className="flex items-center gap-2 hover:text-cyan-500 transition-colors cursor-default"><Globe className="w-3 h-3" /> Domains</span>
          <span className="flex items-center gap-2 hover:text-cyan-500 transition-colors cursor-default"><Shield className="w-3 h-3" /> IPs</span>
          <span className="flex items-center gap-2 hover:text-cyan-500 transition-colors cursor-default"><Mail className="w-3 h-3" /> Emails</span>
          <span className="flex items-center gap-2 hover:text-cyan-500 transition-colors cursor-default"><User className="w-3 h-3" /> Usernames</span>
          <span className="flex items-center gap-2 hover:text-cyan-500 transition-colors cursor-default"><Smartphone className="w-3 h-3" /> Phones</span>
        </div>
      </div>

      {/* Results Section */}
      <AnimatePresence mode="wait">
        {isInvestigating && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="flex flex-col items-center justify-center py-20 px-4 text-center"
          >
            <div className="relative w-24 h-24 mb-8">
              <div className="absolute inset-0 border-4 border-cyan-500/10 rounded-full" />
              <div className="absolute inset-0 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              <div className="absolute inset-0 bg-cyan-500/20 blur-2xl rounded-full animate-pulse" />
              <Shield className="absolute inset-0 m-auto w-10 h-10 text-cyan-500" />
            </div>
            <h3 className="text-2xl font-bold mb-3 tracking-tight">Orchestrating Workflow</h3>
            <p className="text-gray-500 text-sm max-w-xs mx-auto leading-relaxed">
              Querying 100+ intelligence sources and cross-referencing datasets...
            </p>
          </motion.div>
        )}

        {result && !isInvestigating && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="space-y-8"
          >
            {/* Summary Card */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 sm:gap-8">
              <div className="lg:col-span-2 p-6 sm:p-10 rounded-3xl bg-white/5 border border-white/10 relative overflow-hidden">
                <div className="absolute top-0 right-0 p-10 opacity-[0.02]">
                  <Shield className="w-64 h-64" />
                </div>

                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6 mb-10 relative z-10">
                  <div className="flex items-center gap-4">
                    <div className="p-4 bg-cyan-500/10 rounded-2xl border border-cyan-500/20">
                      <Shield className="w-8 h-8 text-cyan-500" />
                    </div>
                    <div>
                      <h2 className="text-2xl sm:text-3xl font-black tracking-tighter">{result.query}</h2>
                      <p className="text-[10px] font-bold text-gray-500 uppercase tracking-[0.2em] mt-1">Investigation ID: {result.id}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button className="p-3 bg-white/5 hover:bg-white/10 rounded-xl transition-all border border-white/5"><Share2 className="w-5 h-5 text-gray-400" /></button>
                    <button className="p-3 bg-white/5 hover:bg-white/10 rounded-xl transition-all border border-white/5"><Download className="w-5 h-5 text-gray-400" /></button>
                  </div>
                </div>
                
                <div className="prose prose-invert max-w-none relative z-10">
                  <div className="text-gray-300 leading-relaxed text-sm sm:text-base bg-black/20 p-6 rounded-2xl border border-white/5">
                    <ReactMarkdown>{result.summary}</ReactMarkdown>
                  </div>
                </div>

                <div className="mt-10 flex flex-wrap items-center gap-6 relative z-10">
                   <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                      <span className="text-[10px] font-bold uppercase tracking-widest text-gray-400">Verified Data</span>
                   </div>
                   <div className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-amber-500" />
                      <span className="text-[10px] font-bold uppercase tracking-widest text-gray-400">{result.timeline.filter(e => e.type === 'danger' || e.type === 'warning').length} Potential Risks</span>
                   </div>
                   <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4 text-gray-500" />
                      <span className="text-[10px] font-bold uppercase tracking-widest text-gray-400">Updated: {format(new Date(result.createdAt), 'HH:mm:ss')}</span>
                   </div>
                </div>
              </div>

              <div className="p-10 rounded-3xl bg-white/5 border border-white/10 flex flex-col items-center justify-center text-center relative overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/5 to-transparent opacity-50" />
                <h3 className="text-[10px] font-black text-gray-500 uppercase tracking-[0.3em] mb-8 relative z-10">Risk Score</h3>
                <div className="relative w-48 h-48 flex items-center justify-center relative z-10">
                  <svg className="w-full h-full -rotate-90">
                    <circle
                      cx="96"
                      cy="96"
                      r="84"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="16"
                      className="text-white/5"
                    />
                    <circle
                      cx="96"
                      cy="96"
                      r="84"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="16"
                      strokeDasharray={527}
                      strokeDashoffset={527 - (527 * result.riskScore) / 100}
                      strokeLinecap="round"
                      className={cn(
                        "transition-all duration-1000",
                        result.riskScore > 70 ? "text-red-500" : result.riskScore > 30 ? "text-amber-500" : "text-emerald-500"
                      )}
                    />
                  </svg>
                  <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-6xl font-black tracking-tighter">{result.riskScore}</span>
                    <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mt-1">Criticality</span>
                  </div>
                </div>
                <p className="mt-10 text-xs font-medium text-gray-400 leading-relaxed relative z-10 px-4">
                  {result.riskScore > 70 ? "High exposure detected. Immediate action recommended." : "Moderate exposure. Monitor for changes."}
                </p>
              </div>
            </div>

            {/* Tabs */}
            <div className="border-b border-white/10 overflow-x-auto scrollbar-hide">
              <div className="flex gap-8 min-w-max px-2">
                {(['overview', 'graph', 'timeline', 'raw'] as const).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={cn(
                      "pb-4 text-xs font-black uppercase tracking-widest transition-all relative",
                      activeTab === tab ? "text-cyan-500" : "text-gray-500 hover:text-white"
                    )}
                  >
                    {tab}
                    {activeTab === tab && (
                      <motion.div
                        layoutId="activeTab"
                        className="absolute bottom-0 left-0 right-0 h-1 bg-cyan-500 rounded-t-full shadow-[0_0_10px_rgba(8,145,178,0.5)]"
                      />
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Tab Content */}
            <div className="min-h-[400px] pb-12">
              {activeTab === 'overview' && (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
                  {result.entities.map((entity) => (
                    <div key={entity.id} className="p-6 rounded-2xl bg-white/5 border border-white/10 hover:border-cyan-500/30 transition-all group">
                      <div className="flex items-center gap-3 mb-4">
                        <div className="p-2 bg-white/5 rounded-lg group-hover:bg-cyan-500/10 transition-colors">
                          <Globe className="w-4 h-4 text-gray-400 group-hover:text-cyan-500" />
                        </div>
                        <span className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">{entity.type}</span>
                      </div>
                      <h4 className="font-bold text-white truncate group-hover:text-cyan-400 transition-colors">{entity.label}</h4>
                      <button className="mt-6 text-[10px] font-black uppercase tracking-widest text-cyan-500 flex items-center gap-1 hover:gap-2 transition-all">
                        View Details <ChevronRight className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'timeline' && (
                <div className="space-y-6 relative before:absolute before:left-4 sm:before:left-6 before:top-2 before:bottom-2 before:w-px before:bg-white/10 px-2">
                  {result.timeline.map((event, idx) => (
                    <div key={event.id} className="relative pl-10 sm:pl-16">
                      <div className={cn(
                        "absolute left-2 sm:left-4 top-1.5 w-4 h-4 rounded-full border-4 border-[#050505] z-10",
                        event.type === 'danger' ? 'bg-red-500' : event.type === 'success' ? 'bg-emerald-500' : event.type === 'warning' ? 'bg-amber-500' : 'bg-cyan-500'
                      )} />
                      <div className="p-6 rounded-2xl bg-white/5 border border-white/10 hover:bg-white/10 transition-all">
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-3">
                          <h4 className="font-bold text-white text-base">{event.title}</h4>
                          <span className="text-[10px] text-gray-500 font-bold uppercase tracking-widest">{format(new Date(event.timestamp), 'HH:mm:ss')}</span>
                        </div>
                        <p className="text-gray-400 text-sm leading-relaxed">{event.description}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'graph' && (
                <div className="h-[500px] sm:h-[600px] rounded-3xl overflow-hidden border border-white/10 bg-black/20">
                  <InvestigationFlow 
                    entities={result.entities} 
                    relationships={result.relationships} 
                  />
                </div>
              )}

              {activeTab === 'raw' && (
                <div className="p-6 rounded-3xl bg-black border border-white/10 font-mono text-xs text-cyan-500/60 overflow-x-auto custom-scrollbar">
                  <pre>{JSON.stringify(result, null, 2)}</pre>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default Investigate;
