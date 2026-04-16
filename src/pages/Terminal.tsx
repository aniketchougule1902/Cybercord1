import React, { useState, useRef, useEffect } from 'react';
import { motion } from 'motion/react';
import { Terminal as TerminalIcon, ChevronRight, Zap, Shield, Globe, Search, Lock } from 'lucide-react';
import { cn } from '../lib/utils';

const Terminal = () => {
  const [history, setHistory] = useState<string[]>([
    'CyberCord OS v1.0.4 - Initializing...',
    'Secure connection established to node_0x4f2...',
    'Type "help" for a list of available commands.',
  ]);
  const [input, setInput] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [history]);

  const handleCommand = (cmd: string) => {
    const c = cmd.toLowerCase().trim();
    let response = '';

    switch (c) {
      case 'help':
        response = 'Available commands: help, clear, scan <target>, whois <domain>, status, version';
        break;
      case 'clear':
        setHistory([]);
        return;
      case 'status':
        response = 'SYSTEM: ONLINE | NODES: 102 | LATENCY: 24ms | AUTH: AGENT_001';
        break;
      case 'version':
        response = 'CyberCord Core v1.0.4 (Build 2026.04.02)';
        break;
      default:
        if (c.startsWith('scan ')) {
          response = `Initializing deep scan for ${c.split(' ')[1]}... [DONE] Results synced to dashboard.`;
        } else if (c.startsWith('whois ')) {
          response = `Querying WHOIS database for ${c.split(' ')[1]}... [SUCCESS] Data retrieved.`;
        } else {
          response = `Command not found: ${c}. Type "help" for assistance.`;
        }
    }

    setHistory(prev => [...prev, `> ${cmd}`, response]);
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
              line.includes('[SUCCESS]') || line.includes('[DONE]') ? "text-emerald-500" : "",
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
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  handleCommand(input);
                  setInput('');
                }
              }}
              className="flex-grow bg-transparent border-none outline-none focus:ring-0 p-0 text-sm"
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
