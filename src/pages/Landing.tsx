import React from 'react';
import { motion } from 'motion/react';
import { Shield, Zap, Globe, Lock, Cpu, BarChart3, ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/utils';

const Landing = () => {
  return (
    <div className="relative overflow-hidden">
      {/* Hero Section */}
      <section className="relative pt-20 pb-32 lg:pt-32 lg:pb-48">
        {/* Background Gradients */}
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full -z-10 overflow-hidden">
          <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyan-500/20 blur-[120px] rounded-full" />
          <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-purple-500/10 blur-[120px] rounded-full" />
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <span className="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium bg-cyan-500/10 text-cyan-500 border border-cyan-500/20 mb-6">
              <Zap className="w-3 h-3 mr-2" />
              AI-Powered OSINT & Ethical Hacking
            </span>
            <h1 className="text-5xl md:text-7xl font-bold tracking-tighter mb-8 bg-clip-text text-transparent bg-gradient-to-b from-white to-white/50">
              The Intelligence OS for <br />
              <span className="text-cyan-500">Cyber Investigators</span>
            </h1>
            <p className="max-w-2xl mx-auto text-lg text-gray-400 mb-10 leading-relaxed">
              Unified investigation workspace with 100+ tools. From beginner-friendly 
              one-click OSINT to enterprise-grade threat intelligence.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                to="/investigate"
                className="px-8 py-4 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg transition-all flex items-center gap-2 shadow-[0_0_20px_rgba(8,145,178,0.4)]"
              >
                Start Investigation <ArrowRight className="w-4 h-4" />
              </Link>
              <Link
                to="/pricing"
                className="px-8 py-4 bg-white/5 hover:bg-white/10 text-white font-semibold rounded-lg border border-white/10 transition-all"
              >
                View Plans
              </Link>
            </div>
          </motion.div>

          {/* Mockup / Visual */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.8, delay: 0.2 }}
            className="mt-20 relative"
          >
            <div className="absolute inset-0 bg-cyan-500/5 blur-3xl -z-10" />
            <div className="rounded-2xl border border-white/10 bg-black/40 backdrop-blur-xl p-4 shadow-2xl overflow-hidden">
              <div className="flex items-center gap-2 mb-4 px-2">
                <div className="w-3 h-3 rounded-full bg-red-500/50" />
                <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                <div className="w-3 h-3 rounded-full bg-green-500/50" />
                <div className="ml-4 h-6 w-64 bg-white/5 rounded-md border border-white/5 flex items-center px-3 text-[10px] text-gray-500">
                  https://cybercord.io/investigate/domain/example.com
                </div>
              </div>
              <div className="aspect-video bg-[#0a0a0a] rounded-lg border border-white/5 flex items-center justify-center relative">
                 {/* Visual representation of a graph */}
                 <div className="absolute inset-0 opacity-20 pointer-events-none">
                    <div className="w-full h-full bg-[radial-gradient(circle_at_center,_var(--tw-gradient-stops))] from-cyan-500/20 via-transparent to-transparent" />
                 </div>
                 <div className="flex flex-col items-center gap-4">
                    <Shield className="w-16 h-16 text-cyan-500 animate-pulse" />
                    <div className="flex gap-2">
                      {[1,2,3,4].map(i => (
                        <div key={i} className="w-12 h-1 bg-cyan-500/20 rounded-full overflow-hidden">
                           <motion.div 
                             animate={{ x: [-48, 48] }}
                             transition={{ duration: 2, repeat: Infinity, delay: i * 0.5 }}
                             className="w-12 h-full bg-cyan-500"
                           />
                        </div>
                      ))}
                    </div>
                    <p className="text-xs font-mono text-cyan-500/60">SYSTEM_READY: ORCHESTRATOR_ONLINE</p>
                 </div>
              </div>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-24 bg-white/[0.02] border-y border-white/5">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            {[
              {
                title: "AI Orchestrator",
                desc: "Dynamic tool selection and function calling for automated intelligence gathering.",
                icon: Cpu,
                color: "text-cyan-500"
              },
              {
                title: "Graph Intelligence",
                desc: "Visualize relationships between entities, IPs, domains, and social profiles.",
                icon: Globe,
                color: "text-purple-500"
              },
              {
                title: "Risk Scoring",
                desc: "Real-time vulnerability assessment and exposure level calculation.",
                icon: BarChart3,
                color: "text-emerald-500"
              }
            ].map((feature, idx) => (
              <motion.div
                key={idx}
                whileHover={{ y: -5 }}
                className="p-8 rounded-2xl bg-white/5 border border-white/10 hover:border-cyan-500/30 transition-all group"
              >
                <feature.icon className={cn("w-10 h-10 mb-6", feature.color)} />
                <h3 className="text-xl font-bold mb-4 text-white group-hover:text-cyan-400 transition-colors">{feature.title}</h3>
                <p className="text-gray-400 leading-relaxed">{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default Landing;
