import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { LayoutDashboard, Search, Shield, AlertTriangle, Users, History, TrendingUp, Zap, Globe } from 'lucide-react';
import { Link } from 'react-router-dom';
import { cn } from '../lib/utils';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, LineChart, Line } from 'recharts';
import { supabase } from '../supabase';
import { format } from 'date-fns';

const data = [
  { name: 'Mon', investigations: 12, threats: 2 },
  { name: 'Tue', investigations: 19, threats: 5 },
  { name: 'Wed', investigations: 15, threats: 3 },
  { name: 'Thu', investigations: 22, threats: 8 },
  { name: 'Fri', investigations: 30, threats: 12 },
  { name: 'Sat', investigations: 25, threats: 4 },
  { name: 'Sun', investigations: 18, threats: 1 },
];

const Dashboard = () => {
  const [recentInvestigations, setRecentInvestigations] = useState<any[]>([]);
  const [stats, setStats] = useState({
    total: 0,
    threats: 0,
    breaches: 0,
    nodes: 102
  });

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

  useEffect(() => {
    if (!user) return;

    const fetchInvestigations = async () => {
      const { data, error } = await supabase
        .from('investigations')
        .select('*')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(5);

      if (!error && data) {
        setRecentInvestigations(data);
        setStats(prev => ({ ...prev, total: data.length }));
      }
    };

    fetchInvestigations();
  }, [user]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-12">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Intelligence Dashboard</h1>
          <p className="text-gray-500">Welcome back, {user?.user_metadata?.full_name || user?.email?.split('@')[0] || 'Agent'}. Here's your current threat landscape.</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="px-4 py-2 bg-white/5 border border-white/10 rounded-lg text-sm font-medium hover:bg-white/10 transition-all">
            Export Data
          </button>
          <Link to="/investigate" className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-sm font-medium transition-all flex items-center gap-2">
            <Zap className="w-4 h-4" /> New Investigation
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-12">
        {[
          { label: "Total Investigations", value: stats.total.toString(), change: "+12%", icon: Search, color: "text-cyan-500" },
          { label: "Active Threats", value: stats.threats.toString(), change: "+4", icon: AlertTriangle, color: "text-amber-500" },
          { label: "Data Breaches Found", value: stats.breaches.toString(), change: "+24%", icon: Shield, color: "text-red-500" },
          { label: "Global Nodes", value: stats.nodes.toString(), change: "Stable", icon: Globe, color: "text-emerald-500" },
        ].map((stat, idx) => (
          <div key={idx} className="p-6 rounded-3xl bg-white/5 border border-white/10 relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-6 opacity-[0.03] group-hover:opacity-[0.08] transition-opacity">
              <stat.icon className="w-16 h-16" />
            </div>
            <div className="flex items-center justify-between mb-6 relative z-10">
              <div className={cn("p-3 bg-white/5 rounded-xl border border-white/5", stat.color)}>
                <stat.icon className="w-5 h-5" />
              </div>
              <span className={cn("text-[10px] font-bold px-2 py-1 rounded-md bg-white/5 border border-white/5", 
                stat.change.startsWith('+') ? "text-emerald-500" : "text-gray-500"
              )}>
                {stat.change}
              </span>
            </div>
            <h3 className="text-gray-500 text-[10px] font-bold uppercase tracking-widest mb-1 relative z-10">{stat.label}</h3>
            <p className="text-3xl font-black tracking-tighter relative z-10">{stat.value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
        {/* Chart */}
        <div className="lg:col-span-2 p-6 sm:p-10 rounded-3xl bg-white/5 border border-white/10">
          <div className="flex items-center justify-between mb-10">
            <h3 className="text-lg font-bold flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-cyan-500" /> Investigation Activity
            </h3>
            <div className="flex items-center gap-4 text-[10px] font-bold uppercase tracking-widest text-gray-500">
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-cyan-500" />
                <span>Queries</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-amber-500" />
                <span>Threats</span>
              </div>
            </div>
          </div>
          <div className="h-[300px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data}>
                <CartesianGrid strokeDasharray="3 3" stroke="#ffffff05" vertical={false} />
                <XAxis 
                  dataKey="name" 
                  stroke="#ffffff20" 
                  fontSize={10} 
                  tickLine={false} 
                  axisLine={false} 
                  dy={10}
                />
                <YAxis 
                  stroke="#ffffff20" 
                  fontSize={10} 
                  tickLine={false} 
                  axisLine={false} 
                  dx={-10}
                />
                <Tooltip 
                  cursor={{ fill: '#ffffff05' }}
                  contentStyle={{ 
                    backgroundColor: '#000', 
                    border: '1px solid #ffffff10', 
                    borderRadius: '12px',
                    fontSize: '12px',
                    fontWeight: 'bold'
                  }}
                  itemStyle={{ padding: '2px 0' }}
                />
                <Bar dataKey="investigations" fill="#06b6d4" radius={[4, 4, 0, 0]} barSize={32} />
                <Bar dataKey="threats" fill="#f59e0b" radius={[4, 4, 0, 0]} barSize={32} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="p-6 sm:p-10 rounded-3xl bg-white/5 border border-white/10">
          <h3 className="text-lg font-bold mb-10 flex items-center gap-2">
            <History className="w-5 h-5 text-cyan-500" /> Recent Activity
          </h3>
          <div className="space-y-8">
            {recentInvestigations.length > 0 ? recentInvestigations.map((item, idx) => (
              <div key={idx} className="flex items-center justify-between group cursor-pointer">
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-xl bg-white/5 border border-white/10 flex items-center justify-center group-hover:bg-cyan-500/10 group-hover:border-cyan-500/30 transition-all">
                    <Search className="w-5 h-5 text-gray-500 group-hover:text-cyan-500" />
                  </div>
                  <div>
                    <h4 className="text-sm font-bold text-white group-hover:text-cyan-400 transition-colors truncate max-w-[120px] sm:max-w-none">{item.query}</h4>
                    <p className="text-[10px] text-gray-500 font-bold uppercase tracking-widest mt-1">{item.type} • {item.createdAt?.seconds ? format(new Date(item.createdAt.seconds * 1000), 'HH:mm') : 'Just now'}</p>
                  </div>
                </div>
                <div className={cn("text-[9px] font-black uppercase tracking-[0.2em] px-2 py-1 rounded-md border",
                  item.status === 'completed' ? 'bg-emerald-500/5 text-emerald-500 border-emerald-500/20' :
                  item.status === 'running' ? 'bg-cyan-500/5 text-cyan-500 border-cyan-500/20 animate-pulse' :
                  'bg-red-500/5 text-red-500 border-red-500/20'
                )}>
                  {item.status}
                </div>
              </div>
            )) : (
              <div className="text-center py-10 text-gray-500">
                <p className="text-sm font-medium">No investigations found.</p>
                <Link to="/investigate" className="text-cyan-500 hover:underline text-xs mt-3 inline-block font-bold uppercase tracking-widest">Start your first one</Link>
              </div>
            )}
          </div>
          <button className="w-full mt-10 pt-8 text-[10px] font-black uppercase tracking-[0.3em] text-gray-500 hover:text-white transition-colors border-t border-white/5">
            View All Activity
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
