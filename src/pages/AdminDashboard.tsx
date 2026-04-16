import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { 
  Shield, Key, AlertTriangle, CheckCircle2, Clock, 
  RefreshCw, Save, Plus, Trash2, ExternalLink,
  Search, Filter, Activity, Database
} from 'lucide-react';
import { supabase } from '../supabase';
import { cn } from '../lib/utils';
import { format } from 'date-fns';

interface APIKeyConfig {
  value: string;
  status: 'active' | 'expired' | 'inactive';
  expiryDate: string;
  lastUpdated: string;
}

interface SystemConfig {
  keys: Record<string, APIKeyConfig>;
}

const AdminDashboard = () => {
  const [config, setConfig] = useState<SystemConfig | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
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
    const checkAdmin = async () => {
      if (!user) return;
      
      // Check if user is admin based on rules logic
      if (user.email === 'aniketvipulchougule@gmail.com') {
        setIsAdmin(true);
      } else {
        const { data } = await supabase.from('users').select('role').eq('id', user.id).single();
        if (data?.role === 'admin') {
          setIsAdmin(true);
        }
      }
    };

    checkAdmin();

    const fetchConfig = async () => {
      const { data, error } = await supabase.from('system_configs').select('*').eq('id', 'api_keys').single();
      if (!error && data) {
        setConfig(data as SystemConfig);
      } else {
        // Initialize if not exists
        const initialConfig: SystemConfig = {
          keys: {
            numverify: { value: '', status: 'inactive', expiryDate: '', lastUpdated: new Date().toISOString() },
            shodan: { value: '', status: 'inactive', expiryDate: '', lastUpdated: new Date().toISOString() },
            censys: { value: '', status: 'inactive', expiryDate: '', lastUpdated: new Date().toISOString() }
          }
        };
        setConfig(initialConfig);
      }
      setIsLoading(false);
    };

    fetchConfig();
  }, [user]);

  const handleUpdateKey = (service: string, field: keyof APIKeyConfig, value: string) => {
    if (!config) return;
    setConfig({
      ...config,
      keys: {
        ...config.keys,
        [service]: {
          ...config.keys[service],
          [field]: value,
          lastUpdated: new Date().toISOString()
        }
      }
    });
  };

  const saveConfig = async () => {
    if (!config || !isAdmin) return;
    setIsSaving(true);
    try {
      await supabase.from('system_configs').upsert({
        id: 'api_keys',
        keys: config.keys,
        updated_at: new Date().toISOString()
      });
      // In a real app, you'd also trigger a backend reload or use a webhook
    } catch (error) {
      console.error("Error saving config:", error);
    } finally {
      setIsSaving(false);
    }
  };

  if (!isAdmin && !isLoading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] text-center px-4">
        <div className="p-4 bg-red-500/10 rounded-full mb-6">
          <Shield className="w-12 h-12 text-red-500" />
        </div>
        <h1 className="text-3xl font-bold mb-2">Access Restricted</h1>
        <p className="text-gray-500 max-w-md">
          You do not have administrative privileges to access this dashboard. 
          Please contact the system administrator if you believe this is an error.
        </p>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 mb-12">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-cyan-500/10 rounded-lg">
              <Database className="w-6 h-6 text-cyan-500" />
            </div>
            <h1 className="text-3xl font-bold tracking-tight">Admin Control Center</h1>
          </div>
          <p className="text-gray-500">Manage global intelligence tool API keys, environment variables, and system health.</p>
        </div>
        <div className="flex items-center gap-3">
          <button 
            onClick={saveConfig}
            disabled={isSaving}
            className="px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-bold rounded-xl transition-all flex items-center gap-2 shadow-[0_0_20px_rgba(8,145,178,0.3)] border border-cyan-400/20"
          >
            {isSaving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
            Save Changes
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
        {/* Sidebar Stats */}
        <div className="space-y-6">
          <div className="p-6 rounded-3xl bg-white/5 border border-white/10">
            <h3 className="text-[10px] font-black text-gray-500 uppercase tracking-widest mb-6">System Overview</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Active Keys</span>
                <span className="text-sm font-bold text-emerald-500">
                  {config ? Object.values(config.keys).filter(k => k.status === 'active').length : 0}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Expired Keys</span>
                <span className="text-sm font-bold text-red-500">
                  {config ? Object.values(config.keys).filter(k => k.status === 'expired').length : 0}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-gray-400">Total Services</span>
                <span className="text-sm font-bold text-white">
                  {config ? Object.keys(config.keys).length : 0}
                </span>
              </div>
            </div>
          </div>

          <div className="p-6 rounded-3xl bg-amber-500/5 border border-amber-500/20">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <h4 className="text-xs font-bold text-amber-500 uppercase tracking-widest">Security Warning</h4>
            </div>
            <p className="text-[11px] text-amber-500/70 leading-relaxed">
              Changes made here affect all users globally. Ensure API keys are valid and have sufficient quota before activating.
            </p>
          </div>
        </div>

        {/* Main Key Management */}
        <div className="lg:col-span-3 space-y-6">
          <div className="flex items-center justify-between mb-2">
            <div className="relative flex-grow max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
              <input 
                type="text"
                placeholder="Search services..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-white/5 border border-white/10 rounded-xl py-2.5 pl-10 pr-4 text-sm focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
              />
            </div>
            <button className="p-2.5 bg-white/5 border border-white/10 rounded-xl text-gray-400 hover:text-white transition-all">
              <Filter className="w-5 h-5" />
            </button>
          </div>

          <div className="grid grid-cols-1 gap-4">
            {config && Object.entries(config.keys)
              .filter(([name]) => name.toLowerCase().includes(searchQuery.toLowerCase()))
              .map(([name, key]) => (
              <motion.div 
                layout
                key={name}
                className="p-6 rounded-3xl bg-white/5 border border-white/10 hover:border-white/20 transition-all"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                  <div className="flex items-center gap-4">
                    <div className={cn(
                      "p-3 rounded-2xl border",
                      key.status === 'active' ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-500" :
                      key.status === 'expired' ? "bg-red-500/10 border-red-500/20 text-red-500" :
                      "bg-gray-500/10 border-gray-500/20 text-gray-500"
                    )}>
                      <Key className="w-6 h-6" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold capitalize">{name}</h3>
                      <div className="flex items-center gap-3 mt-1">
                        <span className={cn(
                          "text-[9px] font-black uppercase tracking-widest px-2 py-0.5 rounded border",
                          key.status === 'active' ? "bg-emerald-500/5 text-emerald-500 border-emerald-500/20" :
                          key.status === 'expired' ? "bg-red-500/5 text-red-500 border-red-500/20" :
                          "bg-gray-500/5 text-gray-500 border-gray-500/20"
                        )}>
                          {key.status}
                        </span>
                        <span className="text-[10px] text-gray-500 font-medium flex items-center gap-1">
                          <Clock className="w-3 h-3" /> Updated {format(new Date(key.lastUpdated), 'MMM d, HH:mm')}
                        </span>
                      </div>
                    </div>
                  </div>

                  <div className="flex-grow max-w-md">
                    <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2">API Key Value</label>
                    <div className="relative">
                      <input 
                        type="text"
                        value={key.value}
                        onChange={(e) => handleUpdateKey(name, 'value', e.target.value)}
                        className="w-full bg-black border border-white/10 rounded-xl py-2 px-4 text-sm font-mono text-cyan-500/80 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                        placeholder="Enter key..."
                      />
                    </div>
                  </div>

                  <div className="flex flex-row md:flex-col gap-3">
                    <div>
                      <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2">Status</label>
                      <select 
                        value={key.status}
                        onChange={(e) => handleUpdateKey(name, 'status', e.target.value as any)}
                        className="bg-black border border-white/10 rounded-xl py-2 px-3 text-xs font-bold focus:outline-none"
                      >
                        <option value="active">Active</option>
                        <option value="expired">Expired</option>
                        <option value="inactive">Inactive</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-2">Expiry</label>
                      <input 
                        type="date"
                        value={key.expiryDate}
                        onChange={(e) => handleUpdateKey(name, 'expiryDate', e.target.value)}
                        className="bg-black border border-white/10 rounded-xl py-2 px-3 text-xs font-bold focus:outline-none"
                      />
                    </div>
                  </div>
                </div>
              </motion.div>
            ))}

            <button className="w-full py-4 border-2 border-dashed border-white/5 rounded-3xl text-gray-500 hover:text-cyan-500 hover:border-cyan-500/30 hover:bg-cyan-500/5 transition-all flex items-center justify-center gap-2 font-bold uppercase tracking-widest text-xs">
              <Plus className="w-4 h-4" /> Add New Service Integration
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AdminDashboard;
