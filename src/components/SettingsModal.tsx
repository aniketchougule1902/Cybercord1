import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  X, Settings, Shield, Bell, Moon, Sun, 
  Key, LogOut, User, Globe, Lock, 
  Check, AlertCircle, ChevronRight, Save, RefreshCw
} from 'lucide-react';
import { cn } from '../lib/utils';
import { supabase } from '../supabase';

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

const SettingsModal = ({ isOpen, onClose }: SettingsModalProps) => {
  const [activeTab, setActiveTab] = useState<'account' | 'security' | 'notifications' | 'appearance'>('account');
  const [theme, setTheme] = useState<'dark' | 'light' | 'system'>('dark');
  const [apiKeys, setApiKeys] = useState({
    numverify: '',
    shodan: '',
    censys: ''
  });
  const [showApiKey, setShowApiKey] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(false);
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
    if (isOpen && user) {
      const fetchSettings = async () => {
        const { data, error } = await supabase
          .from('users')
          .select('settings')
          .eq('id', user.id)
          .single();
          
        if (!error && data?.settings) {
          if (data.settings.apiKeys) {
            setApiKeys(data.settings.apiKeys);
          }
          if (data.settings.appearance?.theme) {
            setTheme(data.settings.appearance.theme);
          }
        }
      };
      fetchSettings();
    }
  }, [isOpen, user]);

  const handleSaveKeys = async () => {
    if (!user) return;
    setIsSaving(true);
    try {
      const { error } = await supabase
        .from('users')
        .upsert({
          id: user.id,
          email: user.email,
          settings: {
            apiKeys,
            appearance: { theme }
          }
        });
        
      if (error) throw error;
      
      setSaveSuccess(true);
      setTimeout(() => setSaveSuccess(false), 3000);
    } catch (error) {
      console.error("Error saving settings:", error);
    } finally {
      setIsSaving(false);
    }
  };

  const handleLogout = async () => {
    try {
      await supabase.auth.signOut();
      onClose();
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  const tabs = [
    { id: 'account', label: 'Account', icon: User },
    { id: 'security', label: 'Security & APIs', icon: Lock },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'appearance', label: 'Appearance', icon: Moon },
  ];

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[60]"
          />
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            className="fixed inset-0 m-auto w-full max-w-4xl h-[600px] bg-[#0a0a0a] border border-white/10 rounded-3xl z-[70] overflow-hidden shadow-2xl flex flex-col md:flex-row"
          >
            {/* Sidebar */}
            <div className="w-full md:w-64 bg-black/40 border-r border-white/10 p-6 flex flex-col">
              <div className="flex items-center gap-3 mb-8">
                <div className="p-2 bg-cyan-500/10 rounded-xl">
                  <Settings className="w-5 h-5 text-cyan-500" />
                </div>
                <h2 className="text-xl font-bold tracking-tight">Settings</h2>
              </div>

              <nav className="space-y-1 flex-grow">
                {tabs.map((tab) => (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id as any)}
                    className={cn(
                      "w-full flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all",
                      activeTab === tab.id 
                        ? "bg-cyan-500/10 text-cyan-500 border border-cyan-500/20" 
                        : "text-gray-400 hover:bg-white/5 hover:text-white"
                    )}
                  >
                    <tab.icon className="w-4 h-4" />
                    {tab.label}
                  </button>
                ))}
              </nav>

              <button 
                onClick={handleLogout}
                className="mt-auto flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium text-red-400 hover:bg-red-500/10 transition-all border border-transparent hover:border-red-500/20"
              >
                <LogOut className="w-4 h-4" />
                Sign Out
              </button>
            </div>

            {/* Content */}
            <div className="flex-grow p-8 overflow-y-auto custom-scrollbar relative">
              <button 
                onClick={onClose}
                className="absolute top-6 right-6 p-2 text-gray-500 hover:text-white hover:bg-white/5 rounded-xl transition-all"
              >
                <X className="w-5 h-5" />
              </button>

              <div className="max-w-xl">
                {activeTab === 'account' && (
                  <div className="space-y-8">
                    <div>
                      <h3 className="text-lg font-bold mb-1">Profile Information</h3>
                      <p className="text-sm text-gray-500 mb-6">Manage your account details and public profile.</p>
                      
                      <div className="flex items-center gap-6 p-6 rounded-2xl bg-white/5 border border-white/10">
                        <div className="relative group">
                          <img 
                            src={user?.photoURL || `https://api.dicebear.com/7.x/avataaars/svg?seed=${user?.email}`} 
                            alt="Avatar" 
                            className="w-20 h-20 rounded-2xl border-2 border-white/10 group-hover:border-cyan-500/50 transition-all"
                          />
                          <div className="absolute inset-0 bg-black/40 rounded-2xl opacity-0 group-hover:opacity-100 flex items-center justify-center transition-all cursor-pointer">
                            <span className="text-[10px] font-bold uppercase tracking-widest">Change</span>
                          </div>
                        </div>
                        <div>
                          <h4 className="text-lg font-bold">{user?.displayName || 'Anonymous Agent'}</h4>
                          <p className="text-sm text-gray-500">{user?.email}</p>
                          <div className="mt-2 flex gap-2">
                            <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-500 text-[10px] font-bold rounded uppercase tracking-widest border border-emerald-500/20">Verified</span>
                            <span className="px-2 py-0.5 bg-cyan-500/10 text-cyan-500 text-[10px] font-bold rounded uppercase tracking-widest border border-cyan-500/20">Pro Plan</span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="p-4 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-between group cursor-pointer hover:bg-white/10 transition-all">
                        <div className="flex items-center gap-3">
                          <Globe className="w-5 h-5 text-gray-400" />
                          <div>
                            <p className="text-sm font-medium">Language</p>
                            <p className="text-xs text-gray-500">English (US)</p>
                          </div>
                        </div>
                        <ChevronRight className="w-4 h-4 text-gray-600 group-hover:text-white transition-all" />
                      </div>
                      <div className="p-4 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-between group cursor-pointer hover:bg-white/10 transition-all">
                        <div className="flex items-center gap-3">
                          <Shield className="w-5 h-5 text-gray-400" />
                          <div>
                            <p className="text-sm font-medium">Privacy Mode</p>
                            <p className="text-xs text-gray-500">Stealth (Enabled)</p>
                          </div>
                        </div>
                        <div className="w-10 h-5 bg-cyan-600 rounded-full relative">
                          <div className="absolute right-1 top-1 w-3 h-3 bg-white rounded-full shadow-sm" />
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'security' && (
                  <div className="space-y-8">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-bold mb-1">API Integrations</h3>
                        <p className="text-sm text-gray-500">Configure external service keys for enhanced reconnaissance.</p>
                      </div>
                      <button 
                        onClick={handleSaveKeys}
                        disabled={isSaving}
                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-bold rounded-xl transition-all flex items-center gap-2"
                      >
                        {isSaving ? <RefreshCw className="w-3 h-3 animate-spin" /> : saveSuccess ? <Check className="w-3 h-3" /> : <Save className="w-3 h-3" />}
                        {saveSuccess ? 'Saved' : 'Save Keys'}
                      </button>
                    </div>
                    
                    <div className="space-y-4">
                      {Object.entries(apiKeys).map(([key, value]) => (
                        <div key={key} className="p-5 rounded-2xl bg-white/5 border border-white/10">
                          <div className="flex items-center justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <Key className="w-4 h-4 text-cyan-500" />
                              <span className="text-sm font-bold uppercase tracking-widest">{key} API Key</span>
                            </div>
                            <button 
                              onClick={() => setShowApiKey(showApiKey === key ? null : key)}
                              className="text-[10px] font-bold text-cyan-500 hover:text-cyan-400 uppercase tracking-widest"
                            >
                              {showApiKey === key ? 'Hide' : 'Show'}
                            </button>
                          </div>
                          <div className="relative">
                            <input 
                              type={showApiKey === key ? 'text' : 'password'}
                              value={value}
                              onChange={(e) => setApiKeys(prev => ({ ...prev, [key]: e.target.value }))}
                              className="w-full bg-black border border-white/10 rounded-xl py-2.5 px-4 text-sm font-mono text-cyan-500/80 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                              placeholder={`Enter ${key} key...`}
                            />
                          </div>
                        </div>
                      ))}
                    </div>

                    <div className="p-4 rounded-2xl bg-amber-500/5 border border-amber-500/20 flex gap-3">
                      <AlertCircle className="w-5 h-5 text-amber-500 shrink-0" />
                      <p className="text-xs text-amber-500/80 leading-relaxed">
                        API keys are stored securely in your profile. Never share your keys with anyone. 
                        User-provided keys will override system defaults for your investigations.
                      </p>
                    </div>
                  </div>
                )}

                {activeTab === 'notifications' && (
                  <div className="space-y-6">
                    <div>
                      <h3 className="text-lg font-bold mb-1">Notification Preferences</h3>
                      <p className="text-sm text-gray-500 mb-6">Control how you receive alerts and intelligence updates.</p>
                      
                      <div className="space-y-4">
                        {[
                          { title: 'Security Alerts', desc: 'Critical threats and login attempts' },
                          { title: 'Scan Completions', desc: 'When long-running background scans finish' },
                          { title: 'Intelligence Reports', desc: 'Weekly summary of your investigations' },
                          { title: 'System Updates', desc: 'New tool releases and platform improvements' }
                        ].map((item, idx) => (
                          <div key={idx} className="flex items-center justify-between p-4 rounded-2xl bg-white/5 border border-white/10">
                            <div>
                              <p className="text-sm font-medium">{item.title}</p>
                              <p className="text-xs text-gray-500">{item.desc}</p>
                            </div>
                            <div className={cn(
                              "w-10 h-5 rounded-full relative cursor-pointer transition-all",
                              idx < 2 ? "bg-cyan-600" : "bg-white/10"
                            )}>
                              <div className={cn(
                                "absolute top-1 w-3 h-3 bg-white rounded-full shadow-sm transition-all",
                                idx < 2 ? "right-1" : "left-1"
                              )} />
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'appearance' && (
                  <div className="space-y-8">
                    <div>
                      <h3 className="text-lg font-bold mb-1">Visual Theme</h3>
                      <p className="text-sm text-gray-500 mb-6">Customize the interface to match your operational environment.</p>
                      
                      <div className="grid grid-cols-3 gap-4">
                        {[
                          { id: 'dark', label: 'Dark', icon: Moon },
                          { id: 'light', label: 'Light', icon: Sun },
                          { id: 'system', label: 'System', icon: Globe }
                        ].map((item) => (
                          <button
                            key={item.id}
                            onClick={() => setTheme(item.id as any)}
                            className={cn(
                              "flex flex-col items-center gap-3 p-6 rounded-2xl border transition-all",
                              theme === item.id 
                                ? "bg-cyan-500/10 border-cyan-500/50 text-cyan-500" 
                                : "bg-white/5 border-white/10 text-gray-500 hover:bg-white/10"
                            )}
                          >
                            <item.icon className="w-6 h-6" />
                            <span className="text-xs font-bold uppercase tracking-widest">{item.label}</span>
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="space-y-4">
                      <label className="text-[10px] font-bold text-gray-500 uppercase tracking-widest">Accent Color</label>
                      <div className="flex gap-4">
                        {['#06b6d4', '#8b5cf6', '#ec4899', '#10b981'].map((color) => (
                          <div 
                            key={color}
                            className={cn(
                              "w-8 h-8 rounded-full cursor-pointer border-2 transition-all",
                              color === '#06b6d4' ? "border-white scale-110" : "border-transparent"
                            )}
                            style={{ backgroundColor: color }}
                          />
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
};

export default SettingsModal;
