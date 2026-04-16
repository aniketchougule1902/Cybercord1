import React, { useState, useEffect } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shield, Search, LayoutDashboard, CreditCard, Settings, Terminal, Menu, X, User, Database } from 'lucide-react';
import { cn } from '../lib/utils';
import SettingsModal from './SettingsModal';
import { supabase } from '../supabase';

const Navbar = () => {
  const location = useLocation();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
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
      if (!user) {
        setIsAdmin(false);
        return;
      }
      
      if (user.email === 'aniketvipulchougule@gmail.com') {
        setIsAdmin(true);
        return;
      }

      try {
        const { data, error } = await supabase
          .from('users')
          .select('role')
          .eq('id', user.id)
          .single();
          
        if (!error && data?.role === 'admin') {
          setIsAdmin(true);
        } else {
          setIsAdmin(false);
        }
      } catch (error) {
        console.error("Error checking admin status:", error);
      }
    };

    checkAdmin();
  }, [user]);

  const navItems = [
    { name: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { name: 'Investigate', path: '/investigate', icon: Search },
    { name: 'Custom', path: '/custom-investigate', icon: Terminal },
    { name: 'Pricing', path: '/pricing', icon: CreditCard },
  ];

  if (isAdmin) {
    navItems.push({ name: 'Admin', path: '/admin', icon: Database });
  }

  return (
    <>
      <nav className="fixed top-0 left-0 right-0 z-50 bg-black/80 backdrop-blur-md border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <Link to="/" className="flex items-center gap-2 group">
                <div className="p-1.5 bg-cyan-500/10 rounded-lg group-hover:bg-cyan-500/20 transition-all">
                  <Shield className="w-6 h-6 text-cyan-500" />
                </div>
                <span className="text-xl font-bold tracking-tighter text-white">CYBER<span className="text-cyan-500">CORD</span></span>
              </Link>
            </div>
            
            <div className="hidden md:block">
              <div className="ml-10 flex items-baseline space-x-1">
                {navItems.map((item) => (
                  <Link
                    key={item.name}
                    to={item.path}
                    className={cn(
                      "px-4 py-2 rounded-xl text-sm font-medium transition-all flex items-center gap-2",
                      location.pathname === item.path
                        ? "bg-cyan-500/10 text-cyan-500 border border-cyan-500/20"
                        : "text-gray-400 hover:bg-white/5 hover:text-white"
                    )}
                  >
                    <item.icon className="w-4 h-4" />
                    {item.name}
                  </Link>
                ))}
              </div>
            </div>
            
            <div className="flex items-center gap-2 md:gap-4">
              <button 
                onClick={() => setIsSettingsOpen(true)}
                className="p-2 text-gray-400 hover:text-white hover:bg-white/5 rounded-xl transition-all"
                title="Settings"
              >
                <Settings className="w-5 h-5" />
              </button>
              
              <div className="hidden sm:block h-6 w-px bg-white/10 mx-2" />

              {user ? (
                <div className="hidden sm:flex items-center gap-3 pl-2">
                  <div className="text-right">
                    <p className="text-xs font-bold text-white leading-none">{user.user_metadata?.full_name?.split(' ')[0] || user.email?.split('@')[0]}</p>
                    <p className="text-[10px] text-gray-500 font-medium tracking-widest uppercase">Pro Agent</p>
                  </div>
                  <img 
                    src={user.user_metadata?.avatar_url || `https://api.dicebear.com/7.x/avataaars/svg?seed=${user.email}`} 
                    alt="Avatar" 
                    className="w-8 h-8 rounded-lg border border-white/10"
                  />
                </div>
              ) : (
                <Link 
                  to="/auth" 
                  className="hidden sm:flex items-center gap-2 px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-bold rounded-xl transition-all shadow-[0_0_15px_rgba(8,145,178,0.3)] border border-cyan-400/20"
                >
                  <User className="w-4 h-4" />
                  Get Started
                </Link>
              )}

              {/* Mobile Menu Toggle */}
              <button 
                onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
                className="md:hidden p-2 text-gray-400 hover:text-white hover:bg-white/5 rounded-xl transition-all"
              >
                {isMobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile Menu */}
        <div className={cn(
          "md:hidden absolute top-16 left-0 right-0 bg-black/95 backdrop-blur-xl border-b border-white/10 transition-all duration-300 overflow-hidden",
          isMobileMenuOpen ? "max-h-[400px] opacity-100 py-6" : "max-h-0 opacity-0 py-0"
        )}>
          <div className="px-4 space-y-2">
            {navItems.map((item) => (
              <Link
                key={item.name}
                to={item.path}
                onClick={() => setIsMobileMenuOpen(false)}
                className={cn(
                  "flex items-center gap-4 px-6 py-4 rounded-2xl text-base font-bold transition-all",
                  location.pathname === item.path
                    ? "bg-cyan-500/10 text-cyan-500 border border-cyan-500/20"
                    : "text-gray-400 hover:bg-white/5 hover:text-white"
                )}
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </Link>
            ))}
            {!user && (
              <Link 
                to="/auth" 
                onClick={() => setIsMobileMenuOpen(false)}
                className="flex items-center justify-center gap-2 w-full mt-4 px-6 py-4 bg-cyan-600 text-white font-bold rounded-2xl"
              >
                <User className="w-5 h-5" />
                Get Started
              </Link>
            )}
          </div>
        </div>
      </nav>

      <SettingsModal 
        isOpen={isSettingsOpen} 
        onClose={() => setIsSettingsOpen(false)} 
      />
    </>
  );
};

export default Navbar;
