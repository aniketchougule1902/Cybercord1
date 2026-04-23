import React, { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Landing from './pages/Landing';
import Dashboard from './pages/Dashboard';
import Investigate from './pages/Investigate';
import CustomInvestigate from './pages/CustomInvestigate';
import Pricing from './pages/Pricing';
import Auth from './pages/Auth';
import Terminal from './pages/Terminal';
import AdminDashboard from './pages/AdminDashboard';
import AICopilot from './components/AICopilot';
import { supabase } from './supabase';

function App() {
  const [isAuthReady, setIsAuthReady] = useState(false);
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
      setIsAuthReady(true);
    });

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => subscription.unsubscribe();
  }, []);

  if (!isAuthReady) {
    return (
      <div className="min-h-screen bg-[#050505] flex items-center justify-center">
        <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <Router>
      <div className="min-h-screen bg-[#050505] text-white font-sans selection:bg-cyan-500/30">
        <Navbar />
        <main className="pt-16">
          <Routes>
            <Route path="/" element={<Landing />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/investigate" element={<Investigate />} />
            <Route path="/custom-investigate" element={<CustomInvestigate />} />
            <Route path="/pricing" element={<Pricing />} />
            <Route path="/terminal" element={<Terminal />} />
            <Route path="/admin" element={<AdminDashboard />} />
            <Route path="/auth" element={<Auth />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
        <AICopilot />
      </div>
    </Router>
  );
}

export default App;
