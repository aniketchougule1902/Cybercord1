import React from 'react';
import { motion } from 'motion/react';
import { Check, Zap, Shield, Globe, Terminal, Users, ArrowRight } from 'lucide-react';
import { cn } from '../lib/utils';

const Pricing = () => {
  const plans = [
    {
      name: "Free",
      price: "0",
      desc: "For individual learners and curious investigators.",
      features: [
        "5 investigations / day",
        "Basic OSINT tools",
        "Public data sources",
        "Community support"
      ],
      cta: "Start Free",
      popular: false
    },
    {
      name: "Starter",
      price: "299",
      desc: "Perfect for hobbyists and security enthusiasts.",
      features: [
        "30 investigations / day",
        "AI Analysis Engine",
        "Basic Graph view",
        "Email intelligence",
        "Priority support"
      ],
      cta: "Get Started",
      popular: false
    },
    {
      name: "Pro",
      price: "799",
      desc: "Advanced tools for professional investigators.",
      features: [
        "Unlimited investigations",
        "Full tool access (100+)",
        "Advanced Graph + Timeline",
        "Credential leak monitoring",
        "API access (limited)"
      ],
      cta: "Go Pro",
      popular: true
    },
    {
      name: "Enterprise",
      price: "1999",
      desc: "Full-scale intelligence for security teams.",
      features: [
        "Team workspaces",
        "Full API access",
        "Live threat monitoring",
        "Custom tool integration",
        "Dedicated account manager"
      ],
      cta: "Contact Sales",
      popular: false
    }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
      <div className="text-center mb-20">
        <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">Simple, Transparent <span className="text-cyan-500">Pricing</span></h1>
        <p className="text-gray-400 max-w-2xl mx-auto text-lg">
          Choose the plan that fits your intelligence needs. From individual research to enterprise-grade threat hunting.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
        {plans.map((plan, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: idx * 0.1 }}
            className={cn(
              "relative p-8 rounded-3xl bg-white/5 border transition-all flex flex-col",
              plan.popular ? "border-cyan-500 shadow-[0_0_30px_rgba(8,145,178,0.2)]" : "border-white/10 hover:border-white/20"
            )}
          >
            {plan.popular && (
              <div className="absolute -top-4 left-1/2 -translate-x-1/2 px-4 py-1 bg-cyan-500 text-black text-[10px] font-bold uppercase tracking-widest rounded-full">
                Most Popular
              </div>
            )}
            
            <div className="mb-8">
              <h3 className="text-xl font-bold mb-2">{plan.name}</h3>
              <div className="flex items-baseline gap-1 mb-4">
                <span className="text-4xl font-bold">₹{plan.price}</span>
                <span className="text-gray-500 text-sm">/month</span>
              </div>
              <p className="text-gray-400 text-sm leading-relaxed">{plan.desc}</p>
            </div>

            <div className="space-y-4 mb-10 flex-grow">
              {plan.features.map((feature, fIdx) => (
                <div key={fIdx} className="flex items-start gap-3 text-sm">
                  <Check className="w-4 h-4 text-cyan-500 mt-0.5 flex-shrink-0" />
                  <span className="text-gray-300">{feature}</span>
                </div>
              ))}
            </div>

            <button className={cn(
              "w-full py-4 rounded-xl font-bold transition-all flex items-center justify-center gap-2",
              plan.popular 
                ? "bg-cyan-600 hover:bg-cyan-500 text-white shadow-[0_0_15px_rgba(8,145,178,0.3)]" 
                : "bg-white/5 hover:bg-white/10 text-white border border-white/10"
            )}>
              {plan.cta} <ArrowRight className="w-4 h-4" />
            </button>
          </motion.div>
        ))}
      </div>

      {/* Comparison or Trust section */}
      <div className="mt-32 p-12 rounded-3xl bg-gradient-to-br from-cyan-500/10 to-purple-500/10 border border-white/10 text-center">
        <h2 className="text-3xl font-bold mb-6">Need a custom solution?</h2>
        <p className="text-gray-400 mb-8 max-w-xl mx-auto">
          We offer custom data feeds, on-premise deployments, and specialized intelligence services for government and large enterprise.
        </p>
        <button className="px-8 py-4 bg-white text-black font-bold rounded-xl hover:bg-gray-200 transition-all">
          Talk to an Expert
        </button>
      </div>
    </div>
  );
};

export default Pricing;
