import React, { useMemo } from 'react';
import ReactFlow, { 
  Background, 
  Controls, 
  MiniMap, 
  Handle, 
  Position,
  NodeProps,
  Edge,
  Node
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Shield, Globe, Mail, User, Smartphone, AlertTriangle } from 'lucide-react';
import { EntityType } from '../types';
import { cn } from '../lib/utils';

const CustomNode = ({ data }: NodeProps) => {
  const Icon = useMemo(() => {
    switch (data.type) {
      case EntityType.DOMAIN: return Globe;
      case EntityType.IP: return Shield;
      case EntityType.EMAIL: return Mail;
      case EntityType.USERNAME: return User;
      case EntityType.PHONE: return Smartphone;
      case EntityType.BREACH: return AlertTriangle;
      default: return Shield;
    }
  }, [data.type]);

  return (
    <div className={cn(
      "px-4 py-3 rounded-xl border bg-black/80 backdrop-blur-md shadow-2xl min-w-[150px]",
      data.risk > 70 ? "border-red-500/50 shadow-red-500/10" : "border-cyan-500/30 shadow-cyan-500/10"
    )}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 bg-cyan-500 border-none" />
      <div className="flex items-center gap-3">
        <div className={cn(
          "p-2 rounded-lg",
          data.risk > 70 ? "bg-red-500/10 text-red-500" : "bg-cyan-500/10 text-cyan-500"
        )}>
          <Icon className="w-4 h-4" />
        </div>
        <div>
          <p className="text-[10px] uppercase tracking-widest text-gray-500 font-bold">{data.type}</p>
          <p className="text-sm font-semibold text-white truncate max-w-[120px]">{data.label}</p>
        </div>
      </div>
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 bg-cyan-500 border-none" />
    </div>
  );
};

const nodeTypes = {
  custom: CustomNode,
};

interface InvestigationFlowProps {
  entities: any[];
  relationships: any[];
}

const InvestigationFlow = ({ entities, relationships }: InvestigationFlowProps) => {
  const nodes: Node[] = useMemo(() => entities.map((e, idx) => ({
    id: e.id,
    type: 'custom',
    position: { x: 250 + (idx * 200) % 600, y: 100 + Math.floor(idx / 3) * 150 },
    data: { 
      label: e.label, 
      type: e.type,
      risk: Math.random() * 100 // Mock risk for visual variety
    },
  })), [entities]);

  const edges: Edge[] = useMemo(() => relationships.map((r) => ({
    id: r.id,
    source: r.source,
    target: r.target,
    label: r.label,
    animated: true,
    style: { stroke: '#06b6d4', strokeWidth: 2 },
    labelStyle: { fill: '#06b6d4', fontWeight: 700, fontSize: 10 },
    labelBgStyle: { fill: '#050505', fillOpacity: 0.8 },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 4,
  })), [relationships]);

  return (
    <div className="w-full h-full rounded-2xl overflow-hidden border border-white/10 bg-[#050505]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        className="bg-dot-white/[0.05]"
      >
        <Background color="#ffffff" gap={20} size={1} />
        <Controls className="bg-black/80 border-white/10 fill-white" />
        <MiniMap 
          nodeColor={(n) => (n.data?.risk > 70 ? '#ef4444' : '#06b6d4')}
          maskColor="rgba(0, 0, 0, 0.6)"
          className="bg-black/80 border-white/10"
        />
      </ReactFlow>
    </div>
  );
};

export default InvestigationFlow;
