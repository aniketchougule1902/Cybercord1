export enum EntityType {
  USER = "USER",
  DOMAIN = "DOMAIN",
  IP = "IP",
  EMAIL = "EMAIL",
  PHONE = "PHONE",
  USERNAME = "USERNAME",
  ORGANIZATION = "ORGANIZATION",
  BREACH = "BREACH"
}

export interface InvestigationEntity {
  id: string;
  type: EntityType;
  label: string;
  data: any;
}

export interface InvestigationRelationship {
  id: string;
  source: string;
  target: string;
  label: string;
}

export interface InvestigationEvent {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  type: "info" | "warning" | "danger" | "success";
}

export interface InvestigationResult {
  id: string;
  query: string;
  type: EntityType;
  status: "pending" | "running" | "completed" | "failed";
  riskScore: number;
  entities: InvestigationEntity[];
  relationships: InvestigationRelationship[];
  timeline: InvestigationEvent[];
  summary?: string;
  createdAt: string;
}
