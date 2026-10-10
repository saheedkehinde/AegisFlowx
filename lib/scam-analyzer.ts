export type RiskLevel = 'high' | 'medium' | 'low' | 'uncertain';

export interface ThreatIndicator {
  name: string;
  evidence: string;
  reason: string;
}

export interface ScamAnalysisResult {
  riskLevel: RiskLevel;
  summary: string;
  indicators: ThreatIndicator[];
  recommendedActions: string[];
  limitations: string[];
  model?: string;
  analyzedAt?: string;
}

export interface ExampleMessage {
  id: string;
  title: string;
  category: string;
  text: string;
  description: string;
}

export const SAMPLE_MESSAGES: ExampleMessage[] = [
  {
    id: 'bank-sms',
    title: 'Urgent Bank Fraud Alert (SMS)',
    category: 'Bank Smishing',
    text: "WELLS FARGO ALERT: Suspicious debit of $1,429.99 to 'BEST BUY ONLINE' flagged on your card ending in 4082. Reply NO if not authorized, or verify identity within 15 minutes to avoid complete account freeze: https://bit.ly/wf-sec-verify-408",
    description: 'High-urgency bank alert impersonation driving victims to a shortened credential-harvesting phishing link.',
  },
  {
    id: 'ceo-giftcard',
    title: 'Executive Impersonation (Email)',
    category: 'Business Email Compromise (BEC)',
    text: "Hi, I'm currently stuck in an all-day confidential executive board review with our major investors and can't take phone calls. I urgently need you to purchase 5x $100 Apple Gift Cards from the nearest store for our strategic partner awards. Please scratch off the back and email photos of the PIN codes directly to this email before 3 PM. Keep this quiet.",
    description: 'Classic CEO fraud coercing an employee to purchase untraceable gift cards under the guise of secrecy.',
  },
  {
    id: 'usps-delivery',
    title: 'Package Delivery Failed (SMS)',
    category: 'Delivery Smishing',
    text: "USPS Tracking: Package shipment #US940012847 cannot be delivered due to incomplete street address numbers. Please update your delivery details and pay the mandatory $1.85 redelivery insurance fee at https://usps-track-resolve.top/deliver within 24 hours or item will be returned to sender.",
    description: 'Deceptive postal notification using small payment fees to harvest credit card details.',
  },
];

export const SAFE_SAMPLE_MESSAGE: ExampleMessage = {
  id: 'safe-message',
  title: 'Legitimate Friendly Note',
  category: 'Clean Message',
  text: "Hey Alex, dinner is confirmed for 7:30 PM tomorrow at Osteria downtown. Looking forward to catching up! Let me know if you need a ride or if you want to invite Sarah as well.",
  description: 'Standard informal communication with no malicious indicators, urgency pressure, or link demands.',
};
