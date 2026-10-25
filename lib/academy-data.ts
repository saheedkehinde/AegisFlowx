'use client';

export interface KnowledgeCheckOption {
  id: string;
  label: string;
  text: string;
}

export interface KnowledgeCheckQuestion {
  id: string;
  scenario: string;
  options: KnowledgeCheckOption[];
  correctOptionId: string;
  explanation: string;
  warningSigns: string[];
  safestAction: string;
}

export interface AcademyLesson {
  id: number;
  title: string;
  category: string;
  level: 'Beginner' | 'Intermediate' | 'Advanced';
  readTime: string;
  summary: string;
  redFlags: string[];
  defenses: string[];
  exampleSnippet: string;
  keyTakeaways: string[];
  questions: KnowledgeCheckQuestion[];
}

export interface ModuleProgress {
  completed: boolean;
  score: number;
  totalQuestions: number;
  percentage: number;
  lastAttemptAt: string;
}

export const ACADEMY_LESSONS: AcademyLesson[] = [
  {
    id: 1,
    title: 'Anatomy of Urgent Bank Fraud Smishing',
    category: 'Financial Phishing',
    level: 'Beginner',
    readTime: '4 min',
    summary:
      'How cybercriminals fabricate unauthorized charges to instill panic and push victims to shortened verification domains.',
    redFlags: [
      'Unusually specific or large fake debit dollar amounts ($1,429.99)',
      'Arbitrary, strict deadlines ("within 15 minutes", "avoid account freeze")',
      'Shortened hyperlinks (bit.ly, tinyurl) masquerading as official portals',
      'Requests to reply "NO" to confirm active phone recipient numbers',
    ],
    defenses: [
      'Never click links sent via unsolicited SMS, even if sender ID says your bank.',
      'Always open the authentic banking app directly from your home screen.',
      'Call the official phone number printed on the back of your physical card.',
    ],
    exampleSnippet:
      "WELLS FARGO ALERT: Suspicious debit of $1,429.99 flagged. Reply NO or click https://bit.ly/wf-sec to avoid account freeze within 15 mins.",
    keyTakeaways: [
      'Banks will never send link shorteners or demand password/PIN verification via unsolicited SMS.',
      'Replying to smishing texts (even "STOP" or "NO") confirms your phone line is actively monitored.',
      'Always originate banking inquiries yourself through the official card-back phone number or verified app.',
    ],
    questions: [
      {
        id: 'q1-1',
        scenario:
          'You receive a text message at 11:42 PM claiming your debit card was just charged $1,894.50 at an electronics retail chain in another state. The text says: "Reply DECLINE immediately to reverse the charge, or visit https://alert-fraud-verify41.net within 10 minutes to unfreeze your account."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Click the link immediately to prevent the fraudulent transaction from posting to your balance.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Reply "DECLINE" to signal that you did not authorize the payment.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Ignore the link, do not reply, and open your bank app directly or call the number on the back of your card.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Forward the message to your coworkers to ask if anyone else’s bank sent a similar alert.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'Both the hyperlink and the "reply DECLINE" prompt are attacker traps. Replying confirms your phone number is active and responsive to financial scares, while clicking the link leads to a credential harvesting site designed to steal your online banking login and debit card PIN.',
        warningSigns: [
          'Severe manufactured time pressure ("within 10 minutes")',
          'Off-brand domain using hyphenated keywords (alert-fraud-verify41.net)',
          'Late-night unsolicited alert directing you to an external web page',
        ],
        safestAction:
          'Navigate independently to your bank by launching your official mobile banking app or calling the trusted telephone number printed on the physical back of your debit card.',
      },
      {
        id: 'q1-2',
        scenario:
          'A text from your credit union warns: "Suspicious wire initiated. A representative will call you in 2 minutes to assist." Shortly after, your phone rings with caller ID displaying your credit union’s genuine phone number. The caller asks for the 6-digit one-time passcode (OTP) just sent to your phone "to verify your identity and cancel the wire."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Read the 6-digit code to the agent so they can cancel the fraudulent wire quickly.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Refuse to disclose the code, hang up immediately, and call your credit union’s fraud department directly via their official number.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Ask the agent for their employee ID badge number, write it down, and then give them the code.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Keep the caller on hold while typing the OTP into the website link they text you.',
          },
        ],
        correctOptionId: 'B',
        explanation:
          'Legitimate financial institutions and customer service agents will NEVER call you and ask for a One-Time Passcode (OTP). The caller ID was spoofed. The attacker already has your password and triggered an OTP prompt on the real bank website, needing you to read it aloud to bypass Two-Factor Authentication (2FA).',
        warningSigns: [
          'Inbound caller requesting a temporary one-time security code',
          'Urgency surrounding an alleged pending wire transfer',
          'Caller ID spoofing mirroring a known financial institution number',
        ],
        safestAction:
          'Hang up immediately without disclosing the code. Outbound dial your bank using a known, trusted phone number from your statements or card.',
      },
      {
        id: 'q1-3',
        scenario:
          'You receive an SMS: "CARD NOTICE: Temporary lock applied to your account due to updated security compliance. Review your profile at https://bit.ly/bank-sec-update to avoid automated suspension."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Paste the URL into a browser expander, and if it redirects to an HTTPS URL, log in there.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'The link uses HTTPS, which guarantees the destination is an encrypted official bank server.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Treat shortened URLs (bit.ly, tinyurl) in unsolicited security notices as malicious lures; delete the text or forward to 7726.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Reply to the text asking what specific security compliance update is needed.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'Banks do not send generic URL shorteners to deliver regulatory compliance alerts. Furthermore, HTTPS encryption only means data in transit is encrypted—it provides zero guarantee that the server owner is legitimate or trustworthy.',
        warningSigns: [
          'Anonymous URL shortener hiding the true destination hostname',
          'Vague "security compliance" pretext without naming your specific branch or account',
          'Threat of automated account suspension',
        ],
        safestAction:
          'Never click link shorteners in unsolicited SMS alerts. Report the message to your mobile carrier by forwarding to 7726 (SPAM).',
      },
    ],
  },
  {
    id: 2,
    title: 'Business Email Compromise (BEC) & Executive Fraud',
    category: 'Corporate Social Engineering',
    level: 'Intermediate',
    readTime: '5 min',
    summary:
      'Attackers impersonating C-level leadership requesting secretive gift card purchases or confidential wire transfers.',
    redFlags: [
      'Sender claims to be stuck in an all-day executive board meeting unable to talk',
      'Strict emphasis on secrecy ("keep this quiet", "strictly confidential")',
      'Requests for untraceable payment media: Apple, Steam, or Vanilla Visa gift cards',
      'Urgent instructions to scratch off PIN codes and send photos immediately',
    ],
    defenses: [
      'No legitimate executive will ever instruct an employee to purchase gift cards for business operations.',
      'Always verify through an out-of-band channel (call internal phone extension or ask in person).',
      'Report the spoofed email header to internal security/IT helpdesk.',
    ],
    exampleSnippet:
      "Hi, I'm currently stuck in an all-day confidential executive board review and can't take phone calls. I urgently need you to purchase 5x $100 Apple Gift Cards before 3 PM. Scratch the back and email photos of the PIN codes. Keep this quiet.",
    keyTakeaways: [
      'Executives will never legitimately demand personal purchases of retail gift cards for corporate business.',
      'Always verify sudden changes to bank wire instructions or remittance addresses through out-of-band verbal phone confirmation.',
      'Check the actual email address header, not just the displayed friendly name.',
    ],
    questions: [
      {
        id: 'q2-1',
        scenario:
          'You receive an email from the display name of your company’s CEO. The sender address is "ceo.office-internal@mail-executive-corp.com" (your company’s real domain is "acmecorp.com"). The email reads: "I am locked in confidential acquisition negotiations all morning. We need to close vendor milestone payments before 1:00 PM. Please wire $42,000 to the attached escrow account immediately. Do not discuss this with the team due to strict SEC blackout rules."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Process the wire immediately because the CEO has executive authority and cited strict SEC confidentiality.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Reply to the email asking if the CEO can provide their corporate credit card instead.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Recognize the lookalike spoofed domain, secrecy pressure, and dual-control bypass; verify out-of-band with your finance lead and report to IT.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Forward the wire instructions to your personal email to review the routing numbers on your phone.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'This is textbook Business Email Compromise (BEC). The sender address uses an external lookalike domain (mail-executive-corp.com instead of acmecorp.com). The artificial urgency, demand for secrecy ("SEC blackout rules"), and evasion of standard dual-approval accounting procedures are classic hallmarks of executive impersonation.',
        warningSigns: [
          'Lookalike external domain mimicking executive leadership',
          'Artificial deadline designed to prevent methodical review',
          'Strict demand for secrecy and bypassing normal verification workflows',
        ],
        safestAction:
          'Halt the transaction, do not reply to the sender, and verify out-of-band via an internal phone extension or in person with authorized finance leadership.',
      },
      {
        id: 'q2-2',
        scenario:
          'An urgent direct message arrives on your corporate chat platform from a profile using your Vice President’s photo and name: "Hey, are you at your desk? I need an urgent favor—I am about to present at a partner dinner and our promotional gifts fell through. Can you run to the store nearby and pick up 6x $200 Apple gift cards? Scratch the backs and DM me photos of the PIN codes right now. I’ll submit your reimbursement first thing tomorrow morning."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Purchase the gift cards quickly since the profile picture and name match your Vice President.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Explain that company expense policy requires gift card requests to involve at least $1,500 to be reimbursable.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Recognize that retail gift cards are untraceable payment instruments never legitimately used for corporate expenses; verify through a secondary channel.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Buy only half the requested amount to minimize company financial risk.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'Gift cards are effectively digital cash. Once PIN codes are transmitted, funds are drained by automated bots within seconds. Legitimate corporate entities do not ask individual employees to purchase retail gift cards with personal funds for executive client meetings.',
        warningSigns: [
          'Request for retail gift cards (Apple, Target, Vanilla Visa)',
          'Instructions to scratch PIN codes and send photos immediately',
          'Promise of retroactive personal expense reimbursement',
        ],
        safestAction:
          'Refuse the request and contact the purported sender via a verified telephone call or in person using established internal contact details.',
      },
      {
        id: 'q2-3',
        scenario:
          'A supplier you work with monthly sends an email from their normal email address: "Please note our banking partner has changed due to a corporate treasury audit. For all upcoming invoice settlements starting this week, route payments to our new account at Apex Commercial Trust." An updated invoice PDF is attached.',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Update the payment routing details immediately since the email came from the supplier’s genuine address.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Contact the supplier’s known finance department using a previously established telephone number (not the number on the new invoice) to verbally confirm bank routing modifications.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Reply to the email asking the sender to confirm that the new account number is correct.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Pay only $1 to test the new account before sending the full invoice payment.',
          },
        ],
        correctOptionId: 'B',
        explanation:
          'Vendor Email Compromise (VEC) occurs when an attacker compromises a legitimate supplier’s email account. Replying to the email merely reaches the attacker who controls the inbox. Out-of-band verbal authentication using a pre-existing trusted phone number is the only reliable verification.',
        warningSigns: [
          'Sudden change of remittance bank routing or account details',
          'Request delivered via email without prior executive notification',
          'Updated contact details printed on the new invoice itself',
        ],
        safestAction:
          'Perform an out-of-band verbal confirmation using an existing, verified phone number from contracts or past audited invoices—never the phone number listed on the new suspicious invoice.',
      },
    ],
  },
  {
    id: 3,
    title: 'Package Delivery Smishing & Advance Fee Schemes',
    category: 'Postal Impersonation',
    level: 'Beginner',
    readTime: '3 min',
    summary:
      'Fake USPS, UPS, or FedEx delivery alerts requesting nominal insurance or redelivery fees to steal credit card details.',
    redFlags: [
      'Claims that delivery address was incomplete or missing street numbers',
      'Request for an unusual nominal fee ($1.85 or $2.10) to cover "reshipment"',
      'Lookalike non-standard domains (usps-track-resolve.top or fedex-delivery.xyz)',
      'Threat of returning package to sender within 24 hours',
    ],
    defenses: [
      'Postal services never require credit card payments via SMS links to deliver mail.',
      'Track parcels directly on the official USPS.com or carrier website using the tracking number.',
      'Forward smishing SMS messages to 7726 (SPAM).',
    ],
    exampleSnippet:
      "USPS Tracking: Package shipment #US940012847 cannot be delivered due to incomplete street address numbers. Please update your delivery details and pay the mandatory $1.85 redelivery insurance fee at https://usps-track-resolve.top/deliver within 24 hours.",
    keyTakeaways: [
      'Nominal fee lures ($1–$3) are designed to steal full credit card credentials, not the small fee itself.',
      'Official postal services do not demand payment via unsolicited SMS links.',
      'Never download executable installer files (.apk, .exe) from delivery notifications.',
    ],
    questions: [
      {
        id: 'q3-1',
        scenario:
          'You receive an SMS: "USPS Notice: Your parcel #940012847 is on hold at our distribution facility due to an incomplete street address. Please confirm your postal address and submit the $1.85 redelivery insurance charge at https://usps-parcel-resolve.online within 24 hours to prevent return to sender."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Pay the $1.85 fee because it is a very small amount and you frequently order items online.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Enter a family member’s credit card number so your personal card is not compromised.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Recognize that postal carriers do not charge redelivery fees via SMS links; track the package independently on the official carrier site.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Click the link to check what item is inside the package before deciding whether to pay.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'The nominal $1.85 fee is an "advance fee lure." The attacker’s objective is not the $1.85, but the full credit card number, expiration date, CVV, and billing address entered into the spoofed payment form, which is then used for unauthorized charges.',
        warningSigns: [
          'Minor fee requested via unsolicited SMS',
          'Threat of package return within a short window',
          'Lookalike domain (usps-parcel-resolve.online instead of official usps.com)',
        ],
        safestAction:
          'Do not click the link. If you are expecting a package, navigate directly to official carrier tracking utilities using the tracking number from your original purchase receipt.',
      },
      {
        id: 'q3-2',
        scenario:
          'An SMS claims: "FedEx delivery update: Driver unable to access your building gate. Schedule your redelivery window and download your digital dispatch slip: https://fedx-mobile-tracking.apk".',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Download the file because the .apk file is the official mobile tracking application.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Do not download or open the file; .apk files are Android package files that can install malware or spyware onto your device.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Open the file in an incognito window to inspect the contents safely.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Forward the .apk file to a computer to install it on a desktop instead.',
          },
        ],
        correctOptionId: 'B',
        explanation:
          'Links prompting you to download executable packages (.apk, .exe, .dmg) deliver mobile malware that can intercept Two-Factor Authentication codes, read incoming text messages, and exfiltrate credentials. Delivery couriers never distribute tracking slips as installable application packages.',
        warningSigns: [
          'Direct link to download an application file (.apk)',
          'Delivery failure pretext requiring software installation',
          'Spoofed brand name in domain (fedx instead of fedex)',
        ],
        safestAction:
          'Immediately delete the text and never install application packages from third-party links outside the official Google Play Store or Apple App Store.',
      },
      {
        id: 'q3-3',
        scenario:
          'You receive an email from a shipping company stating you have an unclaimed international parcel. The email includes a link asking you to verify your full name, Social Security Number, and date of birth to "clear international customs clearance."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Fill out the form if you have relatives overseas who might have sent a surprise gift.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Only enter your date of birth, but leave the Social Security Number field blank.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Recognize that commercial couriers do not ask for full Social Security Numbers via unsolicited web forms; mark the email as phishing.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Call the telephone number provided in the email footer to provide the details verbally.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'Unsolicited international package notices asking for sensitive government identity numbers (such as SSNs) are phishing lures engineered for comprehensive identity theft and fraudulent credit account creation.',
        warningSigns: [
          'Unsolicited international package notice',
          'Request for sensitive personal identifiers (SSN, birthdate)',
          'External unverified web forms claiming customs jurisdiction',
        ],
        safestAction:
          'Treat requests for government identifiers in delivery notices as severe phishing threats. Verify genuine customs procedures directly through licensed customs brokers.',
      },
    ],
  },
  {
    id: 4,
    title: 'Cryptocurrency Recovery & Tech Support Extortion',
    category: 'Advanced Social Engineering',
    level: 'Advanced',
    readTime: '6 min',
    summary:
      'Attackers posing as blockchain investigators or cybersecurity specialists promising to recover lost funds for an upfront fee.',
    redFlags: [
      'Guaranteed recovery of lost crypto assets or stolen wallet funds',
      'Demands for remote desktop access (AnyDesk, TeamViewer)',
      'Upfront "gas fees", "legal escrow", or blockchain verification deposits',
      'Unsolicited DMs on Telegram, Reddit, or Discord offering recovery services',
    ],
    defenses: [
      'Blockchain transactions are mathematically irreversible; anyone promising guaranteed private key recovery is a scammer.',
      'Never install remote desktop software for unverified third parties.',
      'Never disclose 12/24-word seed recovery phrases to anyone.',
    ],
    exampleSnippet:
      "Blockchain Forensic Bureau: We have located your stolen $12,400 USDT. Please connect your wallet to our recovery escrow portal and pay 0.05 ETH gas fee to release funds.",
    keyTakeaways: [
      'Blockchain transactions are irreversible; claims of guaranteed asset recovery are recovery scams.',
      'Legitimate tech support never displays phone numbers in browser pop-up alarm screens.',
      'Your seed recovery phrase is your master cryptographic key—never share it with anyone.',
    ],
    questions: [
      {
        id: 'q4-1',
        scenario:
          'After discussing a cryptocurrency investment loss in an online forum, you receive a direct message from someone claiming to be a "Certified Senior Investigator at the International Blockchain Recovery Bureau." They state: "We traced your lost tokens to an offshore laundering node. We can freeze the transaction and recover your 15.4 ETH, but you must connect your Web3 wallet and deposit a 0.15 ETH forensic gas fee to initiate the smart contract."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Pay the 0.15 ETH fee because recovering 15.4 ETH is worth the small upfront forensic cost.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Connect your wallet, but only if the website displays government seal badges.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Recognize this as a "Recovery Scam"—blockchain transactions are irreversible, and any entity demanding upfront fees or wallet connections is an attacker.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Ask the investigator to sign a non-disclosure agreement before sending the 0.15 ETH.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'This is a classic "Recovery Scam" targeting victims who have already suffered financial losses. Due to the decentralized and immutable architecture of public blockchains, private transactions cannot be reversed or retrieved by third-party "officers." Connecting your wallet or depositing "gas fees" will only result in further financial losses.',
        warningSigns: [
          'Unsolicited direct message offering to recover lost cryptocurrency',
          'Official-sounding fake government/forensic agency names',
          'Demand for upfront "fees" or smart contract approvals to release funds',
        ],
        safestAction:
          'Block and report the user immediately. Never connect Web3 wallets or send funds to self-proclaimed recovery services.',
      },
      {
        id: 'q4-2',
        scenario:
          'While browsing the web, a loud alarm sounds and a full-screen pop-up appears: "CRITICAL ALERT FROM MICROSOFT DEFENDER: Your PC is infected with Trojan:SL/Spyware.66! Financial data and webcam compromised. Do NOT shut down your computer. Call Microsoft Certified Support immediately at 1-888-555-0199."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Call the phone number immediately and follow the technician’s instructions to clean the system.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Allow the technician to install AnyDesk or TeamViewer so they can scan your hard drive.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Recognize this as a fake browser tech support lock screen; close the browser tab (or end the browser task via Task Manager), and do not call the number.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Restart your computer and immediately purchase antivirus software through the link in the pop-up.',
          },
        ],
        correctOptionId: 'C',
        explanation:
          'Legitimate operating system security software (like Microsoft Defender or Apple macOS Gatekeeper) will NEVER display a toll-free telephone number in browser pop-ups and urge you to call someone. These are browser full-screen locks designed to panic users into granting remote desktop access, after which scammers steal files or charge hundreds of dollars for fake cleanup software.',
        warningSigns: [
          'Browser lock screen with sirens, flashing alerts, or synthetic urgency',
          'Prominent phone number displayed inside a web page banner',
          'Instructions not to restart or shut down your computer',
        ],
        safestAction:
          'Force-close the browser window (e.g. Ctrl+W, Alt+F4, or via Task Manager). Do not call the telephone number.',
      },
      {
        id: 'q4-3',
        scenario:
          'A supposed technical support representative for your hardware wallet company messages you on Telegram/Discord: "A critical zero-day vulnerability in the firmware was discovered. To safeguard your assets from being drained, please confirm your 24-word secret recovery phrase so we can migrate your balance to a protected vault."',
        options: [
          {
            id: 'A',
            label: 'A',
            text: 'Provide the 24 words, but omit the last 2 words for security.',
          },
          {
            id: 'B',
            label: 'B',
            text: 'Never disclose your seed recovery phrase to anyone under any circumstances, as possessing the seed phrase grants permanent, complete control of all wallet assets.',
          },
          {
            id: 'C',
            label: 'C',
            text: 'Ask the representative to prove they work for the company by telling you your account username first.',
          },
          {
            id: 'D',
            label: 'D',
            text: 'Type the seed phrase into a text file and send it as a password-protected ZIP archive.',
          },
        ],
        correctOptionId: 'B',
        explanation:
          'Your 12- or 24-word seed phrase is the master cryptographic key to all private keys and assets in your wallet. Legitimate hardware or software wallet companies will never ask for your recovery phrase under any circumstances. Anyone asking for your recovery phrase is attempting to steal your funds.',
        warningSigns: [
          'Inbound message claiming firmware vulnerability or emergency migration',
          'Request for 12/24-word seed recovery phrase',
          'Contact originating from private messaging platforms (Telegram, Discord)',
        ],
        safestAction:
          'Never enter your recovery phrase anywhere except directly onto the physical hardware wallet device itself during initial setup or recovery. Block the sender immediately.',
      },
    ],
  },
];

export const STORAGE_KEY = 'aegisflow_academy_progress_v1';
export const ACADEMY_STORAGE_KEY = STORAGE_KEY;

export function getAcademyProgress(): Record<number, ModuleProgress> {
  if (typeof window === 'undefined') return {};
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

export function saveModuleProgress(
  moduleId: number,
  score: number,
  totalQuestions: number
): Record<number, ModuleProgress> {
  if (typeof window === 'undefined') return {};
  try {
    const current = getAcademyProgress();
    const percentage = Math.round((score / totalQuestions) * 100);
    const updated: Record<number, ModuleProgress> = {
      ...current,
      [moduleId]: {
        completed: true,
        score,
        totalQuestions,
        percentage,
        lastAttemptAt: new Date().toISOString(),
      },
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    window.dispatchEvent(new Event('aegisflow-academy-progress-updated'));
    return updated;
  } catch {
    return {};
  }
}

export function resetModuleProgress(moduleId: number): Record<number, ModuleProgress> {
  if (typeof window === 'undefined') return {};
  try {
    const current = getAcademyProgress();
    delete current[moduleId];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(current));
    window.dispatchEvent(new Event('aegisflow-academy-progress-updated'));
    return current;
  } catch {
    return {};
  }
}

export function resetAllAcademyProgress(): Record<number, ModuleProgress> {
  if (typeof window === 'undefined') return {};
  try {
    localStorage.removeItem(STORAGE_KEY);
    window.dispatchEvent(new Event('aegisflow-academy-progress-updated'));
    return {};
  } catch {
    return {};
  }
}

