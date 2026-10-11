# AegisFlow — Think Before You Trust.
AI-Powered Threat Triage & Defense.

ScamShield AI is an AI-powered decision-support tool that analyzes suspicious text messages, emails, and payment requests to highlight phishing indicators, explain warning signs in plain language, and offer immediate safety steps.

## 🛠️ Tech Stack & Technologies Used

- **Frontend & Framework:** Next.js (App Router), TypeScript, Tailwind CSS
- **UI & Icons:** Lucide React, Shadcn UI / Glassmorphism Styling
- **AI Inference:** Featherless API (`https://api.featherless.ai/v1`)
- **AI Model:** `Qwen/Qwen3-VL-8B-Instruct`
- **Validation & Parsing:** Zod / Native Schema Enforcement
- **Hosting & Deployment:** Vercel

## ⚙️ Architecture & Data Flow

1. **User Input:** Message submitted via Client Interface.
2. **Server Route (`/api/analyze`):** Validates input length & sanitizes request.
3. **Featherless Proxy:** Forwards system/user prompts securely using server-side credentials.
4. **Model Reasoning (`Qwen3-VL`):** Analyzes social engineering patterns & returns structured JSON.
5. **UI Rendering:** Renders risk badge, evidence list, action checklist, and uncertainty disclaimers.

## 🚀 Environment Variables Setup

Configure the following variables in `.env.local` or Vercel:

\`\`\`bash
FEATHERLESS_API_KEY=your_featherless_api_key
FEATHERLESS_MODEL=Qwen/Qwen3-VL-8B-Instruct
\`\`\`
