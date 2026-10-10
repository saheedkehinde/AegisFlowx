import type { Metadata, Viewport } from 'next';
import './globals.css';

export const viewport: Viewport = {
  themeColor: '#0b0f19',
  width: 'device-width',
  initialScale: 1,
};

export const metadata: Metadata = {
  title: 'ScamShield AI — Think Before You Trust | ForgeHacks 2026',
  description:
    'AI-powered scam detection and threat advisory tool for ForgeHacks 2026. Uncover warning signs in suspicious messages and take safe action.',
  openGraph: {
    title: 'ScamShield AI — Think Before You Trust',
    description:
      'AI-powered scam detection and threat advisory tool for ForgeHacks 2026. Uncover warning signs in suspicious messages and take safe action.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'ScamShield AI — Think Before You Trust',
    description:
      'AI-powered scam detection and threat advisory tool for ForgeHacks 2026. Uncover warning signs in suspicious messages and take safe action.',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <body className="min-h-screen bg-[#070b14] text-slate-100 antialiased selection:bg-blue-500 selection:text-white" suppressHydrationWarning>
        {children}
      </body>
    </html>
  );
}
