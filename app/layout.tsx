import type { Metadata, Viewport } from 'next';
import './globals.css';

export const viewport: Viewport = {
  themeColor: '#070b14',
  width: 'device-width',
  initialScale: 1,
};

export const metadata: Metadata = {
  title: 'AegisFlow — AI Cybersecurity Intelligence & Automation Platform',
  description:
    'AegisFlow is an AI-powered cybersecurity intelligence and automation platform that helps people analyze suspicious content, investigate threats, share reports, learn digital safety, and coordinate protective actions.',
  openGraph: {
    title: 'AegisFlow — AI Cybersecurity Intelligence & Automation Platform',
    description:
      'AegisFlow is an AI-powered cybersecurity intelligence and automation platform that helps people analyze suspicious content, investigate threats, share reports, learn digital safety, and coordinate protective actions.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AegisFlow — AI Cybersecurity Intelligence & Automation Platform',
    description:
      'AegisFlow is an AI-powered cybersecurity intelligence and automation platform that helps people analyze suspicious content, investigate threats, share reports, learn digital safety, and coordinate protective actions.',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark scroll-smooth">
      <body
        className="min-h-screen bg-[#070b14] text-slate-100 antialiased selection:bg-cyan-600 selection:text-white"
        suppressHydrationWarning
      >
        {children}
      </body>
    </html>
  );
}
