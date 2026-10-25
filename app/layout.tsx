import type { Metadata, Viewport } from 'next';
import { Space_Grotesk, Inter, IBM_Plex_Mono } from 'next/font/google';
import './globals.css';
import { ThemeProvider } from '@/lib/theme-context';

const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-sans',
});

const spaceGrotesk = Space_Grotesk({
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-display',
});

const ibmPlexMono = IBM_Plex_Mono({
  weight: ['400', '500', '600', '700'],
  subsets: ['latin'],
  display: 'swap',
  variable: '--font-mono',
});

export const viewport: Viewport = {
  themeColor: '#080B12',
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
    <html
      lang="en"
      className={`dark scroll-smooth ${inter.variable} ${spaceGrotesk.variable} ${ibmPlexMono.variable}`}
      data-theme="dark"
      suppressHydrationWarning
    >
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var stored = localStorage.getItem('aegisflow_theme');
                  var isDark = stored === 'dark' || (!stored && window.matchMedia('(prefers-color-scheme: dark)').matches) || !stored;
                  if (stored === 'light') isDark = false;
                  var root = document.documentElement;
                  if (isDark) {
                    root.classList.add('dark');
                    root.classList.remove('light');
                    root.setAttribute('data-theme', 'dark');
                  } else {
                    root.classList.add('light');
                    root.classList.remove('dark');
                    root.setAttribute('data-theme', 'light');
                  }
                } catch (e) {}
              })();
            `,
          }}
        />
      </head>
      <body
        className="min-h-screen bg-[var(--background)] text-[var(--foreground)] antialiased selection:bg-[var(--primary-orange)] selection:text-white transition-colors duration-200"
        suppressHydrationWarning
      >
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
