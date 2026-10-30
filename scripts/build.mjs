import { spawnSync } from 'node:child_process';

// Ensure NODE_ENV is explicitly set to production across all operating systems
// (Windows cmd/PowerShell, Linux, macOS, Vercel, and CI/CD containers)
// without introducing external dependencies like cross-env.
const isWindows = process.platform === 'win32';
const execCmd = isWindows ? 'npx.cmd' : 'npx';

const env = { ...process.env, NODE_ENV: 'production' };

const result = spawnSync(execCmd, ['next', 'build'], {
  env,
  stdio: 'inherit',
  shell: isWindows,
});

process.exit(result.status ?? (result.error ? 1 : 0));
