import { defineConfig } from 'vite';

const csp = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "object-src 'none'",
].join('; ');

// Production-only CSP: Vite's development server injects styles and uses HMR.
export default defineConfig(({ command }) => ({
  base: command === 'build' ? '/pqc-vault-enterprise/' : '/',
  plugins: [{
    name: 'production-csp',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace('<head>', '<head>\n    <meta http-equiv="Content-Security-Policy" content="' + csp + '">');
    },
  }],
}));
