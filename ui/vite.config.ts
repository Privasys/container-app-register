import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Local development: the register runs with REGISTER_DEV_AUTH=1 on :8080
// and the dev server proxies the API and the runtime configuration to it.
export default defineConfig({
    plugins: [react()],
    publicDir: '.public',
    build: { outDir: 'dist', assetsDir: 'assets', sourcemap: false },
    server: {
        port: 5173,
        proxy: {
            '/api': { target: 'http://localhost:8080' },
            '/app-config.js': { target: 'http://localhost:8080' }
        }
    }
});
