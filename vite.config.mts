import path from 'node:path'

import legacy from '@vitejs/plugin-legacy'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import svgr from 'vite-plugin-svgr'

export default defineConfig({
  root: 'src',
  server: { port: 3000 },
  plugins: [
    svgr(),
    react({
      babel: {
        plugins: ['babel-plugin-react-compiler'],
      },
    } as any),
    legacy({
      modernTargets: ['edge>=109', 'safari>=14'],
      renderLegacyChunks: false,
      modernPolyfills: ['es.object.has-own', 'web.structured-clone'],
      additionalModernPolyfills: [
        path.resolve('./src/polyfills/matchMedia.js'),
        path.resolve('./src/polyfills/WeakRef.js'),
        path.resolve('./src/polyfills/RegExp.js'),
      ],
    }),
  ],
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    chunkSizeWarningLimit: 4000,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('monaco-yaml')) return 'monaco-yaml'
          if (
            id.includes('node_modules/react/') ||
            id.includes('node_modules/react-dom/')
          )
            return 'react'
          if (id.includes('node_modules/react-router')) return 'router'
          if (
            id.includes('node_modules/i18next') ||
            id.includes('node_modules/react-i18next')
          )
            return 'i18n'
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve('./src'),
      '@root': path.resolve('.'),
    },
  },
  define: {
    OS_PLATFORM: `"${process.platform}"`,
  },
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'i18next',
      'react-i18next',
    ],
  },
})
