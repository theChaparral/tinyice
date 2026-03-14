import { defineConfig } from 'vite'
import preact from '@preact/preset-vite'
import tailwindcss from '@tailwindcss/vite'
import { resolve } from 'path'

export default defineConfig({
  plugins: [preact(), tailwindcss()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        landing: resolve(__dirname, 'src/entries/landing.html'),
        player: resolve(__dirname, 'src/entries/player.html'),
        explore: resolve(__dirname, 'src/entries/explore.html'),
        embed: resolve(__dirname, 'src/entries/embed.html'),
        developers: resolve(__dirname, 'src/entries/developers.html'),
        login: resolve(__dirname, 'src/entries/login.html'),
        admin: resolve(__dirname, 'src/entries/admin.html'),
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
      '/admin/events': 'http://localhost:8000',
      '/events': 'http://localhost:8000',
      '/webrtc': 'http://localhost:8000',
    },
  },
})
