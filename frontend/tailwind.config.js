/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Manrope', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        ink: '#0a0f14',
        panel: '#10171f',
        panel2: '#151e28',
        line: '#24303b',
        cyan: '#65e4f2',
        mint: '#96edc6',
        amber: '#f4c979',
        coral: '#ff8b86',
      },
    },
  },
  plugins: [],
}
