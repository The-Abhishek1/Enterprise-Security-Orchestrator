/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: { DEFAULT: '#050510', 2: '#0a0a1f' },
        surface: 'rgba(15,15,35,0.7)',
        accent: { DEFAULT: '#6366f1', 2: '#818cf8', glow: 'rgba(99,102,241,0.12)' },
        border: { DEFAULT: 'rgba(255,255,255,0.06)', h: 'rgba(255,255,255,0.12)' },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      backdropBlur: { glass: '24px' },
      animation: { 'fade-up': 'fadeUp .35s ease both' },
      keyframes: { fadeUp: { from: { opacity: 0, transform: 'translateY(8px)' }, to: { opacity: 1, transform: 'translateY(0)' } } },
    },
  },
  plugins: [],
};
