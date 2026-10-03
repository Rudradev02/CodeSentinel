/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', '"Segoe UI"', 'Roboto', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
      },
      colors: {
        sentinel: {
          50: '#f0fdf4',
          100: '#dcfce7',
          500: '#22c55e',
          600: '#16a34a',
          700: '#15803d',
          800: '#166534',
          900: '#14532d',
          950: '#052e16',
        },
        dark: {
          base: '#080C14',
          surface: '#0E1524',
          elevated: '#131C2E',
          card: '#111827',
          border: '#1E293B',
          borderSubtle: 'rgba(30, 41, 59, 0.6)',
        },
      },
      keyframes: {
        scanline: {
          '0%': { transform: 'translateY(-100%)', opacity: '0' },
          '15%': { opacity: '0.7' },
          '85%': { opacity: '0.7' },
          '100%': { transform: 'translateY(800%)', opacity: '0' },
        },
        fadeInUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideInRight: {
          '0%': { opacity: '0', transform: 'translateX(-8px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        progressFill: {
          '0%': { width: '0%' },
          '100%': { width: 'var(--progress-target, 100%)' },
        },
        countUp: {
          '0%': { opacity: '0', transform: 'translateY(4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 8px rgba(6, 182, 212, 0.15)' },
          '50%': { boxShadow: '0 0 16px rgba(6, 182, 212, 0.3)' },
        },
      },
      animation: {
        'scanline': 'scanline 3.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in-up': 'fadeInUp 0.4s cubic-bezier(0.16, 1, 0.3, 1) both',
        'fade-in': 'fadeIn 0.3s ease-out both',
        'slide-in-right': 'slideInRight 0.35s cubic-bezier(0.16, 1, 0.3, 1) both',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'progress-fill': 'progressFill 0.8s cubic-bezier(0.16, 1, 0.3, 1) both',
        'count-up': 'countUp 0.4s cubic-bezier(0.16, 1, 0.3, 1) both',
        'glow-pulse': 'glowPulse 2s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
