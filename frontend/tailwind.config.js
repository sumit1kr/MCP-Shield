/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: '#0B0D10',
        surface: '#14171A',
        'surface-2': '#1A1E22',
        border: '#252A31',
        
        'text-primary': '#F5F7FA',
        'text-secondary': '#9CA3AF',
        'text-muted': '#6B7280',
        
        primary: '#3B82F6',
        'primary-hover': '#2563EB',
        
        critical: '#DC2626',
        high: '#D97706',
        medium: '#D97706',
        low: '#65A30D',
        safe: '#16A34A',
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '6px',
        md: '6px',
        lg: '6px',
        xl: '6px',
        '2xl': '6px',
      },
      spacing: {
        '2': '8px',
        '4': '16px',
        '6': '24px',
        '8': '32px',
        '12': '48px',
      }
    },
  },
  plugins: [],
}
