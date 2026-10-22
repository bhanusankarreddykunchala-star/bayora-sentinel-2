/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bayora: {
          950: '#070d1b',
          900: '#0b1322',
          800: '#101b2f',
          700: '#17314a',
          600: '#1c4a7a',
          500: '#2f7ce0',
          400: '#53d5ff',
          300: '#8fb4ff',
        },
      },
      boxShadow: {
        glow: '0 0 0 1px rgba(110, 168, 255, 0.2), 0 20px 50px rgba(19, 31, 53, 0.6)',
      },
    },
  },
  plugins: [],
};
