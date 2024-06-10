import type { Config } from 'tailwindcss'

const config: Config = {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        orange: {
          950: '#FF6C15',
        },
      },
      gridTemplateColumns: {
        '3-column-layout': '1fr 680px 1fr',
      },
    },
  },
}
export default config
