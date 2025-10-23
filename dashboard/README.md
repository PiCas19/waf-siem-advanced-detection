# WAF Dashboard

React-based dashboard for managing and monitoring the Web Application Firewall.

## Features

- Real-time threat monitoring
- Custom rule management
- JWT-based authentication
- Attack statistics and trends
- IP blocklist management
- Log viewer with filtering

## Development

### Install dependencies
```bash
npm install
```

### Run development server
```bash
npm run dev
```

Dashboard will be available at `http://localhost:3000`

### Build for production
```bash
npm run build
```

### Preview production build
```bash
npm run preview
```

## Technology Stack

- **React 18** - UI framework
- **TypeScript** - Type safety
- **Vite** - Build tool
- **Tailwind CSS** - Styling
- **React Router** - Routing
- **Recharts** - Data visualization
- **Axios** - HTTP client

## Project Structure
```
dashboard/
├── src/
│   ├── components/     # React components
│   ├── services/       # API services
│   ├── hooks/          # Custom hooks
│   ├── context/        # React context
│   ├── types/          # TypeScript types
│   ├── utils/          # Utility functions
│   └── styles/         # Global styles
├── public/             # Static assets
└── dist/               # Build output
```

## Environment Variables

Create `.env` file:
```env
VITE_API_URL=http://localhost:8081
VITE_WS_URL=ws://localhost:8081/ws
```