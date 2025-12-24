# WAF Dashboard

Enterprise-grade React dashboard for comprehensive Web Application Firewall management, real-time threat monitoring, and security analytics.

## Features

### 🛡️ Security Monitoring
- **Real-time Threat Dashboard** - Live statistics, attack trends, and security metrics
- **Attack Trends Analysis** - Historical data visualization with Recharts
- **Geographic Threat Map** - World map showing attack origins with OpenLayers
- **Live Alerts** - Real-time WebSocket notifications for security events
- **Security Logs Viewer** - Advanced filtering, search, and log details

### 🔧 WAF Management
- **Custom Rules** - Create, edit, and test regex-based detection rules
- **Default Rules** - Manage 100+ built-in threat detection rules
- **Rule Testing** - Test rules against sample payloads before deployment
- **IP Blocklist** - Block malicious IPs with reason tracking and history
- **Block History** - Track IP blocking timeline and actions

### 📊 Analytics & Reporting
- **Dashboard Statistics** - Total attacks, blocked requests, top threats
- **Attack Type Breakdown** - Pie charts and bar graphs for threat categories
- **Export Functionality** - Export logs in JSON, CSV, and PDF formats
- **Trend Analysis** - Identify attack patterns over time

### 👤 User Management & Authentication
- **JWT Authentication** - Secure token-based authentication
- **User Registration** - Account creation with email verification
- **Login System** - Secure login with session management
- **Two-Factor Authentication (2FA)** - OTP support with QR code generation
- **Password Management** - Forgot password and reset functionality
- **User Profile** - Profile settings and account management
- **Admin Panel** - User management for administrators
- **Role-Based Access Control** - Permission gates for different user roles

### 🎨 User Experience
- **Responsive Design** - Mobile-friendly Tailwind CSS interface
- **Dark/Light Theme** - Theme switching support
- **Toast Notifications** - User feedback with Snackbar system
- **Loading States** - Skeleton loaders and progress indicators
- **Error Handling** - Comprehensive error boundaries and messages

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
# TypeScript compile and production build
npm run build
```

Build output will be in the `dist/` directory.

### Preview production build
```bash
npm run preview
```

### Code quality
```bash
# Run ESLint
npm run lint
```

## Testing

### Unit & Integration Tests (Vitest)

```bash
# Run tests in watch mode
npm test

# Run tests once
npm run test:run

# Run tests with UI
npm run test:ui

# Generate coverage report
npm run test:coverage
```

### End-to-End Tests (Cypress)

```bash
# Open Cypress UI
npm run cypress:open

# Run Cypress tests headless
npm run cypress:run

# Run E2E tests with dev server (recommended)
npm run test:e2e

# Open E2E tests in interactive mode
npm run test:e2e:open

# Run E2E tests in headed mode
npm run test:e2e:headed
```

### Run All Tests

```bash
# Run unit tests + E2E tests
npm run test:all
```

## Technology Stack

### Core Framework
- **React 18** - Modern UI framework with hooks
- **TypeScript** - Type-safe development
- **Vite** - Lightning-fast build tool and dev server

### Styling & UI
- **Tailwind CSS** - Utility-first CSS framework
- **Lucide React** - Beautiful icon library
- **Responsive Design** - Mobile-first approach

### State Management & Data Fetching
- **TanStack React Query** - Server state management and caching
- **Zustand** - Lightweight client state management
- **React Context** - Auth and Snackbar context providers

### Routing & Navigation
- **React Router v6** - Client-side routing and navigation

### Data Visualization
- **Recharts** - Composable charting library (line, bar, pie charts)
- **OpenLayers (ol)** - Interactive world map for geographic threat visualization

### Authentication & Security
- **JWT** - Token-based authentication
- **QRCode** - 2FA QR code generation
- **Axios** - HTTP client with interceptors for auth

### Testing
- **Vitest** - Unit and integration testing framework
- **Cypress** - End-to-end testing
- **Testing Library** - React component testing utilities
- **Happy DOM / JSDOM** - DOM environment for tests

### Development Tools
- **ESLint** - Code linting
- **TypeScript ESLint** - TypeScript-specific linting
- **PostCSS** - CSS processing
- **Autoprefixer** - CSS vendor prefixing

## Project Structure
```
dashboard/
├── src/
│   ├── components/           # React components
│   │   ├── admin/            # Admin panel components (Users)
│   │   ├── auth/             # Authentication (Login, Register, 2FA, Profile, Settings)
│   │   ├── blocklist/        # IP blocklist management
│   │   ├── common/           # Shared components (Navbar, Sidebar, Card, Chart, Snackbar)
│   │   ├── logs/             # Security logs viewer and filters
│   │   ├── rules/            # WAF rules management and testing
│   │   ├── stats/            # Dashboard statistics and analytics
│   │   └── __tests__/        # Component unit tests
│   ├── contexts/             # React Context providers
│   │   ├── AuthContext.tsx   # Authentication state
│   │   └── SnackbarContext.tsx # Toast notifications
│   ├── services/             # API service layer
│   │   └── api.ts            # Axios client and API methods
│   ├── hooks/                # Custom React hooks
│   ├── types/                # TypeScript type definitions
│   ├── utils/                # Utility functions
│   ├── test/                 # Test utilities and setup
│   ├── App.tsx               # Main application component
│   └── main.tsx              # Application entry point
├── cypress/                  # E2E tests
│   ├── e2e/                  # Test specs
│   ├── fixtures/             # Test data
│   └── support/              # Cypress support files
├── public/                   # Static assets
├── dist/                     # Production build output
├── cypress.config.ts         # Cypress configuration
├── vite.config.ts            # Vite configuration
├── vitest.config.ts          # Vitest configuration
├── tailwind.config.js        # Tailwind CSS configuration
└── tsconfig.json             # TypeScript configuration
```

## Environment Variables

Create a `.env` file in the dashboard root directory:

```env
# API Backend URL
VITE_API_URL=http://localhost:8081

# WebSocket URL for real-time alerts
VITE_WS_URL=ws://localhost:8081/ws

# Optional: Enable debug mode
VITE_DEBUG=false
```

**Production Example:**
```env
VITE_API_URL=https://api.yourwaf.com
VITE_WS_URL=wss://api.yourwaf.com/ws
VITE_DEBUG=false
```

## Application Routes

| Route | Component | Description | Protected |
|-------|-----------|-------------|-----------|
| `/login` | Login | User login page | No |
| `/register` | Register | User registration | No |
| `/forgot-password` | ForgotPassword | Password reset request | No |
| `/set-password` | SetPassword | Password reset form | No |
| `/` | Dashboard | Main dashboard | Yes |
| `/stats` | StatsPage | Detailed statistics | Yes |
| `/rules` | RulesContainer | Custom rules management | Yes |
| `/logs` | LogsPage | Security logs viewer | Yes |
| `/blocklist` | BlocklistPage | IP blocklist management | Yes |
| `/profile` | Profile | User profile | Yes |
| `/settings` | Settings | User settings | Yes |
| `/admin/users` | Users | User management | Admin only |

## API Integration

The dashboard communicates with the backend API using Axios with the following setup:

### API Service (`src/services/api.ts`)
- Base URL from `VITE_API_URL` environment variable
- JWT token automatically attached to requests via interceptors
- Automatic token refresh on 401 responses
- Request/response interceptors for error handling

### WebSocket Connection
- Real-time alerts via WebSocket connection
- Automatic reconnection on disconnect
- Live threat notifications
- Attack trend updates

### Example API Calls
```typescript
import api from '@/services/api';

// Fetch dashboard stats
const stats = await api.get('/api/stats');

// Create custom rule
await api.post('/api/rules', {
  name: 'Block SQL Injection',
  pattern: '(union|select|insert|update|delete)',
  severity: 'high'
});

// Block an IP
await api.post('/api/blocklist', {
  ip: '192.168.1.100',
  reason: 'Repeated XSS attempts'
});
```

## Development Guidelines

### Component Organization
- **Presentational Components**: In `components/` subdirectories
- **Container Components**: Manage state and API calls
- **Shared Components**: In `components/common/`
- **Page Components**: Top-level route components

### State Management Strategy
- **Server State**: TanStack React Query for caching and synchronization
- **Client State**: Zustand for lightweight state
- **Context**: Authentication and global UI state (snackbar)

### Testing Strategy
- **Unit Tests**: Component logic and utilities (Vitest)
- **Integration Tests**: Component interaction (Testing Library)
- **E2E Tests**: User flows and critical paths (Cypress)
- **Coverage Goal**: >80% for critical components

### Code Standards
- TypeScript strict mode enabled
- ESLint for code quality
- Functional components with hooks
- Proper error boundaries
- Accessibility (a11y) considerations

## Deployment

### Production Build

```bash
# Build the application
npm run build

# Output will be in dist/ directory
```

### Serve with Caddy

Example `Caddyfile` configuration:

```caddy
dashboard.yourwaf.com {
    root * /var/www/dashboard/dist
    file_server

    # SPA fallback - serve index.html for all routes
    try_files {path} /index.html

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    # Enable compression
    encode gzip
}
```

### Serve with Nginx

Example Nginx configuration:

```nginx
server {
    listen 80;
    server_name dashboard.yourwaf.com;
    root /var/www/dashboard/dist;
    index index.html;

    # SPA fallback
    location / {
        try_files $uri $uri/ /index.html;
    }

    # Security headers
    add_header X-Frame-Options "DENY";
    add_header X-Content-Type-Options "nosniff";

    # Enable gzip
    gzip on;
    gzip_types text/css application/javascript application/json;
}
```

### Docker Deployment

```dockerfile
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## Troubleshooting

### Common Issues

**API connection errors**
- Verify `VITE_API_URL` is correctly set
- Check that API backend is running on the specified port
- Ensure CORS is configured on the API backend

**WebSocket connection fails**
- Check `VITE_WS_URL` uses correct protocol (`ws://` or `wss://`)
- Verify WebSocket endpoint is accessible
- Check for proxy/firewall blocking WebSocket connections

**Build errors**
- Clear `node_modules` and reinstall: `rm -rf node_modules && npm install`
- Clear Vite cache: `rm -rf node_modules/.vite`
- Ensure Node.js version is 18 or higher

**TypeScript errors**
- Run type checking: `npx tsc --noEmit`
- Check `tsconfig.json` settings
- Ensure all dependencies have type definitions

**Tests failing**
- Clear test cache: `npm test -- --clearCache`
- Check test environment variables
- Verify mock data matches API responses

## Performance Optimization

### Implemented Optimizations
- **Code Splitting**: React Router lazy loading
- **Memoization**: React.memo for expensive components
- **Query Caching**: TanStack React Query cache configuration
- **Bundle Optimization**: Vite automatic code splitting
- **Image Optimization**: WebP format for images
- **Tree Shaking**: Automatic unused code elimination

### Best Practices
- Use React Query for server state (automatic caching)
- Implement virtual scrolling for large lists
- Lazy load routes and components
- Optimize chart rendering with proper keys
- Debounce search inputs

## Security Considerations

- **XSS Protection**: React's built-in escaping
- **CSRF**: CSRF tokens in forms (if needed)
- **Secure Storage**: JWT tokens in httpOnly cookies (if implemented) or localStorage with caution
- **HTTPS Only**: Production must use HTTPS
- **Content Security Policy**: Configure CSP headers on server
- **Dependency Audits**: Run `npm audit` regularly

## Browser Support

- Chrome/Edge (latest 2 versions)
- Firefox (latest 2 versions)
- Safari (latest 2 versions)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Contributing

### Adding New Features

1. Create feature branch: `git checkout -b feature/new-feature`
2. Add components in appropriate directory
3. Write unit tests for logic
4. Add E2E tests for user flows
5. Update this README if needed
6. Submit pull request

### Code Review Checklist
- [ ] TypeScript types defined
- [ ] Unit tests added
- [ ] E2E tests for critical paths
- [ ] No console errors or warnings
- [ ] Responsive design tested
- [ ] Accessibility checked
- [ ] Performance verified

## License

Part of the WAF-SIEM Advanced Detection project. See main [LICENSE](../LICENSE) file.