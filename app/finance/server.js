const express = require('express');

const app = express();
const PORT = 3000;

// Static files PRIMA di tutto
app.use(express.static('public'));

// Health check - both direct and proxy paths
app.get('/health', (req, res) => {
    res.json({ status: 'healthy', service: 'finance', timestamp: new Date().toISOString() });
});

app.get('/finance/health', (req, res) => {
    res.json({ status: 'healthy', service: 'finance', timestamp: new Date().toISOString() });
});

// API mock data - Portfolio
app.get('/api/portfolio', (req, res) => {
    res.json({
        total_value: 2847500.00,
        daily_change: +12450.50,
        daily_change_percent: +0.44,
        assets: [
            { symbol: 'AAPL', shares: 500, value: 85000, change: +2.1 },
            { symbol: 'GOOGL', shares: 200, value: 68000, change: -0.8 },
            { symbol: 'MSFT', shares: 300, value: 102000, change: +1.5 },
            { symbol: 'TSLA', shares: 150, value: 45000, change: +3.2 }
        ]
    });
});

app.get('/finance/api/portfolio', (req, res) => {
    res.json({
        total_value: 2847500.00,
        daily_change: +12450.50,
        daily_change_percent: +0.44,
        assets: [
            { symbol: 'AAPL', shares: 500, value: 85000, change: +2.1 },
            { symbol: 'GOOGL', shares: 200, value: 68000, change: -0.8 },
            { symbol: 'MSFT', shares: 300, value: 102000, change: +1.5 },
            { symbol: 'TSLA', shares: 150, value: 45000, change: +3.2 }
        ]
    });
});

// API mock data - Transactions
app.get('/api/transactions', (req, res) => {
    res.json({
        recent: [
            { date: '2025-11-26', type: 'BUY', symbol: 'AAPL', amount: 50, price: 170.00 },
            { date: '2025-11-25', type: 'SELL', symbol: 'TSLA', amount: 20, price: 300.00 },
            { date: '2025-11-24', type: 'BUY', symbol: 'MSFT', amount: 100, price: 340.00 }
        ]
    });
});

app.get('/finance/api/transactions', (req, res) => {
    res.json({
        recent: [
            { date: '2025-11-26', type: 'BUY', symbol: 'AAPL', amount: 50, price: 170.00 },
            { date: '2025-11-25', type: 'SELL', symbol: 'TSLA', amount: 20, price: 300.00 },
            { date: '2025-11-24', type: 'BUY', symbol: 'MSFT', amount: 100, price: 340.00 }
        ]
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Finance Server running on http://0.0.0.0:${PORT}`);
});