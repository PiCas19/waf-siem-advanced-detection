const express = require('express');
const path = require('path');
const app = express();
const PORT = 3001;

// Static files PRIMA di tutto
app.use(express.static('public'));

// Serve index.html per root path
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Health check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        service: 'industrial', 
        timestamp: new Date().toISOString() 
    });
});

// API mock data - PLC Status
app.get('/api/plc-status', (req, res) => {
    res.json({
        plc_units: [
            { id: 'PLC-001', location: 'Production Line A', status: 'ONLINE', cpu_load: 34, temp: 42 },
            { id: 'PLC-002', location: 'Production Line B', status: 'ONLINE', cpu_load: 67, temp: 48 },
            { id: 'PLC-003', location: 'Warehouse', status: 'WARNING', cpu_load: 89, temp: 56 },
            { id: 'PLC-004', location: 'Quality Control', status: 'ONLINE', cpu_load: 45, temp: 41 }
        ]
    });
});

// API mock data - Protocols
app.get('/api/protocols', (req, res) => {
    res.json({
        active_protocols: [
            { name: 'Modbus TCP', port: 502, connections: 12, status: 'ACTIVE' },
            { name: 'DNP3', port: 20000, connections: 8, status: 'ACTIVE' },
            { name: 'OPC UA', port: 4840, connections: 15, status: 'ACTIVE' },
            { name: 'MQTT', port: 1883, connections: 23, status: 'ACTIVE' }
        ]
    });
});

// API mock data - Sensors
app.get('/api/sensors', (req, res) => {
    res.json({
        readings: [
            { sensor: 'TEMP-01', value: 72.5, unit: '°F', status: 'NORMAL' },
            { sensor: 'PRESS-01', value: 145.2, unit: 'PSI', status: 'NORMAL' },
            { sensor: 'FLOW-01', value: 89.7, unit: 'GPM', status: 'WARNING' },
            { sensor: 'VIBR-01', value: 2.1, unit: 'mm/s', status: 'NORMAL' }
        ]
    });
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Industrial Server running on http://0.0.0.0:${PORT}`);
});