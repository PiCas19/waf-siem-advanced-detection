import React, { useState } from 'react';

interface GeoLocationMarker {
  country: string;
  count: number;
  lat: number;
  lng: number;
  color: string;
}

interface WorldMapProps {
  data: GeoLocationMarker[];
  height?: number;
}

// Projection functions to convert lat/lng to SVG coordinates (Mercator projection)
const mercatorProjection = (lat: number, lng: number, width: number, height: number) => {
  const x = ((lng + 180) / 360) * width;
  const y = ((90 - lat) / 180) * height;
  return { x, y };
};

// Get circle radius based on attack count (respecting intensity legend)
const getMarkerRadius = (count: number): number => {
  if (count >= 50) return 12;
  if (count >= 20) return 10;
  if (count >= 10) return 8;
  return 6;
};

// Simplified SVG world map - basic continent outlines
const WorldMapSVG: React.FC<WorldMapProps> = ({ data, height = 400 }) => {
  const [hoveredCountry, setHoveredCountry] = useState<string | null>(null);
  const width = 800;

  // Basic continent paths (simplified for performance)
  // These are approximate polygons representing major continents/regions
  const continentPaths = [
    // North America
    { d: 'M 100,80 L 150,70 L 150,150 L 100,160 Z', name: 'North America' },
    // South America
    { d: 'M 140,160 L 160,160 L 170,260 L 140,270 Z', name: 'South America' },
    // Europe
    { d: 'M 330,60 L 370,60 L 380,100 L 330,100 Z', name: 'Europe' },
    // Africa
    { d: 'M 350,100 L 410,100 L 420,260 L 350,270 Z', name: 'Africa' },
    // Asia
    { d: 'M 380,60 L 520,50 L 530,150 L 380,160 Z', name: 'Asia' },
    // Australia
    { d: 'M 520,220 L 550,220 L 550,260 L 520,260 Z', name: 'Australia' },
  ];

  return (
    <div className="w-full h-full flex flex-col items-center justify-center bg-gray-900 rounded-lg">
      <svg
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className="border border-gray-700 rounded bg-gray-950"
      >
        {/* Background */}
        <rect width={width} height={height} fill="#111827" />

        {/* Continent backgrounds */}
        <g opacity="0.2">
          {continentPaths.map((path, idx) => (
            <path
              key={idx}
              d={path.d}
              fill="#3b82f6"
              stroke="#1f2937"
              strokeWidth="1"
            />
          ))}
        </g>

        {/* Grid lines (latitude/longitude) */}
        <g stroke="#374151" strokeWidth="0.5" opacity="0.3">
          {/* Vertical lines (longitude) */}
          {Array.from({ length: 13 }).map((_, i) => (
            <line
              key={`v-${i}`}
              x1={(i * width) / 12}
              y1="0"
              x2={(i * width) / 12}
              y2={height}
            />
          ))}
          {/* Horizontal lines (latitude) */}
          {Array.from({ length: 7 }).map((_, i) => (
            <line
              key={`h-${i}`}
              x1="0"
              y1={(i * height) / 6}
              x2={width}
              y2={(i * height) / 6}
            />
          ))}
        </g>

        {/* Country/Region labels */}
        <text x="125" y="120" fontSize="10" fill="#9ca3af" opacity="0.5" textAnchor="middle">
          Americas
        </text>
        <text x="360" y="140" fontSize="10" fill="#9ca3af" opacity="0.5" textAnchor="middle">
          Europe-Africa
        </text>
        <text x="450" y="120" fontSize="10" fill="#9ca3af" opacity="0.5" textAnchor="middle">
          Asia
        </text>
        <text x="535" y="240" fontSize="10" fill="#9ca3af" opacity="0.5" textAnchor="middle">
          Oceania
        </text>

        {/* Attack markers */}
        {data.map((marker, idx) => {
          const { x, y } = mercatorProjection(marker.lat, marker.lng, width, height);
          const radius = getMarkerRadius(marker.count);
          const isHovered = hoveredCountry === marker.country;

          return (
            <g key={idx}>
              {/* Outer circle (glow effect) */}
              <circle
                cx={x}
                cy={y}
                r={radius + 2}
                fill={marker.color}
                opacity={isHovered ? 0.6 : 0.3}
                onMouseEnter={() => setHoveredCountry(marker.country)}
                onMouseLeave={() => setHoveredCountry(null)}
                style={{ cursor: 'pointer', transition: 'all 0.2s' }}
              />
              {/* Main circle */}
              <circle
                cx={x}
                cy={y}
                r={radius}
                fill={marker.color}
                opacity={isHovered ? 1 : 0.8}
                stroke="#ffffff"
                strokeWidth={isHovered ? 2 : 1}
                onMouseEnter={() => setHoveredCountry(marker.country)}
                onMouseLeave={() => setHoveredCountry(null)}
                style={{ cursor: 'pointer', transition: 'all 0.2s' }}
              />
              {/* Tooltip on hover */}
              {isHovered && (
                <g>
                  <rect
                    x={x + 10}
                    y={y - 40}
                    width="140"
                    height="50"
                    fill="#1f2937"
                    stroke={marker.color}
                    strokeWidth="2"
                    rx="4"
                  />
                  <text
                    x={x + 80}
                    y={y - 20}
                    fontSize="12"
                    fontWeight="bold"
                    fill="#f3f4f6"
                    textAnchor="middle"
                  >
                    {marker.country}
                  </text>
                  <text
                    x={x + 80}
                    y={y - 5}
                    fontSize="11"
                    fill="#9ca3af"
                    textAnchor="middle"
                  >
                    Attacks: {marker.count}
                  </text>
                  <text
                    x={x + 80}
                    y={y + 10}
                    fontSize="10"
                    fill="#6b7280"
                    textAnchor="middle"
                  >
                    Lat: {marker.lat.toFixed(1)}, Lng: {marker.lng.toFixed(1)}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Equator and Prime Meridian lines */}
        <line
          x1="0"
          y1={height / 2}
          x2={width}
          y2={height / 2}
          stroke="#4b5563"
          strokeWidth="1"
          strokeDasharray="5,5"
          opacity="0.3"
        />
        <line
          x1={width / 2}
          y1="0"
          x2={width / 2}
          y2={height}
          stroke="#4b5563"
          strokeWidth="1"
          strokeDasharray="5,5"
          opacity="0.3"
        />
      </svg>

      {/* Legend */}
      <div className="mt-4 text-xs text-gray-400">
        <p className="text-center mb-2">Hover over markers for details • Colors represent attack intensity</p>
      </div>
    </div>
  );
};

export default WorldMapSVG;
