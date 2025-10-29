import React, { useEffect, useRef } from 'react';
import Map from 'ol/Map';
import View from 'ol/View';
import TileLayer from 'ol/layer/Tile';
import VectorLayer from 'ol/layer/Vector';
import VectorSource from 'ol/source/Vector';
import OSM from 'ol/source/OSM';
import Feature from 'ol/Feature';
import Point from 'ol/geom/Point';
import { fromLonLat } from 'ol/proj';
import Style from 'ol/style/Style';
import CircleStyle from 'ol/style/Circle';
import Fill from 'ol/style/Fill';
import Stroke from 'ol/style/Stroke';
import Text from 'ol/style/Text';
import Overlay from 'ol/Overlay';
import 'ol/ol.css';

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

const WorldMapOL: React.FC<WorldMapProps> = ({ data, height = 400 }) => {
  const mapContainer = useRef<HTMLDivElement>(null);
  const mapInstance = useRef<Map | null>(null);

  useEffect(() => {
    if (!mapContainer.current) return;

    // Create vector source and layer for attack markers
    const vectorSource = new VectorSource();

    // Add features for each attack location
    data.forEach((marker) => {
      const feature = new Feature({
        geometry: new Point(fromLonLat([marker.lng, marker.lat])),
        country: marker.country,
        count: marker.count,
        color: marker.color,
      });

      // Calculate radius based on attack count - LARGER for better visibility
      const radius = marker.count >= 50 ? 20 : marker.count >= 20 ? 16 : marker.count >= 10 ? 13 : 10;

      // Style with color from intensity legend
      feature.setStyle(
        new Style({
          image: new CircleStyle({
            radius: radius,
            fill: new Fill({ color: marker.color }),
            stroke: new Stroke({ color: '#ffffff', width: 2 }),
          }),
          text: new Text({
            text: marker.count.toString(),
            font: 'bold 14px Arial',
            fill: new Fill({ color: '#ffffff' }),
            offsetY: 0,
            textAlign: 'center',
            textBaseline: 'middle',
          }),
        })
      );

      vectorSource.addFeature(feature);
    });

    const vectorLayer = new VectorLayer({
      source: vectorSource,
    });

    // Create popup overlay
    const popupContainer = document.createElement('div');
    popupContainer.className = 'ol-popup';
    popupContainer.style.position = 'absolute';
    popupContainer.style.backgroundColor = 'rgba(31, 41, 55, 0.95)';
    popupContainer.style.borderRadius = '8px';
    popupContainer.style.padding = '12px';
    popupContainer.style.border = '2px solid rgba(107, 114, 128, 1)';
    popupContainer.style.color = '#f3f4f6';
    popupContainer.style.fontSize = '12px';
    popupContainer.style.zIndex = '1000';
    popupContainer.style.minWidth = '150px';
    popupContainer.style.display = 'none';

    const popup = new Overlay({
      element: popupContainer,
      autoPan: false, // Don't pan map when showing tooltip
    });

    // Initialize map
    const map = new Map({
      target: mapContainer.current,
      layers: [
        new TileLayer({
          source: new OSM(),
        }),
        vectorLayer,
      ],
      overlays: [popup],
      view: new View({
        center: fromLonLat([0, 20]),
        zoom: 2,
        projection: 'EPSG:3857',
      }),
    });

    mapInstance.current = map;

    // Handle pointer move (hover) events
    map.on('pointermove', (evt) => {
      const pixel = map.getEventPixel(evt.originalEvent);
      const hit = map.hasFeatureAtPixel(pixel);

      if (hit) {
        map.getViewport().style.cursor = 'pointer';

        // Get hovered feature
        const feature = map.forEachFeatureAtPixel(pixel, (feat) => {
          return feat;
        });

        if (feature) {
          const country = feature.get('country');
          const count = feature.get('count');
          const geometry = feature.getGeometry();
          const color = feature.get('color');

          if (geometry && geometry instanceof Point) {
            const coords = geometry.getCoordinates();
            popup.setPosition(coords);

            const content = `
              <div style="text-align: center;">
                <p style="margin: 0 0 4px 0; font-weight: bold; color: ${color};">${country}</p>
                <p style="margin: 0 0 4px 0; color: #9ca3af;">Attacks: ${count}</p>
                <p style="margin: 0; font-size: 10px; color: #6b7280;">
                  Lat: ${coords[1].toFixed(2)}<br/>
                  Lng: ${coords[0].toFixed(2)}
                </p>
              </div>
            `;
            popupContainer.innerHTML = content;
            popupContainer.style.display = 'block';
          }
        }
      } else {
        map.getViewport().style.cursor = 'grab';
        popupContainer.style.display = 'none';
      }
    });

    // Cleanup
    return () => {
      if (mapInstance.current) {
        mapInstance.current.setTarget(undefined);
      }
    };
  }, [data]);

  return (
    <div
      ref={mapContainer}
      style={{
        width: '100%',
        height: `${height}px`,
        borderRadius: '8px',
        overflow: 'hidden',
        border: '1px solid #374151',
      }}
      className="ol-map-container"
    />
  );
};

export default WorldMapOL;
