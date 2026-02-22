import { useEffect, useRef, useCallback, useState } from "react";
import { MapView } from "@/components/Map";

/** Country centroid coordinates for geo-threat mapping */
const COUNTRY_COORDS: Record<string, { lat: number; lng: number }> = {
  "United States": { lat: 39.8283, lng: -98.5795 },
  "China": { lat: 35.8617, lng: 104.1954 },
  "Russia": { lat: 61.524, lng: 105.3188 },
  "Germany": { lat: 51.1657, lng: 10.4515 },
  "Brazil": { lat: -14.235, lng: -51.9253 },
  "India": { lat: 20.5937, lng: 78.9629 },
  "Netherlands": { lat: 52.1326, lng: 5.2913 },
  "South Korea": { lat: 35.9078, lng: 127.7669 },
  "United Kingdom": { lat: 55.3781, lng: -3.436 },
  "France": { lat: 46.2276, lng: 2.2137 },
  "Japan": { lat: 36.2048, lng: 138.2529 },
  "Australia": { lat: -25.2744, lng: 133.7751 },
  "Canada": { lat: 56.1304, lng: -106.3468 },
  "Iran": { lat: 32.4279, lng: 53.688 },
  "North Korea": { lat: 40.3399, lng: 127.5101 },
  "Ukraine": { lat: 48.3794, lng: 31.1656 },
  "Turkey": { lat: 38.9637, lng: 35.2433 },
  "Israel": { lat: 31.0461, lng: 34.8516 },
  "Vietnam": { lat: 14.0583, lng: 108.2772 },
  "Indonesia": { lat: -0.7893, lng: 113.9213 },
  "Mexico": { lat: 23.6345, lng: -102.5528 },
  "Pakistan": { lat: 30.3753, lng: 69.3451 },
  "Nigeria": { lat: 9.082, lng: 8.6753 },
  "South Africa": { lat: -30.5595, lng: 22.9375 },
  "Egypt": { lat: 26.8206, lng: 30.8025 },
  "Romania": { lat: 45.9432, lng: 24.9668 },
  "Poland": { lat: 51.9194, lng: 19.1451 },
  "Italy": { lat: 41.8719, lng: 12.5674 },
  "Spain": { lat: 40.4637, lng: -3.7492 },
  "Sweden": { lat: 60.1282, lng: 18.6435 },
  "Argentina": { lat: -38.4161, lng: -63.6167 },
  "Colombia": { lat: 4.5709, lng: -74.2973 },
  "Thailand": { lat: 15.87, lng: 100.9925 },
  "Singapore": { lat: 1.3521, lng: 103.8198 },
  "Malaysia": { lat: 4.2105, lng: 101.9758 },
  "Philippines": { lat: 12.8797, lng: 121.774 },
  "Bangladesh": { lat: 23.685, lng: 90.3563 },
  "Saudi Arabia": { lat: 23.8859, lng: 45.0792 },
  "UAE": { lat: 23.4241, lng: 53.8478 },
  "Taiwan": { lat: 23.6978, lng: 120.9605 },
};

/** Threat level to OKLCH color mapping (matches Amethyst Nexus) */
function getThreatColor(avgLevel: number): string {
  if (avgLevel >= 10) return "oklch(0.637 0.237 15.0)";   // critical red
  if (avgLevel >= 8)  return "oklch(0.705 0.213 41.0)";   // high orange
  if (avgLevel >= 6)  return "oklch(0.795 0.184 86.0)";   // medium yellow
  if (avgLevel >= 4)  return "oklch(0.541 0.281 293.009)"; // low purple
  return "oklch(0.789 0.154 211.53)";                      // info cyan
}

function getThreatColorHex(avgLevel: number): string {
  if (avgLevel >= 10) return "#ef4444";
  if (avgLevel >= 8)  return "#f97316";
  if (avgLevel >= 6)  return "#eab308";
  if (avgLevel >= 4)  return "#a855f7";
  return "#06b6d4";
}

function getThreatLabel(avgLevel: number): string {
  if (avgLevel >= 10) return "Critical";
  if (avgLevel >= 8)  return "High";
  if (avgLevel >= 6)  return "Medium";
  if (avgLevel >= 4)  return "Low";
  return "Info";
}

/** Dark-mode map styling for Amethyst Nexus theme */
const DARK_MAP_STYLES: google.maps.MapTypeStyle[] = [
  { elementType: "geometry", stylers: [{ color: "#0f0a1a" }] },
  { elementType: "labels.text.stroke", stylers: [{ color: "#0f0a1a" }] },
  { elementType: "labels.text.fill", stylers: [{ color: "#6b5b8a" }] },
  { featureType: "administrative.country", elementType: "geometry.stroke", stylers: [{ color: "#2d1f4e" }] },
  { featureType: "administrative.country", elementType: "labels.text.fill", stylers: [{ color: "#7c6b9a" }] },
  { featureType: "administrative.province", elementType: "geometry.stroke", stylers: [{ color: "#1a1030" }] },
  { featureType: "water", elementType: "geometry", stylers: [{ color: "#080510" }] },
  { featureType: "water", elementType: "labels.text.fill", stylers: [{ color: "#3a2d5c" }] },
  { featureType: "landscape", elementType: "geometry", stylers: [{ color: "#0f0a1a" }] },
  { featureType: "road", stylers: [{ visibility: "off" }] },
  { featureType: "transit", stylers: [{ visibility: "off" }] },
  { featureType: "poi", stylers: [{ visibility: "off" }] },
];

interface ThreatGeoData {
  country: string;
  count: number;
  avgLevel: number;
}

interface ThreatMapProps {
  data: ThreatGeoData[];
  className?: string;
}

export function ThreatMap({ data, className }: ThreatMapProps) {
  const mapRef = useRef<google.maps.Map | null>(null);
  const circlesRef = useRef<google.maps.Circle[]>([]);
  const infoWindowRef = useRef<google.maps.InfoWindow | null>(null);
  const [mapReady, setMapReady] = useState(false);

  const clearOverlays = useCallback(() => {
    circlesRef.current.forEach(c => c.setMap(null));
    circlesRef.current = [];
    if (infoWindowRef.current) {
      infoWindowRef.current.close();
    }
  }, []);

  /** Draw threat circles when data or map changes */
  useEffect(() => {
    if (!mapReady || !mapRef.current || data.length === 0) return;

    clearOverlays();

    const map = mapRef.current;
    const maxCount = Math.max(...data.map(d => d.count));

    // Create info window for hover
    if (!infoWindowRef.current) {
      infoWindowRef.current = new google.maps.InfoWindow({ disableAutoPan: true });
    }
    const infoWindow = infoWindowRef.current;

    data.forEach(d => {
      const coords = COUNTRY_COORDS[d.country];
      if (!coords) return;

      // Scale radius: 150km min to 800km max based on count
      const ratio = d.count / maxCount;
      const radius = 150000 + ratio * 650000;

      const colorHex = getThreatColorHex(d.avgLevel);

      const circle = new google.maps.Circle({
        map,
        center: coords,
        radius,
        fillColor: colorHex,
        fillOpacity: 0.25 + ratio * 0.35,
        strokeColor: colorHex,
        strokeOpacity: 0.7,
        strokeWeight: 1.5,
        clickable: true,
        zIndex: Math.round(d.avgLevel * 10),
      });

      // Hover tooltip
      circle.addListener("mouseover", () => {
        const threatLabel = getThreatLabel(d.avgLevel);
        const content = `
          <div style="
            background: rgba(15, 10, 26, 0.95);
            border: 1px solid ${colorHex}40;
            border-radius: 8px;
            padding: 10px 14px;
            font-family: 'Inter', sans-serif;
            color: #e2daf0;
            min-width: 180px;
            backdrop-filter: blur(12px);
          ">
            <div style="font-size: 13px; font-weight: 600; margin-bottom: 6px; color: #f0eaf8;">
              ${d.country}
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
              <span style="font-size: 11px; color: #9b8bb8;">Threat Events</span>
              <span style="font-size: 11px; font-family: 'JetBrains Mono', monospace; color: #f0eaf8;">${d.count.toLocaleString()}</span>
            </div>
            <div style="display: flex; justify-content: space-between; margin-bottom: 3px;">
              <span style="font-size: 11px; color: #9b8bb8;">Avg Severity</span>
              <span style="font-size: 11px; font-family: 'JetBrains Mono', monospace; color: ${colorHex};">${d.avgLevel.toFixed(1)}</span>
            </div>
            <div style="display: flex; justify-content: space-between;">
              <span style="font-size: 11px; color: #9b8bb8;">Threat Level</span>
              <span style="
                font-size: 10px;
                font-weight: 600;
                padding: 1px 6px;
                border-radius: 4px;
                background: ${colorHex}20;
                color: ${colorHex};
                border: 1px solid ${colorHex}40;
              ">${threatLabel}</span>
            </div>
          </div>
        `;
        infoWindow.setContent(content);
        infoWindow.setPosition(coords);
        infoWindow.open(map);
      });

      circle.addListener("mouseout", () => {
        infoWindow.close();
      });

      circlesRef.current.push(circle);
    });

    return () => clearOverlays();
  }, [data, mapReady, clearOverlays]);

  const handleMapReady = useCallback((map: google.maps.Map) => {
    mapRef.current = map;

    // Apply dark theme styling
    map.setOptions({
      styles: DARK_MAP_STYLES,
      backgroundColor: "#0f0a1a",
      mapTypeControl: false,
      streetViewControl: false,
      fullscreenControl: false,
      zoomControl: true,
      gestureHandling: "cooperative",
    });

    setMapReady(true);
  }, []);

  return (
    <MapView
      className={className ?? "w-full h-full rounded-lg overflow-hidden"}
      initialCenter={{ lat: 25, lng: 10 }}
      initialZoom={2}
      onMapReady={handleMapReady}
    />
  );
}
