/**
 * Inbox Guardian - Cyber IP Geolocation & World Map Visualizer
 * Dark high-tech SVG/Canvas world map with animated node pulses,
 * curved connection lines (Origin -> Relay -> Destination) & interactive hover cards.
 */

class MapVisualizer {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
    if (!this.container) return;
    this.locations = [];
    this.init();
  }

  init() {
    this.container.innerHTML = `
      <div style="position: relative; width: 100%; height: 100%; overflow: hidden; background: #040714;">
        <svg id="world-map-svg" viewBox="0 0 1000 500" style="width: 100%; height: 100%; display: block;" preserveAspectRatio="xMidYMid meet">
          <!-- Cyber Grid Pattern -->
          <defs>
            <pattern id="map-grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(56, 189, 248, 0.05)" stroke-width="0.5"/>
            </pattern>
            <linearGradient id="arc-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stop-color="#ef4444" />
              <stop offset="50%" stop-color="#f59e0b" />
              <stop offset="100%" stop-color="#00f2fe" />
            </linearGradient>
            <filter id="glow-effect" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feComposite in="SourceGraphic" in2="blur" operator="over" />
            </filter>
          </defs>

          <rect width="1000" height="500" fill="url(#map-grid)" />

          <!-- Stylized World Continents (Cyber Simplified Outlines) -->
          <g class="continents-group" fill="rgba(15, 23, 42, 0.75)" stroke="rgba(56, 189, 248, 0.18)" stroke-width="0.8">
            <!-- North America -->
            <path d="M 120,80 Q 200,60 260,90 Q 290,130 250,170 Q 220,230 190,260 Q 150,220 110,160 Z" />
            <!-- South America -->
            <path d="M 230,280 Q 300,300 290,370 Q 260,440 220,460 Q 200,380 210,320 Z" />
            <!-- Europe -->
            <path d="M 450,100 Q 550,80 540,150 Q 500,180 440,170 Q 420,130 450,100 Z" />
            <!-- Africa -->
            <path d="M 460,200 Q 560,210 550,310 Q 520,400 480,410 Q 430,320 440,240 Z" />
            <!-- Asia -->
            <path d="M 560,90 Q 750,70 850,130 Q 820,240 720,270 Q 640,230 570,180 Z" />
            <!-- Australia -->
            <path d="M 760,340 Q 860,330 870,410 Q 800,440 750,400 Z" />
          </g>

          <!-- Animated Connection Path Layer -->
          <g id="map-arcs-layer"></g>

          <!-- Interactive IP Nodes Layer -->
          <g id="map-nodes-layer"></g>
        </svg>

        <!-- Dynamic Hover Tooltip -->
        <div id="map-tooltip" style="position: absolute; display: none; background: rgba(9, 15, 32, 0.95); border: 1px solid #00f2fe; border-radius: 8px; padding: 10px 14px; font-family: var(--font-mono); font-size: 0.75rem; color: #fff; pointer-events: none; z-index: 100; box-shadow: 0 8px 24px rgba(0,0,0,0.8);"></div>
      </div>
    `;

    this.svg = document.getElementById('world-map-svg');
    this.arcsLayer = document.getElementById('map-arcs-layer');
    this.nodesLayer = document.getElementById('map-nodes-layer');
    this.tooltip = document.getElementById('map-tooltip');
  }

  /**
   * Convert latitude/longitude to SVG 1000x500 coordinates (Equirectangular approximation)
   */
  latLongToXY(lat, lon) {
    const x = (lon + 180) * (1000 / 360);
    const y = (90 - lat) * (500 / 180);
    return { x, y };
  }

  /**
   * Render geolocation pins and animated transmission hops
   */
  render(geolocations) {
    if (!geolocations || geolocations.length === 0) return;
    this.locations = geolocations;

    this.arcsLayer.innerHTML = '';
    this.nodesLayer.innerHTML = '';

    const points = geolocations.map(loc => {
      const { x, y } = this.latLongToXY(loc.latitude, loc.longitude);
      return { ...loc, x, y };
    });

    // 1. Draw connecting arcs between consecutive nodes
    for (let i = 0; i < points.length - 1; i++) {
      const p1 = points[i];
      const p2 = points[i + 1];

      // Calculate control point for curved bezier arc
      const midX = (p1.x + p2.x) / 2;
      const midY = Math.min(p1.y, p2.y) - Math.abs(p1.x - p2.x) * 0.2 - 20;

      const pathData = `M ${p1.x} ${p1.y} Q ${midX} ${midY} ${p2.x} ${p2.y}`;

      const pathElem = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      pathElem.setAttribute('d', pathData);
      pathElem.setAttribute('fill', 'none');
      pathElem.setAttribute('stroke', 'url(#arc-gradient)');
      pathElem.setAttribute('stroke-width', '2.5');
      pathElem.setAttribute('class', 'map-arc-animated');
      pathElem.setAttribute('filter', 'url(#glow-effect)');

      this.arcsLayer.appendChild(pathElem);
    }

    // 2. Draw nodes and pulsing radar circles
    points.forEach((p, idx) => {
      const nodeColor = idx === 0 ? '#ef4444' : (idx === points.length - 1 ? '#00f2fe' : '#f59e0b');
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.setAttribute('transform', `translate(${p.x}, ${p.y})`);
      g.style.cursor = 'pointer';

      // Pulsing outer radar circle
      const pulseCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      pulseCircle.setAttribute('r', '14');
      pulseCircle.setAttribute('fill', 'none');
      pulseCircle.setAttribute('stroke', nodeColor);
      pulseCircle.setAttribute('stroke-width', '1.5');
      pulseCircle.setAttribute('opacity', '0.6');
      pulseCircle.setAttribute('class', 'scan-pulse');

      // Core point
      const coreCircle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      coreCircle.setAttribute('r', '6');
      coreCircle.setAttribute('fill', nodeColor);
      coreCircle.setAttribute('stroke', '#ffffff');
      coreCircle.setAttribute('stroke-width', '1.5');

      // Label
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.setAttribute('y', '-12');
      text.setAttribute('text-anchor', 'middle');
      text.setAttribute('fill', '#ffffff');
      text.setAttribute('font-size', '10px');
      text.setAttribute('font-family', 'var(--font-mono)');
      text.setAttribute('font-weight', 'bold');
      text.textContent = `${p.city || p.ip}`;

      g.appendChild(pulseCircle);
      g.appendChild(coreCircle);
      g.appendChild(text);

      // Tooltip events
      g.addEventListener('mouseenter', (e) => {
        this.showTooltip(p, e);
      });
      g.addEventListener('mousemove', (e) => {
        this.updateTooltipPosition(e);
      });
      g.addEventListener('mouseleave', () => {
        this.hideTooltip();
      });

      this.nodesLayer.appendChild(g);
    });
  }

  showTooltip(loc, e) {
    this.tooltip.innerHTML = `
      <div style="font-weight: bold; color: ${loc.risk_score > 60 ? '#f87171' : '#00f2fe'}; margin-bottom: 4px;">
        ${loc.type || 'IP Node'}: ${loc.ip}
      </div>
      <div>Location: ${loc.city}, ${loc.country}</div>
      <div>ASN: ${loc.asn} (${loc.isp})</div>
      <div>Risk Reputation: <strong>${loc.reputation}</strong></div>
      <div style="font-size: 0.65rem; color: #64748b; margin-top: 4px;">*${loc.disclaimer || 'Approximate BGP Telemetry'}</div>
    `;
    this.tooltip.style.display = 'block';
    this.updateTooltipPosition(e);
  }

  updateTooltipPosition(e) {
    const rect = this.container.getBoundingClientRect();
    const x = e.clientX - rect.left + 15;
    const y = e.clientY - rect.top + 15;
    this.tooltip.style.left = `${x}px`;
    this.tooltip.style.top = `${y}px`;
  }

  hideTooltip() {
    this.tooltip.style.display = 'none';
  }
}
