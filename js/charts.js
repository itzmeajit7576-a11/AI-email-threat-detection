/**
 * Inbox Guardian - Custom Cyber Analytics & Chart Engine
 * Lightweight, high-DPI Canvas/SVG charts for cybersecurity dashboards.
 * Zero external library bloat; designed with sleek glowing strokes & gradients.
 */

class CyberCharts {
  /**
   * Render Threat Categories Radar / Polar Area Chart
   */
  static renderRadarChart(canvasId, categoriesData) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth;
    const height = canvas.height = canvas.parentElement.clientHeight || 280;

    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 40;

    const labels = Object.keys(categoriesData);
    const values = Object.values(categoriesData);
    const numPoints = labels.length;
    const angleStep = (Math.PI * 2) / numPoints;

    ctx.clearRect(0, 0, width, height);

    // Draw concentric web rings
    const rings = 4;
    for (let r = 1; r <= rings; r++) {
      const currentRadius = (radius / rings) * r;
      ctx.beginPath();
      for (let i = 0; i < numPoints; i++) {
        const angle = i * angleStep - Math.PI / 2;
        const x = centerX + Math.cos(angle) * currentRadius;
        const y = centerY + Math.sin(angle) * currentRadius;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.closePath();
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.15)';
      ctx.lineWidth = 1;
      ctx.stroke();
    }

    // Draw spoke lines
    for (let i = 0; i < numPoints; i++) {
      const angle = i * angleStep - Math.PI / 2;
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(centerX + Math.cos(angle) * radius, centerY + Math.sin(angle) * radius);
      ctx.strokeStyle = 'rgba(56, 189, 248, 0.15)';
      ctx.stroke();

      // Draw label
      const lx = centerX + Math.cos(angle) * (radius + 20);
      const ly = centerY + Math.sin(angle) * (radius + 15);
      ctx.fillStyle = '#94a3b8';
      ctx.font = '10px "JetBrains Mono", monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(labels[i], lx, ly);
    }

    // Draw data polygon
    ctx.beginPath();
    for (let i = 0; i < numPoints; i++) {
      const val = values[i] / 100;
      const angle = i * angleStep - Math.PI / 2;
      const x = centerX + Math.cos(angle) * (radius * val);
      const y = centerY + Math.sin(angle) * (radius * val);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.closePath();

    ctx.fillStyle = 'rgba(239, 68, 68, 0.25)';
    ctx.fill();
    ctx.strokeStyle = '#ef4444';
    ctx.lineWidth = 2;
    ctx.stroke();

    // Data points
    for (let i = 0; i < numPoints; i++) {
      const val = values[i] / 100;
      const angle = i * angleStep - Math.PI / 2;
      const x = centerX + Math.cos(angle) * (radius * val);
      const y = centerY + Math.sin(angle) * (radius * val);
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#00f2fe';
      ctx.fill();
    }
  }

  /**
   * Render Risk Distribution Horizontal Bar Chart
   */
  static renderRiskBarChart(canvasId, distribution) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth;
    const height = canvas.height = canvas.parentElement.clientHeight || 280;

    ctx.clearRect(0, 0, width, height);

    const keys = Object.keys(distribution);
    const values = Object.values(distribution);
    const colors = ['#10b981', '#eab308', '#f97316', '#ef4444', '#dc2626'];
    const maxVal = Math.max(...values, 10);
    const barHeight = 22;
    const spacing = (height - (keys.length * barHeight)) / (keys.length + 1);

    keys.forEach((key, idx) => {
      const y = spacing + idx * (barHeight + spacing);
      const label = key;
      const val = values[idx];
      const barWidth = ((width - 130) * (val / maxVal));

      // Label
      ctx.fillStyle = '#94a3b8';
      ctx.font = '11px "JetBrains Mono", monospace';
      ctx.textAlign = 'left';
      ctx.fillText(label, 10, y + 15);

      // Background track
      ctx.fillStyle = 'rgba(255, 255, 255, 0.05)';
      ctx.fillRect(100, y, width - 150, barHeight);

      // Value bar
      ctx.fillStyle = colors[idx] || '#38bdf8';
      ctx.fillRect(100, y, barWidth, barHeight);

      // Value text
      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 11px "Inter", sans-serif';
      ctx.fillText(`${val}%`, 100 + barWidth + 8, y + 15);
    });
  }

  /**
   * Render Authentication Status Donut Chart
   */
  static renderAuthDonut(canvasId, authData) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth;
    const height = canvas.height = canvas.parentElement.clientHeight || 280;

    const centerX = width / 2;
    const centerY = height / 2;
    const outerRadius = Math.min(centerX, centerY) - 25;
    const innerRadius = outerRadius * 0.65;

    ctx.clearRect(0, 0, width, height);

    const total = authData.pass + authData.fail + (authData.neutral || 0);
    if (total === 0) return;

    const slices = [
      { val: authData.pass, color: '#10b981', label: 'PASS' },
      { val: authData.fail, color: '#ef4444', label: 'FAIL' },
      { val: authData.neutral || 0, color: '#64748b', label: 'NEUTRAL' }
    ];

    let currentAngle = -Math.PI / 2;

    slices.forEach(slice => {
      if (slice.val === 0) return;
      const sliceAngle = (slice.val / total) * Math.PI * 2;

      ctx.beginPath();
      ctx.arc(centerX, centerY, outerRadius, currentAngle, currentAngle + sliceAngle);
      ctx.arc(centerX, centerY, innerRadius, currentAngle + sliceAngle, currentAngle, true);
      ctx.closePath();

      ctx.fillStyle = slice.color;
      ctx.fill();

      currentAngle += sliceAngle;
    });

    // Inner circle cutout
    ctx.beginPath();
    ctx.arc(centerX, centerY, innerRadius, 0, Math.PI * 2);
    ctx.fillStyle = '#090f20';
    ctx.fill();

    // Center text
    ctx.fillStyle = '#ffffff';
    ctx.font = 'bold 18px "Outfit", sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(`${Math.round((authData.pass / total) * 100)}%`, centerX, centerY - 6);
    ctx.fillStyle = '#94a3b8';
    ctx.font = '10px "JetBrains Mono", monospace';
    ctx.fillText('AUTH PASS', centerX, centerY + 14);
  }

  /**
   * Render 24-Hour Scan Activity Line Chart
   */
  static renderScanActivityLine(canvasId) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth;
    const height = canvas.height = canvas.parentElement.clientHeight || 280;

    ctx.clearRect(0, 0, width, height);

    const points = [14, 22, 18, 35, 48, 62, 55, 78, 92, 85, 96, 88, 105, 118, 95, 130, 142, 125, 150, 138, 160, 152, 170, 165];
    const maxVal = Math.max(...points) + 20;
    const stepX = (width - 40) / (points.length - 1);

    // Draw gradient fill
    const grad = ctx.createLinearGradient(0, 0, 0, height);
    grad.addColorStop(0, 'rgba(0, 242, 254, 0.35)');
    grad.addColorStop(1, 'rgba(0, 242, 254, 0.0)');

    ctx.beginPath();
    points.forEach((val, i) => {
      const x = 20 + i * stepX;
      const y = height - 30 - ((val / maxVal) * (height - 60));
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.lineTo(20 + (points.length - 1) * stepX, height - 30);
    ctx.lineTo(20, height - 30);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw line
    ctx.beginPath();
    points.forEach((val, i) => {
      const x = 20 + i * stepX;
      const y = height - 30 - ((val / maxVal) * (height - 60));
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = '#00f2fe';
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Bottom time markers
    ctx.fillStyle = '#64748b';
    ctx.font = '9px "JetBrains Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText('00:00', 30, height - 10);
    ctx.fillText('06:00', width * 0.28, height - 10);
    ctx.fillText('12:00', width * 0.52, height - 10);
    ctx.fillText('18:00', width * 0.76, height - 10);
    ctx.fillText('NOW', width - 30, height - 10);
  }
}
