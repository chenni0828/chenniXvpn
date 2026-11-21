// Fixed, local line icons. Consumers can insert the result directly into markup.
const shapes = {
  overview: '<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/>',
  activity: '<path d="M2.5 12h4l3.4-8.5 4.6 17 3-8.5h4"/>',
  network: '<rect x="8.5" y="3" width="7" height="5.5" rx="1.3"/><path d="M12 8.5v4.2M5.6 16v-3.3h12.8V16"/><rect x="2.5" y="16" width="6.2" height="5" rx="1.1"/><rect x="15.3" y="16" width="6.2" height="5" rx="1.1"/>',
  chart: '<path d="M3.3 3.7v16.6h17.4M6.5 15.6l4.1-5.7 3.7 2.8 6-7"/>',
  up: '<path d="M12 20V4m-6 6 6-6 6 6"/>',
  down: '<path d="M12 4v16m-6-6 6 6 6-6"/>',
  gauge: '<path d="M4.2 18a8.7 8.7 0 1 1 15.6 0H4.2Z"/><path d="m12 13.4 4.2-4.2"/><circle cx="12" cy="13.5" r="1.2"/>',
  layers: '<path d="m12 3 9 4.8-9 4.8-9-4.8L12 3ZM3 12l9 4.8 9-4.8M3 16.3l9 4.7 9-4.7"/>',
  check: '<path d="m4.5 12.5 5 5L19.5 7"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5.2l3.4 2"/>',
  upload: '<path d="M12 15V3m-4.6 4.6L12 3l4.6 4.6M4 14.5v4.2A1.8 1.8 0 0 0 5.8 20.5h12.4a1.8 1.8 0 0 0 1.8-1.8v-4.2"/>',
  download: '<path d="M12 3v12m-4.6-4.6L12 15l4.6-4.6M4 14.5v4.2a1.8 1.8 0 0 0 1.8 1.8h12.4a1.8 1.8 0 0 0 1.8-1.8v-4.2"/>',
  settings: '<path d="M4 6.5h9m4 0h3M4 12h3m4 0h9M4 17.5h11m4 0h1"/><circle cx="15" cy="6.5" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="17" cy="17.5" r="2"/>',
  arrow: '<path d="M4 12h15m-6.2-6.2L19 12l-6.2 6.2"/>',
  copy: '<path d="M15.5 6.5V5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2H7"/><rect x="8" y="7" width="12" height="14" rx="2"/>',
  qr: '<rect x="3" y="3" width="6.5" height="6.5" rx="1"/><rect x="14.5" y="3" width="6.5" height="6.5" rx="1"/><rect x="3" y="14.5" width="6.5" height="6.5" rx="1"/><path d="M14.5 14.5H18v3.2h3V21m-6.5-2.5V21m6.5-6.5v.2"/>',
  cloud: '<path d="M7 18.5a4.5 4.5 0 1 1 .9-8.9 5.9 5.9 0 0 1 11.4 1.6 3.7 3.7 0 0 1-1 7.3H7Z"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="3.8" ry="9"/><path d="M3.5 9.2h17m-17 5.6h17"/>',
  refresh: '<path d="M20.2 10a8.3 8.3 0 0 0-13.8-4l-2.2 2.1M4 3.7v4.7h4.7M3.8 14a8.3 8.3 0 0 0 13.8 4l2.2-2.1m.2 4.4v-4.7h-4.7"/>',
  close: '<path d="m6 6 12 12M18 6 6 18"/>',
  edit: '<path d="m4 16.2 10.9-11 4 4L8 20l-5 1 1-4.8Zm8.9-8.9 4 4"/>',
  terminal: '<rect x="2.7" y="4.3" width="18.6" height="15.4" rx="2.5"/><path d="m6.5 9 3 3-3 3m6 0h4.7"/>',
  lock: '<rect x="5" y="10.2" width="14" height="10.5" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 4v2.6"/>',
  server: '<rect x="3" y="3.5" width="18" height="7.5" rx="1.8"/><rect x="3" y="13" width="18" height="7.5" rx="1.8"/><path d="M6.5 7.2h.2m-.2 9.5h.2M11 7.2h6.2M11 16.7h6.2"/>',
  shield: '<path d="m12 2.8 8 3.3v5.5c0 4.3-4 8-8 9.8-4-1.8-8-5.5-8-9.8V6.1l8-3.3Z"/><path d="m8.4 11.8 2.4 2.5 4.8-5"/>',
  calendar: '<rect x="3.5" y="5.5" width="17" height="15" rx="2"/><path d="M7.8 3v5m8.4-5v5M4 10.5h16"/>',
  file: '<path d="M6 3.2h8l4.5 4.5v12.2H6z"/><path d="M14 3.5v4.4h4.2M9 12h6m-6 4h4"/>',
  link: '<path d="m9 15 6-6m-6.6 3.1-2 2a3.9 3.9 0 0 0 5.5 5.5l3.2-3.2m.5-4.5 2-2a3.9 3.9 0 1 0-5.5-5.5L9 7.6"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5.3m0-8.8v.2"/>',
};

export function icon(name) {
  const shape = Object.hasOwn(shapes, name) ? shapes[name] : shapes.activity;
  return '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' + shape + '</svg>';
}

function updateNavigation() {
  const section = (location.hash.slice(1).split('/')[1] || '').split('?')[0];
  document.querySelectorAll('.main-nav a').forEach(link => {
    const active = link.hash === '#/' + section;
    if (active) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  });
}

document.querySelectorAll('[data-icon]').forEach(slot => {
  slot.innerHTML = icon(slot.dataset.icon);
});
updateNavigation();
window.addEventListener('hashchange', updateNavigation);

const WINDOW_SECONDS = 15 * 60;
const channels = [
  { key: 'rx_bps', color: '--plot-rx', dash: [5, 4] },
  { key: 'tx_bps', color: '--plot-tx', dash: [] },
];
const tickTime = new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
const tickNumber = new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 });
const chartData = new WeakMap();
const watched = new Set();
const resize = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(entries => {
  for (const entry of entries) {
    if (entry.target.isConnected) paintTraffic(entry.target, chartData.get(entry.target));
  }
});

function axisStep(peak, rows) {
  if (peak <= 0) return 1;
  const raw = peak / rows;
  const scale = 10 ** Math.floor(Math.log10(raw));
  return ([1, 2, 2.5, 5, 10].find(item => item * scale >= raw) || 10) * scale;
}

function rateUnit(peak) {
  if (peak >= 1e9) return { size: 1e9, label: 'Gbps' };
  if (peak >= 1e6) return { size: 1e6, label: 'Mbps' };
  if (peak >= 1e3) return { size: 1e3, label: 'Kbps' };
  return { size: 1, label: 'bps' };
}

function segments(points, key, x, y) {
  const result = [];
  let current = [];
  let previousTime;
  for (const point of points) {
    const rate = point[key];
    if (!Number.isFinite(rate) || rate < 0 || point.ts - previousTime > 15) {
      if (current.length) result.push(current);
      current = [];
    }
    if (Number.isFinite(rate) && rate >= 0) current.push([x(point.ts), y(rate)]);
    previousTime = point.ts;
  }
  if (current.length) result.push(current);
  return result;
}

function trace(ctx, line) {
  ctx.beginPath();
  ctx.moveTo(line[0][0], line[0][1]);
  for (let index = 1; index < line.length; index++) ctx.lineTo(line[index][0], line[index][1]);
}

function paintTraffic(canvas, data) {
  const bounds = canvas.getBoundingClientRect();
  const width = Math.round(bounds.width);
  const height = Math.round(bounds.height);
  if (width < 40 || height < 45) return;
  const ratio = Math.min(window.devicePixelRatio || 1, 3);
  if (canvas.width !== Math.round(width * ratio)) canvas.width = Math.round(width * ratio);
  if (canvas.height !== Math.round(height * ratio)) canvas.height = Math.round(height * ratio);
  const ctx = canvas.getContext('2d');
  if (!ctx) return;
  const theme = getComputedStyle(canvas);
  const axisColor = theme.getPropertyValue('--muted').trim();
  const gridColor = theme.getPropertyValue('--line').trim();
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const end = Math.max(Date.now() / 1000, data.at(-1)?.ts || 0);
  const start = end - WINDOW_SECONDS;
  const points = data.filter(point => point.ts >= start && point.ts <= end);
  let peak = 0;
  for (const point of points) {
    for (const { key } of channels) {
      if (Number.isFinite(point[key])) peak = Math.max(peak, point[key]);
    }
  }
  const rows = height < 150 ? 3 : 4;
  const unit = rateUnit(peak);
  const step = axisStep(peak / unit.size, rows);
  const max = step * rows * unit.size;
  const left = 41;
  const right = width - 9;
  const top = 24;
  const bottom = height - 23;
  const x = time => left + (time - start) / WINDOW_SECONDS * (right - left);
  const y = value => bottom - value / max * (bottom - top);
  ctx.font = '12px "IBM Plex Mono", "Cascadia Mono", Consolas, monospace';
  ctx.textBaseline = 'middle';
  ctx.textAlign = 'left';
  ctx.fillStyle = axisColor;
  ctx.fillText(unit.label, 0, 8);
  ctx.lineWidth = 1;
  for (let row = 0; row <= rows; row++) {
    const position = top + (bottom - top) * row / rows;
    ctx.setLineDash(row === rows ? [] : [3, 5]);
    ctx.strokeStyle = gridColor;
    ctx.beginPath();
    ctx.moveTo(left, Math.round(position) + .5);
    ctx.lineTo(right, Math.round(position) + .5);
    ctx.stroke();
    ctx.fillText(tickNumber.format((rows - row) * step), 0, position);
  }
  const ticks = width > 500 ? 5 : 3;
  ctx.setLineDash([]);
  for (let tick = 0; tick <= ticks; tick++) {
    const time = start + WINDOW_SECONDS * tick / ticks;
    ctx.textAlign = tick === 0 ? 'left' : tick === ticks ? 'right' : 'center';
    ctx.fillText(tickTime.format(new Date(time * 1000)), x(time), height - 7);
  }
  let hasMeasurements = false;
  for (const channel of channels) {
    const lines = segments(points, channel.key, x, y);
    if (!lines.length) continue;
    hasMeasurements = true;
    const color = theme.getPropertyValue(channel.color).trim();
    ctx.setLineDash(channel.dash);
    for (const line of lines) {
      if (line.length === 1) {
        ctx.beginPath();
        ctx.arc(line[0][0], line[0][1], 2, 0, 2 * Math.PI);
        ctx.fillStyle = color;
        ctx.fill();
        continue;
      }
      trace(ctx, line);
      ctx.lineWidth = 2.1;
      ctx.lineJoin = 'round';
      ctx.lineCap = 'round';
      ctx.strokeStyle = color;
      ctx.stroke();
    }
  }
  if (!hasMeasurements) {
    ctx.font = '14px "Inter", "Microsoft YaHei UI", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillStyle = axisColor;
    ctx.fillText('近 15 分钟暂无采样', (left + right) / 2, (top + bottom) / 2);
  }
}

export function drawTraffic(canvas, points = []) {
  if (!canvas) return;
  const data = Array.isArray(points)
    ? points.filter(point => point && Number.isFinite(point.ts)).sort((a, b) => a.ts - b.ts)
    : [];
  chartData.set(canvas, data);
  canvas.setAttribute('role', 'img');
  canvas.setAttribute('aria-label', '最近 15 分钟上传与下载速率。有效采样点之间断开表示期间缺少数据。');
  for (const old of watched) {
    if (!old.isConnected) {
      resize?.unobserve(old);
      watched.delete(old);
    }
  }
  if (!watched.has(canvas)) {
    watched.add(canvas);
    resize?.observe(canvas);
  }
  paintTraffic(canvas, data);
}
