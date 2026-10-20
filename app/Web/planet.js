/* Планета на фоне: точечный глобус на canvas без внешних библиотек.
 *
 *   Planet.init(canvasElement)
 *   Planet.setScene('auth' | 'main')        размер и положение планеты
 *   Planet.setState('idle' | 'connecting' | 'connected')
 *   Planet.setServer({ lat, lon } | null)   где стоит сервер (метка и линия соединения)
 */
(() => {
  'use strict';

  const TAU = Math.PI * 2;
  const rad = (d) => (d * Math.PI) / 180;
  const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
  const smooth = (a, b, v) => { const t = clamp((v - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };

  /* ---------- шум для «материков» ---------- */
  function hash3(x, y, z) {
    let h = Math.imul(x, 374761393) ^ Math.imul(y, 668265263) ^ Math.imul(z, 1274126177);
    h = Math.imul(h ^ (h >>> 13), 1103515245);
    h ^= h >>> 16;
    return (h >>> 0) / 4294967296;
  }
  const fade = (t) => t * t * (3 - 2 * t);
  const mix = (a, b, t) => a + (b - a) * t;
  function noise3(x, y, z) {
    const xi = Math.floor(x), yi = Math.floor(y), zi = Math.floor(z);
    const xf = fade(x - xi), yf = fade(y - yi), zf = fade(z - zi);
    const c = (dx, dy, dz) => hash3(xi + dx, yi + dy, zi + dz);
    return mix(
      mix(mix(c(0, 0, 0), c(1, 0, 0), xf), mix(c(0, 1, 0), c(1, 1, 0), xf), yf),
      mix(mix(c(0, 0, 1), c(1, 0, 1), xf), mix(c(0, 1, 1), c(1, 1, 1), xf), yf),
      zf
    );
  }
  const fbm = (x, y, z) => noise3(x, y, z) * 0.55 + noise3(x * 2.1, y * 2.1, z * 2.1) * 0.3 + noise3(x * 4.3, y * 4.3, z * 4.3) * 0.15;

  /* ---------- точки на сфере ---------- */
  const COUNT = 2600;
  const px = new Float32Array(COUNT), py = new Float32Array(COUNT), pz = new Float32Array(COUNT);
  const land = new Uint8Array(COUNT);
  (function buildPoints() {
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < COUNT; i++) {
      const y = 1 - (2 * (i + 0.5)) / COUNT;
      const r = Math.sqrt(1 - y * y);
      const th = i * golden;
      const x = Math.cos(th) * r, z = Math.sin(th) * r;
      px[i] = x; py[i] = y; pz[i] = z;
      land[i] = fbm(x * 1.7 + 11.3, y * 1.7 + 4.1, z * 1.7 + 7.9) > 0.535 ? 1 : 0;
    }
  })();

  /* ---------- состояние ---------- */
  const SCENES = {
    auth: { cy: 0.19, r: (w, h) => Math.min(w * 0.19, h * 0.11), dim: 0.85 },
    main: { cy: 0.39, r: (w, h) => Math.min(w * 0.33, h * 0.19), dim: 1 },
  };

  let canvas = null, ctx = null, dpr = 1, W = 0, H = 0;
  let scene = 'main', vpn = 'idle', server = null;
  let cur = { cy: 0.39, r: 140, dim: 1 };
  let yaw = 0.6, tilt = 0.3, arc = 0, tint = 0;
  let last = 0, running = false;
  const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function resize() {
    if (!canvas) return;
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    W = canvas.clientWidth; H = canvas.clientHeight;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
  }

  function vec(lat, lon) {
    const la = rad(lat), lo = rad(lon);
    return [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)];
  }

  function frame(now) {
    if (!running) return;
    requestAnimationFrame(frame);
    if (document.hidden || !ctx || W === 0) { last = now; return; }

    const dt = Math.min(0.05, (now - last) / 1000 || 0.016);
    last = now;

    // положение и размер планеты плавно подстраиваются под экран
    const sc = SCENES[scene];
    const k = 1 - Math.exp(-dt * 4);
    cur.cy += (sc.cy * H - cur.cy) * k;
    cur.r += (sc.r(W, H) - cur.r) * k;
    cur.dim += (sc.dim - cur.dim) * k;
    const cx = W / 2, cy = cur.cy, R = cur.r;

    // вращение: свободное, пока нет соединения; при соединении поворачиваем к серверу
    if (server && vpn !== 'idle') {
      const ty = -rad(server.lon);
      let d = ty - yaw;
      d = Math.atan2(Math.sin(d), Math.cos(d));
      yaw += d * (1 - Math.exp(-dt * 2.2));
      tilt += (clamp(rad(server.lat), -0.2, 0.55) - tilt) * (1 - Math.exp(-dt * 2.2));
    } else {
      yaw += dt * (reduceMotion ? 0.02 : 0.08);
      tilt += (0.3 - tilt) * (1 - Math.exp(-dt * 1.5));
    }
    const arcTarget = vpn === 'connected' ? 1 : vpn === 'connecting' ? 0.55 : 0;
    arc += (arcTarget - arc) * (1 - Math.exp(-dt * 1.6));
    tint += ((vpn === 'connected' ? 1 : 0) - tint) * (1 - Math.exp(-dt * 2));

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, W, H);

    const accent = [139, 108, 255], ok = [61, 220, 132];
    const glow = accent.map((c, i) => Math.round(mix(c, ok[i], tint)));

    // свечение атмосферы
    let g = ctx.createRadialGradient(cx, cy, R * 0.9, cx, cy, R * 1.55);
    g.addColorStop(0, `rgba(${glow},${0.5 * cur.dim})`);
    g.addColorStop(0.3, `rgba(${glow},${0.16 * cur.dim})`);
    g.addColorStop(1, `rgba(${glow},0)`);
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(cx, cy, R * 1.55, 0, TAU); ctx.fill();

    // тело планеты
    g = ctx.createRadialGradient(cx - R * 0.35, cy - R * 0.4, R * 0.1, cx, cy, R);
    g.addColorStop(0, 'rgba(46,30,120,0.95)');
    g.addColorStop(1, 'rgba(10,6,36,0.96)');
    ctx.fillStyle = g;
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.fill();

    // точки
    const cyw = Math.cos(yaw), syw = Math.sin(yaw), ct = Math.cos(tilt), st = Math.sin(tilt);
    const lx = -0.5, ly = 0.6, lz = 0.62;
    for (let i = 0; i < COUNT; i++) {
      const x = px[i], y = py[i], z = pz[i];
      const x1 = x * cyw + z * syw;
      const z1 = -x * syw + z * cyw;
      const y2 = y * ct - z1 * st;
      const z2 = y * st + z1 * ct;
      if (z2 <= 0) continue;
      const lit = clamp(x1 * lx + y2 * ly + z2 * lz, 0, 1);
      const edge = smooth(0, 0.45, z2);
      const isLand = land[i] === 1;
      const a = edge * (isLand ? 0.95 : 0.42) * (0.35 + 0.65 * lit) * cur.dim;
      if (a < 0.03) continue;
      const base = isLand ? 225 : 150;
      const rr = Math.round(mix(base * 0.8, ok[0], tint * (isLand ? 0.7 : 0.3)));
      const gg = Math.round(mix(base * 0.72, ok[1], tint * (isLand ? 0.7 : 0.3)));
      const bb = Math.round(mix(255, ok[2], tint * (isLand ? 0.6 : 0.2)));
      ctx.fillStyle = `rgba(${rr},${gg},${bb},${a.toFixed(3)})`;
      const s = (isLand ? 2.1 : 1.3) * (0.55 + 0.45 * z2) * (R / 140 + 0.35);
      ctx.fillRect(sx(cx, R, x1) - s / 2, sy(cy, R, y2) - s / 2, s, s);
    }

    // кромка
    ctx.lineWidth = 1;
    ctx.strokeStyle = `rgba(${glow},${0.35 * cur.dim})`;
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.stroke();

    if (server) drawServer(now, cx, cy, R, glow);
  }

  const sx = (cx, R, x) => cx + x * R;
  const sy = (cy, R, y) => cy - y * R;

  function project(v, lift) {
    const cyw = Math.cos(yaw), syw = Math.sin(yaw), ct = Math.cos(tilt), st = Math.sin(tilt);
    const x = v[0] * lift, y = v[1] * lift, z = v[2] * lift;
    const x1 = x * cyw + z * syw;
    const z1 = -x * syw + z * cyw;
    return [x1, y * ct - z1 * st, y * st + z1 * ct];
  }

  function drawServer(now, cx, cy, R, glow) {
    const target = vec(server.lat, server.lon);
    const origin = vec(server.lat - 20, server.lon - 48); // «ваше устройство»: условная точка, чтобы нарисовать маршрут

    // дуга соединения
    if (arc > 0.02) {
      const steps = 48, upto = Math.floor(steps * arc);
      const dot = Math.max(-1, Math.min(1, origin[0] * target[0] + origin[1] * target[1] + origin[2] * target[2]));
      const omega = Math.acos(dot) || 1e-6;
      const sinO = Math.sin(omega);
      const at = (t) => {
        const a = Math.sin((1 - t) * omega) / sinO, b = Math.sin(t * omega) / sinO;
        const v = [a * origin[0] + b * target[0], a * origin[1] + b * target[1], a * origin[2] + b * target[2]];
        return project(v, 1 + 0.2 * Math.sin(Math.PI * t));
      };
      ctx.lineWidth = 1.6;
      ctx.strokeStyle = `rgba(${glow},0.85)`;
      ctx.beginPath();
      let pen = false;
      for (let i = 0; i <= upto; i++) {
        const p = at(i / steps);
        if (p[2] <= 0) { pen = false; continue; }
        const X = sx(cx, R, p[0]), Y = sy(cy, R, p[1]);
        if (pen) ctx.lineTo(X, Y); else { ctx.moveTo(X, Y); pen = true; }
      }
      ctx.stroke();

      // «пакет» бежит по дуге
      if (vpn === 'connected') {
        const tt = ((now * 0.00045) % 1) * arc;
        const p = at(tt);
        if (p[2] > 0) {
          ctx.fillStyle = 'rgba(255,255,255,0.95)';
          ctx.beginPath(); ctx.arc(sx(cx, R, p[0]), sy(cy, R, p[1]), 2.4, 0, TAU); ctx.fill();
        }
      }
      const o = project(origin, 1);
      if (o[2] > 0) {
        ctx.strokeStyle = 'rgba(255,255,255,0.8)'; ctx.lineWidth = 1.4;
        ctx.beginPath(); ctx.arc(sx(cx, R, o[0]), sy(cy, R, o[1]), 3.6, 0, TAU); ctx.stroke();
      }
    }

    // метка сервера с пульсирующим кольцом
    const p = project(target, 1);
    if (p[2] > 0.02) {
      const X = sx(cx, R, p[0]), Y = sy(cy, R, p[1]);
      const ph = reduceMotion ? 0.5 : (now * 0.0007) % 1;
      ctx.strokeStyle = `rgba(${glow},${(1 - ph) * 0.8})`;
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(X, Y, 5 + ph * 16, 0, TAU); ctx.stroke();
      ctx.fillStyle = vpn === 'connected' ? 'rgb(61,220,132)' : 'rgb(255,255,255)';
      ctx.beginPath(); ctx.arc(X, Y, 4, 0, TAU); ctx.fill();
    }
  }

  window.Planet = {
    init(el) {
      canvas = el;
      ctx = canvas.getContext ? canvas.getContext('2d') : null;
      resize();
      window.addEventListener('resize', resize);
      if (ctx && !running) { running = true; last = performance.now(); requestAnimationFrame(frame); }
    },
    setScene(name) { if (SCENES[name]) scene = name; },
    setState(s) { vpn = s; },
    setServer(s) { server = s && typeof s.lat === 'number' && typeof s.lon === 'number' ? { lat: s.lat, lon: s.lon } : null; },
  };
})();
