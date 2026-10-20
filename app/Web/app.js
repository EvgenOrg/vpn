/* Интерфейс Security VPN.
 * Внутри Windows-приложения общается с C# через WebView2 (postMessage).
 * Если открыть index.html в обычном браузере, включается демо-режим с имитацией сервера:
 * удобно смотреть и править дизайн без сборки приложения.
 */
(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const hasHost = !!(window.chrome && window.chrome.webview);

  /* ====================== мост с C# ====================== */

  const pending = new Map();
  let seq = 0;
  let eventHandler = () => {};

  const host = {
    call(cmd, args = {}) {
      return new Promise((resolve, reject) => {
        const id = ++seq;
        pending.set(id, { resolve, reject });
        window.chrome.webview.postMessage({ id, cmd, args });
      });
    },
    onEvent(fn) { eventHandler = fn; },
  };

  if (hasHost) {
    window.chrome.webview.addEventListener('message', (e) => {
      const m = e.data;
      if (m && m.id && pending.has(m.id)) {
        const p = pending.get(m.id);
        pending.delete(m.id);
        if (m.ok) p.resolve(m.data); else p.reject(new Error(m.error || 'Неизвестная ошибка'));
      } else if (m && m.event) {
        eventHandler(m);
      }
    });
  }

  /* Демо-режим (без приложения) */
  const demo = (() => {
    const wait = (ms, v) => new Promise((r) => setTimeout(() => r(v), ms));
    const location = { countryCode: 'NL', city: 'Amsterdam', lat: 52.37, lon: 4.9 };
    let user = null, state = 'disconnected', since = 0, timer = null, steps = [];
    let handler = () => {};
    const emit = (m) => handler(m);
    const setState = (s, message = '') => { state = s; emit({ event: 'state', state: s, message, since }); };
    const clear = () => { steps.forEach(clearTimeout); steps = []; clearInterval(timer); };

    return {
      onEvent(fn) { handler = fn; },
      async call(cmd, a = {}) {
        switch (cmd) {
          case 'init':
            return wait(300, { name: 'Security VPN', inviteRequired: true, location, loggedIn: !!user, username: user, state, since, demo: true });
          case 'login':
            if (!a.username || (a.password || '').length < 8) throw new Error('Неверный логин или пароль');
            user = a.username; return wait(500, { username: user });
          case 'register':
            if (a.invite !== 'demo') throw new Error('Неверный код приглашения (в демо-режиме это слово demo)');
            user = a.username; return wait(700, { username: user });
          case 'changePassword': return wait(500, {});
          case 'logout': clear(); user = null; state = 'disconnected'; return {};
          case 'connect':
            since = 0; setState('connecting', 'Получаем настройки…');
            steps.push(setTimeout(() => setState('connecting', 'Запускаем защищённый канал…'), 900));
            steps.push(setTimeout(() => {
              since = Date.now(); setState('connected');
              timer = setInterval(() => emit({
                event: 'stats', down: 1.2e6 + Math.random() * 4e6, up: 2e5 + Math.random() * 8e5, ping: 22 + Math.round(Math.random() * 6),
              }), 1000);
            }, 2200));
            return {};
          case 'disconnect': clear(); since = 0; setState('disconnected'); return {};
          default: return {};
        }
      },
    };
  })();

  // Демо: открыт в обычном браузере или приложение запущено с ключом --demo (адрес ?demo=1)
  const demoMode = !hasHost || new URLSearchParams(window.location.search).has('demo');
  const bridge = demoMode ? demo : host;
  bridge.onEvent((m) => onEvent(m));

  /* ====================== состояние ====================== */

  const S = { mode: 'login', inviteRequired: false, configError: null, loggedIn: false, vpn: 'disconnected', since: 0, busy: false };

  /* ====================== утилиты ====================== */

  let toastTimer = 0;
  function toast(text, isError = false) {
    const el = $('toast');
    el.textContent = text;
    el.classList.toggle('err', isError);
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 3800);
  }

  function setBusy(btn, busy) {
    btn.disabled = busy;
    btn.classList.toggle('busy', busy);
  }

  function fmtSpeed(bytesPerSec) {
    const bits = Math.max(0, bytesPerSec || 0) * 8;
    if (bits >= 1e6) return [(bits / 1e6).toFixed(bits >= 1e8 ? 0 : 1), 'Мбит/с'];
    return [String(Math.round(bits / 1e3)), 'кбит/с'];
  }

  function fmtTime(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const p = (n) => String(n).padStart(2, '0');
    return `${p(Math.floor(s / 3600))}:${p(Math.floor((s % 3600) / 60))}:${p(s % 60)}`;
  }

  function countryName(code) {
    try { return new Intl.DisplayNames(['ru'], { type: 'region' }).of(code) || code; } catch { return code; }
  }

  /* ====================== экраны ====================== */

  function show(name) {
    $('screen-auth').classList.toggle('hidden', name !== 'auth');
    $('screen-main').classList.toggle('hidden', name !== 'main');
    Planet.setScene(name === 'auth' ? 'auth' : 'main');
  }

  function setMode(mode) {
    S.mode = mode;
    const reg = mode === 'register';
    $('tab-login').setAttribute('aria-selected', String(!reg));
    $('tab-register').setAttribute('aria-selected', String(reg));
    $('f-repeat').classList.toggle('hidden', !reg);
    $('f-invite').classList.toggle('hidden', !(reg && S.inviteRequired));
    $('f-password').autocomplete = reg ? 'new-password' : 'current-password';
    $('auth-submit').firstElementChild.textContent = reg ? 'Создать аккаунт' : 'Войти';
    $('auth-error').textContent = '';
  }

  function enterMain(username) {
    S.loggedIn = true;
    $('user-name').textContent = username;
    $('f-password').value = ''; $('f-repeat').value = '';
    show('main');
  }

  function leaveToAuth() {
    S.loggedIn = false;
    applyVpn('disconnected');
    setMode('login');
    show('auth');
  }

  /* ====================== вход и регистрация ====================== */

  function validateAuth() {
    const u = $('f-username').value.trim();
    const p = $('f-password').value;
    if (!u || !p) return 'Введите логин и пароль';
    if (S.mode === 'register') {
      if (!/^[A-Za-z0-9_]{3,30}$/.test(u)) return 'Логин: 3–30 символов, латиница, цифры и _';
      if (p.length < 8) return 'Пароль должен быть не короче 8 символов';
      if (p !== $('f-repeat').value) return 'Пароли не совпадают';
      if (S.inviteRequired && !$('f-invite').value.trim()) return 'Введите код приглашения';
    }
    return '';
  }

  async function submitAuth(e) {
    e.preventDefault();
    if (S.configError || S.busy) return;
    const problem = validateAuth();
    $('auth-error').textContent = problem;
    if (problem) return;

    S.busy = true; setBusy($('auth-submit'), true);
    try {
      const username = $('f-username').value.trim();
      const args = { username, password: $('f-password').value };
      if (S.mode === 'register') args.invite = $('f-invite').value.trim();
      const res = await bridge.call(S.mode, args);
      enterMain(res.username || username);
    } catch (err) {
      $('auth-error').textContent = err.message;
    } finally {
      S.busy = false; setBusy($('auth-submit'), false);
    }
  }

  /* ====================== VPN ====================== */

  function applyServer(loc) {
    if (loc && loc.countryCode) {
      $('srv-code').textContent = loc.countryCode.toUpperCase();
      $('srv-country').textContent = countryName(loc.countryCode);
      $('srv-city').textContent = loc.city || ' ';
    }
    Planet.setServer(loc && typeof loc.lat === 'number' ? loc : null);
  }

  function applyVpn(state, message = '', since = 0) {
    S.vpn = state;
    S.since = since || 0;
    document.body.dataset.vpn = state;

    const text = { disconnected: 'Не защищено', connecting: 'Подключение…', connected: 'Вы защищены', error: 'Не удалось подключиться' }[state] || '';
    $('status-text').textContent = text;
    $('status-sub').textContent = message || (state === 'connected' ? 'Ваш трафик идёт через защищённый канал' : ' ');
    $('srv-state').textContent = { disconnected: 'Готов', connecting: 'Подключаем', connected: 'Подключено', error: 'Ошибка' }[state] || '';
    $('power').setAttribute('aria-label', state === 'disconnected' || state === 'error' ? 'Подключить' : state === 'connecting' ? 'Отменить подключение' : 'Отключить');
    Planet.setState(state === 'connected' ? 'connected' : state === 'connecting' ? 'connecting' : 'idle');

    if (state !== 'connected') {
      $('timer').textContent = '00:00:00';
      resetStats();
    }
    if (state === 'error' && message) toast(message, true);
  }

  function resetStats() {
    $('st-down').textContent = '0'; $('st-down-u').textContent = 'кбит/с';
    $('st-up').textContent = '0'; $('st-up-u').textContent = 'кбит/с';
    $('st-ping').textContent = '—';
  }

  function onEvent(m) {
    if (m.event === 'state') {
      applyVpn(m.state, m.message || '', m.since || 0);
    } else if (m.event === 'sessionExpired') {
      leaveToAuth();
      toast(m.message || 'Сессия истекла, войдите заново', true);
    } else if (m.event === 'stats') {
      const [d, du] = fmtSpeed(m.down), [u, uu] = fmtSpeed(m.up);
      $('st-down').textContent = d; $('st-down-u').textContent = du;
      $('st-up').textContent = u; $('st-up-u').textContent = uu;
      $('st-ping').textContent = m.ping > 0 ? String(Math.round(m.ping)) : '—';
    }
  }

  setInterval(() => {
    if (S.vpn === 'connected' && S.since) $('timer').textContent = fmtTime(Date.now() - S.since);
  }, 500);

  async function onPower() {
    try {
      if (S.vpn === 'disconnected' || S.vpn === 'error') {
        applyVpn('connecting', 'Подготовка…');
        await bridge.call('connect');
      } else {
        await bridge.call('disconnect');
      }
    } catch (err) {
      applyVpn('error', err.message);
    }
  }

  /* ====================== меню и смена пароля ====================== */

  function toggleMenu(open) {
    const menu = $('user-menu');
    const next = typeof open === 'boolean' ? open : menu.classList.contains('hidden');
    menu.classList.toggle('hidden', !next);
    $('user-chip').setAttribute('aria-expanded', String(next));
  }

  async function submitPassword(e) {
    e.preventDefault();
    const o = $('p-old').value, n = $('p-new').value, r = $('p-repeat').value;
    const err = $('pw-error');
    err.textContent = '';
    if (!o || !n || !r) { err.textContent = 'Заполните все поля'; return; }
    if (n.length < 8) { err.textContent = 'Новый пароль должен быть не короче 8 символов'; return; }
    if (n !== r) { err.textContent = 'Новые пароли не совпадают'; return; }
    if (n === o) { err.textContent = 'Новый пароль должен отличаться от старого'; return; }

    setBusy($('pw-submit'), true);
    try {
      await bridge.call('changePassword', { oldPassword: o, newPassword: n });
      $('dlg-password').close();
      toast('Пароль изменён');
    } catch (ex) {
      err.textContent = ex.message;
    } finally {
      setBusy($('pw-submit'), false);
    }
  }

  async function logout() {
    toggleMenu(false);
    try { await bridge.call('logout'); } catch { /* выходим в любом случае */ }
    leaveToAuth();
  }

  /* ====================== запуск ====================== */

  function wire() {
    $('tab-login').addEventListener('click', () => setMode('login'));
    $('tab-register').addEventListener('click', () => setMode('register'));
    $('auth-form').addEventListener('submit', submitAuth);
    $('pw-toggle').addEventListener('click', () => {
      const f = $('f-password');
      const showIt = f.type === 'password';
      f.type = showIt ? 'text' : 'password';
      $('f-repeat').type = f.type;
      $('pw-toggle').setAttribute('aria-label', showIt ? 'Скрыть пароль' : 'Показать пароль');
    });

    $('power').addEventListener('click', onPower);
    $('user-chip').addEventListener('click', (e) => { e.stopPropagation(); toggleMenu(); });
    document.addEventListener('click', (e) => { if (!$('user-menu').contains(e.target)) toggleMenu(false); });
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') toggleMenu(false); });

    $('menu-logout').addEventListener('click', logout);
    $('menu-password').addEventListener('click', () => {
      toggleMenu(false);
      ['p-old', 'p-new', 'p-repeat'].forEach((id) => { $(id).value = ''; });
      $('pw-error').textContent = '';
      $('dlg-password').showModal();
    });
    $('pw-cancel').addEventListener('click', () => $('dlg-password').close());
    $('pw-form').addEventListener('submit', submitPassword);

    // кнопки окна и перетаскивание за заголовок работают только внутри приложения
    $('btn-min').addEventListener('click', () => hasHost && bridge.call('window', { action: 'minimize' }));
    $('btn-close').addEventListener('click', () => (hasHost ? bridge.call('window', { action: 'close' }) : toast('В демо-режиме окно не закрывается')));
    $('titlebar').addEventListener('mousedown', (e) => {
      if (hasHost && e.button === 0 && !e.target.closest('button')) bridge.call('window', { action: 'drag' });
    });
  }

  async function start() {
    Planet.init($('planet'));
    Planet.setScene('auth');
    wire();
    applyVpn('disconnected');
    setMode('login');

    let info;
    try {
      info = await bridge.call('init');
    } catch (err) {
      info = { configError: err.message };
    }

    S.inviteRequired = !!info.inviteRequired;
    S.configError = info.configError || null;
    applyServer(info.location);
    setMode('login');

    if (info.demo) toast('Демо-режим: вход с любым логином и паролем от 8 символов, код приглашения: demo');

    if (S.configError) {
      const n = $('config-error');
      n.textContent = S.configError;
      n.classList.remove('hidden');
      $('auth-submit').disabled = true;
      show('auth');
      return;
    }
    if (info.offline) toast(info.offline, true);

    if (info.loggedIn) {
      enterMain(info.username);
      applyVpn(info.state || 'disconnected', info.message || '', info.since || 0);
    } else {
      show('auth');
    }
  }

  start();
})();
