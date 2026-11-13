'use strict';

// Ten sam algorytm co KPB.Services/MojaSluzbaCode.cs - zmiana jednego bez drugiego unieważni
// wszystkie dostępy. Kod losuje SAM TELEFON przy prośbie o dostęp (nie ma go na papierze) i wysyła
// go administratorowi; po zatwierdzeniu w KPB w pamięci telefonu zostaje tylko klucz AES i id wpisu.
// Dostęp działa rok od zatwierdzenia - potem wpis znika z pliku i trzeba poprosić o nowy.
// Od 2026-10-25 klucz w telefonie jest dodatkowo zamknięty PIN-em (4-6 cyfr, PBKDF2 + AES-GCM):
// bez PIN-u strona nic nie pokaże, 5 złych prób albo 30 dni bez otwierania kasuje dostęp,
// a po 2 minutach bezczynności strona znowu pyta o PIN.
const SALT_PREFIX = 'KPB-MojaSluzba-v1|';
const ITERATIONS = 600000;
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 16;      // starsze telefony mają 12 znaków - też działają
const PIN_MAX_FAILS = 5;
const UNUSED_DAYS = 30;
const LOCK_AFTER_MS = 2 * 60 * 1000;
const PUSH_ATTEMPTS = 3;
const MISSING_GRACE_DAYS = 5;
const WAITING_CHECK_MS = 30000;
const STORAGE_KEY = 'kpb-moja-sluzba';
const SESSION_KEY = 'kpb-moja-sluzba-sesja';
const DATA_FILE = 'moja-sluzba.json';
// Publiczny klucz wysyłki powiadomień; prywatny jest tylko w sekrecie GitHub Actions.
const VAPID_PUBLIC_KEY = 'BMdIs6T8zcpJKll-h7lqEPP1nYB7-beF-lGvTkbAfdB-X3BD7DXr76P1IdYkTdD7AFVlIfZ4ETvpbNLJGFi2IZM';

function normalizeCode(input) {
  return (input || '').replace(/[\s-]/g, '').toUpperCase();
}

function formatCode(code) {
  const c = normalizeCode(code);
  return c.length === CODE_LENGTH || c.length === 12 ? c.match(/.{4}/g).join('-') : c;
}

// Losowanie z odrzucaniem (256 nie dzieli się przez 31), żeby każdy znak był równie prawdopodobny.
function generateCode() {
  const limit = 256 - (256 % ALPHABET.length);
  let code = '';
  while (code.length < CODE_LENGTH) {
    for (const b of globalThis.crypto.getRandomValues(new Uint8Array(32))) {
      if (b < limit && code.length < CODE_LENGTH) code += ALPHABET[b % ALPHABET.length];
    }
  }
  return code;
}

function toHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function toBase64(bytes) {
  let s = '';
  bytes.forEach(b => { s += String.fromCharCode(b); });
  return btoa(s);
}

function fromBase64(text) {
  const s = atob(text);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

async function deriveCredentials(code) {
  const subtle = globalThis.crypto.subtle;
  const normalized = normalizeCode(code);
  const encoder = new TextEncoder();
  const saltHash = new Uint8Array(await subtle.digest('SHA-256', encoder.encode(SALT_PREFIX + normalized)));
  const baseKey = await subtle.importKey('raw', encoder.encode(normalized), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: saltHash.slice(0, 16), iterations: ITERATIONS }, baseKey, 512));
  return { key: toBase64(bits.slice(0, 32)), id: toHex(bits.slice(32, 64)) };
}

// Wpis osoby i pełne rozkazy szyfrowane tak samo (AES-256-GCM, tag na końcu ct), różnymi kluczami.
// Klucz w telefonie zamknięty PIN-em: osobna sól na telefon, ta sama liczba iteracji co kod.
async function pinKey(pin, salt) {
  const subtle = globalThis.crypto.subtle;
  const baseKey = await subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function lockKey(pin, keyBase64) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv },
    await pinKey(pin, salt), new TextEncoder().encode(keyBase64)));
  return { salt: toBase64(salt), iv: toBase64(iv), ct: toBase64(ct) };
}

// Zły PIN = wyjątek z AES-GCM (tag się nie zgadza).
async function unlockKey(pin, lock) {
  const plain = await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(lock.iv) },
    await pinKey(pin, fromBase64(lock.salt)), fromBase64(lock.ct));
  return new TextDecoder().decode(plain);
}

async function decryptEntry(keyBase64, entry) {
  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey('raw', fromBase64(keyBase64), 'AES-GCM', false, ['decrypt']);
  const plain = await subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(entry.iv) }, key, fromBase64(entry.ct));
  return JSON.parse(new TextDecoder().decode(plain).trim());
}

// Adres powiadomień do wiadomości dla admina: zaszyfrowany kluczem wpisu tego telefonu, tym samym
// AES-GCM co wpis (KPB.Services/MojaSluzbaPushRegistration odszyfrowuje i po tym poznaje telefon).
async function buildPushBlob(credentials, subscription) {
  const json = subscription.toJSON();
  const plain = JSON.stringify({ endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth });
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await globalThis.crypto.subtle.importKey('raw', fromBase64(credentials.key), 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plain)));
  return `KPB-PUSH1:${credentials.id}:${toBase64(iv)}:${toBase64(ct)}`;
}

async function buildPushMessage(name, credentials, subscription) {
  return `${name} włącza powiadomienia Moja służba.\n${await buildPushBlob(credentials, subscription)}`;
}

// Ten sam skrót co MojaSluzbaPushSubscription.Hash w KPB.
async function pushHash(endpoint) {
  const hash = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(endpoint)));
  return toHex(hash).slice(0, 16);
}

const SHIFT_ROMAN = { 1: 'I', 2: 'II', 3: 'III' };

// Lista "Dalej" pod kartą najbliższej służby: służby na innej zmianie i dyżury, od najbliższej daty.
// Starsza kopia danych w telefonie (bez internetu) może mieć tylko homeDuty.
function buildNextItems(entry, today) {
  const duties = entry.md || (entry.homeDuty || []).map(d => ({ date: d.date, duty: 'Dyżur domowy' }));
  const items = [
    ...(entry.os || []).map(o => ({
      date: o.date,
      icon: '🚒',
      what: [`służba Zm. ${SHIFT_ROMAN[o.shift] || ''}`.trim(), o.vehicle, o.function].filter(Boolean).join(' · ')
    })),
    ...duties.map(d => ({ date: d.date, icon: d.duty === 'Oficer operacyjny' ? '⭐' : '🏠', what: (d.duty || '').toLowerCase() }))
  ];
  return items.filter(i => i.date >= today).sort((a, b) => (a.date < b.date ? -1 : a.date > b.date ? 1 : 0));
}

if (typeof module !== 'undefined') {
  module.exports = { normalizeCode, formatCode, generateCode, deriveCredentials, decryptEntry, lockKey, unlockKey, buildPushBlob, buildPushMessage, pushHash, buildNextItems };
}

if (typeof document !== 'undefined') {
  // Przez kilka minut po aktualizacji telefon może mieć nowy skrypt i starą stronę. Brakujący element
  // nie może wtedy zatrzymać całej aplikacji - po prostu nie będzie widoczny.
  const $ = id => document.getElementById(id) || document.createElement('div');
  const form = $('requestForm');
  const nameInput = $('nameInput');
  const requestButton = $('requestButton');
  const errorText = $('errorText');

  const SHIFT_NAMES = { 1: 'Zmiana I', 2: 'Zmiana II', 3: 'Zmiana III' };
  const DAY_NAMES = ['niedziela', 'poniedziałek', 'wtorek', 'środa', 'czwartek', 'piątek', 'sobota'];
  const DAY_SHORT = ['niedz.', 'pon.', 'wt.', 'śr.', 'czw.', 'pt.', 'sob.'];

  let current = null;   // { key, id } aktualnie zalogowanej osoby - klucz tylko w pamięci, po odblokowaniu PIN-em
  let unlocked = null;  // { key, id } po wpisaniu PIN-u, kasowane po LOCK_AFTER_MS bezczynności
  let lastActivity = Date.now();
  let pinMode = null;   // 'enter' | 'setup'
  let pendingSetup = null; // { state, result } - zatwierdzony, czeka na ustawienie PIN-u
  let view = null;      // { entry, generatedAt, rozkazy }
  let tab = 'mine';
  let dayIndex = 0;
  let notificationsOn = false; // admin włączył przypomnienia (jawna flaga w pliku z danymi)
  let pendingUnsubscribe = Promise.resolve();
  let waitingTimer = null;
  let waitingCheckRunning = false;

  function pad(n) { return String(n).padStart(2, '0'); }

  function parseIso(iso) {
    const [y, m, d] = iso.split('-').map(Number);
    return new Date(y, m - 1, d);
  }

  function formatDate(iso) {
    const date = parseIso(iso);
    return `${DAY_NAMES[date.getDay()]}, ${pad(date.getDate())}.${pad(date.getMonth() + 1)}.${date.getFullYear()}`;
  }

  function formatDayMonthYear(iso) {
    const date = parseIso(iso);
    return `${pad(date.getDate())}.${pad(date.getMonth() + 1)}.${date.getFullYear()}`;
  }

  function todayIso() {
    const now = new Date();
    return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}`;
  }

  function shiftText(shift) {
    return SHIFT_NAMES[shift] ? `${SHIFT_NAMES[shift]} · 8:00 – 8:00` : '';
  }

  function formatGeneratedAt(text) {
    const date = new Date(text);
    if (isNaN(date)) return text;
    return `${pad(date.getDate())}.${pad(date.getMonth() + 1)}.${date.getFullYear()}, ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // W pamięci telefonu przed zatwierdzeniem: { name, code, requestedAt, key, id, approved: false } - kod
  // trzymamy, żeby dało się wysłać prośbę jeszcze raz. Po zatwierdzeniu: { name, id, approved: true,
  // lock, fails, lastOpen } - klucz jest tylko zaszyfrowany PIN-em (lock), kodu już nie ma.
  function loadState() {
    try {
      const saved = JSON.parse(localStorage.getItem(STORAGE_KEY));
      return saved && saved.id && (saved.key || saved.lock) ? saved : null;
    } catch { return null; }
  }

  function saveState(state) {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch { /* tryb prywatny */ }
  }

  // Odświeżenie palcem przeładowuje stronę i kasuje klucz z pamięci. Przez LOCK_AFTER_MS od ostatniego
  // użycia trzymamy go w pamięci tej karty, żeby nie pytać o PIN; po tym czasie i po zamknięciu
  // aplikacji PIN obowiązuje jak zawsze.
  function saveSession() {
    if (!unlocked) return;
    try { sessionStorage.setItem(SESSION_KEY, JSON.stringify({ ...unlocked, at: lastActivity })); } catch { /* bez kopii zapyta o PIN */ }
  }

  function clearSession() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch { /* nic do skasowania */ }
  }

  function restoreSession(state) {
    let saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch { /* jak brak kopii */ }
    clearSession();
    if (!saved || saved.id !== state.id || !saved.key || Date.now() - saved.at > LOCK_AFTER_MS) return;
    unlocked = { key: saved.key, id: saved.id };
    lastActivity = saved.at;
  }

  function forget() {
    unlocked = null;
    clearSession();
    try { localStorage.removeItem(STORAGE_KEY); } catch { /* tryb prywatny */ }
    // Telefon bez dostępu nie powinien dalej dostawać przypomnień. Kasowanie adresu idzie przez sieć,
    // więc nowa prośba musi na nie poczekać (subscribePush), inaczej dostałaby adres chwilę przed jego
    // skasowaniem i wysłała do KPB już martwy.
    if ('serviceWorker' in navigator) {
      pendingUnsubscribe = navigator.serviceWorker.getRegistration()
        .then(r => r && r.pushManager && r.pushManager.getSubscription())
        .then(s => s && s.unsubscribe())
        .catch(() => { /* bez znaczenia dla usunięcia dostępu */ });
    }
  }

  function showError(target, message) {
    target.textContent = message;
    target.hidden = false;
  }

  function hideAll() {
    for (const id of ['disabledCard', 'missingCard', 'mineView', 'allView', 'footer', 'tabs', 'waitingView', 'pinView']) $(id).hidden = true;
    stopWaitingChecks();
    document.body.classList.remove('wide');
    form.hidden = true;
  }

  function showRequest(expired, name, lostMessage) {
    current = null;
    view = null;
    pendingSetup = null;
    hideAll();
    form.hidden = false;
    $('expiredText').hidden = !expired;
    $('lostText').hidden = !lostMessage;
    if (lostMessage) $('lostText').textContent = lostMessage;
    errorText.hidden = true;
    nameInput.value = name || '';
    $('pushAskNote').hidden = !canAskForPush();
  }

  function canAskForPush() {
    return notificationsOn && 'serviceWorker' in navigator && 'PushManager' in window && 'Notification' in window
      && Notification.permission !== 'denied';
  }

  // Usługa powiadomień telefonu potrafi chwilowo odmówić, stąd kilka prób.
  async function subscribePush(registration) {
    await pendingUnsubscribe;
    const padded = VAPID_PUBLIC_KEY.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - VAPID_PUBLIC_KEY.length % 4) % 4);
    for (let attempt = 1; ; attempt++) {
      try {
        return await registration.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: fromBase64(padded) });
      } catch (error) {
        if (attempt >= PUSH_ATTEMPTS || Notification.permission !== 'granted') throw error;
        await new Promise(resolve => setTimeout(resolve, attempt * 1500));
      }
    }
  }

  // Dokłada adres powiadomień do prośby o dostęp i zapamiętuje wynik, żeby strona mogła go pokazać.
  // Każdy problem zostawia prośbę ważną: dostęp działa, tylko bez przypomnień.
  async function attachPush(state, permission) {
    delete state.push;
    delete state.pushError;
    if (!permission) return;
    const work = (async () => {
      if (await permission !== 'granted') return { error: 'brak zgody na powiadomienia' };
      return { push: await buildPushBlob(state, await subscribePush(await navigator.serviceWorker.ready)) };
    })().catch(error => ({ error: (error && error.message) || 'nieznany błąd' }));
    const result = await Promise.race([work,
      new Promise(resolve => setTimeout(() => resolve({ error: 'telefon nie odpowiedział na czas' }), 60000))]);
    if (result.push) state.push = result.push;
    else state.pushError = result.error;
  }

  // Gdy adres poszedł z prośbą, nie ma o czym mówić. Gdy nie poszedł, widać to od razu i można
  // spróbować jeszcze raz przed wysłaniem.
  function renderRequestPush(state) {
    const text = $('pushStatusText');
    const retry = canAskForPush() && !state.push;
    $('pushRetryButton').hidden = !retry;
    text.hidden = !notificationsOn || !!state.push;
    if (retry) text.textContent = `Powiadomienia: NIE dołączone${state.pushError ? ` (${state.pushError})` : ''}. Spróbuj jeszcze raz przed wysłaniem albo wyślij bez nich.`;
    else if (!state.push) text.textContent = 'Powiadomienia: niedostępne na tym telefonie albo zablokowane w jego ustawieniach. Dostęp dostaniesz bez przypomnień.';
  }

  function showWaiting(state, message) {
    current = null;
    view = null;
    hideAll();
    const when = new Date(state.requestedAt);
    $('waitingInfo').textContent = `Prośba z ${pad(when.getDate())}.${pad(when.getMonth() + 1)}.${when.getFullYear()}, ` +
      `${pad(when.getHours())}:${pad(when.getMinutes())} · ${state.name}`;
    $('waitingCode').textContent = formatCode(state.code);
    $('waitingError').hidden = !message;
    if (message) $('waitingError').textContent = message;
    renderRequestPush(state);
    $('waitingView').hidden = false;
    waitingTimer = setInterval(checkWaitingQuietly, WAITING_CHECK_MS);
  }

  // Dopóki ekran czekania jest otwarty, strona sama sprawdza, czy prośbę już zatwierdzono. Po cichu:
  // brak internetu albo brak zatwierdzenia niczego na ekranie nie zmienia.
  function stopWaitingChecks() {
    clearInterval(waitingTimer);
    waitingTimer = null;
  }

  async function checkWaitingQuietly() {
    if (waitingCheckRunning || waitingTimer === null || document.visibilityState !== 'visible') return;
    const state = loadState();
    if (!state || state.approved) return;
    waitingCheckRunning = true;
    try {
      if (await check(state)) await start();
    } catch { /* spróbuje przy następnym razie */ } finally {
      waitingCheckRunning = false;
    }
  }

  function showPin(mode, name) {
    current = null;
    view = null;
    pinMode = mode;
    hideAll();
    const setup = mode === 'setup';
    $('pinTitle').textContent = setup ? 'Dostęp przyznany - ustaw PIN' : `Wpisz PIN${name ? `, ${name.split(' ')[0]}` : ''}`;
    $('pinIntro').textContent = setup
      ? 'Wymyśl 4-6 cyfr. Bez PIN-u nikt, kto weźmie Twój telefon, nie zobaczy rozkazu. Nie da się go odzyskać - po zapomnieniu trzeba poprosić o nowy dostęp.'
      : `Strona jest zablokowana. Po ${PIN_MAX_FAILS} złych próbach telefon traci dostęp.`;
    $('pinRepeatField').hidden = !setup;
    $('pinButton').textContent = setup ? 'Ustaw PIN' : 'Odblokuj';
    $('pinForgotButton').hidden = setup;
    $('pinInput').value = '';
    $('pinRepeat').value = '';
    $('pinError').hidden = true;
    $('pinView').hidden = false;
    $('pinInput').focus();
  }

  // Administrator wyłączył usługę - plik nie ma żadnych wpisów, pokazujemy tylko komunikat.
  function showDisabled() {
    current = null;
    view = null;
    hideAll();
    $('disabledCard').hidden = false;
  }

  // Wpisu nie ma w pliku. Odebrany dostęp i zła wysyłka (stara kopia bazy, inny komputer) wyglądają
  // z telefonu tak samo, więc klucz zostaje przez kilka dni: po naprawie w KPB telefon działa dalej.
  function showMissing() {
    current = null;
    view = null;
    hideAll();
    $('missingCard').hidden = false;
  }

  function renderMine(entry, hasFull) {
    $('resultDate').textContent = entry.date ? formatDate(entry.date) : 'Brak zaplanowanej służby';
    $('resultShift').textContent = shiftText(entry.shift);

    $('stateOn').hidden = entry.status !== 'on';
    $('stateOff').hidden = entry.status !== 'off';
    $('statePending').hidden = entry.status === 'on' || entry.status === 'off';

    if (entry.status === 'on') {
      $('vehicleBlock').hidden = !entry.vehicle;
      $('functionBlock').hidden = !entry.function;
      $('resultVehicle').textContent = entry.vehicle || '';
      $('resultFunction').textContent = entry.function || '';
      // Oficer i dyżur domowy są na stałe pod kwadratem, tu tylko pozostałe dyżury tej służby.
      const otherDuties = (entry.duty || '').split(', ').filter(d => d && !PERMANENT_DUTIES.includes(d)).join(', ');
      $('dutyBlock').hidden = !otherDuties;
      $('resultDuty').textContent = otherDuties;
    }

    renderNext(entry);
    $('staleText').hidden = !(entry.date && entry.date < todayIso());
    $('fullOffText').hidden = hasFull;
  }

  const PERMANENT_DUTIES = ['Oficer operacyjny', 'Dyżur domowy'];

  function renderNext(entry) {
    const list = $('nextList');
    list.replaceChildren();
    const items = buildNextItems(entry, todayIso());
    for (const item of items) {
      const date = parseIso(item.date);
      const row = el('div', 'next-row');
      row.append(el('span', 'next-when', `${item.icon} ${DAY_SHORT[date.getDay()]} ${pad(date.getDate())}.${pad(date.getMonth() + 1)}`),
        el('span', 'next-what', item.what));
      list.append(row);
    }
    $('nextCard').hidden = items.length === 0;
  }

  // "GCBA 5/36 381F25" -> nazwa "GCBA 5/36" + numer operacyjny "381F25" po prawej w nagłówku karty.
  function splitVehicleName(name) {
    const match = /^(.*\S)\s+(\d{3}[A-Z]\d{2,3})$/.exec(name || '');
    return match ? { name: match[1], reg: match[2] } : { name: name || '', reg: '' };
  }

  function isMineRozkaz(r, token) {
    if (!token) return false;
    const people = (r.duties || []).concat(...(r.vehicles || []).map(v => v.crew || []));
    return people.some(p => p.t === token);
  }

  function personRow(person, token) {
    const row = el('div', person.t && person.t === token ? 'row me' : 'row');
    row.append(el('span', 'fn', person.fn), el('span', 'who', person.who));
    return row;
  }

  function renderAll() {
    const token = view.entry.t;
    const rozkazy = (view.rozkazy || []).filter(r => r.date >= todayIso());

    const picker = $('dayPicker');
    picker.replaceChildren();
    $('rozkazBody').replaceChildren();
    $('dutyStrip').replaceChildren();
    const empty = rozkazy.length === 0;
    for (const id of ['rozkazHeader', 'dutyStrip', 'rozkazBody', 'mineHint']) $(id).hidden = empty;
    $('noRozkazyText').hidden = !empty;
    if (empty) return;
    if (dayIndex >= rozkazy.length) dayIndex = 0;

    rozkazy.forEach((r, i) => {
      const date = parseIso(r.date);
      const button = el('button', i === dayIndex ? 'day active' : 'day');
      button.type = 'button';
      button.setAttribute('aria-pressed', String(i === dayIndex));
      const badge = el('span', `shift-badge s${r.shift}`, `Zm. ${SHIFT_ROMAN[r.shift] || ''}${isMineRozkaz(r, token) ? ' · Ty' : ''}`);
      button.append(el('span', 'dow', DAY_NAMES[date.getDay()]),
        el('span', 'dm', `${pad(date.getDate())}.${pad(date.getMonth() + 1)}`), badge);
      button.addEventListener('click', () => { dayIndex = i; renderAll(); });
      picker.append(button);
    });

    const r = rozkazy[dayIndex];
    $('rozkazNumber').textContent = `Rozkaz nr ${r.number}`;
    $('rozkazDate').textContent = `${formatDate(r.date)} · ${SHIFT_NAMES[r.shift] || ''}`;
    $('rozkazMine').hidden = !isMineRozkaz(r, token);

    // Dyżury jako pasek kafelków nad autami.
    const strip = $('dutyStrip');
    for (const person of r.duties || []) {
      const tile = el('div', person.t && person.t === token ? 'duty-tile me' : 'duty-tile');
      tile.append(el('div', 'fn', person.fn), el('div', 'who', person.who));
      strip.append(tile);
    }
    strip.hidden = (r.duties || []).length === 0;

    const body = $('rozkazBody');
    for (const vehicle of r.vehicles || []) {
      const { name, reg } = splitVehicleName(vehicle.name);
      const car = el('div', 'car');
      const head = el('div', 'car-head');
      head.append(el('span', 'car-name', name), el('span', 'car-reg', reg));
      car.append(head);
      for (const person of vehicle.crew || []) car.append(personRow(person, token));
      body.append(car);
    }
  }

  function render() {
    const hasFull = Array.isArray(view.rozkazy);
    hideAll();
    $('tabs').hidden = !hasFull;
    if (!hasFull) tab = 'mine';
    $('tabMine').classList.toggle('active', tab === 'mine');
    $('tabAll').classList.toggle('active', tab === 'all');
    $('tabMine').setAttribute('aria-pressed', String(tab === 'mine'));
    $('tabAll').setAttribute('aria-pressed', String(tab === 'all'));

    document.body.classList.toggle('wide', tab === 'all');
    if (tab === 'mine') {
      renderMine(view.entry, hasFull);
      $('mineView').hidden = false;
    } else {
      renderAll();
      $('allView').hidden = false;
    }
    $('generatedText').textContent = `Stan na ${view.generatedAt ? formatGeneratedAt(view.generatedAt) : '-'}` +
      (view.entry.until ? ` · dostęp do ${formatDayMonthYear(view.entry.until)}` : '') +
      (offline ? ' (bez internetu - ostatnie pobrane dane)' : '');
    $('footer').hidden = false;
    renderPush().catch(() => { $('pushCard').hidden = true; });
  }

  // Powiadomienia: karta tylko wtedy, gdy admin je włączył. Dwa osobne kliknięcia (zgoda, potem
  // wysłanie), bo iPhone wymaga świeżego kliknięcia osobno do zgody i osobno do udostępniania.
  let pushMessage = null;

  function showPush(text, showEnable, showSend) {
    $('pushText').textContent = text;
    $('pushButton').hidden = !showEnable;
    $('pushSendButton').hidden = !showSend;
    $('pushCard').hidden = false;
  }

  async function renderPush() {
    $('pushCard').hidden = true;
    if (!view || !view.entry.pe) return;
    if (isIos && !isStandalone) {
      showPush('Powiadomienia na iPhonie: dodaj stronę do ekranu początkowego i otwórz ją z ikonki (iOS 16.4 lub nowszy).', false, false);
      return;
    }
    if (!('serviceWorker' in navigator) || !('PushManager' in window) || !('Notification' in window)) {
      showPush('Ten telefon albo przeglądarka nie obsługuje powiadomień.', false, false);
      return;
    }
    if (Notification.permission === 'denied') {
      showPush('Powiadomienia są zablokowane w ustawieniach telefonu dla tej strony. Odblokuj je, żeby dostawać przypomnienia.', false, false);
      return;
    }
    const registration = await navigator.serviceWorker.ready;
    const subscription = await registration.pushManager.getSubscription();
    if (subscription && Notification.permission === 'granted') {
      if (view.entry.pn && view.entry.pn === await pushHash(subscription.endpoint)) {
        showPush('Powiadomienia włączone: nowy rozkaz Twojej służby, zmiana Twojego miejsca w nim oraz dzień przed oficerem lub dyżurem domowym, około 18:00.', false, false);
        return;
      }
      pushMessage = await buildPushMessage(loadState().name, current, subscription);
      showPush('Jeszcze jeden krok: wyślij wiadomość do administratora. Po zatwierdzeniu w KPB powiadomienia zaczną działać.', false, true);
      return;
    }
    showPush('Powiadomienie o nowym rozkazie Twojej służby i o zmianie Twojego miejsca w nim, przypomnienie dzień przed oficerem lub dyżurem domowym, około 18:00, także przy zamkniętej stronie.', true, false);
  }

  $('pushButton').addEventListener('click', async () => {
    try {
      if (await Notification.requestPermission() !== 'granted') { await renderPush(); return; }
      await subscribePush(await navigator.serviceWorker.ready);
      await renderPush();
    } catch (error) {
      showPush(`Nie udało się włączyć powiadomień: ${error.message || 'nieznany błąd'}.`, true, false);
    }
  });

  $('pushSendButton').addEventListener('click', async () => {
    if (!pushMessage) return;
    const subject = 'Moja służba - włączenie powiadomień';
    if (navigator.share) {
      try { await navigator.share({ title: subject, text: pushMessage }); return; } catch (error) { if (error && error.name === 'AbortError') return; }
    }
    location.href = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(pushMessage)}`;
  });

  let offline = false;  // dane z kopii w telefonie (sw.js), bo nie ma internetu

  async function loadData() {
    const response = await fetch(DATA_FILE, { cache: 'no-store' });
    if (!response.ok) throw new Error('Nie udało się pobrać danych. Spróbuj za chwilę.');
    offline = response.headers.get('X-KPB-Offline') === '1';
    return response.json();
  }

  async function check(credentials) {
    const data = await loadData();
    notificationsOn = data.notifications === 1;
    if (data.enabled === false) return { disabled: true };
    const encrypted = data.entries && data.entries[credentials.id];
    if (!encrypted) return null;
    let entry;
    try {
      entry = await decryptEntry(credentials.key, encrypted);
    } catch {
      return null;
    }
    // Pełne rozkazy są tylko wtedy, gdy admin je włączył - wtedy klucz do nich jest w naszym wpisie.
    let rozkazy = null;
    if (data.full && entry.rk) {
      try { rozkazy = (await decryptEntry(entry.rk, data.full)).rozkazy || []; } catch { rozkazy = null; }
    }
    // Godzina eksportu jest w zaszyfrowanym wpisie ("g"); jawne generatedAt tylko w starszych plikach.
    return { entry, generatedAt: entry.g || data.generatedAt, rozkazy };
  }

  // Jedno wejście dla każdego stanu: brak dostępu -> prośba, czeka -> sprawdzamy, czy już zatwierdzono,
  // zatwierdzony -> PIN, potem dane; zatwierdzony, ale wpisu już nie ma -> dostęp wygasł/odebrany.
  async function start() {
    const state = loadState();
    if (!state) {
      const data = await loadData().catch(() => null);
      notificationsOn = !!data && data.notifications === 1;
      if (data && data.enabled === false) showDisabled(); else showRequest(false);
      return;
    }
    if (state.lock) {
      if (state.lastOpen && Date.now() - state.lastOpen > UNUSED_DAYS * 86400000) {
        forget();
        showRequest(false, state.name, `Strona nie była otwierana ponad ${UNUSED_DAYS} dni, więc ten telefon stracił dostęp. Poproś o nowy.`);
        return;
      }
      if (!unlocked) restoreSession(state);
      if (!unlocked || unlocked.id !== state.id) {
        showPin('enter', state.name);
        return;
      }
    }
    const credentials = state.lock ? unlocked : state;
    let result;
    try {
      result = await check(credentials);
    } catch (error) {
      if (state.approved) { showRequest(false, state.name); showError(errorText, error.message); }
      else showWaiting(state, error.message);
      return;
    }
    if (result && result.disabled) {
      showDisabled();
      return;
    }
    if (!result) {
      if (state.approved) {
        state.missingSince = state.missingSince || Date.now();
        const expired = state.until && state.until < todayIso();
        if (expired || Date.now() - state.missingSince > MISSING_GRACE_DAYS * 86400000) {
          forget();
          showRequest(true, state.name);
          return;
        }
        saveState(state);
        showMissing();
      } else {
        showWaiting(state);
      }
      return;
    }
    // Pierwsze otwarcie po zatwierdzeniu (albo stary zapis bez PIN-u): najpierw PIN, dopiero potem dane.
    if (!state.lock) {
      pendingSetup = { state, result };
      showPin('setup');
      return;
    }
    state.lastOpen = Date.now();
    state.until = result.entry.until;
    delete state.missingSince;
    saveState(state);
    current = credentials;
    view = result;
    render();
  }

  function lockNow() {
    if (!unlocked) return;
    unlocked = null;
    clearSession();
    const state = loadState();
    if (state && state.lock) showPin('enter', state.name);
  }

  for (const type of ['pointerdown', 'keydown', 'scroll', 'touchstart']) {
    addEventListener(type, () => { lastActivity = Date.now(); }, { passive: true });
  }
  // Zegar w tle bywa wstrzymany, więc sprawdzamy też przy powrocie na kartę.
  setInterval(() => { if (unlocked && Date.now() - lastActivity > LOCK_AFTER_MS) lockNow(); else saveSession(); }, 15000);
  addEventListener('pagehide', saveSession);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') lastActivity = Math.min(lastActivity, Date.now());
    else if (unlocked && Date.now() - lastActivity > LOCK_AFTER_MS) lockNow();
    else checkWaitingQuietly();
  });

  $('pinView').addEventListener('submit', async event => {
    event.preventDefault();
    const pin = $('pinInput').value.trim();
    const pinError = $('pinError');
    pinError.hidden = true;
    if (!/^[0-9]{4,6}$/.test(pin)) {
      showError(pinError, 'PIN to 4-6 cyfr.');
      return;
    }
    const button = $('pinButton');
    const label = button.textContent;
    setBusy(button, true, 'Chwila...', label);
    try {
      if (pinMode === 'setup') {
        if (pin !== $('pinRepeat').value.trim()) {
          showError(pinError, 'PIN-y się różnią.');
          return;
        }
        if (!pendingSetup) { await start(); return; }
        const { state, result } = pendingSetup;
        const lock = await lockKey(pin, state.key);
        saveState({ name: state.name, id: state.id, approved: true, lock, fails: 0, lastOpen: Date.now() });
        unlocked = { key: state.key, id: state.id };
        pendingSetup = null;
        lastActivity = Date.now();
        current = unlocked;
        view = result;
        render();
        return;
      }
      const state = loadState();
      if (!state || !state.lock) { await start(); return; }
      let key;
      try {
        key = await unlockKey(pin, state.lock);
      } catch {
        state.fails = (state.fails || 0) + 1;
        if (state.fails >= PIN_MAX_FAILS) {
          forget();
          showRequest(false, state.name, `${PIN_MAX_FAILS} razy zły PIN - ten telefon stracił dostęp. Poproś o nowy.`);
          return;
        }
        saveState(state);
        $('pinInput').value = '';
        showError(pinError, `Zły PIN. Zostało prób: ${PIN_MAX_FAILS - state.fails}.`);
        return;
      }
      state.fails = 0;
      saveState(state);
      unlocked = { key, id: state.id };
      lastActivity = Date.now();
      await start();
    } catch (error) {
      showError(pinError, error.message || 'Coś poszło nie tak.');
    } finally {
      setBusy(button, false, '', label);
    }
  });

  $('pinForgotButton').addEventListener('click', () => {
    if (!confirm('Bez PIN-u nie da się odblokować strony. Usunąć dostęp z tego telefonu i poprosić o nowy?')) return;
    const state = loadState();
    forget();
    showRequest(false, state && state.name);
  });

  function setBusy(button, busy, label, idleLabel) {
    button.disabled = busy;
    button.textContent = busy ? label : idleLabel;
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    errorText.hidden = true;
    const name = nameInput.value.trim().replace(/\s+/g, ' ');
    if (name.length < 3 || !name.includes(' ')) {
      showError(errorText, 'Wpisz imię i nazwisko.');
      return;
    }
    setBusy(requestButton, true, 'Przygotowuję...', 'Poproś o dostęp');
    try {
      // Zgoda od razu, w tym samym kliknięciu: iPhone odrzuca pytanie zadane później.
      const permission = canAskForPush() ? Notification.requestPermission().catch(() => 'denied') : null;
      const code = generateCode();
      const credentials = await deriveCredentials(code);
      const state = { name, code, requestedAt: Date.now(), key: credentials.key, id: credentials.id, approved: false };
      await attachPush(state, permission);
      saveState(state);
      showWaiting(state);
    } catch (error) {
      showError(errorText, error.message || 'Coś poszło nie tak.');
    } finally {
      setBusy(requestButton, false, '', 'Poproś o dostęp');
    }
  });

  $('sendButton').addEventListener('click', async () => {
    const state = loadState();
    if (!state || !state.code) return;
    const subject = 'Moja służba - prośba o dostęp';
    const text = `${state.name} prosi o dostęp do Moja służba.\nKod telefonu: ${formatCode(state.code)}` +
      (state.push ? `\n${state.push}` : '');
    if (navigator.share) {
      try { await navigator.share({ title: subject, text }); return; } catch (error) { if (error && error.name === 'AbortError') return; }
    }
    location.href = `mailto:?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(text)}`;
  });

  $('pushRetryButton').addEventListener('click', async () => {
    const state = loadState();
    if (!state || !state.code) return;
    const button = $('pushRetryButton');
    const label = button.textContent;
    setBusy(button, true, 'Chwila...', label);
    try {
      await attachPush(state, Notification.requestPermission().catch(() => 'denied'));
      saveState(state);
      renderRequestPush(state);
    } finally {
      setBusy(button, false, '', label);
    }
  });

  $('cancelButton').addEventListener('click', () => {
    if (!confirm('Anulować prośbę o dostęp? Kod z tej prośby przestanie być ważny.')) return;
    const state = loadState();
    forget();
    showRequest(false, state && state.name);
  });

  $('missingRefreshButton').addEventListener('click', () => {
    start().catch(error => { showRequest(false); showError(errorText, error.message); });
  });

  $('missingRequestButton').addEventListener('click', () => {
    if (!confirm('Poprosić o nowy dostęp? Ten telefon straci obecny dostęp.')) return;
    const state = loadState();
    forget();
    showRequest(false, state && state.name);
  });

  $('tabMine').addEventListener('click', () => { tab = 'mine'; if (view) render(); });
  $('tabAll').addEventListener('click', () => { tab = 'all'; if (view) render(); });

  $('refreshButton').addEventListener('click', () => {
    start().catch(error => { showRequest(false); showError(errorText, error.message); });
  });

  $('logoutButton').addEventListener('click', () => {
    if (!confirm('Usunąć dostęp z tego telefonu? Żeby znowu sprawdzać służbę, trzeba będzie poprosić o nowy dostęp.')) return;
    const state = loadState();
    forget();
    tab = 'mine';
    showRequest(false, state && state.name);
  });

  // Na iPhonie ikonka na ekranie ma osobną pamięć od Safari - dostęp trzeba wziąć już z ikonki.
  const isIos = /iPhone|iPad|iPod/.test(navigator.userAgent);
  const isStandalone = navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
  $('iosHint').hidden = !(isIos && !isStandalone);

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => { /* bez kopii offline strona i tak działa */ });
  }

  if (!globalThis.crypto || !globalThis.crypto.subtle) {
    showRequest(false);
    showError(errorText, 'Ta strona musi być otwarta przez bezpieczne połączenie (https).');
    requestButton.disabled = true;
  } else {
    start().catch(error => { showRequest(false); showError(errorText, error.message); });
  }
}
