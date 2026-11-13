/* 口令宝 · OTP 验证器 — 应用逻辑 */
import {
  generateTOTP, generateNextTOTP, formatCode,
  parseOtpauthURI, buildOtpauthURI, validateEntry, normalizeSecret,
} from './totp.js';
import {
  isMigrationText, parseMigrationPayload, MigrationSession,
} from './migration.js';
import {
  createEncryptedZip, readZip, inspectZip, isZipBytes,
} from './zipcrypt.js';

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const VAULT_KEY = 'otp-vault-v1';

const state = {
  entries: [],
  encrypted: false,
  pinKey: null,
  salt: null,
  pendingBlob: null,
  locked: false,
  masked: false,
  query: '',
  editingId: null,
  codeCache: new Map(),
  deferredPrompt: null,
  migration: new MigrationSession(),
  migrationPreview: [],
  pendingZipBytes: null,
};

/* ---------------- 基础工具 ---------------- */
const enc = new TextEncoder();
const dec = new TextDecoder();

function toast(msg, ms = 2200) {
  const el = $('#toast');
  el.textContent = msg;
  el.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.remove('show'), ms);
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function uid() {
  return globalThis.crypto?.randomUUID?.() || `id-${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

function toB64(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromB64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function hashCode(s) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

function avatar(initial, seed) {
  const hue = hashCode(seed) % 360;
  return `<div class="avatar" style="background:linear-gradient(135deg,hsl(${hue} 72% 58%),hsl(${(hue + 28) % 360} 70% 44%))">${esc(initial)}</div>`;
}

function initialOf(name) {
  const s = String(name || '?').trim();
  return s ? s[0].toUpperCase() : '?';
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch { /* ignore */ }
    ta.remove();
  }
}

/* ---------------- 本地加密存储 ---------------- */
async function deriveKey(pin, saltBytes) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations: 150000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function saveVault() {
  const plain = enc.encode(JSON.stringify({ v: 1, entries: state.entries }));
  if (state.encrypted && state.pinKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, state.pinKey, plain);
    localStorage.setItem(VAULT_KEY, JSON.stringify({
      v: 1, encrypted: true, salt: state.salt,
      iv: toB64(iv), data: toB64(new Uint8Array(cipher)),
    }));
  } else {
    localStorage.setItem(VAULT_KEY, JSON.stringify({ v: 1, encrypted: false, entries: state.entries }));
  }
}

async function loadVault() {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) return;
  let obj;
  try { obj = JSON.parse(raw); } catch { return; }
  if (obj.encrypted) {
    state.encrypted = true;
    state.salt = obj.salt;
    state.pendingBlob = obj;
    state.locked = true;
  } else {
    state.entries = Array.isArray(obj.entries) ? obj.entries : [];
  }
}

async function unlock(pin) {
  const blob = state.pendingBlob || JSON.parse(localStorage.getItem(VAULT_KEY));
  const key = await deriveKey(pin, fromB64(blob.salt));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.data)
  );
  const data = JSON.parse(dec.decode(plain));
  state.entries = Array.isArray(data.entries) ? data.entries : [];
  state.pinKey = key;
  state.salt = blob.salt;
  state.pendingBlob = null;
  state.locked = false;
  $('#lock-screen').classList.add('hidden');
  $('#unlock-error').classList.add('hidden');
  $('#unlock-pin').value = '';
  render();
  await tick();
}

function lock() {
  if (!state.encrypted) {
    state.masked = true;
    $('#btn-hide').textContent = '显示';
    applyMask();
    toast('已隐藏验证码；启用 PIN 加密锁可真正加密数据');
    return;
  }
  state.entries = [];
  state.codeCache.clear();
  state.pinKey = null;
  state.pendingBlob = JSON.parse(localStorage.getItem(VAULT_KEY));
  state.locked = true;
  $('#list').innerHTML = '';
  $('#lock-screen').classList.remove('hidden');
  setTimeout(() => $('#unlock-pin').focus(), 50);
}

async function enablePin(pin) {
  if (!/^\d{4,12}$/.test(pin)) throw new Error('PIN 需为 4-12 位数字');
  const salt = crypto.getRandomValues(new Uint8Array(16));
  state.salt = toB64(salt);
  state.pinKey = await deriveKey(pin, salt);
  state.encrypted = true;
  await saveVault();
}

async function verifyPin(pin) {
  const blob = JSON.parse(localStorage.getItem(VAULT_KEY));
  const key = await deriveKey(pin, fromB64(blob.salt));
  await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.data)
  );
  return key;
}

async function disablePin(pin) {
  await verifyPin(pin); // 校验失败会抛错
  state.encrypted = false;
  state.pinKey = null;
  state.salt = null;
  await saveVault(); // 以明文写回
}

/* ---------------- 渲染 ---------------- */
function visibleEntries() {
  const q = state.query.trim().toLowerCase();
  return [...state.entries]
    .filter((e) => !q || `${e.issuer} ${e.account}`.toLowerCase().includes(q))
    .sort((a, b) => (b.pinned ? 1 : 0) - (a.pinned ? 1 : 0) || (a.createdAt || 0) - (b.createdAt || 0));
}

const ICONS = {
  pin: '<svg viewBox="0 0 24 24" class="ico"><path d="m15 3 6 6-3 1-4 4-1 5-2-2-4 4-1-1 4-4-2-2 5-1 4-4 1-3Z"/></svg>',
  edit: '<svg viewBox="0 0 24 24" class="ico"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/></svg>',
  del: '<svg viewBox="0 0 24 24" class="ico"><path d="M4 7h16M9 7V4h6v3m-8 0 1 13h8l1-13M10 11v6m4-6v6"/></svg>',
};

function cardHTML(e) {
  return `
  <article class="otp-card ${e.pinned ? 'pinned' : ''}" data-id="${esc(e.id)}">
    ${e.pinned ? '<i class="pin-badge"></i>' : ''}
    <div class="card-head">
      ${avatar(initialOf(e.issuer), e.issuer || e.account || '?')}
      <div class="card-meta">
        <strong>${esc(e.issuer || '未命名')}</strong>
        <span>${esc(e.account || '未填写账号')}</span>
      </div>
      <div class="card-tools">
        <button class="icon-btn ${e.pinned ? 'active' : ''}" data-act="pin" title="置顶/取消置顶" aria-label="置顶">${ICONS.pin}</button>
        <button class="icon-btn" data-act="edit" title="编辑" aria-label="编辑">${ICONS.edit}</button>
        <button class="icon-btn" data-act="del" title="删除" aria-label="删除">${ICONS.del}</button>
      </div>
    </div>
    <div class="code-row">
      <div class="code" data-code title="点击复制验证码">------</div>
      <span class="copy-hint">点击复制</span>
    </div>
    <div class="card-foot"><span class="next">下组 --</span><span class="remain">--s</span></div>
    <div class="progress"><i></i></div>
  </article>`;
}

function applyMask() {
  $$('#list [data-code]').forEach((el) => el.classList.toggle('masked', state.masked));
  $('#btn-hide').textContent = state.masked ? '显示' : '隐藏';
}

function render() {
  if (state.locked) return;
  const list = visibleEntries();
  $('#list').innerHTML = list.map(cardHTML).join('');
  $('#count').textContent = state.entries.length
    ? `${state.entries.length} 个账号${state.query ? ` · 匹配 ${list.length}` : ''}`
    : '';
  $('#empty').classList.toggle('hidden', state.entries.length > 0);
  applyMask();
  return tick();
}

async function tick() {
  if (state.locked) return;
  const now = Date.now();
  for (const card of $$('#list .otp-card')) {
    const entry = state.entries.find((x) => x.id === card.dataset.id);
    if (!entry) continue;
    const period = Number(entry.period) || 30;
    let cached = state.codeCache.get(entry.id);
    if (!cached || cached.counter !== Math.floor(now / 1000 / period) || cached.secret !== entry.secret) {
      try {
        const cur = await generateTOTP({ ...entry, timestamp: now });
        const nxt = await generateNextTOTP(entry, now);
        cached = { counter: cur.counter, code: cur.code, next: nxt.code, secret: entry.secret };
        state.codeCache.set(entry.id, cached);
        $('[data-code]', card).textContent = formatCode(cached.code);
        $('.next', card).textContent = `下组 ${formatCode(cached.next)}`;
      } catch (err) {
        $('[data-code]', card).textContent = '密钥有误';
        $('[data-code]', card).title = err.message;
        continue;
      }
    }
    const remaining = period - (Math.floor(now / 1000) % period);
    $('.remain', card).textContent = `${remaining}s`;
    const bar = $('.progress > i', card);
    bar.style.width = `${(remaining / period) * 100}%`;
    const warn = remaining <= 5;
    $('[data-code]', card).classList.toggle('warn', warn);
    $('.progress', card).classList.toggle('warn', warn);
  }
}

/* ---------------- 增删改 ---------------- */
async function addOrUpdate(entry) {
  const clean = validateEntry(entry);
  if (state.editingId) {
    const idx = state.entries.findIndex((x) => x.id === state.editingId);
    if (idx >= 0) state.entries[idx] = { ...state.entries[idx], ...clean };
  } else {
    state.entries.push({
      ...clean, id: uid(), pinned: false, createdAt: Date.now(),
    });
  }
  state.codeCache.clear();
  await saveVault();
  await render();
}

function confirmBox(title, text, okLabel = '确定') {
  return new Promise((resolve) => {
    $('#confirm-title').textContent = title;
    $('#confirm-text').textContent = text;
    $('#confirm-ok').textContent = okLabel;
    const dlg = $('#dlg-confirm');
    const cleanup = (result) => {
      dlg.close();
      $('#confirm-ok').onclick = null;
      $('#confirm-cancel').onclick = null;
      resolve(result);
    };
    $('#confirm-ok').onclick = () => cleanup(true);
    $('#confirm-cancel').onclick = () => cleanup(false);
    dlg.showModal();
  });
}

/* ---------------- 谷歌验证器批量迁移 ---------------- */
function migrationDuplicate(a) {
  const secret = normalizeSecret(a.secret);
  return !!secret && state.entries.some((e) => normalizeSecret(e.secret) === secret);
}

function resetMigration() {
  state.migration.reset();
  state.migrationPreview = [];
  renderMigrationProgress();
}

function renderMigrationProgress() {
  const s = state.migration;
  const p = s.progress();
  const count = s.accounts().length;
  const has = s.parts.size > 0;
  const label = p.mode === 'batch'
    ? `已读取 ${p.total}/${p.size} 张二维码${p.missing.length
      ? ` · 还缺第 ${p.missing.map((i) => i + 1).join('、')} 张` : ' · 已集齐'}`
    : `已读取 ${p.total} 张二维码`;
  $$('.migration-progress').forEach((el) => {
    el.classList.toggle('hidden', !has);
    if (!has) return;
    $('.mp-label', el).textContent = `${label} · 共 ${count} 个账号`;
    $('.mp-bar > i', el).style.width = p.mode === 'batch'
      ? `${Math.round((p.total / p.size) * 100)}%` : '100%';
  });
}

/** 把若干条二维码文本加入当前批次，返回成功条数与最后的错误 */
function ingestMigrationTexts(texts) {
  let ok = 0; let lastErr = '';
  for (const t of texts) {
    const v = String(t ?? '').trim();
    if (!v || !isMigrationText(v)) continue;
    try { state.migration.add(v); ok++; }
    catch (err) { lastErr = err.message; }
  }
  renderMigrationProgress();
  return { ok, lastErr };
}

function openMigrationReview() {
  const accounts = state.migration.accounts();
  if (!accounts.length) { toast('这批二维码里没有可导入的账号'); return false; }
  state.migrationPreview = accounts.map((a) => {
    const duplicate = migrationDuplicate(a);
    return { ...a, duplicate, selected: !a.skipReason && !duplicate };
  });
  renderMigrationReview();
  $('#dlg-migration').showModal();
  return true;
}

function renderMigrationReview() {
  const items = state.migrationPreview;
  const p = state.migration.progress();
  const checkable = items.filter((x) => !x.skipReason);
  const unsupported = items.length - checkable.length;
  const duplicated = checkable.filter((x) => x.duplicate).length;
  $('#gm-summary').textContent = `共解析出 ${items.length} 个账号 · 可导入 ${checkable.filter((x) => !x.duplicate).length} 个`
    + (unsupported ? ` · ${unsupported} 个不支持` : '')
    + (duplicated ? ` · ${duplicated} 个密钥已存在` : '');

  const warn = $('#gm-warning');
  if (p.mode === 'batch' && p.missing.length) {
    warn.textContent = `⚠️ 这批导出共 ${p.size} 张二维码，目前只读取到 ${p.total} 张（还缺第 ${p.missing.map((i) => i + 1).join('、')} 张）。可以先导入已读到的账号，或点「继续扫码」补齐。`;
    warn.classList.remove('hidden');
  } else {
    warn.classList.add('hidden');
  }

  $('#gm-list').innerHTML = items.map((x, i) => `
    <label class="gm-item ${x.skipReason || x.duplicate ? 'disabled' : ''}">
      <input type="checkbox" data-gm-idx="${i}" ${x.selected ? 'checked' : ''} ${x.skipReason ? 'disabled' : ''}>
      <span class="gm-avatar">${esc(initialOf(x.issuer))}</span>
      <span class="gm-text"><strong>${esc(x.issuer)}</strong><small>${esc(x.account || '未填写账号')}</small></span>
      <span class="gm-tag">${esc(x.algorithm)} · ${x.digits} 位</span>
      ${x.skipReason ? `<span class="gm-bad">${esc(x.skipReason)}</span>`
        : x.duplicate ? '<span class="gm-bad dup">密钥已存在</span>' : ''}
    </label>`).join('');

  const n = items.filter((x) => x.selected).length;
  $('#gm-count').textContent = `已选 ${n} 个`;
  $('#btn-gm-import').textContent = `导入选中 ${n} 个账号`;
  $('#btn-gm-import').disabled = n === 0;
  $('#gm-all').checked = checkable.length > 0 && items.every((x) => x.skipReason || x.selected);
}

async function importSelectedMigration() {
  const chosen = state.migrationPreview.filter((x) => x.selected);
  if (!chosen.length) return;
  let added = 0; let skipped = 0;
  for (const item of chosen) {
    try {
      const clean = validateEntry(item);
      if (state.entries.some((e) => normalizeSecret(e.secret) === clean.secret)) { skipped++; continue; }
      state.entries.push({ ...clean, id: uid(), pinned: false, createdAt: Date.now() });
      added++;
    } catch { skipped++; }
  }
  state.codeCache.clear();
  await saveVault();
  await render();
  $('#dlg-migration').close();
  closeAdd();
  resetMigration();
  toast(`已从谷歌验证器导入 ${added} 个账号${skipped ? `，跳过 ${skipped} 个重复/无效项` : ''}`, 3200);
}

/* ---------------- 弹窗 / 标签页 ---------------- */
function openAdd(tab = 'scan', entry = null) {
  state.editingId = entry?.id || null;
  $('#add-title').textContent = entry ? '编辑账号' : '添加账号';
  $('#f-issuer').value = entry?.issuer || '';
  $('#f-account').value = entry?.account || '';
  $('#f-secret').value = entry?.secret || '';
  $('#f-algorithm').value = entry?.algorithm || 'SHA1';
  $('#f-digits').value = String(entry?.digits || 6);
  $('#f-period').value = String(entry?.period || 30);
  $('#f-uri').value = '';
  renderMigrationProgress();
  switchTab(entry ? 'manual' : tab);
  $('#dlg-add').showModal();
}

function closeAdd() {
  stopScan();
  $('#dlg-add').close();
  state.editingId = null;
}

function switchTab(name) {
  $$('.tab').forEach((t) => t.classList.toggle('active', t.dataset.tab === name));
  $$('.tab-panel').forEach((p) => p.classList.toggle('hidden', p.dataset.panel !== name));
  if (name !== 'scan') stopScan();
}

/* ---------------- 二维码识别 ---------------- */
let scanStream = null;
let scanTimer = null;
let scanning = false;
const scanCanvas = document.createElement('canvas');
const scanCtx = scanCanvas.getContext('2d', { willReadFrequently: true });
let detector = null;

async function loadJsQR() {
  if (window.jsQR) return window.jsQR;
  await new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = './vendor/jsQR.js';
    s.onload = resolve;
    s.onerror = () => reject(new Error('二维码解码组件加载失败'));
    document.head.appendChild(s);
  });
  return window.jsQR;
}

function scanStatus(msg, both = true) {
  $('#scan-status').textContent = msg;
  if (both) $('#gm-status').textContent = msg;
}

async function decodeCanvas(canvas) {
  try {
    if (!('BarcodeDetector' in window)) throw new Error('no native detector');
    if (!detector) detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    const found = await detector.detect(canvas);
    if (found.length) return found[0].rawValue;
  } catch { /* 回退到 jsQR */ }
  try {
    const jsQR = await loadJsQR();
    const img = scanCtx.getImageData(0, 0, canvas.width, canvas.height);
    const result = jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' });
    return result?.data || null;
  } catch {
    return null;
  }
}

function drawToCanvas(source, w, h) {
  const scale = Math.min(1, 800 / Math.max(w, h));
  scanCanvas.width = Math.max(1, Math.round(w * scale));
  scanCanvas.height = Math.max(1, Math.round(h * scale));
  scanCtx.drawImage(source, 0, 0, scanCanvas.width, scanCanvas.height);
  return scanCanvas;
}

/**
 * 处理一条二维码文本。
 * 返回 true = 已处理完并可停止扫码；'continue' = 识别成功但还要继续扫下一张；false = 失败。
 */
async function handleScanText(text) {
  const value = String(text || '').trim();
  if (!value) return false;

  // 谷歌验证器「导出账号」二维码：可能分成多张，需要连续扫
  if (isMigrationText(value)) {
    try {
      const res = state.migration.add(value);
      renderMigrationProgress();
      if (res.restart) toast('检测到新一批导出二维码，已重新计数', 1800);
      if (res.status === 'duplicate') return 'continue'; // 同一张重复识别，忽略
      const p = state.migration.progress();
      if (p.complete) {
        stopScan();
        return openMigrationReview() ? true : 'continue';
      }
      scanStatus(`✅ 已读取第 ${p.total}/${p.size} 张，请翻到下一张二维码继续扫`);
      return 'continue';
    } catch (err) {
      scanStatus(`谷歌导出二维码解析失败：${err.message}`);
      return false;
    }
  }

  if (!/^otpauth:\/\/totp\//i.test(value)) {
    scanStatus('这不是 OTP 二维码，请扫描网站「两步验证」或谷歌验证器「导出账号」的二维码');
    return false;
  }
  try {
    const parsed = parseOtpauthURI(value);
    await addOrUpdate(parsed);
    closeAdd();
    toast(`已添加 ${parsed.issuer}`);
    return true;
  } catch (err) {
    scanStatus(`解析失败：${err.message}`);
    return false;
  }
}

let lastScanText = '';
let lastScanAt = 0;

async function cameraLoop() {
  if (!scanning) return;
  const video = $('#scan-video');
  if (video.readyState >= 2 && video.videoWidth) {
    const canvas = drawToCanvas(video, video.videoWidth, video.videoHeight);
    const text = await decodeCanvas(canvas);
    if (text && scanning) {
      // 同一张二维码短时间内不重复处理，给翻页留时间
      const now = Date.now();
      if (text !== lastScanText || now - lastScanAt > 1800) {
        lastScanText = text;
        lastScanAt = now;
        const r = await handleScanText(text);
        if (r === true) return;
      }
    }
  }
  scanTimer = setTimeout(cameraLoop, 220);
}

function stopScan() {
  scanning = false;
  lastScanText = '';
  clearTimeout(scanTimer);
  if (scanStream) {
    scanStream.getTracks().forEach((t) => t.stop());
    scanStream = null;
  }
  const video = $('#scan-video');
  video.pause();
  video.srcObject = null;
  scanStatus('点击下方按钮开启摄像头，把二维码放进框内', false);
  $('#btn-camera').textContent = '开启摄像头';
}

async function startCamera() {
  if (!navigator.mediaDevices?.getUserMedia) {
    scanStatus('当前环境不支持摄像头，请用「上传二维码图片」');
    return;
  }
  if (scanning) { stopScan(); return; }
  try {
    scanStream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' }, width: { ideal: 1280 } }, audio: false,
    });
    const video = $('#scan-video');
    video.srcObject = scanStream;
    await video.play();
    scanning = true;
    lastScanText = '';
    lastScanAt = 0;
    $('#btn-camera').textContent = '关闭摄像头';
    scanStatus('识别中…把二维码放进框内；谷歌导出的多张二维码请连续扫完');
    cameraLoop();
  } catch (err) {
    scanStatus(`无法访问摄像头（${err.name}）。可改用「上传二维码图片」`);
  }
}

/**
 * 解码一张图片里的二维码。
 * Android WebView 从相册选择器拿到的是 content:// 文件，createImageBitmap 在部分机型上
 * 会报 "The source image could not be decoded."，因此优先走 <img> + object URL，失败再回退。
 */
async function decodeImageFile(file) {
  let source; let w; let h; let cleanup = () => {};
  try {
    const url = URL.createObjectURL(file);
    cleanup = () => URL.revokeObjectURL(url);
    const img = await new Promise((resolve, reject) => {
      const el = new Image();
      el.onload = () => resolve(el);
      el.onerror = () => reject(new Error('图片无法加载'));
      el.src = url;
    });
    source = img; w = img.naturalWidth; h = img.naturalHeight;
  } catch {
    cleanup();
    const bitmap = await createImageBitmap(file);
    source = bitmap; w = bitmap.width; h = bitmap.height;
    cleanup = () => bitmap.close?.();
  }
  try {
    return await decodeCanvas(drawToCanvas(source, w, h));
  } finally {
    cleanup();
  }
}

/** 一次处理一张或多张二维码截图：谷歌导出会自动合并分批 */
async function processImageFiles(fileList) {
  const files = [...(fileList || [])];
  if (!files.length) return;
  const texts = [];
  for (let i = 0; i < files.length; i++) {
    scanStatus(`正在识别第 ${i + 1}/${files.length} 张图片…`);
    try {
      const text = await decodeImageFile(files[i]);
      if (text) texts.push(String(text).trim());
      else scanStatus(`第 ${i + 1} 张里没找到二维码，换一张更清晰的试试`);
    } catch (err) {
      scanStatus(`第 ${i + 1} 张读取失败：${err.message}`);
    }
  }
  if (!texts.length) return;
  scanStatus(`识别完成，共读取 ${texts.length} 张二维码${texts.length < files.length ? `（${files.length - texts.length} 张未识别）` : ''}`);

  const mig = texts.filter(isMigrationText);
  const rest = texts.filter((t) => !isMigrationText(t));
  let added = 0; let lastErr = '';
  for (const v of rest) {
    if (!/^otpauth:\/\/totp\//i.test(v)) { lastErr = '这不是 TOTP 二维码'; continue; }
    try { await addOrUpdate(parseOtpauthURI(v)); added++; }
    catch (err) { lastErr = err.message; }
  }

  if (mig.length) {
    const r = ingestMigrationTexts(mig);
    if (!r.ok && !added) {
      scanStatus(`解析失败：${r.lastErr || '二维码内容无法识别'}`);
      return;
    }
    stopScan();
    openMigrationReview();
    if (added) toast(`另已添加 ${added} 个普通二维码账号`);
    return;
  }
  if (added) { closeAdd(); toast(`已添加 ${added} 个账号`); }
  else scanStatus(`识别失败：${lastErr || '未找到有效的 OTP 二维码'}`);
}

/* ---------------- 备份（加密 ZIP） ---------------- */
function backupJSON() {
  return JSON.stringify({
    app: 'otp-vault', version: 1, exportedAt: new Date().toISOString(),
    entries: state.entries,
    uris: state.entries.map(buildOtpauthURI),
  }, null, 2);
}

function bytesToB64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

/** 浏览器用 Blob 下载；安卓壳走原生桥写入系统「下载」目录 */
function saveBytes(bytes, filename) {
  const bridge = window.OtpVault;
  if (bridge && typeof bridge.saveBackup === 'function') {
    const r = String(bridge.saveBackup(bytesToB64(bytes), filename) || '');
    if (r.startsWith('error:')) throw new Error(r.slice(6));
    return r; // 'ok' | 'picker'
  }
  const blob = new Blob([bytes], { type: 'application/zip' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  return 'ok';
}

function openExportDialog() {
  if (!state.entries.length) { toast('还没有账号，先添加后再导出'); return; }
  $('#ex-password').value = '';
  $('#ex-password2').value = '';
  syncChoiceStyles();
  $('#dlg-export').showModal();
  setTimeout(() => $('#ex-password').focus(), 60);
}

function syncChoiceStyles() {
  $$('.choice').forEach((c) => c.classList.toggle('selected', $('input', c).checked));
}

function selectedExportMode() {
  return $$('input[name="ex-mode"]').find((r) => r.checked)?.value || 'aes';
}

async function doExport() {
  const pwd = $('#ex-password').value;
  const pwd2 = $('#ex-password2').value;
  if (pwd.length < 6) { toast('密码至少 6 位，建议用更长的密码', 3200); return; }
  if (pwd !== pwd2) { toast('两次输入的密码不一致', 3200); return; }
  const btn = $('#btn-ex-save');
  btn.disabled = true;
  btn.textContent = '正在加密…';
  try {
    const zip = await createEncryptedZip({
      content: backupJSON(), password: pwd, mode: selectedExportMode(),
    });
    const name = `otp-backup-${new Date().toISOString().slice(0, 10)}.zip`;
    const result = saveBytes(zip, name);
    $('#dlg-export').close();
    toast(result === 'picker' ? '请在弹出的窗口选择保存位置' : `已导出加密备份 ${name}`, 3600);
  } catch (err) {
    toast(`导出失败：${err.message}`, 3600);
  } finally {
    btn.disabled = false;
    btn.textContent = '生成加密 ZIP';
    $('#ex-password').value = '';
    $('#ex-password2').value = '';
  }
}

/** 把备份里的文本解析成账号并合并进本机（兼容旧版明文 JSON / otpauth 列表） */
async function applyBackupText(text) {
  const trimmed = String(text).trim();
  if (!trimmed) throw new Error('备份内容为空');
  let incoming = [];
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    const obj = JSON.parse(trimmed);
    const raw = Array.isArray(obj) ? obj : (obj.entries || []);
    incoming = raw.map((e) => (e.secret ? e : parseOtpauthURI(String(e))));
  } else {
    const lines = trimmed.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    for (const line of lines) {
      if (isMigrationText(line)) {
        incoming.push(...parseMigrationPayload(line).accounts.filter((a) => !a.skipReason));
      } else {
        incoming.push(parseOtpauthURI(line));
      }
    }
  }
  let added = 0;
  for (const item of incoming) {
    const clean = validateEntry(item);
    const dup = state.entries.some((e) =>
      e.secret === clean.secret && e.issuer === clean.issuer && e.account === clean.account);
    if (dup) continue;
    state.entries.push({ ...clean, id: uid(), pinned: false, createdAt: Date.now() });
    added++;
  }
  await saveVault();
  await render();
  toast(`导入完成：新增 ${added} 个账号${incoming.length - added ? `，跳过 ${incoming.length - added} 个重复/无效项` : ''}`);
}

function openEncryptedBackup(bytes, filename) {
  state.pendingZipBytes = bytes;
  $('#zip-pass-name').textContent = filename || '加密备份.zip';
  $('#zip-password').value = '';
  $('#zip-pass-error').classList.add('hidden');
  $('#dlg-zip-pass').showModal();
  setTimeout(() => $('#zip-password').focus(), 60);
}

async function unlockBackup() {
  const pwd = $('#zip-password').value;
  if (!pwd || !state.pendingZipBytes) return;
  const btn = $('#btn-zip-open');
  btn.disabled = true;
  btn.textContent = '正在解密…';
  try {
    const { text } = await readZip(state.pendingZipBytes, pwd);
    $('#dlg-zip-pass').close();
    state.pendingZipBytes = null;
    await applyBackupText(text);
  } catch (err) {
    $('#zip-pass-error').textContent = err.message;
    $('#zip-pass-error').classList.remove('hidden');
    $('#zip-password').select();
  } finally {
    btn.disabled = false;
    btn.textContent = '解锁并导入';
  }
}

async function importBackup(file) {
  if (!file) return;
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    let text;
    if (isZipBytes(bytes)) {
      if (inspectZip(bytes).encrypted) {
        openEncryptedBackup(bytes, file.name);
        return;
      }
      text = (await readZip(bytes)).text;
    } else {
      text = await file.text();
    }
    await applyBackupText(text);
  } catch (err) {
    toast(`导入失败：${err.message}`, 3600);
  }
}

/* ---------------- 设置面板 ---------------- */
function renderPinSettings() {
  const on = state.encrypted;
  $('#pin-badge').textContent = on ? '已启用' : '未启用';
  $('#pin-badge').classList.toggle('on', on);
  $('#pin-desc').textContent = on
    ? '密钥已用 PIN 派生的密钥加密保存。锁定或重新打开应用时需要输入 PIN。忘记 PIN 只能清空数据重新添加。'
    : '开启后，所有密钥会用 PIN 派生的密钥进行 AES-GCM 加密，锁定或重新打开时需要输入 PIN。';
  $('#pin-input').placeholder = on ? '输入当前 PIN' : '设置 4 位以上数字 PIN';
  $('#pin-input').value = '';
  $('#btn-pin-save').textContent = on ? '关闭加密锁' : '启用';
  $('#btn-pin-remove').classList.toggle('hidden', !on);
  $('#btn-pin-remove').textContent = '忘记 PIN？清空加密数据重新添加';
}

/* ---------------- 安装引导 ---------------- */
function setupInstall() {
  // 原生 Android 壳内已经是可安装 App，不再显示网页安装引导
  if (/OTPVaultAndroid/.test(navigator.userAgent)) {
    $('#btn-install').classList.add('hidden');
    return;
  }
  const standalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
  const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) ||
    (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  const tip = $('#install-tip');
  const showTip = (html) => {
    $('#install-tip-text').innerHTML = html;
    tip.classList.remove('hidden');
  };

  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    state.deferredPrompt = e;
    if (!standalone) $('#btn-install').classList.remove('hidden');
  });
  $('#btn-install').addEventListener('click', async () => {
    if (!state.deferredPrompt) return;
    state.deferredPrompt.prompt();
    const { outcome } = await state.deferredPrompt.userChoice;
    state.deferredPrompt = null;
    $('#btn-install').classList.add('hidden');
    toast(outcome === 'accepted' ? '正在安装…' : '已取消安装');
  });
  window.addEventListener('appinstalled', () => {
    $('#btn-install').classList.add('hidden');
    showTip('✅ 安装完成！现在可以从桌面或开始菜单打开「口令宝」，离线也能用。');
  });
  $('#install-tip-close').addEventListener('click', () => tip.classList.add('hidden'));

  if (isIOS && !standalone) {
    showTip('在 iPhone / iPad 上点击底部「分享」按钮 → 选择「添加到主屏幕」，即可像 App 一样打开。');
  } else if (!standalone && !state.deferredPrompt) {
    // 稍后若浏览器未触发安装事件，给出手动安装提示
    setTimeout(() => {
      if (!state.deferredPrompt && !$('#btn-install').classList.contains('hidden')) return;
      if (state.deferredPrompt) return;
      showTip('想装到桌面？在浏览器菜单中选择「安装应用 / 安装此站点」或「创建快捷方式」即可。');
    }, 2500);
  }
}

/* ---------------- 事件绑定 ---------------- */
function bindEvents() {
  $('#btn-add').addEventListener('click', () => openAdd('scan'));
  $$('[data-open-add]').forEach((b) =>
    b.addEventListener('click', () => openAdd(b.dataset.openAdd)));
  $$('[data-close]').forEach((b) =>
    b.addEventListener('click', () => {
      if (b.dataset.close === 'dlg-add') closeAdd();
      else $(`#${b.dataset.close}`).close();
    }));
  $('#dlg-add').addEventListener('close', () => { stopScan(); state.editingId = null; });
  $$('.tab').forEach((t) => t.addEventListener('click', () => switchTab(t.dataset.tab)));

  $('#btn-camera').addEventListener('click', startCamera);
  $('#scan-file').addEventListener('change', (e) => {
    processImageFiles(e.target.files);
    e.target.value = '';
  });
  $('#gm-files').addEventListener('change', (e) => {
    processImageFiles(e.target.files);
    e.target.value = '';
  });
  $$('.mp-open').forEach((b) => b.addEventListener('click', () => {
    stopScan();
    openMigrationReview();
  }));
  $$('.mp-reset').forEach((b) => b.addEventListener('click', () => {
    resetMigration();
    toast('已清空本次读取的二维码');
  }));

  $('#btn-save-manual').addEventListener('click', async () => {
    try {
      await addOrUpdate({
        issuer: $('#f-issuer').value.trim(),
        account: $('#f-account').value.trim(),
        secret: $('#f-secret').value,
        algorithm: $('#f-algorithm').value,
        digits: Number($('#f-digits').value),
        period: Number($('#f-period').value),
      });
      closeAdd();
      toast(state.editingId ? '已保存修改' : '账号已添加');
    } catch (err) { toast(err.message, 3000); }
  });

  $('#btn-save-uri').addEventListener('click', async () => {
    const lines = $('#f-uri').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!lines.length) return toast('请先粘贴 otpauth 或 otpauth-migration 链接');
    const mig = lines.filter(isMigrationText);
    const rest = lines.filter((l) => !isMigrationText(l));
    let ok = 0; let lastErr = '';
    for (const line of rest) {
      try { await addOrUpdate(parseOtpauthURI(line)); ok++; }
      catch (err) { lastErr = err.message; }
    }
    if (mig.length) {
      const r = ingestMigrationTexts(mig);
      if (!r.ok && !ok) return toast(`解析失败：${r.lastErr || lastErr}`, 3400);
      $('#f-uri').value = '';
      openMigrationReview();
      if (ok) toast(`另已添加 ${ok} 个 otpauth 账号`);
    } else if (ok) {
      closeAdd(); toast(`已添加 ${ok} 个账号`);
    } else {
      toast(`解析失败：${lastErr}`, 3400);
    }
  });

  $('#btn-gm-parse').addEventListener('click', () => {
    const lines = $('#gm-links').value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (!lines.length) return toast('请先粘贴导出二维码的链接，或选择截图');
    const r = ingestMigrationTexts(lines);
    if (!r.ok) return toast(`解析失败：${r.lastErr || '没有找到谷歌导出数据'}`, 3400);
    $('#gm-links').value = '';
    openMigrationReview();
  });

  $('#gm-list').addEventListener('change', (e) => {
    const input = e.target.closest('[data-gm-idx]');
    if (!input) return;
    state.migrationPreview[Number(input.dataset.gmIdx)].selected = input.checked;
    renderMigrationReview();
  });
  $('#gm-all').addEventListener('change', (e) => {
    state.migrationPreview.forEach((x) => { if (!x.skipReason) x.selected = e.target.checked; });
    renderMigrationReview();
  });
  $('#btn-gm-import').addEventListener('click', importSelectedMigration);
  $('#btn-gm-rescan').addEventListener('click', () => {
    $('#dlg-migration').close();
    switchTab('scan');
    if (!$('#dlg-add').open) $('#dlg-add').showModal();
    startCamera();
  });
  $('#btn-gm-clear').addEventListener('click', () => {
    $('#dlg-migration').close();
    resetMigration();
    toast('已清空，可重新扫描');
  });

  $('#search').addEventListener('input', (e) => { state.query = e.target.value; render(); });
  $('#btn-hide').addEventListener('click', () => { state.masked = !state.masked; applyMask(); });

  $('#list').addEventListener('click', async (e) => {
    const card = e.target.closest('.otp-card');
    if (!card) return;
    const id = card.dataset.id;
    const entry = state.entries.find((x) => x.id === id);
    if (!entry) return;
    const actBtn = e.target.closest('[data-act]');
    if (actBtn) {
      const act = actBtn.dataset.act;
      if (act === 'pin') {
        entry.pinned = !entry.pinned;
        await saveVault(); await render();
      } else if (act === 'edit') {
        openAdd('manual', entry);
      } else if (act === 'del') {
        const yes = await confirmBox('删除账号', `确定删除「${entry.issuer}${entry.account ? ' · ' + entry.account : ''}」吗？删除后该账号的验证码将无法恢复。`, '删除');
        if (!yes) return;
        state.entries = state.entries.filter((x) => x.id !== id);
        state.codeCache.delete(id);
        await saveVault(); await render();
        toast('已删除');
      }
      return;
    }
    if (e.target.closest('[data-code]') && !state.masked) {
      const cached = state.codeCache.get(id);
      if (cached) { await copyText(cached.code); toast(`已复制 ${formatCode(cached.code)}`); }
    }
  });

  $('#btn-lock').addEventListener('click', lock);
  $('#btn-unlock').addEventListener('click', async () => {
    const pin = $('#unlock-pin').value.trim();
    if (!pin) return;
    try {
      await unlock(pin);
      toast('已解锁');
    } catch {
      $('#unlock-error').classList.remove('hidden');
      $('#unlock-pin').select();
    }
  });
  $('#unlock-pin').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') $('#btn-unlock').click();
  });

  $('#btn-settings').addEventListener('click', () => {
    renderPinSettings();
    $('#dlg-settings').showModal();
  });
  $('#btn-export').addEventListener('click', openExportDialog);
  $('#btn-ex-cancel').addEventListener('click', () => $('#dlg-export').close());
  $('#btn-ex-save').addEventListener('click', doExport);
  $('#ex-password2').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doExport();
  });
  $$('input[name="ex-mode"]').forEach((r) =>
    r.addEventListener('change', syncChoiceStyles));
  $('#btn-zip-cancel').addEventListener('click', () => $('#dlg-zip-pass').close());
  $('#btn-zip-open').addEventListener('click', unlockBackup);
  $('#zip-password').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') unlockBackup();
  });
  $('#dlg-zip-pass').addEventListener('close', () => { state.pendingZipBytes = null; });
  $('#import-file').addEventListener('change', (e) => {
    importBackup(e.target.files?.[0]);
    e.target.value = '';
  });
  $('#btn-pin-save').addEventListener('click', async () => {
    const pin = $('#pin-input').value.trim();
    if (!pin) return toast('请输入 PIN');
    try {
      if (state.encrypted) {
        await disablePin(pin);
        toast('加密锁已关闭，数据以明文保存在本机');
      } else {
        await enablePin(pin);
        toast('PIN 加密锁已启用');
      }
      renderPinSettings();
    } catch (err) {
      toast(state.encrypted ? 'PIN 不正确，请重试' : err.message, 3000);
    }
  });
  $('#btn-pin-remove').addEventListener('click', async () => {
    const yes = await confirmBox('清空加密数据', '忘记 PIN 后无法恢复已有密钥。确定清空全部账号并关闭加密锁吗？', '清空数据');
    if (!yes) return;
    state.encrypted = false; state.pinKey = null; state.salt = null;
    state.entries = []; state.codeCache.clear();
    await saveVault(); await render();
    renderPinSettings();
    toast('已清空');
  });
  $('#btn-clear').addEventListener('click', async () => {
    const yes = await confirmBox('清空所有账号', '这将删除本机保存的全部密钥，操作不可撤销。建议先导出备份。', '全部清空');
    if (!yes) return;
    state.entries = []; state.codeCache.clear();
    await saveVault(); await render();
    $('#dlg-settings').close();
    toast('已清空所有账号');
  });

  $('#btn-demo').addEventListener('click', async () => {
    await addOrUpdate({
      issuer: '示例 · GitHub', account: 'demo@example.com',
      secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30,
    });
    toast('演示账号已添加，可随时删除');
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) tick();
  });
}

/* ---------------- 启动 ---------------- */
async function init() {
  if (!globalThis.crypto?.subtle) {
    document.body.innerHTML = '<div style="padding:40px;text-align:center;font-family:sans-serif">当前环境不支持 Web Crypto（需通过 https 或 localhost 打开）。请用本地服务或在线地址访问本应用。</div>';
    return;
  }
  await loadVault();
  bindEvents();
  setupInstall();
  // Android 壳由内置本地服务直接提供资源，无需 Service Worker 缓存
  if (!/OTPVaultAndroid/.test(navigator.userAgent)
      && 'serviceWorker' in navigator && location.protocol !== 'file:') {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
  setInterval(tick, 1000);
  if (state.locked) {
    $('#lock-screen').classList.remove('hidden');
    setTimeout(() => $('#unlock-pin').focus(), 50);
  } else {
    await render();
  }
  if (new URLSearchParams(location.search).get('action') === 'add') openAdd('scan');
}

init().catch((err) => {
  console.error(err);
  toast(`启动失败：${err.message}`, 5000);
});
