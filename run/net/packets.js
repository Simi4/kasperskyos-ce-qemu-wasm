/* Живая панель сетевых пакетов qemu-wasm.
 * Перехватывает WebSocket, через который emscripten эмулирует TCP для
 * -netdev socket. В потоке — кадры с 4-байтным BE-префиксом длины,
 * внутри — Ethernet-кадры гостя. */
(function () {
  const isWorker = typeof document === 'undefined';
  const bc = new BroadcastChannel('kos-net-packets');
  const streams = { in: new Uint8Array(0), out: new Uint8Array(0) };
  const stats = { in: 0, out: 0 };
  let tbody = null, statsEl = null, bodyEl = null;
  let seq = 0;
  const MAX_ROWS = 500;

  const mac = (b, o) => Array.from(b.subarray(o, o + 6))
    .map(x => x.toString(16).padStart(2, '0')).join(':');
  const ip4 = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

  function decodeDhcp(src, dst, u) {
    const types = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
    let t = 0;
    for (let i = 240; i + 1 < u.length;) {
      const opt = u[i];
      if (opt === 255) break;
      if (opt === 0) { i++; continue; }
      if (opt === 53) { t = u[i + 2]; break; }
      i += 2 + u[i + 1];
    }
    return { proto: 'DHCP', info: `${types[t] || 'type ' + t} ${ip4(u, 16)} (${src} → ${dst})` };
  }

  function decodeDns(src, dst, sp, dp, u) {
    if (u.length < 12) return { proto: 'DNS', info: `${src} → ${dst}` };
    const isResp = (u[2] & 0x80) !== 0;
    let name = '', i = 12;
    while (i < u.length && u[i] !== 0 && name.length < 120) {
      const n = u[i];
      if ((n & 0xc0) === 0xc0) break; // compression pointer
      name += String.fromCharCode(...u.subarray(i + 1, i + 1 + n)) + '.';
      i += 1 + n;
    }
    const qtype = u[i + 2];
    const types = { 1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 65: 'HTTPS' };
    return { proto: 'DNS', info: `${isResp ? 'ответ' : 'запрос'} ${types[qtype] || qtype || ''} ${name} (${src}:${sp} → ${dst}:${dp})` };
  }

  function decode(f) {
    if (f.length < 14) return { proto: '?', info: f.length + ' байт' };
    const et = (f[12] << 8) | f[13];
    if (et === 0x0806 && f.length >= 42) {
      const op = (f[20] << 8) | f[21];
      const ops = { 1: 'who-has', 2: 'is-at', 3: 'RARP req', 4: 'RARP reply' };
      return { proto: 'ARP', info: `${ops[op] || op} ${ip4(f, 38)}, sender ${ip4(f, 28)} (${mac(f, 22)})` };
    }
    if (et === 0x86dd) return { proto: 'IPv6', info: `${mac(f, 6)} → ${mac(f, 0)}` };
    if (et !== 0x0800) return { proto: '0x' + et.toString(16), info: `${mac(f, 6)} → ${mac(f, 0)}, ${f.length} байт` };
    const ihl = (f[14] & 15) * 4;
    const p = f[23];
    const src = ip4(f, 26), dst = ip4(f, 30);
    const base = 14 + ihl;
    if (p === 1) {
      const names = { 0: 'echo reply', 8: 'echo request', 3: 'dest unreach', 11: 'ttl exceeded' };
      return { proto: 'ICMP', info: `${names[f[base]] || 'type ' + f[base]}: ${src} → ${dst}` };
    }
    if (p === 6) {
      const sp = (f[base] << 8) | f[base + 1], dp = (f[base + 2] << 8) | f[base + 3];
      const fl = f[base + 13];
      const flags = [['S', 2], ['A', 16], ['F', 1], ['R', 4], ['P', 8]]
        .filter(x => fl & x[1]).map(x => x[0]).join('');
      return { proto: 'TCP', info: `${src}:${sp} → ${dst}:${dp} [${flags}]` };
    }
    if (p === 17) {
      const sp = (f[base] << 8) | f[base + 1], dp = (f[base + 2] << 8) | f[base + 3];
      const u = f.subarray(base + 8);
      if ((sp === 67 && dp === 68) || (sp === 68 && dp === 67)) return decodeDhcp(src, dst, u);
      if (sp === 53 || dp === 53) return decodeDns(src, dst, sp, dp, u);
      if (sp === 123 || dp === 123) return { proto: 'NTP', info: `${src}:${sp} → ${dst}:${dp}` };
      return { proto: 'UDP', info: `${src}:${sp} → ${dst}:${dp}, ${u.length}б` };
    }
    return { proto: 'IP/' + p, info: `${src} → ${dst}` };
  }

  function onFrame(dir, frame) {
    stats[dir]++;
    const { proto, info } = decode(frame);
    if (isWorker) {
      // qemu работает в pthread-worker'е — шлём пакеты на страницу
      bc.postMessage({ dir, proto, info, stats: { in: stats.in, out: stats.out } });
      return;
    }
    renderRow(dir, proto, info, stats);
  }

  function renderRow(dir, proto, info, st) {
    if (statsEl) statsEl.textContent = `гость→хост: ${st.out} · хост→гость: ${st.in}`;
    if (!tbody) return;
    const tr = document.createElement('tr');
    tr.className = dir === 'out' ? 'net-out' : 'net-in';
    const time = new Date().toLocaleTimeString('ru-RU');
    tr.innerHTML = `<td>${++seq}</td><td>${time}</td><td>${dir === 'out' ? '→' : '←'}</td><td>${proto}</td><td></td>`;
    tr.lastChild.textContent = info;
    tbody.appendChild(tr);
    while (tbody.rows.length > MAX_ROWS) tbody.deleteRow(0);
    if (bodyEl) bodyEl.scrollTop = bodyEl.scrollHeight;
  }

  function feed(dir, chunk) {
    const prev = streams[dir];
    const buf = new Uint8Array(prev.length + chunk.length);
    buf.set(prev); buf.set(chunk, prev.length);
    let off = 0;
    while (buf.length - off >= 4) {
      const n = (buf[off] << 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3];
      if (n > 65535 || n === 0) { off = buf.length; break; }
      if (buf.length - off < 4 + n) break;
      onFrame(dir, buf.subarray(off + 4, off + 4 + n));
      off += 4 + n;
    }
    streams[dir] = buf.slice(off);
  }

  function debug(proto, info) {
    if (isWorker) bc.postMessage({ dir: 'out', proto, info, stats: { in: 0, out: 0 } });
    else renderRow('out', proto, info, stats);
  }

  /* Виртуальный WebSocket: принимает поток Ethernet-кадров от qemu и
   * передаёт его в панель. Ответов нет — режим предназначен только для наблюдения. */
  class VirtualWebSocket extends EventTarget {
    constructor(url) {
      super();
      this.url = url;
      this.readyState = 0;
      this.binaryType = 'blob';
      this.onopen = this.onmessage = this.onerror = this.onclose = null;
      setTimeout(() => {
        this.readyState = 1;
        const ev = new Event('open');
        if (this.onopen) this.onopen(ev);
        this.dispatchEvent(ev);
      }, 0);
    }
    send(data) {
      if (this.readyState !== 1) return;
      const observe = (buf) => feed('out', new Uint8Array(buf));
      if (data instanceof ArrayBuffer) observe(data);
      else if (ArrayBuffer.isView(data)) {
        observe(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
      } else if (data instanceof Blob) data.arrayBuffer().then(observe);
    }
    close() {
      this.readyState = 3;
      const ev = new Event('close');
      if (this.onclose) this.onclose(ev);
      this.dispatchEvent(ev);
    }
  }
  VirtualWebSocket.CONNECTING = 0;
  VirtualWebSocket.OPEN = 1;
  VirtualWebSocket.CLOSING = 2;
  VirtualWebSocket.CLOSED = 3;

  function install() {
    globalThis.addEventListener('error', (e) => {
      bc.postMessage({ dir: 'out', proto: 'ERR', info: String(e.message || e), stats: { in: 0, out: 0 } });
    });
    globalThis.addEventListener('unhandledrejection', (e) => {
      bc.postMessage({ dir: 'out', proto: 'REJ', info: String(e.reason && e.reason.message || e.reason), stats: { in: 0, out: 0 } });
    });
    const Native = globalThis.WebSocket;
    const Wrapped = function (url, protocols) {
      // ws://net-browser/ = in-browser стек (net=browser), остальное — реальные WS
      if (url === 'ws://net-browser/') {
        return new VirtualWebSocket(url);
      }
      const ws = new Native(url, protocols);
      ws.addEventListener('message', (ev) => {
        if (ev.data instanceof ArrayBuffer) feed('in', new Uint8Array(ev.data));
        else if (ev.data instanceof Blob) ev.data.arrayBuffer().then(b => feed('in', new Uint8Array(b)));
      });
      const send = ws.send.bind(ws);
      ws.send = (data) => {
        try {
          if (data instanceof ArrayBuffer) feed('out', new Uint8Array(data));
          else if (ArrayBuffer.isView(data)) feed('out', new Uint8Array(data.buffer, data.byteOffset, data.byteLength));
          else if (data instanceof Blob) data.arrayBuffer().then(b => feed('out', new Uint8Array(b)));
        } catch (e) { /* не мешаем основному потоку */ }
        return send(data);
      };
      return ws;
    };
    // emscripten может использовать статические константы и prototype
    Wrapped.CONNECTING = Native.CONNECTING;
    Wrapped.OPEN = Native.OPEN;
    Wrapped.CLOSING = Native.CLOSING;
    Wrapped.CLOSED = Native.CLOSED;
    Wrapped.prototype = Native.prototype;
    globalThis.WebSocket = Wrapped;
  }

  function createPanel() {
    const style = document.createElement('style');
    style.textContent = `
      #net-panel { border-top: 1px solid #21262d; background: #0d1117; display: flex;
        flex-direction: column; height: 220px; flex: none; font: 12px Consolas, monospace; }
      #net-panel.collapsed #net-body { display: none; }
      #net-panel.collapsed { height: auto; }
      #net-head { display: flex; gap: 14px; align-items: center; padding: 5px 12px;
        color: #7d8590; border-bottom: 1px solid #21262d; }
      #net-head b { color: #e6edf3; font-weight: 600; }
      #net-head button { margin-left: auto; background: #161b22; color: #7d8590;
        border: 1px solid #30363d; border-radius: 4px; padding: 2px 10px; cursor: pointer; }
      #net-head button + button { margin-left: 0; }
      #net-body { overflow-y: auto; flex: 1; }
      #net-body table { width: 100%; border-collapse: collapse; }
      #net-body td { padding: 1px 10px; white-space: nowrap; text-align: left; }
      #net-body td:last-child { white-space: normal; word-break: break-all; }
      #net-body thead td { color: #7d8590; position: sticky; top: 0; background: #0d1117; }
      .net-out td { color: #7ee2a8; }
      .net-in td { color: #79b8ff; }
    `;
    document.head.appendChild(style);
    const el = document.createElement('div');
    el.id = 'net-panel';
    el.innerHTML = `
      <div id="net-head"><b>Сетевые пакеты</b><span id="net-stats">гость→хост: 0 · хост→гость: 0</span>
        <button id="net-toggle">Свернуть</button><button id="net-clear">Очистить</button></div>
      <div id="net-body"><table>
        <thead><tr><td>#</td><td>Время</td><td></td><td>Протокол</td><td>Информация</td></tr></thead>
        <tbody></tbody></table></div>`;
    document.body.appendChild(el);
    tbody = el.querySelector('tbody');
    statsEl = el.querySelector('#net-stats');
    bodyEl = el.querySelector('#net-body');
    el.querySelector('#net-toggle').onclick = (ev) => {
      el.classList.toggle('collapsed');
      ev.target.textContent = el.classList.contains('collapsed') ? 'Развернуть' : 'Свернуть';
    };
    el.querySelector('#net-clear').onclick = () => { tbody.innerHTML = ''; };
    // пакеты из pthread-worker'а qemu
    bc.onmessage = (ev) => {
      const d = ev.data;
      renderRow(d.dir, d.proto, d.info, d.stats);
    };
  }

  globalThis.NetPackets = { install, createPanel };
})();
