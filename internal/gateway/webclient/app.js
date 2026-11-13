(() => {
  const out = document.getElementById('out');
  const status = document.getElementById('status');
  const line = document.getElementById('line');
  let ws = null;
  const dec = new TextDecoder();
  const enc = new TextEncoder();

  function append(text) {
    out.textContent += text.replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, '').replace(/\r/g, '');
    out.scrollTop = out.scrollHeight;
  }

  document.getElementById('connect').addEventListener('submit', (e) => {
    e.preventDefault();
    if (ws) { ws.close(); return; }
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    ws = new WebSocket(scheme + '//' + location.host + '/', [document.getElementById('proto').value]);
    ws.binaryType = 'arraybuffer';
    status.textContent = 'Connecting…';
    ws.onopen = () => {
      status.textContent = 'Connected (' + ws.protocol + ')';
      document.getElementById('go').textContent = 'Disconnect';
      // Identify ourselves the way real web clients do, as soon as we connect.
      sendHello();
      line.focus();
    };
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') append('[GMCP] ' + ev.data + '\n');
      else append(dec.decode(ev.data));
    };
    ws.onclose = (ev) => { status.textContent = 'Disconnected (' + ev.code + ')'; document.getElementById('go').textContent = 'Connect'; ws = null; };
  });

  document.getElementById('send').addEventListener('submit', (e) => {
    e.preventDefault();
    if (!ws || ws.readyState !== 1) return;
    append(line.value + '\n');
    ws.send(enc.encode(line.value + '\n'));
    line.value = '';
  });
  function sendHello() {
    if (ws && ws.readyState === 1) ws.send('Core.Hello {"client":"Sentience test client","version":"1"}');
  }
  document.getElementById('hello').addEventListener('click', sendHello);
  document.getElementById('bad').addEventListener('click', () => {
    if (ws && ws.readyState === 1) ws.send('Core.Hello {not json');
  });
})();
