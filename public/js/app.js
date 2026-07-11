/**
 * app.js
 * Lógica del lado del cliente (Frontend). Controla la simulación de tráfico,
 * actualización de terminal de logs, métricas en tiempo real y la App Apex Vault.
 */

// Estado global del cliente
let activeTab = 'console';
let logsList = [];
let normalTrafficIntervalId = null;
let isNormalSimulating = false;
let exfiltratedUsersFound = new Set();

// IPs fijas para auditoría clara
const ATTACK_IPS = {
  brute_force: '198.51.100.42',
  sqli: '203.0.113.88',
  ddos_prefix: '185.220.101.' // Simula botnet Tor o distribuida
};

// User agents para simulación
const AGENTS = {
  normal: [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36'
  ],
  brute_force: 'Hydra/9.5-src (https://github.com/vanhauser-thc/thc-hydra)',
  sqli: 'sqlmap/1.8.2#stable (https://sqlmap.org)',
  ddos: 'Mozilla/5.0 (compatible; BotnetFlood/2.1; +http://floodsim.com)'
};

// Datos del usuario logueado actualmente en la App de Banco
let loggedUser = null;

// Inicialización de la página
document.addEventListener('DOMContentLoaded', () => {
  fetchSecuritySettings();
  
  // Iniciar sondeo (polling) de logs cada 1.2 segundos
  fetchLogs();
  setInterval(fetchLogs, 1200);

  // Intentar cargar sesión bancaria si quedó en memoria (opcional)
  checkBankSession();
});

/* ==========================================================================
   SISTEMA DE PESTAÑAS
   ========================================================================== */
function switchTab(tabName) {
  activeTab = tabName;
  
  // Actualizar botones de pestaña
  document.getElementById('tab-console-btn').classList.toggle('active', tabName === 'console');
  document.getElementById('tab-bank-btn').classList.toggle('active', tabName === 'bank');
  
  // Actualizar paneles visibles
  document.getElementById('tab-console').classList.toggle('active', tabName === 'console');
  document.getElementById('tab-bank').classList.toggle('active', tabName === 'bank');
}


/* ==========================================================================
   CONFIGURACIÓN DE SEGURIDAD (WAF/VULNERABILIDADES)
   ========================================================================== */
async function fetchSecuritySettings() {
  try {
    const res = await fetch('/api/security-settings');
    const settings = await res.json();
    
    // Sincronizar UI
    document.getElementById('toggle-waf').checked = settings.wafActive;
    document.getElementById('toggle-sqli').checked = settings.sqliVulnerable;
    document.getElementById('toggle-brute').checked = settings.bruteForceVulnerable;
    document.getElementById('toggle-ddos').checked = settings.ddosVulnerable;

    updateWAFBadge(settings.wafActive);
  } catch (err) {
    console.error("Error al sincronizar configuraciones de seguridad:", err);
  }
}

async function updateSecuritySettings() {
  const settings = {
    wafActive: document.getElementById('toggle-waf').checked,
    sqliVulnerable: document.getElementById('toggle-sqli').checked,
    bruteForceVulnerable: document.getElementById('toggle-brute').checked,
    ddosVulnerable: document.getElementById('toggle-ddos').checked
  };

  try {
    const res = await fetch('/api/security-settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(settings)
    });
    const data = await res.json();
    if (data.success) {
      updateWAFBadge(data.settings.wafActive);
    }
  } catch (err) {
    console.error("Error al actualizar políticas en el backend:", err);
  }
}

function updateWAFBadge(isActive) {
  const badge = document.getElementById('waf-badge');
  const banner = document.getElementById('bank-waf-status-banner');
  const bannerText = document.getElementById('bank-waf-status-text');

  if (isActive) {
    badge.textContent = 'ACTIVO';
    badge.className = 'badge active';
    banner.className = 'bank-waf-banner secure';
    bannerText.textContent = 'Seguridad de la App: Alta Protección (WAF ACTIVO e Inspeccionando)';
  } else {
    badge.textContent = 'INACTIVO';
    badge.className = 'badge inactive';
    banner.className = 'bank-waf-banner';
    bannerText.textContent = 'Seguridad de la App: Estado Estándar (WAF Desactivado)';
  }
}


/* ==========================================================================
   VISOR DE LOGS (TERMINAL DE AUDITORÍA) & ESTADÍSTICAS
   ========================================================================== */
let lastLogsCount = 0;
let requestRates = []; // Guardar timestamp de solicitudes para RPS

async function fetchLogs() {
  try {
    const res = await fetch('/api/logs');
    const logs = await res.json();
    
    logsList = logs;
    renderLogs();
    calculateStats();
  } catch (err) {
    console.error("Error consultando logs:", err);
  }
}

function renderLogs() {
  const terminal = document.getElementById('log-terminal');
  const filter = document.getElementById('log-filter').value;
  
  // Guardar posición del scroll
  const isScrolledToBottom = terminal.scrollHeight - terminal.clientHeight <= terminal.scrollTop + 30;

  // Limpiar terminal
  terminal.innerHTML = '';

  // Filtrar logs
  const filteredLogs = logsList.filter(log => {
    if (filter === 'ALL') return true;
    return log.type === filter;
  });

  if (filteredLogs.length === 0) {
    terminal.innerHTML = '<div class="log-line system-line">[SISTEMA] No hay registros para este filtro.</div>';
    return;
  }

  // Renderizar registros (los logs vienen del más nuevo al más viejo, invertimos para la terminal)
  filteredLogs.slice().reverse().forEach(log => {
    const logRow = document.createElement('div');
    logRow.className = `log-line ${getLineClass(log.type)}`;
    
    // Formatear metadatos
    const statusClass = `status-${log.status}`;
    const payloadHtml = log.payload ? `<span class="log-payload">> Detalle: ${escapeHtml(log.payload)}</span>` : '';
    
    logRow.innerHTML = `
      <span class="log-meta">[${log.timestamp}]</span>
      <span class="log-ip">${log.ip}</span>
      <span class="log-method">${log.method}</span>
      <span>${escapeHtml(log.url)}</span>
      <span class="log-status ${statusClass}">${log.status}</span>
      ${payloadHtml}
    `;
    
    terminal.appendChild(logRow);
  });

  // Auto-scroll si el usuario estaba abajo
  if (isScrolledToBottom) {
    terminal.scrollTop = terminal.scrollHeight;
  }
}

function getLineClass(type) {
  switch (type) {
    case 'NORMAL': return 'normal-line';
    case 'BRUTE_FORCE': return 'brute-line';
    case 'SQL_INJECTION': return 'sqli-line';
    case 'HTTP_FLOOD': return 'ddos-line';
    default: return 'system-line';
  }
}

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function calculateStats() {
  const total = logsList.length;
  const attacks = logsList.filter(l => l.type !== 'NORMAL').length;
  
  // Calcular tasa de bloqueo (de peticiones de ataque, cuántas no devolvieron 200/401 normales)
  // O de forma más simple: cuántas devolvieron 403 o 429
  const blockedAttacks = logsList.filter(l => l.type !== 'NORMAL' && (l.status === 403 || l.status === 429)).length;
  const totalAttacks = logsList.filter(l => l.type !== 'NORMAL').length;
  
  const blockRate = totalAttacks > 0 ? Math.round((blockedAttacks / totalAttacks) * 100) : 100;

  // Actualizar métricas rápidas
  document.getElementById('stat-total-req').textContent = total;
  document.getElementById('stat-attack-req').textContent = attacks;
  document.getElementById('stat-success-rate').textContent = `${blockRate}%`;

  // Calcular RPS aproximado
  // Contamos peticiones en los últimos 3 segundos y dividimos entre 3
  const now = Date.now();
  const recentReqs = logsList.filter(l => {
    // Como el log no tiene epoch directo, asumimos base aproximada
    return true; // Simplificado
  });

  // Cálculo de simulación de RPS
  let activeRps = 0.0;
  if (isNormalSimulating) activeRps += 0.7;
  // Si hay ráfagas activas se calcula
  document.getElementById('current-rps').textContent = activeRps.toFixed(1);

  // Estimación de tamaño de archivo (e.g. 250 bytes por log)
  const estSizeKB = Math.round((total * 250) / 1024);
  document.getElementById('log-file-size').textContent = `${estSizeKB} KB`;
}

async function clearLogs() {
  if (confirm("¿Estás seguro de que deseas vaciar todos los archivos de registros?")) {
    try {
      const res = await fetch('/api/clear-logs', { method: 'POST' });
      const data = await res.json();
      if (data.success) {
        logsList = [];
        exfiltratedUsersFound.clear();
        document.getElementById('exfiltration-monitor-card').classList.add('hidden');
        renderLogs();
        calculateStats();
      }
    } catch (e) {
      alert("Error limpiando logs.");
    }
  }
}

function downloadLogs(format) {
  window.open(`/api/download-logs?format=${format}`, '_blank');
}


/* ==========================================================================
   ORQUESTADOR DE SIMULACIÓN DE TRÁFICO Y ATAQUES
   ========================================================================== */

/**
 * 1. Simulación de Tráfico de Usuario Normal (Background Loop)
 */
function toggleNormalTrafficSim() {
  const btn = document.getElementById('btn-traffic-normal');
  const progContainer = document.getElementById('progress-normal-container');

  if (isNormalSimulating) {
    // Detener simulación
    clearInterval(normalTrafficIntervalId);
    isNormalSimulating = false;
    btn.innerHTML = '▶️ Iniciar Tráfico';
    btn.className = 'btn btn-emerald';
    progContainer.classList.add('hidden');
  } else {
    // Iniciar simulación
    isNormalSimulating = true;
    btn.innerHTML = '⏹️ Detener Tráfico';
    btn.className = 'btn btn-gray';
    progContainer.classList.remove('hidden');
    
    // Lanzar ráfagas cíclicas
    normalTrafficIntervalId = setInterval(async () => {
      // Elegir un usuario aleatorio
      const users = ['fabri', 'testuser', 'invitado', 'maria_finance', 'carlos_security'];
      const user = users[Math.floor(Math.random() * users.length)];
      const randomIP = `192.168.1.${Math.floor(Math.random() * 80) + 10}`;
      const userAgent = AGENTS.normal[Math.floor(Math.random() * AGENTS.normal.length)];

      // 1. Simular navegación general
      const actions = [
        { method: 'GET', url: '/api/dashboard-data?userId=2', status: 200, payload: 'Dashboard View' },
        { method: 'GET', url: '/api/search?query=Amazon&userId=2', status: 200, payload: 'Search: Amazon' },
        { method: 'GET', url: '/api/search?query=Starbucks&userId=2', status: 200, payload: 'Search: Starbucks' },
        { method: 'POST', url: '/api/login', status: 200, payload: `Login attempt - User: ${user}` }
      ];
      
      const randomAction = actions[Math.floor(Math.random() * actions.length)];

      // Enviar solicitud de simulación al backend
      await fetch('/api/admin/simulate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'NORMAL',
          ip: randomIP,
          userAgent: userAgent,
          method: randomAction.method,
          url: randomAction.url,
          status: randomAction.status,
          payload: randomAction.payload
        })
      });

      fetchLogs();
    }, 1500);
  }
}

/**
 * 2. Simulación de Ataque de Fuerza Bruta
 */
async function triggerBruteForceSim() {
  const btn = document.getElementById('btn-attack-brute');
  const progContainer = document.getElementById('progress-brute-container');
  const progBar = document.getElementById('progress-brute');

  btn.disabled = true;
  progContainer.classList.remove('hidden');
  progBar.style.width = '0%';

  const passwordsDictionary = [
    '123456', 'password', '12345', '123456789', 'admin', 'qwerty', '12345678', '111111', 
    '123123', 'admin123', 'root', 'security', 'login', 'contraseña', 'welcome', 'test',
    'pass123', 'superadmin', 'finance', 'apex123', 'fabri123', 'banco', 'secreto', 'master'
  ];

  const totalAttempts = 50;
  let currentAttempt = 0;

  // Lógica de ráfaga
  for (let i = 0; i < totalAttempts; i++) {
    // 5% de probabilidad de usar la contraseña real al final para simular éxito, el resto fallos
    const useCorrect = (i === totalAttempts - 1) && !document.getElementById('toggle-brute').checked;
    const pwd = useCorrect ? 'admin123' : passwordsDictionary[Math.floor(Math.random() * passwordsDictionary.length)];

    // Realizar llamada asíncrona rápida simulando Hydra
    fetch('/api/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-simulated-ip': ATTACK_IPS.brute_force,
        'x-simulated-user-agent': AGENTS.brute_force,
        'x-simulated-attack': 'brute_force'
      },
      body: JSON.stringify({ username: 'admin', password: pwd })
    }).catch(e => {});

    currentAttempt++;
    const pct = Math.round((currentAttempt / totalAttempts) * 100);
    progBar.style.width = `${pct}%`;

    // Pausa muy pequeña (100ms) para simular ráfagas rápidas de Hydra
    await new Promise(resolve => setTimeout(resolve, 60));
  }

  // Esperar a que se escriban los registros y refrescar
  setTimeout(() => {
    fetchLogs();
    btn.disabled = false;
    progContainer.classList.add('hidden');
  }, 1000);
}

/**
 * 3. Simulación de Ataque SQL Injection (SQLi)
 */
async function triggerSQLiSim() {
  const btn = document.getElementById('btn-attack-sqli');
  const progContainer = document.getElementById('progress-sqli-container');
  const progBar = document.getElementById('progress-sqli');

  btn.disabled = true;
  progContainer.classList.remove('hidden');
  progBar.style.width = '0%';

  // Lista de payloads de SQL Injection que probará sqlmap
  const sqliPayloads = [
    'coffee', // normal
    "' OR '1'='1", // bypass simple
    "1' OR '1'='1",
    "' OR 1=1 --", // comentario estándar
    "' OR true --",
    "admin' --", // bypass usuario
    "' UNION SELECT 1, 2, 3, 4, 5 --", // sondeo de columnas
    "' UNION SELECT username, password_hash, email, balance, account_number FROM users --" // exfiltración real
  ];

  let current = 0;
  for (const payload of sqliPayloads) {
    try {
      const res = await fetch(`/api/search?query=${encodeURIComponent(payload)}&userId=2`, {
        headers: {
          'x-simulated-ip': ATTACK_IPS.sqli,
          'x-simulated-user-agent': AGENTS.sqli,
          'x-simulated-attack': 'sqli'
        }
      });
      
      const data = await res.json();
      
      // Si la inyección fue exitosa y trajo datos exfiltrados (por ejemplo hashes de otros usuarios)
      if (data.injected && data.data && data.data.length > 8) {
        // Encontrar usuarios exfiltrados en los resultados
        data.data.forEach(item => {
          if (item.description && item.description.startsWith('EXFILTRACIÓN DB')) {
            // Extraer info de la cadena formateada en database.js
            // Formato: EXFILTRACIÓN DB - User: [admin] Email: [admin@apexvault.com] Hash: [8c6...]
            const userMatch = item.description.match(/User: \[(.*?)\]/);
            const emailMatch = item.description.match(/Email: \[(.*?)\]/);
            const hashMatch = item.description.match(/Hash: \[(.*?)\]/);
            
            if (userMatch) {
              const username = userMatch[1];
              if (!exfiltratedUsersFound.has(username)) {
                exfiltratedUsersFound.add(username);
                addExfiltratedRow(username, emailMatch ? emailMatch[1] : '', hashMatch ? hashMatch[1] : '', item.type, item.amount);
              }
            }
          }
        });
        
        // Mostrar tabla monitor
        document.getElementById('exfiltration-monitor-card').classList.remove('hidden');
      }

    } catch (e) {
      console.error(e);
    }

    current++;
    progBar.style.width = `${Math.round((current / sqliPayloads.length) * 100)}%`;
    await new Promise(r => setTimeout(r, 400)); // sqlmap suele tener un delay por petición
  }

  setTimeout(() => {
    fetchLogs();
    btn.disabled = false;
    progContainer.classList.add('hidden');
  }, 1000);
}

function addExfiltratedRow(user, email, hash, role, balance) {
  const tbody = document.getElementById('exfiltrated-data-rows');
  const row = document.createElement('tr');
  row.className = 'text-red';
  row.innerHTML = `
    <td><strong>${escapeHtml(user)}</strong></td>
    <td>${escapeHtml(email)}</td>
    <td><code style="font-size: 0.72rem; color: #fb7185;">${escapeHtml(hash)}</code></td>
    <td>${role.replace('Role: ', '')}</td>
    <td><strong>$${balance.toFixed(2)}</strong></td>
  `;
  tbody.appendChild(row);
}

/**
 * 4. Simulación de Ataque HTTP Flood (DDoS)
 */
async function triggerHTTPFloodSim() {
  const btn = document.getElementById('btn-attack-ddos');
  const progContainer = document.getElementById('progress-ddos-container');
  const progBar = document.getElementById('progress-ddos');

  btn.disabled = true;
  progContainer.classList.remove('hidden');
  progBar.style.width = '0%';

  const totalRequests = 300;
  let sent = 0;

  // Para evitar sobrecargar la memoria del navegador en un bucle síncrono,
  // dividimos el envío de 300 peticiones en 3 bloques de 100 de forma concurrente
  const batchSize = 75;
  const numBatches = totalRequests / batchSize;

  for (let b = 0; b < numBatches; b++) {
    const promises = [];
    
    for (let i = 0; i < batchSize; i++) {
      // Simular múltiples IPs de la botnet (distribuidas en el rango del prefijo)
      const botIP = `${ATTACK_IPS.ddos_prefix}${Math.floor(Math.random() * 254) + 1}`;
      
      const p = fetch('/api/dashboard-data?userId=2', {
        headers: {
          'x-simulated-ip': botIP,
          'x-simulated-user-agent': AGENTS.ddos
        }
      })
      .then(() => {
        sent++;
        progBar.style.width = `${Math.round((sent / totalRequests) * 100)}%`;
      })
      .catch(() => {
        sent++;
        progBar.style.width = `${Math.round((sent / totalRequests) * 100)}%`;
      });
      
      promises.push(p);
    }

    // Ejecutar el bloque concurrente
    await Promise.all(promises);
    await new Promise(r => setTimeout(r, 400)); // Separación de bloques
  }

  setTimeout(() => {
    fetchLogs();
    btn.disabled = false;
    progContainer.classList.add('hidden');
  }, 1000);
}


/* ==========================================================================
   APLICACIÓN WEB OBJETIVO (APEX VAULT PORTAL BANCARIO)
   ========================================================================== */

function checkBankSession() {
  const session = sessionStorage.getItem('bank_session');
  if (session) {
    loggedUser = JSON.parse(session);
    showBankDashboard();
  } else {
    showBankLogin();
  }
}

async function handleBankLogin(e) {
  e.preventDefault();
  const userInp = document.getElementById('bank-username').value;
  const passInp = document.getElementById('bank-password').value;
  
  const errBox = document.getElementById('login-error-msg');
  const succBox = document.getElementById('login-success-msg');
  
  errBox.classList.add('hidden');
  succBox.classList.add('hidden');

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: userInp, password: passInp })
    });

    const data = await res.json();
    
    if (res.status === 200 && data.success) {
      succBox.textContent = data.injected ? 
        "¡Acceso Concedido mediante SQL Injection!" : 
        "Inicio de sesión correcto. Redireccionando...";
      succBox.classList.remove('hidden');

      loggedUser = data.user;
      sessionStorage.setItem('bank_session', JSON.stringify(loggedUser));
      
      // Actualizar terminal de logs al instante
      fetchLogs();

      setTimeout(() => {
        showBankDashboard();
      }, 1000);
    } else {
      errBox.textContent = data.error || "Error al iniciar sesión.";
      errBox.classList.remove('hidden');
      fetchLogs();
    }
  } catch (err) {
    errBox.textContent = "Error de red al intentar conectar con el servidor bancario.";
    errBox.classList.remove('hidden');
  }
}

function handleBankLogout() {
  sessionStorage.removeItem('bank_session');
  loggedUser = null;
  showBankLogin();
}

function showBankLogin() {
  document.getElementById('bank-login-screen').classList.remove('hidden');
  document.getElementById('bank-dashboard-screen').classList.add('hidden');
  document.getElementById('login-error-msg').classList.add('hidden');
  document.getElementById('login-success-msg').classList.add('hidden');
  document.getElementById('bank-username').value = '';
  document.getElementById('bank-password').value = '';
}

async function showBankDashboard() {
  document.getElementById('bank-login-screen').classList.add('hidden');
  document.getElementById('bank-dashboard-screen').classList.remove('hidden');

  // Cargar datos
  document.getElementById('logged-user-name').textContent = loggedUser.username === 'admin' ? 'Administrador de Servidores (ROOT)' : loggedUser.username;
  document.getElementById('logged-user-role').textContent = loggedUser.role === 'administrator' ? 'Superusuario del Sistema' : 'Cliente Corporativo Apex';
  
  // Realizar GET para cargar el balance y transacciones
  await loadDashboardData();
}

async function loadDashboardData() {
  try {
    const res = await fetch(`/api/dashboard-data?userId=${loggedUser.id}`);
    const data = await res.json();
    
    document.getElementById('logged-user-balance').textContent = `$${data.balance.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
    document.getElementById('logged-user-account').textContent = data.account_number;
    
    renderTransactionsTable(data.transactions);
    
    // Reiniciar visor SQL de movimientos
    document.getElementById('executed-sql-code').textContent = `SELECT * FROM transactions WHERE user_id = ${loggedUser.id} AND description LIKE '%[TEXT]%'`;
    document.getElementById('results-count').textContent = `${data.transactions.length} resultados`;
  } catch (e) {
    console.error("Error cargando dashboard:", e);
  }
}

function renderTransactionsTable(transactions) {
  const tbody = document.getElementById('transactions-data-rows');
  tbody.innerHTML = '';

  if (transactions.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--color-text-muted);">No hay transacciones registradas.</td></tr>';
    return;
  }

  transactions.forEach(t => {
    const row = document.createElement('tr');
    const isDebit = t.amount < 0 || t.type === 'debit';
    const amountClass = isDebit ? 'amount-debit' : 'amount-credit';
    const formattedAmount = (isDebit ? '' : '+') + `$${Math.abs(t.amount).toFixed(2)}`;
    
    row.innerHTML = `
      <td><span style="color: var(--color-text-muted); font-family: var(--font-mono);">${t.id}</span></td>
      <td>${t.date}</td>
      <td><strong>${escapeHtml(t.description)}</strong></td>
      <td><span class="badge ${isDebit ? 'badge-red' : 'active'}">${t.type.toUpperCase()}</span></td>
      <td><span class="${amountClass}">${formattedAmount}</span></td>
    `;
    tbody.appendChild(row);
  });
}

async function handleTransactionSearch(e) {
  e.preventDefault();
  const searchVal = document.getElementById('transaction-search-input').value;
  const feed = document.getElementById('search-feedback-msg');
  
  feed.classList.add('hidden');

  try {
    const res = await fetch(`/api/search?query=${encodeURIComponent(searchVal)}&userId=${loggedUser.id}`);
    const data = await res.json();
    
    // Actualizar monitor SQL
    document.getElementById('executed-sql-code').textContent = data.query;

    if (res.status === 200 && data.success) {
      renderTransactionsTable(data.data);
      document.getElementById('results-count').textContent = `${data.data.length} resultados`;
      fetchLogs();
    } else {
      feed.textContent = data.error || "Acceso Denegado por el Cortafuegos.";
      feed.classList.remove('hidden');
      fetchLogs();
    }
  } catch (err) {
    feed.textContent = "Error de red al consultar el historial bancario.";
    feed.classList.remove('hidden');
  }
}
