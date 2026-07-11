/**
 * server.js
 * Servidor Express principal. Controla la lógica de la aplicación web,
 * el WAF (Firewall de Aplicación Web) activable, y el Motor de Logs.
 */

const express = require('express');
const path = require('path');
const fs = require('fs');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración de middlewares para parsear JSON y urlencoded
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir archivos estáticos de la carpeta public
app.use(express.static(path.join(__dirname, 'public')));

// Ruta de logs
const LOGS_DIR = path.join(__dirname, 'logs');
const CLF_LOG_PATH = path.join(LOGS_DIR, 'app_traffic.log');
const JSON_LOG_PATH = path.join(LOGS_DIR, 'app_traffic.json');
const CSV_LOG_PATH = path.join(LOGS_DIR, 'app_traffic.csv');

// Asegurar que la carpeta logs exista al iniciar
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR);
}

// Inicializar archivos de logs con encabezados si no existen
function initLogFiles() {
  // CSV necesita encabezados
  if (!fs.existsSync(CSV_LOG_PATH) || fs.statSync(CSV_LOG_PATH).size === 0) {
    fs.writeFileSync(CSV_LOG_PATH, "Timestamp,IP,Method,URL,StatusCode,Bytes,UserAgent,TrafficType,QueryOrPayload,VulnerableMode,WAFActive\n");
  }
  // CLF y JSON simplemente se inicializan vacíos si no existen
  if (!fs.existsSync(CLF_LOG_PATH)) {
    fs.writeFileSync(CLF_LOG_PATH, "");
  }
  if (!fs.existsSync(JSON_LOG_PATH)) {
    fs.writeFileSync(JSON_LOG_PATH, "");
  }
}
initLogFiles();

// Estado de configuraciones de seguridad (WAF y Vulnerabilidades)
let securitySettings = {
  sqliVulnerable: true,        // True = vulnerable a SQLi; False = Sanitizado/Parametrizado
  bruteForceVulnerable: true,  // True = sin límite de intentos; False = Con Rate Limiting activado
  ddosVulnerable: true,        // True = sin protección; False = Con bloqueo DDoS activado
  wafActive: false            // Firewall de aplicación web global activado
};

// Registro temporal en memoria para visualización rápida en el Dashboard
let recentLogsInMemory = [];
const MAX_MEM_LOGS = 100;

// Registro en memoria de intentos de login por IP (para simular Rate Limiting)
let loginAttempts = {};

// Registro en memoria de peticiones por IP en el último segundo (para mitigar HTTP Flood / DDoS)
let ddosTracker = {};

/**
 * Motor de Logs - Registra cualquier petición en formato CLF, JSON y CSV
 */
function logRequest(req, status, bytesSent, type, payloadInfo = "") {
  const timestamp = new Date();
  
  // 1. IP del cliente (priorizamos si viene simulada en headers de la simulación de ataque)
  const clientIP = req.headers['x-simulated-ip'] || req.ip || req.connection.remoteAddress || '127.0.0.1';
  
  // 2. User Agent (priorizamos simulado)
  const userAgent = req.headers['x-simulated-user-agent'] || req.headers['user-agent'] || 'Mozilla/5.0';
  
  const method = req.method;
  const url = req.originalUrl || req.url;
  
  // Sanitizar payloads para el archivo CSV (evitar comas que rompan columnas)
  const cleanPayload = payloadInfo.replace(/,/g, ';').replace(/"/g, '""').replace(/\n/g, ' ');

  // A. FORMATO APACHE/NGINX CLF (Common Log Format)
  // Formato: 127.0.0.1 - - [27/May/2026:23:45:00 -0500] "GET /url HTTP/1.1" 200 4520 "http://referrer.com" "UserAgent" [TYPE]
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const day = String(timestamp.getDate()).padStart(2, '0');
  const month = months[timestamp.getMonth()];
  const year = timestamp.getFullYear();
  const hours = String(timestamp.getHours()).padStart(2, '0');
  const minutes = String(timestamp.getMinutes()).padStart(2, '0');
  const seconds = String(timestamp.getSeconds()).padStart(2, '0');
  const formattedDate = `${day}/${month}/${year}:${hours}:${minutes}:${seconds} -0500`;
  
  const clfLine = `${clientIP} - - [${formattedDate}] "${method} ${url} HTTP/1.1" ${status} ${bytesSent} "-" "${userAgent}" [${type}] [Payload: ${cleanPayload}]\n`;
  
  // B. FORMATO JSON (JSON Lines)
  const jsonEntry = {
    timestamp: timestamp.toISOString(),
    ip: clientIP,
    method: method,
    url: url,
    statusCode: status,
    bytes: bytesSent,
    userAgent: userAgent,
    trafficType: type,
    payload: payloadInfo,
    vulnerableState: {
      sqli: securitySettings.sqliVulnerable,
      bruteforce: securitySettings.bruteForceVulnerable,
      ddos: securitySettings.ddosVulnerable
    },
    wafActive: securitySettings.wafActive
  };
  const jsonLine = JSON.stringify(jsonEntry) + "\n";

  // C. FORMATO CSV
  const csvLine = `"${timestamp.toISOString()}","${clientIP}","${method}","${url}",${status},${bytesSent},"${userAgent.replace(/"/g, '""')}","${type}","${cleanPayload}",${securitySettings.sqliVulnerable ? "Vulnerable" : "Secure"},${securitySettings.wafActive ? "ON" : "OFF"}\n`;

  // Escribir a archivos
  try {
    fs.appendFileSync(CLF_LOG_PATH, clfLine);
    fs.appendFileSync(JSON_LOG_PATH, jsonLine);
    fs.appendFileSync(CSV_LOG_PATH, csvLine);
  } catch (err) {
    console.error("Error al escribir archivos de log:", err);
  }

  // Guardar en memoria para mostrar en la interfaz en tiempo real
  const memLog = {
    id: Date.now() + Math.random().toString(36).substring(2, 5),
    timestamp: timestamp.toLocaleTimeString(),
    ip: clientIP,
    method: method,
    url: url,
    status: status,
    userAgent: userAgent,
    type: type,
    payload: payloadInfo
  };
  
  recentLogsInMemory.unshift(memLog);
  if (recentLogsInMemory.length > MAX_MEM_LOGS) {
    recentLogsInMemory.pop();
  }
}

/**
 * Middleware para simular protección DDoS y registrar accesos globales
 * Si DDoS protection está ON, limita las peticiones por segundo por IP
 */
app.use((req, res, next) => {
  // Ignorar peticiones a archivos estáticos (.css, .js, imágenes) para no saturar los logs de ataques
  if (req.url.includes('/css/') || req.url.includes('/js/') || req.url.includes('/favicon.ico')) {
    return next();
  }

  // Si son rutas de la API del administrador del simulador, tampoco las catalogamos como tráfico de usuario normal/ataque
  if (req.url.startsWith('/api/admin') || req.url.startsWith('/api/logs') || req.url.startsWith('/api/security-settings')) {
    return next();
  }

  const clientIP = req.headers['x-simulated-ip'] || req.ip || '127.0.0.1';
  const now = Math.floor(Date.now() / 1000); // Segundos actuales

  // Inicializar tracking DDoS
  if (!ddosTracker[clientIP] || ddosTracker[clientIP].sec !== now) {
    ddosTracker[clientIP] = { sec: now, count: 0 };
  }
  ddosTracker[clientIP].count++;

  // Si la mitigación DDoS está ACTIVA y las peticiones superan el umbral (e.g. 5 peticiones por segundo por IP)
  if (!securitySettings.ddosVulnerable && securitySettings.wafActive && ddosTracker[clientIP].count > 5) {
    const errorMsg = "DDoS Protection - Limit Exceeded";
    logRequest(req, 429, errorMsg.length, "HTTP_FLOOD", `BLOCKED: IP ${clientIP} exceeded rate limits`);
    return res.status(429).json({ error: "Too Many Requests - DDoS Protection Triggered" });
  }

  next();
});


/* ==========================================================================
   RUTAS DE LA APLICACIÓN WEB SIMULADA (APEX VAULT)
   ========================================================================== */

/**
 * Endpoint de Login (Soporta simulación de Fuerza Bruta)
 */
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const clientIP = req.headers['x-simulated-ip'] || req.ip || '127.0.0.1';
  const isAttackSimulated = req.headers['x-simulated-attack'] === 'brute_force';
  
  const trafficType = isAttackSimulated ? "BRUTE_FORCE" : "NORMAL";
  const payloadStr = `User: ${username} | Pass: ${password}`;

  // Si el WAF/Rate Limiting está activo para Fuerza Bruta
  if (!securitySettings.bruteForceVulnerable && securitySettings.wafActive) {
    const now = Date.now();
    if (!loginAttempts[clientIP]) {
      loginAttempts[clientIP] = [];
    }
    
    // Filtrar intentos en los últimos 10 segundos
    loginAttempts[clientIP] = loginAttempts[clientIP].filter(t => now - t < 10000);
    
    // Si hay más de 3 intentos en 10 segundos, bloqueamos
    if (loginAttempts[clientIP].length >= 3) {
      const errorMsg = "Brute Force Protection - Account Locked Temporarily";
      logRequest(req, 429, errorMsg.length, trafficType, `BLOCKED Rate Limit: ${payloadStr}`);
      return res.status(429).json({ 
        success: false, 
        error: "Demasiados intentos de inicio de sesión. Por favor, inténtelo de nuevo en 10 segundos." 
      });
    }
    
    loginAttempts[clientIP].push(now);
  }

  // WAF genérico para verificar inyección SQL en el login si está el WAF global activo
  if (securitySettings.wafActive && !securitySettings.sqliVulnerable) {
    const sqlKeywords = [/\bunion\b/i, /\bselect\b/i, /' or /i, /--/];
    const isSQLiAttempt = sqlKeywords.some(rx => rx.test(username) || rx.test(password));
    
    if (isSQLiAttempt) {
      const blockMsg = "WAF: SQL Injection detected and blocked";
      logRequest(req, 403, blockMsg.length, "SQL_INJECTION", `BLOCKED SQLi: ${payloadStr}`);
      return res.status(403).json({ success: false, error: "Acceso denegado por políticas de seguridad (WAF)." });
    }
  }

  // Ejecutamos autenticación en el motor de base de datos
  const dbResult = db.loginUser(username, password, securitySettings.sqliVulnerable);

  if (dbResult.success) {
    // Login correcto
    const respMsg = JSON.stringify({ success: true, user: { username: dbResult.user.username, role: dbResult.user.role } });
    
    // Si fue por inyección SQL, catalogar como SQL_INJECTION exitoso
    const cataloguedType = dbResult.injected ? "SQL_INJECTION" : trafficType;
    
    logRequest(req, 200, respMsg.length, cataloguedType, `SUCCESS: ${payloadStr} ${dbResult.injected ? '[SQLi Bypass!]' : ''}`);
    
    // Reiniciar intentos de login en caso de éxito
    loginAttempts[clientIP] = [];
    
    return res.json({
      success: true,
      user: {
        id: dbResult.user.id,
        username: dbResult.user.username,
        email: dbResult.user.email,
        role: dbResult.user.role,
        balance: dbResult.user.balance,
        account_number: dbResult.user.account_number
      },
      injected: dbResult.injected,
      query: dbResult.queryExecuted
    });
  } else {
    // Login fallido
    const errorMsg = JSON.stringify({ success: false, error: dbResult.error });
    logRequest(req, 401, errorMsg.length, trafficType, `FAILED: ${payloadStr}`);
    return res.status(401).json({ success: false, error: dbResult.error, query: dbResult.queryExecuted });
  }
});

/**
 * Buscador de transacciones (Vulnerable / Seguro contra SQLi)
 */
app.get('/api/search', (req, res) => {
  const { query, userId } = req.query;
  const userIdentifier = userId ? parseInt(userId) : 2; // Por defecto el usuario "fabri"
  const isAttackSimulated = req.headers['x-simulated-attack'] === 'sqli';
  
  const trafficType = isAttackSimulated ? "SQL_INJECTION" : "NORMAL";
  const payloadStr = `Search Term: "${query || ''}" | UserID: ${userIdentifier}`;

  if (!query) {
    const errorMsg = "Missing search query";
    logRequest(req, 400, errorMsg.length, trafficType, payloadStr);
    return res.status(400).json({ error: errorMsg });
  }

  // Si WAF está activo y está en modo "Seguro" (o el WAF está protegiendo activamente)
  if (securitySettings.wafActive && (!securitySettings.sqliVulnerable || securitySettings.wafActive)) {
    // Chequear firmas comunes de SQL injection
    const sqlPatternRegex = /(\b(union|select|insert|update|delete|drop|alter|where|or)\b)|('|--|\/\*|\*\/)/i;
    if (sqlPatternRegex.test(query)) {
      const blockMsg = "WAF Blocked SQL Injection";
      logRequest(req, 403, blockMsg.length, "SQL_INJECTION", `BLOCKED SQLi: ${payloadStr}`);
      return res.status(403).json({ 
        error: "Bloqueado por el WAF de Apex Vault. Intento de SQL Injection detectado.", 
        blocked: true 
      });
    }
  }

  // Ejecutamos la consulta en nuestra BD simulada
  const searchResult = db.searchTransactions(userIdentifier, query, securitySettings.sqliVulnerable);

  const cataloguedType = searchResult.injected ? "SQL_INJECTION" : trafficType;
  const resultLength = JSON.stringify(searchResult.data).length;

  logRequest(
    req, 
    200, 
    resultLength, 
    cataloguedType, 
    `QUERY: ${searchResult.queryExecuted} | RESULTS: ${searchResult.data.length} ${searchResult.injected ? '[SQLi Vulnerability Exploited!]' : ''}`
  );

  return res.json({
    success: true,
    data: searchResult.data,
    query: searchResult.queryExecuted,
    injected: searchResult.injected,
    message: searchResult.message || "Búsqueda completada"
  });
});

/**
 * Endpoint de Dashboard (Tráfico normal simulado de consulta de datos bancarios)
 */
app.get('/api/dashboard-data', (req, res) => {
  const { userId } = req.query;
  const userIdentifier = userId ? parseInt(userId) : 2;
  const user = db.USERS.find(u => u.id === userIdentifier);

  if (!user) {
    logRequest(req, 404, 9, "NORMAL", `User Dashboard lookup failed: ID ${userIdentifier}`);
    return res.status(404).json({ error: "User not found" });
  }

  // Filtrar transacciones del usuario
  const userTransactions = db.TRANSACTIONS.filter(t => t.user_id === user.id);
  const data = {
    account_number: user.account_number,
    balance: user.balance,
    transactions: userTransactions,
    email: user.email,
    role: user.role
  };

  const responseLength = JSON.stringify(data).length;
  logRequest(req, 200, responseLength, "NORMAL", `Viewed Dashboard - User: ${user.username}`);
  
  return res.json(data);
});


/* ==========================================================================
   RUTAS DE LA CONSOLA DE CONTROL DEL SIMULADOR & ADMINISTRACIÓN
   ========================================================================== */

/**
 * Obtener estado de la configuración de seguridad
 */
app.get('/api/security-settings', (req, res) => {
  res.json(securitySettings);
});

/**
 * Modificar la configuración de seguridad (WAF/Vulnerabilidades)
 */
app.post('/api/security-settings', (req, res) => {
  const { sqliVulnerable, bruteForceVulnerable, ddosVulnerable, wafActive } = req.body;
  
  if (sqliVulnerable !== undefined) securitySettings.sqliVulnerable = sqliVulnerable;
  if (bruteForceVulnerable !== undefined) securitySettings.bruteForceVulnerable = bruteForceVulnerable;
  if (ddosVulnerable !== undefined) securitySettings.ddosVulnerable = ddosVulnerable;
  if (wafActive !== undefined) securitySettings.wafActive = wafActive;

  // Loguear el cambio de políticas como un evento normal administrativo
  logRequest(req, 200, 2, "NORMAL", `SECURITY SETTINGS UPDATED: WAF=${securitySettings.wafActive ? 'ON':'OFF'}, SQLi_Vuln=${securitySettings.sqliVulnerable ? 'YES':'NO'}, BF_Vuln=${securitySettings.bruteForceVulnerable ? 'YES':'NO'}, DDoS_Vuln=${securitySettings.ddosVulnerable ? 'YES':'NO'}`);

  res.json({ success: true, settings: securitySettings });
});

/**
 * Obtener los registros en memoria (Polling para la terminal web)
 */
app.get('/api/logs', (req, res) => {
  res.json(recentLogsInMemory);
});

/**
 * Limpiar el archivo de logs y la memoria
 */
app.post('/api/clear-logs', (req, res) => {
  try {
    fs.writeFileSync(CLF_LOG_PATH, "");
    fs.writeFileSync(JSON_LOG_PATH, "");
    fs.writeFileSync(CSV_LOG_PATH, "Timestamp,IP,Method,URL,StatusCode,Bytes,UserAgent,TrafficType,QueryOrPayload,VulnerableMode,WAFActive\n");
    
    recentLogsInMemory = [];
    loginAttempts = {};
    ddosTracker = {};

    logRequest(req, 200, 2, "NORMAL", "LOGS CLEARED BY RESEARCHER");
    
    res.json({ success: true, message: "Todos los archivos de logs han sido limpiados." });
  } catch (err) {
    res.status(500).json({ error: "Error al borrar los logs en el disco." });
  }
});

/**
 * Endpoint para descargar archivos de logs en formatos estructurados
 */
app.get('/api/download-logs', (req, res) => {
  const { format } = req.query;
  
  if (format === 'json') {
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename=app_traffic.json');
    // Leemos el JSON lines y podemos envolverlo en un array o servirlo tal cual.
    // Para facilidades de descarga y lectura, lo convertimos en un array JSON válido.
    try {
      const fileContent = fs.readFileSync(JSON_LOG_PATH, 'utf-8');
      const lines = fileContent.trim().split('\n').filter(l => l.length > 0);
      const jsonArray = lines.map(line => JSON.parse(line));
      return res.send(JSON.stringify(jsonArray, null, 2));
    } catch (e) {
      return res.status(500).send("Error generando JSON.");
    }
  } 
  
  if (format === 'csv') {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=app_traffic.csv');
    return res.sendFile(CSV_LOG_PATH);
  }

  // Por defecto retorna el CLF (Common Log Format) de Nginx/Apache
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename=app_traffic.log');
  return res.sendFile(CLF_LOG_PATH);
});

/**
 * Endpoint simulador interno
 * Permite que el frontend le ordene al backend generar logs simulados
 * de forma directa para simular peticiones sin saturar el ancho de banda del navegador.
 */
app.post('/api/admin/simulate', (req, res) => {
  const { type, ip, userAgent, method, url, status, payload } = req.body;
  
  // Simular la estructura de req
  const simulatedReq = {
    method: method || 'GET',
    originalUrl: url || '/index.html',
    url: url || '/index.html',
    ip: ip || '127.0.0.1',
    headers: {
      'x-simulated-ip': ip || '127.0.0.1',
      'x-simulated-user-agent': userAgent || 'SimulatedBot/1.0',
      'user-agent': userAgent || 'SimulatedBot/1.0'
    }
  };

  const payloadStr = typeof payload === 'object' ? JSON.stringify(payload) : String(payload || '');
  logRequest(simulatedReq, status || 200, Math.floor(Math.random() * 500) + 100, type || 'NORMAL', payloadStr);

  res.json({ success: true });
});

// Levantar el servidor
app.listen(PORT, () => {
  console.log(`================================================================`);
  console.log(`🔒 Servidor del simulador de seguridad iniciado con éxito.`);
  console.log(`🌐 Aplicación activa en: http://localhost:${PORT}`);
  console.log(`📁 Registrando logs en la carpeta: ${LOGS_DIR}`);
  console.log(`================================================================`);
});
