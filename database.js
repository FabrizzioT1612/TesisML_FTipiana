/**
 * database.js
 * Motor de Base de Datos SQL Simulado para Demostraciones de Ciberseguridad.
 * 
 * Permite simular consultas SQL reales y es vulnerable a SQL Injection (SQLi)
 * de forma controlada para fines educativos y análisis de logs.
 */

// Datos simulados (Semilla)
const USERS = [
  { id: 1, username: "admin", email: "admin@apexvault.com", password_hash: "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918", role: "administrator", balance: 154320.50, account_number: "ES12-9876-5432-1098" }, // hash de admin123
  { id: 2, username: "fabri", email: "fabri@gmail.com", password_hash: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", role: "user", balance: 5420.00, account_number: "ES12-1234-5678-9012" }, // hash de password
  { id: 3, username: "testuser", email: "testuser@apexvault.com", password_hash: "098f6bcd4621d373cade4e832627b4f6", role: "user", balance: 120.00, account_number: "ES12-4567-8901-2345" }, // hash de test
  { id: 4, username: "carlos_security", email: "carlos@security.com", password_hash: "2b013ac244cf5e28a52932c96c464bb0", role: "analyst", balance: 12500.75, account_number: "ES12-8901-2345-6789" }
];

const TRANSACTIONS = [
  { id: 1, user_id: 2, date: "2026-05-25 10:30:15", description: "Compra Amazon ES", amount: -45.99, type: "debit" },
  { id: 2, user_id: 2, date: "2026-05-25 14:15:22", description: "Nómina Mensual Apex", amount: 2500.00, type: "credit" },
  { id: 3, user_id: 2, date: "2026-05-26 09:05:00", description: "Cafetería Starbucks", amount: -6.50, type: "debit" },
  { id: 4, user_id: 2, date: "2026-05-27 18:40:11", description: "Transferencia a Cuenta Ahorro", amount: -300.00, type: "debit" },
  { id: 5, user_id: 1, date: "2026-05-26 12:00:00", description: "Auditoría Externa Servidores", amount: -1500.00, type: "debit" },
  { id: 6, user_id: 1, date: "2026-05-27 08:30:00", description: "Depósito de Seguridad Apex Corp", amount: 50000.00, type: "credit" },
  { id: 7, user_id: 3, date: "2026-05-24 11:22:33", description: "Suscripción Netflix", amount: -17.99, type: "debit" },
  { id: 8, user_id: 4, date: "2026-05-27 15:00:00", description: "Transferencia Recibida Carlos S.", amount: 800.00, type: "credit" }
];

/**
 * Simula la ejecución de una consulta de Autenticación (Login)
 * @param {string} username 
 * @param {string} password 
 * @param {boolean} isVulnerable - Si está en modo vulnerable (concatena strings y permite bypass SQLi)
 * @returns {Object} { success: boolean, user: Object, queryExecuted: string, error: string }
 */
function loginUser(username, password, isVulnerable) {
  let queryExecuted = "";
  
  if (isVulnerable) {
    // Simulación de consulta vulnerable concatenada
    queryExecuted = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    // Evaluamos inyección básica: si el nombre de usuario contiene " ' OR '1'='1 " o similares
    const cleanUsername = username.trim().toLowerCase();
    const cleanPassword = password.trim().toLowerCase();
    
    // Caso 1: Inyección clásica de bypass: ' OR '1'='1
    const bypassPatterns = [
      "' or '1'='1",
      "' or 1=1",
      "' or ''='",
      "admin' --",
      "admin'/*",
      "' or true --"
    ];
    
    const isBypass = bypassPatterns.some(pattern => 
      cleanUsername.includes(pattern) || cleanPassword.includes(pattern)
    );

    if (isBypass) {
      // Retorna el primer usuario de la base de datos (normalmente el administrador)
      return {
        success: true,
        user: USERS[0], // Devuelve admin
        queryExecuted: queryExecuted,
        injected: true
      };
    }

    // Caso 2: Login normal dentro de lógica vulnerable
    const user = USERS.find(u => u.username.toLowerCase() === username.toLowerCase());
    // (Por simplicidad en la demo, si no es inyección, chequeamos que la contraseña hash o plana coincida)
    if (user && (user.password_hash === password || password === "admin123" || password === "password" || password === "test")) {
      return { success: true, user, queryExecuted, injected: false };
    }
    
    return { success: false, queryExecuted, error: "Credenciales incorrectas" };
  } else {
    // Consulta segura parametrizada (simulada)
    queryExecuted = `SELECT * FROM users WHERE username = ? AND password = ?`;
    
    // En el modo seguro, no se evalúan patrones de bypass y se buscan coincidencias exactas y seguras
    const user = USERS.find(u => u.username.toLowerCase() === username.toLowerCase());
    // Comprobamos la contraseña
    if (user && (password === "admin123" && user.username === "admin" || 
                 password === "password" && user.username === "fabri" || 
                 password === "test" && user.username === "testuser")) {
      return { success: true, user, queryExecuted, injected: false };
    }
    
    return { success: false, queryExecuted, error: "Credenciales incorrectas" };
  }
}

/**
 * Simula la ejecución de un buscador de transacciones
 * @param {number} userId - ID del usuario logueado actualmente
 * @param {string} searchTerm - El término de búsqueda
 * @param {boolean} isVulnerable - Si está activo el modo vulnerable a SQLi
 * @returns {Object} { data: Array, queryExecuted: string, injected: boolean }
 */
function searchTransactions(userId, searchTerm, isVulnerable) {
  let queryExecuted = "";
  
  if (isVulnerable) {
    queryExecuted = `SELECT * FROM transactions WHERE user_id = ${userId} AND description LIKE '%${searchTerm}%'`;
    
    const searchLower = searchTerm.toLowerCase();
    
    // 1. Detección de bypass SQLi: ' OR 1=1 --
    if (searchLower.includes("' or 1=1") || searchLower.includes("' or '1'='1") || searchLower.includes("' or true --")) {
      // Devuelve TODAS las transacciones de la base de datos (de todos los usuarios)
      return {
        data: TRANSACTIONS,
        queryExecuted: queryExecuted,
        injected: true,
        message: "SQL Injection exitoso: Bypass de ID de usuario y obtención de todos los registros."
      };
    }
    
    // 2. Detección de UNION SELECT para extraer datos de la tabla usuarios
    if (searchLower.includes("union select") || searchLower.includes("union all select")) {
      // Simula la unión y devuelve los datos de la tabla de usuarios mapeados en el formato de transacciones
      const mappedUsers = USERS.map(u => ({
        id: u.id,
        user_id: u.id,
        date: "SYSTEM_HASH_EXTRACTED",
        description: `EXFILTRACIÓN DB - User: [${u.username}] Email: [${u.email}] Hash: [${u.password_hash}]`,
        amount: u.balance,
        type: `Role: ${u.role}`
      }));
      
      return {
        data: [...TRANSACTIONS.filter(t => t.user_id === userId), ...mappedUsers],
        queryExecuted: queryExecuted,
        injected: true,
        message: "SQL Injection exitoso: Exfiltración de datos confidenciales de la tabla 'users' vía UNION SELECT."
      };
    }
    
    // Consulta normal en modo vulnerable
    const userTrans = TRANSACTIONS.filter(t => 
      t.user_id === userId && 
      t.description.toLowerCase().includes(searchLower)
    );
    return { data: userTrans, queryExecuted, injected: false };
  } else {
    // Consulta segura parametrizada
    queryExecuted = `SELECT * FROM transactions WHERE user_id = ? AND description LIKE ?`;
    
    // En modo seguro, tratamos la entrada puramente como texto
    const searchLower = searchTerm.toLowerCase();
    const userTrans = TRANSACTIONS.filter(t => 
      t.user_id === userId && 
      t.description.toLowerCase().includes(searchLower)
    );
    return { data: userTrans, queryExecuted, injected: false };
  }
}

module.exports = {
  loginUser,
  searchTransactions,
  USERS,
  TRANSACTIONS
};
