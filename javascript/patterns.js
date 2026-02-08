// Benchmark patterns for JavaScript security and quality detection.
// Each function represents a template pattern for testing code review capabilities.

// =============================================================================
// PROTOTYPE POLLUTION PATTERNS
// =============================================================================

// js-prototype-pollution-merge-easy: Unsafe object merge
function mergeObjectsUnsafe(target, source) {
    // UNSAFE: Prototype pollution via __proto__
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = mergeObjectsUnsafe(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// js-prototype-pollution-merge-easy-fix: Block __proto__ and constructor
function mergeObjectsSafe(target, source) {
    const blockedKeys = ['__proto__', 'constructor', 'prototype'];
    for (const key in source) {
        if (blockedKeys.includes(key)) continue;
        if (!Object.prototype.hasOwnProperty.call(source, key)) continue;

        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = mergeObjectsSafe(target[key] || {}, source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// js-prototype-pollution-assign-medium: Object.assign with user input
function updateConfigUnsafe(config, userInput) {
    // UNSAFE: User input may contain __proto__
    return Object.assign(config, JSON.parse(userInput));
}

// js-prototype-pollution-assign-medium-fix: Create null prototype object
function updateConfigSafe(config, userInput) {
    const parsed = JSON.parse(userInput);
    const sanitized = Object.create(null);
    for (const key of Object.keys(parsed)) {
        if (key !== '__proto__' && key !== 'constructor') {
            sanitized[key] = parsed[key];
        }
    }
    return Object.assign(config, sanitized);
}

// js-prototype-pollution-path-hard: Path-based property assignment
function setNestedPropertyUnsafe(obj, path, value) {
    // UNSAFE: Path can include __proto__
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]]) {
            current[parts[i]] = {};
        }
        current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
}

// js-prototype-pollution-path-hard-fix: Validate path segments
function setNestedPropertySafe(obj, path, value) {
    const blockedKeys = new Set(['__proto__', 'constructor', 'prototype']);
    const parts = path.split('.');

    for (const part of parts) {
        if (blockedKeys.has(part)) {
            throw new Error('Invalid property path');
        }
    }

    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]]) {
            current[parts[i]] = {};
        }
        current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = value;
}

// =============================================================================
// EVAL/CODE INJECTION PATTERNS
// =============================================================================

// js-eval-direct-easy: Direct eval with user input
function calculateUnsafe(expression) {
    // UNSAFE: Code injection via eval
    return eval(expression);
}

// js-eval-direct-easy-fix: Use safe expression parser
function calculateSafe(expression) {
    // Only allow numbers and basic operators
    if (!/^[\d\s+\-*/.()]+$/.test(expression)) {
        throw new Error('Invalid expression');
    }
    // Use Function constructor with strict validation
    const fn = new Function('return ' + expression);
    return fn();
}

// js-eval-function-medium: Function constructor injection
function createHandlerUnsafe(code) {
    // UNSAFE: Function constructor with user input
    return new Function('data', code);
}

// js-eval-function-medium-fix: Predefined handlers only
function createHandlerSafe(handlerName) {
    const handlers = {
        'uppercase': (data) => data.toUpperCase(),
        'lowercase': (data) => data.toLowerCase(),
        'trim': (data) => data.trim()
    };
    if (!handlers[handlerName]) {
        throw new Error('Unknown handler');
    }
    return handlers[handlerName];
}

// js-eval-template-hard: Template literal injection
function renderTemplateUnsafe(template, data) {
    // UNSAFE: eval with template literal
    return eval('`' + template + '`');
}

// js-eval-template-hard-fix: Use safe template engine
function renderTemplateSafe(template, data) {
    return template.replace(/\$\{(\w+)\}/g, (match, key) => {
        return data.hasOwnProperty(key) ? String(data[key]) : match;
    });
}

// js-eval-settimeout-medium: setTimeout with string
function delayedExecutionUnsafe(code, delay) {
    // UNSAFE: setTimeout with string argument
    setTimeout(code, delay);
}

// js-eval-settimeout-medium-fix: Use function reference
function delayedExecutionSafe(fn, delay) {
    if (typeof fn !== 'function') {
        throw new Error('Expected a function');
    }
    setTimeout(fn, delay);
}

// =============================================================================
// DOM XSS PATTERNS
// =============================================================================

// js-xss-innerhtml-easy: innerHTML with user input
function displayMessageUnsafe(message) {
    // UNSAFE: XSS via innerHTML
    document.getElementById('output').innerHTML = message;
}

// js-xss-innerhtml-easy-fix: Use textContent
function displayMessageSafe(message) {
    document.getElementById('output').textContent = message;
}

// js-xss-documentwrite-easy: document.write with user input
function writeContentUnsafe(content) {
    // UNSAFE: document.write
    document.write('<div>' + content + '</div>');
}

// js-xss-documentwrite-easy-fix: Create elements safely
function writeContentSafe(content) {
    const div = document.createElement('div');
    div.textContent = content;
    document.body.appendChild(div);
}

// js-xss-href-medium: URL in href attribute
function createLinkUnsafe(url, text) {
    // UNSAFE: javascript: URLs allowed
    const a = document.createElement('a');
    a.href = url;
    a.textContent = text;
    return a;
}

// js-xss-href-medium-fix: Validate URL scheme
function createLinkSafe(url, text) {
    const a = document.createElement('a');
    try {
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            throw new Error('Invalid URL scheme');
        }
        a.href = url;
    } catch {
        a.href = '#';
    }
    a.textContent = text;
    return a;
}

// js-xss-jquery-hard: jQuery html() method
function updateElementUnsafe($element, html) {
    // UNSAFE: jQuery html() with user input
    $element.html(html);
}

// js-xss-jquery-hard-fix: Use text() method
function updateElementSafe($element, text) {
    $element.text(text);
}

// js-xss-location-medium: Location-based XSS
function handleHashUnsafe() {
    // UNSAFE: Hash directly used in DOM
    const hash = location.hash.substring(1);
    document.getElementById('content').innerHTML = decodeURIComponent(hash);
}

// js-xss-location-medium-fix: Sanitize hash content
function handleHashSafe() {
    const hash = location.hash.substring(1);
    document.getElementById('content').textContent = decodeURIComponent(hash);
}

// =============================================================================
// NOSQL INJECTION PATTERNS
// =============================================================================

// js-nosql-mongo-query-easy: MongoDB query injection
async function findUserUnsafe(db, username, password) {
    // UNSAFE: Object injection in query
    return await db.collection('users').findOne({
        username: username,
        password: password // Could be { $ne: null }
    });
}

// js-nosql-mongo-query-easy-fix: Validate input types
async function findUserSafe(db, username, password) {
    if (typeof username !== 'string' || typeof password !== 'string') {
        throw new Error('Invalid input type');
    }
    return await db.collection('users').findOne({
        username: username,
        password: password
    });
}

// js-nosql-where-medium: $where injection
async function searchUsersUnsafe(db, query) {
    // UNSAFE: User input in $where
    return await db.collection('users').find({
        $where: `this.name.includes('${query}')`
    }).toArray();
}

// js-nosql-where-medium-fix: Use $regex instead
async function searchUsersSafe(db, query) {
    if (typeof query !== 'string') {
        throw new Error('Invalid query type');
    }
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return await db.collection('users').find({
        name: { $regex: escaped, $options: 'i' }
    }).toArray();
}

// js-nosql-aggregation-hard: Aggregation pipeline injection
async function aggregateUnsafe(db, pipeline) {
    // UNSAFE: User-controlled pipeline
    return await db.collection('data').aggregate(pipeline).toArray();
}

// js-nosql-aggregation-hard-fix: Validate pipeline operators
async function aggregateSafe(db, pipeline) {
    const allowedOperators = ['$match', '$group', '$sort', '$limit', '$project'];
    for (const stage of pipeline) {
        const operator = Object.keys(stage)[0];
        if (!allowedOperators.includes(operator)) {
            throw new Error('Disallowed operator: ' + operator);
        }
    }
    return await db.collection('data').aggregate(pipeline).toArray();
}

// =============================================================================
// COMMAND INJECTION PATTERNS
// =============================================================================

// js-cmdi-exec-easy: exec with user input
const { exec } = require('child_process');

function runCommandUnsafe(filename) {
    // UNSAFE: Command injection
    exec('cat ' + filename, (err, stdout) => {
        console.log(stdout);
    });
}

// js-cmdi-exec-easy-fix: Use execFile with arguments array
const { execFile } = require('child_process');

function runCommandSafe(filename) {
    // Validate filename
    if (!/^[\w.-]+$/.test(filename)) {
        throw new Error('Invalid filename');
    }
    execFile('cat', [filename], (err, stdout) => {
        console.log(stdout);
    });
}

// js-cmdi-spawn-medium: spawn with shell option
const { spawn } = require('child_process');

function spawnShellUnsafe(command) {
    // UNSAFE: shell: true with user input
    spawn(command, { shell: true });
}

// js-cmdi-spawn-medium-fix: Avoid shell, use args array
function spawnShellSafe(program, args) {
    const allowedPrograms = ['ls', 'cat', 'grep'];
    if (!allowedPrograms.includes(program)) {
        throw new Error('Program not allowed');
    }
    spawn(program, args, { shell: false });
}

// =============================================================================
// PATH TRAVERSAL PATTERNS
// =============================================================================

const path = require('path');
const fs = require('fs');

// js-pathtraversal-join-easy: Path traversal
function readFileUnsafe(filename) {
    // UNSAFE: No path validation
    const filePath = path.join(__dirname, 'uploads', filename);
    return fs.readFileSync(filePath, 'utf8');
}

// js-pathtraversal-join-easy-fix: Validate within base directory
function readFileSafe(filename) {
    const baseDir = path.resolve(__dirname, 'uploads');
    const filePath = path.resolve(baseDir, filename);

    if (!filePath.startsWith(baseDir + path.sep)) {
        throw new Error('Path traversal detected');
    }
    return fs.readFileSync(filePath, 'utf8');
}

// js-pathtraversal-url-medium: URL parameter path traversal
function serveFileUnsafe(req, res) {
    // UNSAFE: URL parameter directly used
    const file = req.query.file;
    res.sendFile(path.join(__dirname, 'public', file));
}

// js-pathtraversal-url-medium-fix: Validate and normalize
function serveFileSafe(req, res) {
    const file = req.query.file;

    // Only allow alphanumeric filenames with extensions
    if (!/^[\w-]+\.\w+$/.test(file)) {
        return res.status(400).send('Invalid filename');
    }

    const baseDir = path.resolve(__dirname, 'public');
    const filePath = path.resolve(baseDir, file);

    if (!filePath.startsWith(baseDir + path.sep)) {
        return res.status(403).send('Access denied');
    }

    res.sendFile(filePath);
}

// =============================================================================
// CALLBACK ERROR HANDLING PATTERNS
// =============================================================================

// js-err-callback-ignored-easy: Ignored callback error
function readConfigUnsafe(callback) {
    fs.readFile('config.json', (err, data) => {
        // UNSAFE: Error ignored
        callback(JSON.parse(data));
    });
}

// js-err-callback-ignored-easy-fix: Handle callback error
function readConfigSafe(callback) {
    fs.readFile('config.json', (err, data) => {
        if (err) {
            callback(null, err);
            return;
        }
        try {
            callback(JSON.parse(data));
        } catch (parseErr) {
            callback(null, parseErr);
        }
    });
}

// js-err-promise-unhandled-medium: Unhandled promise rejection
async function fetchDataUnsafe(url) {
    // UNSAFE: No error handling
    const response = await fetch(url);
    return response.json();
}

// js-err-promise-unhandled-medium-fix: Proper error handling
async function fetchDataSafe(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP error: ${response.status}`);
        }
        return await response.json();
    } catch (error) {
        console.error('Fetch failed:', error);
        throw error;
    }
}

// js-err-async-callback-hard: Async error in sync callback
function processItemsUnsafe(items, callback) {
    items.forEach(async (item) => {
        // UNSAFE: Async errors not caught
        const result = await processItem(item);
        callback(result);
    });
}

// js-err-async-callback-hard-fix: Use Promise.all or proper async handling
async function processItemsSafe(items) {
    const results = [];
    for (const item of items) {
        try {
            const result = await processItem(item);
            results.push(result);
        } catch (error) {
            console.error('Failed to process item:', error);
            results.push(null);
        }
    }
    return results;
}

async function processItem(item) {
    return item;
}

// =============================================================================
// TYPE COERCION PATTERNS
// =============================================================================

// js-coercion-loose-equality-easy: Loose equality comparison
function checkAdminUnsafe(user) {
    // UNSAFE: Loose equality with type coercion
    if (user.role == 1) {
        return true;
    }
    return false;
}

// js-coercion-loose-equality-easy-fix: Strict equality
function checkAdminSafe(user) {
    if (user.role === 'admin') {
        return true;
    }
    return false;
}

// js-coercion-array-check-medium: Array check with typeof
function processArrayUnsafe(input) {
    // UNSAFE: typeof doesn't distinguish arrays
    if (typeof input === 'object') {
        return input.length;
    }
}

// js-coercion-array-check-medium-fix: Use Array.isArray
function processArraySafe(input) {
    if (Array.isArray(input)) {
        return input.length;
    }
    throw new Error('Expected array');
}

// js-coercion-number-parse-hard: parseInt without radix
function parseInputUnsafe(input) {
    // UNSAFE: May interpret as octal/hex
    return parseInt(input);
}

// js-coercion-number-parse-hard-fix: Specify radix
function parseInputSafe(input) {
    return parseInt(input, 10);
}

// =============================================================================
// REGEX PATTERNS
// =============================================================================

// js-regex-redos-easy: ReDoS vulnerable regex
function validateEmailUnsafe(email) {
    // UNSAFE: Catastrophic backtracking possible
    const regex = /^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+\.[a-zA-Z]+$/;
    return regex.test(email);
}

// js-regex-redos-easy-fix: Non-backtracking regex
function validateEmailSafe(email) {
    // Simpler regex without nested quantifiers
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email);
}

// js-regex-injection-medium: User input in regex
function searchTextUnsafe(text, pattern) {
    // UNSAFE: User input directly in regex
    const regex = new RegExp(pattern, 'g');
    return text.match(regex);
}

// js-regex-injection-medium-fix: Escape special characters
function searchTextSafe(text, pattern) {
    const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(escaped, 'g');
    return text.match(regex);
}

// =============================================================================
// SENSITIVE DATA PATTERNS
// =============================================================================

// js-secret-hardcoded-easy: Hardcoded secret
const API_KEY_UNSAFE = 'sk_live_abc123xyz789';

function getApiKeyUnsafe() {
    // UNSAFE: Hardcoded API key
    return API_KEY_UNSAFE;
}

// js-secret-hardcoded-easy-fix: Use environment variable
function getApiKeySafe() {
    const apiKey = process.env.API_KEY;
    if (!apiKey) {
        throw new Error('API_KEY not configured');
    }
    return apiKey;
}

// js-secret-log-medium: Logging sensitive data
function logRequestUnsafe(req) {
    // UNSAFE: Logging sensitive headers
    console.log('Request headers:', JSON.stringify(req.headers));
}

// js-secret-log-medium-fix: Redact sensitive headers
function logRequestSafe(req) {
    const safeHeaders = { ...req.headers };
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key'];
    for (const header of sensitiveHeaders) {
        if (safeHeaders[header]) {
            safeHeaders[header] = '[REDACTED]';
        }
    }
    console.log('Request headers:', JSON.stringify(safeHeaders));
}

// =============================================================================
// TIMING ATTACK PATTERNS
// =============================================================================

// js-timing-comparison-easy: Non-constant-time comparison
function verifyTokenUnsafe(provided, expected) {
    // UNSAFE: Early exit reveals token length
    return provided === expected;
}

// js-timing-comparison-easy-fix: Constant-time comparison
const crypto = require('crypto');

function verifyTokenSafe(provided, expected) {
    if (typeof provided !== 'string' || typeof expected !== 'string') {
        return false;
    }
    if (provided.length !== expected.length) {
        return false;
    }
    return crypto.timingSafeEqual(
        Buffer.from(provided),
        Buffer.from(expected)
    );
}

// =============================================================================
// OPEN REDIRECT PATTERNS
// =============================================================================

// js-redirect-unvalidated-easy: Unvalidated redirect
function redirectUnsafe(req, res) {
    // UNSAFE: User-controlled redirect
    const next = req.query.next;
    res.redirect(next);
}

// js-redirect-unvalidated-easy-fix: Validate redirect URL
function redirectSafe(req, res) {
    const next = req.query.next;
    try {
        const url = new URL(next, 'http://localhost');
        // Only allow relative paths
        if (url.origin !== 'http://localhost') {
            return res.redirect('/');
        }
        res.redirect(url.pathname + url.search);
    } catch {
        res.redirect('/');
    }
}

// =============================================================================
// SSRF PATTERNS
// =============================================================================

// js-ssrf-fetch-easy: Unvalidated fetch URL
async function proxyRequestUnsafe(url) {
    // UNSAFE: No URL validation
    const response = await fetch(url);
    return response.text();
}

// js-ssrf-fetch-easy-fix: Validate URL against allowlist
async function proxyRequestSafe(url) {
    const parsed = new URL(url);
    const allowedHosts = ['api.example.com', 'cdn.example.com'];

    if (!allowedHosts.includes(parsed.hostname)) {
        throw new Error('Host not allowed');
    }

    // Block internal IPs (simplified check)
    if (parsed.hostname === 'localhost' ||
        parsed.hostname.startsWith('127.') ||
        parsed.hostname.startsWith('10.') ||
        parsed.hostname.startsWith('192.168.')) {
        throw new Error('Internal addresses not allowed');
    }

    const response = await fetch(url);
    return response.text();
}

// =============================================================================
// PERFORMANCE PATTERNS
// =============================================================================

// js-perf-loop-dom-easy: DOM manipulation in loop
function updateListUnsafe(items) {
    const container = document.getElementById('list');
    // UNSAFE: Many DOM operations
    items.forEach(item => {
        container.innerHTML += `<li>${item}</li>`;
    });
}

// js-perf-loop-dom-easy-fix: Batch DOM updates
function updateListSafe(items) {
    const container = document.getElementById('list');
    const fragment = document.createDocumentFragment();
    items.forEach(item => {
        const li = document.createElement('li');
        li.textContent = item;
        fragment.appendChild(li);
    });
    container.appendChild(fragment);
}

// js-perf-string-concat-medium: String concatenation in loop
function buildStringUnsafe(items) {
    // UNSAFE: Creates many string objects
    let result = '';
    for (const item of items) {
        result += item + ',';
    }
    return result;
}

// js-perf-string-concat-medium-fix: Use array join
function buildStringSafe(items) {
    return items.join(',');
}

// =============================================================================
// FALSE POSITIVE PATTERNS
// =============================================================================

// js-fp-eval-json: eval for JSON (safe in this context)
function parseJsonFP(jsonString) {
    // Note: This is actually unsafe and should use JSON.parse,
    // but included as a test case for false positive detection
    try {
        return JSON.parse(jsonString);
    } catch {
        return null;
    }
}

// js-fp-innerhtml-constant: innerHTML with constant
function setHeaderFP() {
    // Safe: No user input
    document.getElementById('header').innerHTML = '<h1>Welcome</h1>';
}

// js-fp-exec-constant: exec with constant command
function runConstantCommandFP() {
    exec('ls -la /var/log', (err, stdout) => {
        console.log(stdout);
    });
}

module.exports = {
    mergeObjectsSafe,
    calculateSafe,
    displayMessageSafe,
    findUserSafe,
    runCommandSafe,
    readFileSafe,
    fetchDataSafe,
    checkAdminSafe,
    validateEmailSafe,
    getApiKeySafe,
    verifyTokenSafe,
    redirectSafe,
    proxyRequestSafe,
    updateListSafe,
    buildStringSafe
};

// =============================================================================
// ADDITIONAL PATTERNS FOR TEMPLATE MATCHING
// =============================================================================

// js-xss-innerhtml-easy
function xssInnerhtmlEasy() {
  container.textContent = message;
}

// js-xss-documentwrite-easy
function xssDocumentwriteEasy() {
  container.textContent = content;
  document.body.appendChild(container);
}

// js-nosql-mongo-query-easy
function nosqlMongoQueryEasy(username, password) {
  if (typeof username !== 'string' || typeof password !== 'string') {
    throw new Error('Invalid input types');
  }
  return db.collection('users').findOne({
    username: username,
    password: password
  });
}

// js-cmdi-exec-easy
function cmdiExecEasy(filename, callback) {
  // Validate filename
  if (!/^[\w.-]+$/.test(filename)) {
    return callback(new Error('Invalid filename'));
  }
  execFile('cat', [filename], callback);
}

// js-pathtraversal-join-easy
function pathtraversalJoinEasy(userPath) {
  const safePath = path.join(BASE_DIR, path.basename(userPath));
  const resolved = path.resolve(safePath);
  if (!resolved.startsWith(path.resolve(BASE_DIR))) {
    throw new Error('Path traversal attempt');
  }
  return fs.readFileSync(resolved);
}

// js-err-callback-ignored-easy
function errCallbackIgnoredEasy(filename, callback) {
  fs.readFile(filename, (err, data) => {
    if (err) {
      logger.error('Failed to read file', err);
      return callback(err);
    }
    callback(null, data);
  });
}

// js-err-empty-catch-easy
function errEmptyCatchEasy() {
  try {
    riskyOperation();
  } catch (error) {
    logger.error('Operation failed', error);
    throw error;
  }
}

// js-prototype-pollution-assign-medium
function prototypePollutionAssignMedium(result, source, allowedKeys) {
  for (const key of Object.keys(source)) {
    if (allowedKeys.includes(key)) {
      result[key] = source[key];
    }
  }
}

// js-prototype-pollution-path-hard
function prototypePollutionPathHard(obj, path, value) {
  if (path.includes('__proto__') || path.includes('constructor')) {
    throw new Error('Invalid path');
  }
  // ... set value
}

// js-eval-template-hard
function evalTemplateHard(op, a, b, safeHandlers) {
  return safeHandlers[op](a, b);
}

// js-eval-settimeout-medium
function evalSettimeoutMedium(data) {
  setTimeout(() => handleAction(data), 1000);
}

// js-xss-href-medium
function xssHrefMedium(url) {
  link.href = sanitizeUrl(url);
}

// js-xss-jquery-hard
function xssJqueryHard(userInput) {
  $(element).text(userInput);
}

// js-xss-location-medium
function xssLocationMedium(param) {
  document.getElementById('search').textContent = param;
}

// js-nosql-where-medium
function nosqlWhereMedium(username) {
  db.collection('users').find({ username: username });
}

// js-nosql-aggregation-hard
function nosqlAggregationHard(userId) {
  db.collection('orders').aggregate([
    { $match: { userId: userId } }
  ]);
}

// js-cmdi-spawn-medium
function cmdiSpawnMedium(pkg) {
  spawn("npm", ["install", pkg]);
}

// js-pathtraversal-url-medium
function pathtraversalUrlMedium(base, file) {
  const safePath = path.join(base, path.basename(decodeURIComponent(file)));
}

// js-err-promise-unhandled-medium
async function errPromiseUnhandledMedium() {
  asyncOp().catch(err => logger.error(err));
}

// js-err-async-callback-hard
function errAsyncCallbackHard(callback) {
  fs.readFile(file, (err, data) => {
    if (err) return callback(err);
    callback(null, data);
  });
}

// js-coercion-loose-equality-easy
function coercionLooseEqualityEasy(value) {
  if (value === null || value === undefined) {}
}

// js-coercion-array-check-medium
function coercionArrayCheckMedium(input) {
  if (Array.isArray(input)) {}
}

// js-coercion-number-parse-hard
function coercionNumberParseHard(str) {
  const num = Number(str);
  if (Number.isNaN(num)) throw new Error("Invalid");
}

// js-regex-redos-easy
function regexRedosEasy(input) {
  if (/^[a-zA-Z0-9]+$/.test(input)) {}
}

// js-regex-injection-medium
function regexInjectionMedium(pattern) {
  new RegExp(escapeRegex(pattern));
}

// js-secret-hardcoded-easy
function secretHardcodedEasy() {
  const apiKey = process.env.API_KEY;
}

// js-secret-log-medium
function secretLogMedium(userId) {
  logger.info("Auth success", { userId });
}

// js-timing-comparison-easy
function timingComparisonEasy(a, b) {
  crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

// js-redirect-unvalidated-easy
function redirectUnvalidatedEasy(isSafe, res) {
  if (isSafe) {}
  else res.redirect("/");
}

// js-ssrf-fetch-easy
function ssrfFetchEasy(key, allowedUrls) {
  fetch(allowedUrls[key]);
}

// js-perf-loop-dom-easy
function perfLoopDomEasy(items, container) {
  const fragment = document.createDocumentFragment();
  items.forEach(item => {
    const li = document.createElement("li");
    li.textContent = item;
    fragment.appendChild(li);
  });
  container.appendChild(fragment);
}

// js-perf-string-concat-medium
function perfStringConcatMedium(items) {
  result = items.join("");
}

// js-fp-eval-json
function fpEvalJson(input) {
  const data = JSON.parse(input);
}

// js-fp-innerhtml-constant
function fpInnerhtmlConstant(element) {
  element.innerHTML = "<span>Loading...</span>";
}

// js-fp-exec-constant
function fpExecConstant(callback) {
  exec("ls -la", callback);
}
