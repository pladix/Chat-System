const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const CryptoJS = require('crypto-js');
const axios = require('axios');
const requestIp = require('request-ip');
const helmet = require('helmet');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const SECRET_KEY = 'sua-chave-secreta-aqui';
const TELEGRAM_BOT_TOKEN = '6493285512:AAGSWlNtN_JfP-pb5K_M0YE_40jzev90WP8';
const TELEGRAM_CHAT_ID = '-1002408412523';
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'public', 'uploads');
const VISITOR_TOKEN_EXPIRY = 5 * 60 * 1000;

// Inicializa pastas e arquivos
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const usersFile = path.join(DATA_DIR, 'users.json');
const messagesFile = path.join(DATA_DIR, 'messages.json');
const activeChatsFile = path.join(DATA_DIR, 'active_chats.json');
const sessionsFile = path.join(DATA_DIR, 'sessions.json');
const bannedFile = path.join(DATA_DIR, 'banned.json');
const tokensFile = path.join(DATA_DIR, 'tokens.json');

if (!fs.existsSync(usersFile)) fs.writeFileSync(usersFile, JSON.stringify([], null, 2));
if (!fs.existsSync(messagesFile)) fs.writeFileSync(messagesFile, JSON.stringify([], null, 2));
if (!fs.existsSync(activeChatsFile)) fs.writeFileSync(activeChatsFile, JSON.stringify([], null, 2));
if (!fs.existsSync(sessionsFile)) fs.writeFileSync(sessionsFile, JSON.stringify([], null, 2));
if (!fs.existsSync(bannedFile)) fs.writeFileSync(bannedFile, JSON.stringify([], null, 2));
if (!fs.existsSync(tokensFile)) fs.writeFileSync(tokensFile, JSON.stringify([], null, 2));

// Configuração do multer
const storage = multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`)
});
const upload = multer({ storage });

// Middleware de segurança com CSP ajustado
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", 'https://cdnjs.cloudflare.com', "'unsafe-inline'"], // Permite Font Awesome, Toastr e inline styles
            scriptSrc: ["'self'", 'https://cdn.tailwindcss.com', 'https://cdnjs.cloudflare.com'], // Permite Tailwind, jQuery, Toastr
            connectSrc: ["'self'", 'ws://localhost:3000', 'https://api.telegram.org'], // Permite WebSocket e Telegram
            imgSrc: ["'self'", 'data:', 'https://*'], // Permite imagens locais e externas
            fontSrc: ["'self'", 'https://cdnjs.cloudflare.com'], // Permite fontes do Font Awesome
            objectSrc: ["'none'"],
            upgradeInsecureRequests: []
        }
    }
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 5 * 60 * 1000, max: 10 }));

function encryptPayload(payload) {
    return CryptoJS.AES.encrypt(JSON.stringify(payload), SECRET_KEY).toString();
}

function decryptPayload(encrypted) {
    const bytes = CryptoJS.AES.decrypt(encrypted, SECRET_KEY);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

async function logToTelegram(message) {
    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: message,
            parse_mode: 'Markdown'
        });
    } catch (error) {
        console.error('Erro ao enviar para Telegram:', error);
    }
}

function getUserInfo(req) {
    const ip = requestIp.getClientIp(req);
    const userAgent = req.headers['user-agent'] || 'Desconhecido';
    const acceptLanguage = req.headers['accept-language'] || 'Desconhecido';
    const referer = req.headers['referer'] || 'Desconhecido';
    const cookies = req.headers['cookie'] || 'Nenhum';
    return { ip, userAgent, acceptLanguage, referer, cookies, timestamp: new Date().toISOString() };
}

function generateVisitorToken(ip) {
    const tokens = JSON.parse(fs.readFileSync(tokensFile));
    const token = CryptoJS.lib.WordArray.random(16).toString();
    tokens.push({ token, ip, createdAt: Date.now(), expiresAt: Date.now() + VISITOR_TOKEN_EXPIRY, used: false });
    fs.writeFileSync(tokensFile, JSON.stringify(tokens, null, 2));
    return token;
}

function validateVisitorToken(token, ip) {
    const tokens = JSON.parse(fs.readFileSync(tokensFile));
    const tokenEntry = tokens.find(t => t.token === token && t.ip === ip && !t.used && Date.now() < t.expiresAt);
    if (tokenEntry) {
        tokenEntry.used = true;
        fs.writeFileSync(tokensFile, JSON.stringify(tokens.filter(t => Date.now() < t.expiresAt), null, 2));
        return true;
    }
    return false;
}

function isBanned(req) {
    const banned = JSON.parse(fs.readFileSync(bannedFile));
    const ip = requestIp.getClientIp(req);
    return banned.some(b => b.ip === ip);
}

function banUser(req, reason) {
    const banned = JSON.parse(fs.readFileSync(bannedFile));
    const userInfo = getUserInfo(req);
    if (!banned.some(b => b.ip === userInfo.ip)) {
        banned.push({ ...userInfo, reason, bannedAt: new Date().toISOString() });
        fs.writeFileSync(bannedFile, JSON.stringify(banned, null, 2));
        logToTelegram(`🚫 Usuário banido:\nIP: ${userInfo.ip}\nUser-Agent: ${userInfo.userAgent}\nMotivo: ${reason}`);
    }
}

function blockBannedAndDDoS(req, res, next) {
    const userInfo = getUserInfo(req);
    if (isBanned(req)) {
        logToTelegram(`🚫 Requisição bloqueada (banido)\nIP: ${userInfo.ip}`);
        return res.status(403).json({ error: 'Você foi banido por atividades suspeitas.' });
    }

    const rateLimitExceeded = req.rateLimit && req.rateLimit.remaining === 0;
    if (rateLimitExceeded) {
        banUser(req, 'Excesso de requisições (suspeita de DDoS)');
        return res.redirect(302, 'https://www.google.com');
    }

    const tokenVisitor = req.headers['x-token-visitor'];
    if (!tokenVisitor || !validateVisitorToken(tokenVisitor, userInfo.ip)) {
        logToTelegram(`🚨 Requisição sem token visitante válido\nIP: ${userInfo.ip}`);
        return res.status(403).json({ error: 'Token visitante inválido ou expirado' });
    }

    next();
}

app.use(blockBannedAndDDoS);

app.get('/visitor-token', (req, res) => {
    const userInfo = getUserInfo(req);
    const token = generateVisitorToken(userInfo.ip);
    res.json({ token });
});

app.post('/register', async (req, res) => {
    const encryptedPayload = req.body.payload;
    const userInfo = getUserInfo(req);
    const tokenId = req.headers['x-token-id'];

    if (!encryptedPayload || !tokenId || tokenId !== 'REGISTER_TOKEN') {
        logToTelegram(`🚨 Tentativa de registro inválida\nIP: ${userInfo.ip}`);
        return res.status(400).json({ error: 'Payload ou token inválido' });
    }

    const { username, password } = decryptPayload(encryptedPayload);
    if (!username || !password || username.length < 3 || password.length < 6) {
        logToTelegram(`🚨 Tentativa inválida de registro: ${username || 'desconhecido'}\nIP: ${userInfo.ip}`);
        return res.status(400).json({ error: 'Dados inválidos' });
    }

    const users = JSON.parse(fs.readFileSync(usersFile));
    if (users.find(u => u.username === username)) {
        logToTelegram(`🚨 Tentativa de registro duplicado: ${username}\nIP: ${userInfo.ip}`);
        banUser(req, 'Múltiplas tentativas de registro duplicado');
        return res.status(400).json({ error: 'Usuário já existe' });
    }

    const userId = `user_${Math.random().toString(36).substr(2, 9)}`;
    const newUser = {
        username,
        password: CryptoJS.SHA256(password).toString(),
        id: userId,
        verified: false,
        info: userInfo
    };
    users.push(newUser);
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));

    const token = jwt.sign({ userId: userId }, SECRET_KEY, { expiresIn: '1h' });
    const sessions = JSON.parse(fs.readFileSync(sessionsFile));
    sessions.push({ token, userId: userId, info: userInfo });
    fs.writeFileSync(sessionsFile, JSON.stringify(sessions, null, 2));

    logToTelegram(`✅ Novo usuário registrado: ${username}\nIP: ${userInfo.ip}\nUser-Agent: ${userInfo.userAgent}\nAccept-Language: ${userInfo.acceptLanguage}\nReferer: ${userInfo.referer}\nCookies: ${userInfo.cookies}`);
    res.json({ success: true, token, userId, username });
});

app.post('/login', async (req, res) => {
    const encryptedPayload = req.body.payload;
    const userInfo = getUserInfo(req);
    const tokenId = req.headers['x-token-id'];

    if (!encryptedPayload || !tokenId || tokenId !== 'LOGIN_TOKEN') {
        logToTelegram(`🚨 Tentativa de login inválida\nIP: ${userInfo.ip}`);
        return res.status(400).json({ error: 'Payload ou token inválido' });
    }

    const { username, password } = decryptPayload(encryptedPayload);
    const users = JSON.parse(fs.readFileSync(usersFile));
    const user = users.find(u => u.username === username && u.password === CryptoJS.SHA256(password).toString());
    if (!user) {
        logToTelegram(`🚨 Falha no login: ${username}\nIP: ${userInfo.ip}`);
        return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    const sessions = JSON.parse(fs.readFileSync(sessionsFile));
    sessions.push({ token, userId: user.id, info: userInfo });
    fs.writeFileSync(sessionsFile, JSON.stringify(sessions, null, 2));

    logToTelegram(`✅ Login bem-sucedido: ${username}\nIP: ${userInfo.ip}\nUser-Agent: ${userInfo.userAgent}`);
    res.json({ token, userId: user.id, username: user.username });
});

app.post('/upload', verifyToken, upload.single('file'), (req, res) => {
    const userInfo = getUserInfo(req);
    logToTelegram(`📎 Upload de arquivo por ${req.userId}\nIP: ${userInfo.ip}`);
    res.json({ filePath: `/uploads/${req.file.filename}` });
});

function verifyToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    const userInfo = getUserInfo(req);
    if (!token) {
        logToTelegram(`🚨 Tentativa de acesso sem token\nIP: ${userInfo.ip}`);
        return res.status(403).json({ error: 'Token não fornecido' });
    }
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            logToTelegram(`🚨 Token inválido detectado\nIP: ${userInfo.ip}`);
            return res.status(401).json({ error: 'Token inválido' });
        }
        req.userId = decoded.userId;
        next();
    });
}

wss.on('connection', (ws, req) => {
    const userInfo = getUserInfo(req);
    if (isBanned(req)) {
        ws.close(1008, 'Você foi banido por atividades suspeitas.');
        logToTelegram(`🚫 Conexão WebSocket recusada\nIP: ${userInfo.ip}\nMotivo: Usuário banido`);
        return;
    }

    ws.on('message', (message) => {
        const data = JSON.parse(message);

        if (data.type === 'login') {
            jwt.verify(data.token, SECRET_KEY, (err, decoded) => {
                ws.userId = err ? `anon_${Math.random().toString(36).substr(2, 9)}` : decoded.userId;
                const users = JSON.parse(fs.readFileSync(usersFile));
                ws.username = users.find(u => u.id === ws.userId)?.username || ws.userId;
                ws.verified = users.find(u => u.id === ws.userId)?.verified || false;
                if (!data.token) {
                    logToTelegram(`👤 Entrada anônima: ${ws.username}\nIP: ${userInfo.ip}\nUser-Agent: ${userInfo.userAgent}`);
                }
                updateActiveUsers(ws.userId, ws.username, ws.verified);
            });
        }

        if (data.type === 'message') {
            const msg = {
                from: ws.userId,
                fromUsername: ws.username,
                to: data.to,
                content: data.content,
                file: data.file || null,
                timestamp: new Date().toISOString()
            };
            saveMessage(msg);
            broadcastMessage(msg);
        }

        if (data.type === 'typing') {
            broadcastTyping(ws.username, data.to);
        }
    });

    ws.on('close', () => removeActiveUser(ws.userId));
});

function saveMessage(msg) {
    const messages = JSON.parse(fs.readFileSync(messagesFile));
    messages.push(msg);
    fs.writeFileSync(messagesFile, JSON.stringify(messages, null, 2));
}

function updateActiveUsers(userId, username, verified) {
    const activeChats = JSON.parse(fs.readFileSync(activeChatsFile));
    const existing = activeChats.find(chat => chat.id === userId);
    if (!existing) {
        activeChats.push({ id: userId, username, verified });
        fs.writeFileSync(activeChatsFile, JSON.stringify(activeChats, null, 2));
        broadcastActiveUsers();
    }
}

function removeActiveUser(userId) {
    const activeChats = JSON.parse(fs.readFileSync(activeChatsFile));
    const updated = activeChats.filter(chat => chat.id !== userId);
    fs.writeFileSync(activeChatsFile, JSON.stringify(updated, null, 2));
    broadcastActiveUsers();
}

function broadcastMessage(msg) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && (client.userId === msg.to || client.userId === msg.from)) {
            client.send(JSON.stringify({ type: 'message', data: msg }));
        }
    });
}

function broadcastTyping(from, to) {
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN && client.userId === to) {
            client.send(JSON.stringify({ type: 'typing', from }));
        }
    });
}

function broadcastActiveUsers() {
    const activeChats = JSON.parse(fs.readFileSync(activeChatsFile));
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ type: 'active_users', data: activeChats }));
        }
    });
}

server.listen(3000, () => console.log('Server running on port 3000'));