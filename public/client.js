let ws;
let currentChatWith = null;
let token = localStorage.getItem('token');
let userId = null;
let username = null;
let visitorToken = null;
const SECRET_KEY = 'sua-chave-secreta-aqui'; // Deve ser igual ao backend

toastr.options = {
    positionClass: 'toast-top-right',
    timeOut: 3000,
    progressBar: true
};

// Obtém token visitante ao carregar a página
async function getVisitorToken() {
    const res = await fetch('/visitor-token');
    const data = await res.json();
    visitorToken = data.token;
}

function showRegister() {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('register-form').classList.remove('hidden');
}

function showLogin() {
    document.getElementById('register-form').classList.add('hidden');
    document.getElementById('login-form').classList.remove('hidden');
}

async function register() {
    const registerUsername = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    const payload = { username: registerUsername, password };
    const encryptedPayload = CryptoJS.AES.encrypt(JSON.stringify(payload), SECRET_KEY).toString();

    const res = await fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-token-id': 'REGISTER_TOKEN',
            'x-token-visitor': visitorToken
        },
        body: JSON.stringify({ payload: encryptedPayload })
    });
    const data = await res.json();
    if (data.success) {
        toastr.success('Registrado com sucesso! Entrando...', 'Sucesso', { iconClass: 'toast-success fas fa-check' });
        token = data.token;
        userId = data.userId;
        username = data.username;
        localStorage.setItem('token', token);
        initChat();
    } else {
        toastr.error(data.error, 'Erro', { iconClass: 'toast-error fas fa-times' });
        if (data.error === 'Você foi banido por atividades suspeitas.') {
            showBannedModal();
        }
    }
}

async function login() {
    const loginUsername = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const payload = { username: loginUsername, password };
    const encryptedPayload = CryptoJS.AES.encrypt(JSON.stringify(payload), SECRET_KEY).toString();

    const res = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'x-token-id': 'LOGIN_TOKEN',
            'x-token-visitor': visitorToken
        },
        body: JSON.stringify({ payload: encryptedPayload })
    });
    const data = await res.json();
    if (data.token) {
        token = data.token;
        userId = data.userId;
        username = data.username;
        localStorage.setItem('token', token);
        toastr.success('Login realizado!', 'Sucesso', { iconClass: 'toast-success fas fa-check' });
        initChat();
    } else {
        toastr.error(data.error, 'Erro', { iconClass: 'toast-error fas fa-times' });
        if (data.error === 'Você foi banido por atividades suspeitas.') {
            showBannedModal();
        }
    }
}

function loginAsAnon() {
    username = 'Anônimo';
    initChat();
}

function initChat() {
    document.getElementById('auth-modal').classList.add('hidden');
    document.getElementById('chat-app').classList.remove('hidden');
    ws = new WebSocket('ws://localhost:3000');
    
    ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'login', token }));
    };

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'active_users') updateActiveUsers(data.data);
        if (data.type === 'message') displayMessage(data.data);
        if (data.type === 'typing') showTyping(data.from);
    };

    ws.onclose = (event) => {
        if (event.code === 1008) {
            showBannedModal();
        }
    };

    loadEmojiPicker();
    document.getElementById('user-id').textContent = userId || 'Anônimo';
    document.getElementById('user-username').textContent = username;
}

function updateActiveUsers(users) {
    const ul = document.getElementById('active-users');
    ul.innerHTML = '';
    users.forEach(user => {
        const li = document.createElement('li');
        li.className = 'p-2 bg-gray-700 rounded cursor-pointer hover:bg-cyan-600 flex items-center';
        li.innerHTML = `${user.username}${user.verified ? ' <i class="fas fa-check-circle text-green-400 ml-2"></i>' : ''}`;
        li.onclick = () => startChat(user.id, user.username);
        ul.appendChild(li);
    });
}

function startChat(userId, username) {
    currentChatWith = userId;
    document.getElementById('chat-with').textContent = username;
    document.getElementById('messages').innerHTML = '';
}

async function sendMessage() {
    const input = document.getElementById('message-input');
    if (input.value && currentChatWith) {
        const encrypted = CryptoJS.AES.encrypt(input.value, SECRET_KEY).toString();
        ws.send(JSON.stringify({ type: 'message', to: currentChatWith, content: encrypted }));
        input.value = '';
        toastr.info('Mensagem enviada!', 'Info', { iconClass: 'toast-info fas fa-info-circle' });
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('file-input');
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    const res = await fetch('/upload', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'x-token-id': 'UPLOAD_TOKEN',
            'x-token-visitor': visitorToken
        },
        body: formData
    });
    const data = await res.json();
    if (data.filePath) {
        const encrypted = CryptoJS.AES.encrypt('Anexo', SECRET_KEY).toString();
        ws.send(JSON.stringify({ type: 'message', to: currentChatWith, content: encrypted, file: data.filePath }));
        toastr.success('Arquivo enviado!', 'Sucesso', { iconClass: 'toast-success fas fa-check' });
    } else if (data.error === 'Você foi banido por atividades suspeitas.') {
        showBannedModal();
    }
}

function displayMessage(msg) {
    if (msg.from === currentChatWith || msg.to === currentChatWith) {
        const div = document.createElement('div');
        div.className = 'p-2 bg-gray-700 rounded mb-2';
        const decryptedContent = decryptMessage(msg.content);
        div.innerHTML = `<strong>${msg.fromUsername}:</strong> ${decryptedContent}`;
        if (msg.file) {
            if (msg.file.match(/\.(jpg|png|gif)$/)) {
                div.innerHTML += `<br><img src="${msg.file}" class="max-w-xs rounded mt-2">`;
            } else if (msg.file.match(/\.(mp4|webm)$/)) {
                div.innerHTML += `<br><video src="${msg.file}" controls class="max-w-xs rounded mt-2"></video>`;
            } else {
                div.innerHTML += `<br><a href="${msg.file}" target="_blank" class="text-cyan-400">Download</a>`;
            }
        }
        document.getElementById('messages').appendChild(div);
    }
}

function decryptMessage(encrypted) {
    const bytes = CryptoJS.AES.decrypt(encrypted, SECRET_KEY);
    return bytes.toString(CryptoJS.enc.Utf8);
}

function showTyping(from) {
    if (from === document.getElementById('chat-with').textContent) {
        const typing = document.getElementById('typing');
        typing.textContent = `${from} está digitando...`;
        setTimeout(() => typing.textContent = '', 2000);
    }
}

function toggleEmojiPicker() {
    const picker = document.getElementById('emoji-picker');
    picker.classList.toggle('hidden');
}

function loadEmojiPicker() {
    const picker = document.getElementById('emoji-picker');
    const emojis = ['😀', '😂', '😍', '😢', '😡', '👍', '👎', '❤️', '🎉', '🔥'];
    emojis.forEach(emoji => {
        const btn = document.createElement('button');
        btn.textContent = emoji;
        btn.className = 'text-2xl';
        btn.onclick = () => {
            document.getElementById('message-input').value += emoji;
            picker.classList.add('hidden');
        };
        picker.appendChild(btn);
    });
}

function showProfileModal() {
    document.getElementById('profile-modal').classList.remove('hidden');
}

function showBannedModal() {
    document.getElementById('auth-modal').classList.add('hidden');
    document.getElementById('chat-app').classList.add('hidden');
    document.getElementById('banned-modal').classList.remove('hidden');
    localStorage.removeItem('token');
}

function closeModal(modalId) {
    document.getElementById(modalId).classList.add('hidden');
}

document.getElementById('message-input').addEventListener('input', () => {
    if (currentChatWith) {
        ws.send(JSON.stringify({ type: 'typing', to: currentChatWith }));
    }
});

document.getElementById('message-input').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
});

// Inicializa com token visitante
getVisitorToken().then(() => {
    if (token) {
        fetch('/login', {
            headers: {
                'Authorization': `Bearer ${token}`,
                'x-token-id': 'CHECK_TOKEN',
                'x-token-visitor': visitorToken
            }
        })
        .then(res => res.json())
        .then(data => {
            if (data.userId) {
                userId = data.userId;
                username = data.username;
                initChat();
            } else if (data.error === 'Você foi banido por atividades suspeitas.') {
                showBannedModal();
            }
        })
        .catch(() => localStorage.removeItem('token'));
    }
});