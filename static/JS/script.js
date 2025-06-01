import * as Recorder from './recorder.js';
import { sodium } from './libsodium.js';

let mediaRecorder;
let audioChunks = [];

// Initialize encryption
await sodium.ready;

// WebSocket Connection
const socket = io.connect('http://' + document.domain + ':' + location.port);

// Typing Indicator
function showTyping() {
    document.getElementById('typingIndicator').style.display = 'flex';
}

function hideTyping() {
    document.getElementById('typingIndicator').style.display = 'none';
}

// Example integration
document.getElementById('sendButton').addEventListener('click', function () {
    const message = document.getElementById('messageInput').value;
    if (!message.trim()) return;

    // Display user's message
    appendMessage('You', message);
    document.getElementById('messageInput').value = '';

    // Show typing indicator
    showTyping();

    // Simulate bot response after a short delay (replace with real fetch/response)
    setTimeout(() => {
        appendMessage('Bot', 'Typing simulation response...');
        hideTyping();
    }, 1500);
});

function appendMessage(sender, message) {
    const chatArea = document.querySelector('.chat-area');
    const msgDiv = document.createElement('div');
    msgDiv.classList.add('message');
    msgDiv.innerHTML = `<strong>${sender}:</strong> ${message}`;
    chatArea.appendChild(msgDiv);
    chatArea.scrollTop = chatArea.scrollHeight;
}

// Voice Recording
document.getElementById('recordButton').addEventListener('click', async () => {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    audioChunks = [];

    mediaRecorder.ondataavailable = (e) => {
        audioChunks.push(e.data);
    };

    mediaRecorder.onstop = async () => {
        const audioBlob = new Blob(audioChunks, { type: 'audio/webm' });
        const formData = new FormData();
        formData.append('file', audioBlob, 'audio.webm');

        const response = await fetch('/upload', {
            method: 'POST',
            headers: {
                'Authorization': 'Bearer ' + localStorage.getItem('token')
            },
            body: formData
        });

        const data = await response.json();
        sendEncryptedMessage(`audio:${data.file_path}`);
    };

    mediaRecorder.start();
    setTimeout(() => mediaRecorder.stop(), 5000); // Record for 5 seconds
});

// End-to-End Encryption
async function encryptMessage(message, publicKey) {
    const recipientKey = sodium.from_base64(publicKey, sodium.base64_variants.URLSAFE);
    const encrypted = sodium.crypto_box_seal(message, recipientKey);
    return sodium.to_base64(encrypted, sodium.base64_variants.URLSAFE);
}

async function sendEncryptedMessage(content) {
    const publicKey = localStorage.getItem('publicKey');
    const encrypted = await encryptMessage(content, publicKey);

    const response = await fetch('/chat', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: JSON.stringify({
            message: encrypted,
            encrypted: true
        })
    });

    const result = await response.json();
    if (result.bot_reply) {
        const chatArea = document.getElementById('chatArea');
        const botMessage = document.createElement('div');
        botMessage.classList.add('chat-message');
        botMessage.innerHTML = `<strong>Bot:</strong> ${result.bot_reply}`;
        chatArea.appendChild(botMessage);
    }
}

// File Upload
document.getElementById('fileInput').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch('/upload', {
        method: 'POST',
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        },
        body: formData
    });

    const data = await response.json();
    sendEncryptedMessage(`file:${data.file_path}`);
});
// Example: Delete conversation button handler
async function deleteConversation(topicId) {
    const response = await fetch(`/conversations/${topicId}/delete`, {
        method: 'DELETE',
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        }
    });
    const result = await response.json();
    if (result.success) {
        alert('Conversation deleted!');
        fetchConversations(); // Refresh the list
    } else {
        alert('Failed to delete conversation: ' + (result.error || 'Unknown error'));
    }
}
