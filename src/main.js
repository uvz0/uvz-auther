// ============================================================================
// TAURI IPC & INITIALIZATION (Beginning of a sexy totp generator)
// ============================================================================

// Lazy access: don't touch window.__TAURI__ at load time (it may not be ready)
function invoke(cmd, args = {}) {
  return window.__TAURI__.core.invoke(cmd, args);
}

// In-memory state
let keys = []; 
let totpIntervals = {}; 

// ============================================================================
// INITIALIZATION !
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  await loadKeysFromFile();
  renderKeyCards();
});

// ============================================================================
// EVENT LISTENERS
// ============================================================================

function setupEventListeners() {
  const manualPanel = document.getElementById('manual-panel');
  const toggleBtn = document.getElementById('toggle-manual-panel');

  // Dropdown toggle for manual key form
  if (toggleBtn && manualPanel) {
    toggleBtn.addEventListener('click', () => {
      const isOpen = manualPanel.classList.toggle('open');
      toggleBtn.classList.toggle('open', isOpen);
    });
  }

  // Add key button
  document.getElementById('add-manual-btn').addEventListener('click', () => {
    addKeyManual();
  });

  // Password visibility toggle
  document.getElementById('toggle-password').addEventListener('click', () => {
    togglePasswordVisibility();
  });

  // Enter key support
  document.getElementById('secret-name').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addKeyManual();
  });
  document.getElementById('secret-value').addEventListener('keypress', (e) => {
    if (e.key === 'Enter') addKeyManual();
  });
}

function clearInputs() {
  document.getElementById('secret-name').value = '';
  document.getElementById('secret-value').value = '';
}

// ============================================================================
// PASSWORD VISIBILITY TOGGLE
// ============================================================================

function togglePasswordVisibility() {
  const input = document.getElementById('secret-value');
  const btn = document.getElementById('toggle-password');
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  btn.textContent = isPassword ? '🙈' : '👁️';
}

// ============================================================================
// BASE32 VALIDATION
// ============================================================================

function isValidBase32(input) {
  // Base32 alphabet (RFC 4648): A-Z, 2-7, padding with =
  const base32Regex = /^[A-Z2-7]+=*$/;
  return base32Regex.test(input.toUpperCase()) && input.length > 0;
}


// ============================================================================
// KEY MANAGEMENT
// ============================================================================

async function loadKeysFromFile() {
  try {
    const raw = await invoke('load_keys');
    // Normalize Rust tuples [name, secret] to objects {name, secret}
    if (Array.isArray(raw)) {
      keys = raw.map(k => Array.isArray(k) ? { name: k[0], secret: k[1] } : k);
    } else {
      keys = [];
    }
  } catch (error) {
    showToast(`Failed to load keys: ${error}`, 'error');
  }
}

async function addKeyToFile(name, secret) {
  try {
    await invoke('add_key', { name, secret });
  } catch (error) {
    throw new Error(`Failed to save key: ${error}`);
  }
}

async function deleteKeyFromFile(name) {
  try {
    await invoke('delete_key', { name });
  } catch (error) {
    throw new Error(`Failed to delete key: ${error}`);
  }
}

// ============================================================================
// ADD KEY - MANUAL
// ============================================================================

async function addKeyManual() {
  const name = document.getElementById('secret-name').value.trim();
  const secret = document.getElementById('secret-value').value.trim();

  // Validation
  if (!name) {
    showToast('Please enter a key name', 'error');
    return;
  }

  if (!secret) {
    showToast('Please enter a secret', 'error');
    return;
  }

  if (!isValidBase32(secret)) {
    showToast('Secret must be valid Base32 (A-Z, 2-7, optional padding)', 'error');
    return;
  }

  try {
    // Check for duplicates
    if (keys.some(k => k.name === name)) {
      showToast('A key with this name already exists (it will be updated)', 'error');
      return;
    }

    // Save to file
    await addKeyToFile(name, secret);

    // Update in-memory state
    keys.push({ name, secret });

    // Render
    renderKeyCards();
    clearInputs();
    showToast(`Key "${name}" added successfully`, 'success');
  } catch (error) {
    showToast(`${error.message}`, 'error');
  }
}

// ============================================================================
// ADD KEY - FROM URI
// ============================================================================

async function addKeyFromURI() {
  const uri = document.getElementById('uri-input').value.trim();

  if (!uri) {
    showToast('Please enter a URI', 'error');
    return;
  }

  try {
    const parsedKeys = parseURI(uri);

    for (const parsedKey of parsedKeys) {
      const { name, secret } = parsedKey;

      // Check for duplicates
      if (keys.some(k => k.name === name)) {
        showToast(`Key "${name}" already exists (it will be updated)`, 'error');
        continue;
      }

      // Save to file
      await addKeyToFile(name, secret);

      // Update in-memory state
      keys.push({ name, secret });
    }

    // Render
    renderKeyCards();
    clearInputs();
    switchMode('manual');
    showToast(`${parsedKeys.length} key(s) added successfully`, 'success');
  } catch (error) {
    showToast(`${error.message}`, 'error');
  }
}

// ============================================================================
// DELETE KEY
// ============================================================================

async function deleteKey(name) {
  if (!confirm(`Delete key "${name}"? This cannot be undone.`)) {
    return;
  }

  try {
    // Delete from file
    await deleteKeyFromFile(name);

    // Update in-memory state
    keys = keys.filter(k => k.name !== name);

    // Stop TOTP interval
    if (totpIntervals[name]) {
      clearInterval(totpIntervals[name]);
      delete totpIntervals[name];
    }

    // Render
    renderKeyCards();
    showToast(`Key "${name}" deleted`, 'success');
  } catch (error) {
    showToast(`${error.message}`, 'error');
  }
}

// ============================================================================
// TOTP GENERATION & TIMER
// ============================================================================

/**
 * Generate TOTP for a key
 */
async function generateTOTP(secret, counter) {
  try {
    const totp = await invoke('generate_totp', { secret, counter });
    return totp;
  } catch (error) {
    console.error(`Failed to generate TOTP: ${error}`);
    return 'ERROR';
  }
}

/**
 * Get current counter (seconds since epoch / 30)
 */
function getCurrentCounter() {
  return Math.floor(Date.now() / 1000 / 30);
}

/**
 * Get remaining seconds for current TOTP (0-30)
 */
function getRemainingSeconds() {
  return 30 - (Math.floor(Date.now() / 1000) % 30);
}

/**
 * Update TOTP display for a key
 */
async function updateKeyTOTP(name, secret) {
  const counter = getCurrentCounter();
  const remaining = getRemainingSeconds();
  const totp = await generateTOTP(secret, counter);

  const card = document.querySelector(`[data-key-name="${escapeDataAttribute(name)}"]`);
  if (!card) return;

  // Update TOTP display
  const totpElement = card.querySelector('.key-totp');
  if (totpElement) {
    totpElement.textContent = totp;
  }

  // Update timer circle
  const timerCircle = card.querySelector('.timer-circle');
  if (timerCircle) {
    const progress = remaining / 30;
    timerCircle.style.setProperty('--progress', progress);
    const timerText = timerCircle.querySelector('.timer-text');
    if (timerText) {
      timerText.textContent = remaining;
    }
  }
}

/**
 * Start TOTP timer for a key
 */
function startTOTPTimer(name, secret) {
  // Clear existing interval
  if (totpIntervals[name]) {
    clearInterval(totpIntervals[name]);
  }

  // Initial update
  updateKeyTOTP(name, secret);

  // Update every second
  totpIntervals[name] = setInterval(() => {
    updateKeyTOTP(name, secret);
  }, 1000);
}

// ============================================================================
// RENDERING
// ============================================================================

function renderKeyCards() {
  const container = document.getElementById('keys-container');

  // Stop all intervals
  Object.values(totpIntervals).forEach(id => clearInterval(id));
  totpIntervals = {};

  if (keys.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <p>No keys added yet.</p>
        <p class="empty-state-hint">Add your first key to get started!</p>
      </div>
    `;
    return;
  }

  container.innerHTML = keys.map(({ name, secret }) => `
    <div class="key-card" data-key-name="${escapeDataAttribute(name)}">
      <div class="timer-circle" style="--progress: 1">
        <span class="timer-text">30</span>
      </div>
      <div class="key-content">
        <div class="key-name">${escapeHtml(name)}</div>
        <div class="key-totp-container">
          <span class="key-totp">000000</span>
          <span class="copy-indicator">Click to copy</span>
        </div>
      </div>
      <button class="delete-btn" type="button" title="Delete key">
        ✕
      </button>
    </div>
  `).join('');

  // Attach event listeners
  keys.forEach(({ name, secret }) => {
    const card = container.querySelector(`[data-key-name="${escapeDataAttribute(name)}"]`);
    
    // Copy to clipboard on click
    card.addEventListener('click', async (e) => {
      if (e.target.classList.contains('delete-btn')) return;
      const counter = getCurrentCounter();
      const totp = await generateTOTP(secret, counter);
      await copyToClipboard(totp);
      showToast('TOTP copied to clipboard', 'success');
    });

    // Delete button
    card.querySelector('.delete-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      deleteKey(name);
    });

    // Start TOTP timer
    startTOTPTimer(name, secret);
  });
}

// ============================================================================
// UTILITIES
// ============================================================================

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function escapeDataAttribute(text) {
  return text.replace(/[^\w-]/g, '_');
}

async function copyToClipboard(text) {
  try {
    await invoke('copy_to_clipboard', { totp: text });
  } catch (error) {
    console.error('Failed to copy to clipboard:', error);
    showToast('Failed to copy to clipboard', 'error');
  }
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = `toast show ${type}`;

  // Auto-hide after 4 seconds
  setTimeout(() => {
    toast.classList.remove('show');
  }, 4000);
}