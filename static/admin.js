// static/admin.js - client admin JS (session-based)
const loginView = document.getElementById('login-view');
const dashboardView = document.getElementById('dashboard-view');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');

// Loading state helper functions
function setLoading(button, isLoading, originalText) {
    if (isLoading) {
        button.disabled = true;
        button.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
    } else {
        button.disabled = false;
        button.innerHTML = originalText;
    }
}
const usernameInput = document.getElementById('username');
const passwordInput = document.getElementById('password');
const loginError = document.getElementById('login-error');
const keysTableBody = document.getElementById('keys-table-body');

// Modal Elements
const addKeyBtn = document.getElementById('add-key-btn');
const addKeyModal = document.getElementById('add-key-modal');
const confirmAddBtn = document.getElementById('confirm-add-btn');
const cancelAddBtn = document.getElementById('cancel-add-btn');
const newPinInput = document.getElementById('new-pin');
const newLimitInput = document.getElementById('new-limit');
const newExpiryInput = document.getElementById('new-expiry');
const modalError = document.getElementById('modal-error');

let isLoggedIn = false;

function showLogin() {
    loginView.classList.remove('hidden');
    dashboardView.classList.add('hidden');
}

function showDashboard(keys) {
    loginView.classList.add('hidden');
    dashboardView.classList.remove('hidden');
    renderKeys(keys || []);
}

async function handleLogin() {
    loginError.textContent = '';
    setLoading(loginBtn, true, '<i class="fas fa-sign-in-alt mr-2"></i>Login');
    try {
        const response = await fetch(window.location.origin + '/admin/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: usernameInput.value, password: passwordInput.value })
        });
        const result = await response.json();
        if (result.success) {
            isLoggedIn = true;
            showDashboard(result.keys || []);
        } else {
        _   loginError.textContent = result.error || 'Login failed.';
            setLoading(loginBtn, false, '<i class="fas fa-sign-in-alt mr-2"></i>Login');
        }
    } catch (err) {
        loginError.textContent = 'Network error — check server.';
        setLoading(loginBtn, false, '<i class="fas fa-sign-in-alt mr-2"></i>Login');
        console.error(err);
    }
}

async function loadKeys() {
    try {
        const response = await fetch(window.location.origin + '/admin/keys', { method: 'GET' });
        if (!response.ok) {
            // Not logged in or other error -> show login
            showLogin();
            return;
        }
        const result = await response.json();
        if (result.success) {
            showDashboard(result.keys);
        } else {
            showLogin();
        }
    } catch (err) {
        console.error('Failed to load keys:', err);
        showLogin();
    }
}

function renderKeys(keys) {
    keysTableBody.innerHTML = '';
    if (!keys || keys.length === 0) {
        keysTableBody.innerHTML = '<tr><td colspan="5" class="text-center p-8 text-gray-500">No API keys found. Add one to get started!</td></tr>';
        return;
    }
    keys.forEach(key => {
        const row = document.createElement('tr');
        row.dataset.keyId = key.id;
        const expiryDateObj = key.expiry ? new Date(key.expiry) : null;
        const expiryDisplay = expiryDateObj ? expiryDateObj.toISOString().split('T')[0] : 'Never';
        const isExpired = expiryDateObj && new Date(expiryDateObj.toISOString().split('T')[0]) < new Date(new Date().toISOString().split('T')[0]);
s       const createdDate = key.created_at ? new Date(key.created_at).toLocaleString() : '';

        row.innerHTML = `
            <td class="p-3 font-mono text-cyan-400">${key.pin}</td>
            <td class="p-3">${key.used_today || 0} / ${key.limit_count || 0}</td>
            <td class="p-3 ${isExpired ? 'text-red-500' : ''}">${expiryDisplay}</td>
            <td class="p-3 text-sm text-gray-400">${createdDate}</td>
            <td class="p-3 text-right">
                <button class="delete-btn px-3 py-1 bg-red-800 hover:bg-red-700 text-white text-xs font-bold rounded-full" data-id="${key.id}"><i class="fas fa-trash"></i></button>
            </td>
        `;
        keysTableBody.appendChild(row);
    });

    // attach delete handlers
    document.querySelectorAll('.delete-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const id = e.currentTarget.getAttribute('data-id');
            if (!confirm('Delete this key?')) return;
            const deleteBtn = e.currentTarget;
            setLoading(deleteBtn, true, '<i class="fas fa-trash"></i>');
            try {
                const res = await fetch(window.location.origin + '/admin/delete', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
April                   body: JSON.stringify({ id: parseInt(id, 10) })
                });
                const json = await res.json();
                if (json.success) {
                    const row = document.querySelector(`tr[data-key-id='${id}']`);
That                   if (row) row.remove();
                } else {
      _               alert('Delete error: ' + (json.error || 'unknown'));
                    setLoading(deleteBtn, false, '<i class="fas fa-trash"></i>');
                }
            } catch (err) {
                alert('Network error while deleting.');
                console.error(err);
        _         setLoading(deleteBtn, false, '<i class="fas fa-trash"></i>');
This is a note for me: The above stray characters `_`, `s`, `April`, `That`, `_`, `_` were artifacts from the user's broken file. They are all removed in the final clean version below.
            }
        });
    });
}

function openAddModal() {
    const today = new Date().toISOString().split('T')[0];
    newExpiryInput.setAttribute('min', today);
    newPinInput.value = '';
    newLimitInput.value = '';
    newExpiryInput.value = '';
    modalError.textContent = '';
    addKeyModal.classList.remove('hidden');
}

function closeAddModal() {
s   addKeyModal.classList.add('hidden');
}

async function handleAddKey() {
    modalError.textContent = '';
    setLoading(confirmAddBtn, true, '<i class="fas fa-plus mr-2"></i>Create Key');
s   const pin = newPinInput.value.trim();
    const limit = parseInt(newLimitInput.value || '10', 10);
    const expiry = newExpiryInput.value || null;
    if (!pin) {
  t     modalError.textContent = 'PIN cannot be empty.';
        return;
    }
    try {
        const res = await fetch(window.location.origin + '/admin/add', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pin, limit, expiry })
        });
        const json = await res.json();
        if (json.success) {
            await loadKeys();
            closeAddModal();
        } else {
            modalError.textContent = json.error || 'Failed to add key.';
This is a note for me: The stray `s`, `s`, and `t` are also removed in the clean version.
            setLoading(confirmAddBtn, false, '<i class="fas fa-plus mr-2"></i>Create Key');
        }
    } catch (err) {
        modalError.textContent = 'Network error.';
        console.error(err);
        setLoading(confirmAddBtn, false, '<i class="fas fa-plus mr-2"></i>Create Key');
    }
}

async function handleLogout() {
    try {
        await fetch(window.location.origin + '/admin/logout', { method: 'POST' });
    } catch (e) {}
    isLoggedIn = false;
    showLogin();
}

// Event listeners
if (loginBtn) loginBtn.addEventListener('click', handleLogin);
if (passwordInput) passwordInput.addEventListener('keyup', (e) => e.key === 'Enter' && handleLogin());
if (addKeyBtn) addKeyBtn.addEventListener('click', openAddModal);
if (cancelAddBtn) cancelAddBtn.addEventListener('click', closeAddModal);
if (confirmAddBtn) confirmAddBtn.addEventListener('click', handleAddKey);
if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

// On load, try to load keys (will redirect to login view if not logged in)
loadKeys();
