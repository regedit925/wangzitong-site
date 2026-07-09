/**
 * 后台管理 - 公共JS模块
 * 处理认证、API请求、通用工具函数
 */

const API_BASE = '/api';

// ====== 认证检查 ======
async function checkAuth() {
    const token = localStorage.getItem('admin_token');

    if (!token) {
        window.location.href = '/admin/login.html';
        return null;
    }

    try {
        const res = await fetch(`${API_BASE}/auth/me`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (res.status === 401 || res.status === 403) {
            // token无效，清除并跳转登录
            localStorage.removeItem('admin_token');
            localStorage.removeItem('admin_user');
            window.location.href = '/admin/login.html';
            return null;
        }

        const data = await res.json();
        
        // 更新页面上的用户信息
        if (data.user) {
            updateUserInfo(data.user);
        }

        return data.user;
    } catch (e) {
        console.error('认证检查失败:', e);
        return null;
    }
}

// 更新用户信息显示
function updateUser(user) {
    const nameEl = document.getElementById('displayName');
    if (nameEl) {
        nameEl.textContent = user.displayName || user.username;
    }
}

function handleLogout() {
    const token = localStorage.getItem('admin_token');
    
    // 调用登出接口（记录日志）
    fetch(`${API_BASE}/auth/logout`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
    }).catch(() => {});

    localStorage.removeItem('admin_token');
    localStorage.removeItem('admin_user');
    window.location.href = '/admin/login.html';
}

// ====== API请求封装 ======

/**
 * GET请求
 */
async function apiGet(url) {
    const token = localStorage.getItem('admin_token');
    const res = await fetch(API_BASE + url, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    
    await handleError(res);
    return res.json();
}

/**
 * POST请求
 */
async function apiPost(url, data) {
    const token = localStorage.getItem('admin_token');
    const res = await fetch(API_BASE + url, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    
    await handleError(res);
    return res.json();
}

/**
 * PUT请求
 */
async function apiPut(url, data) {
    const token = localStorage.getItem('admin_token');
    const res = await fetch(API_BASE + url, {
        method: 'PUT',
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    
    await handleError(res);
    return res.json();
}

/**
 * DELETE请求
 */
async function apiDelete(url) {
    const token = localStorage.getItem('admin_token');
    const res = await fetch(API_BASE + url, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    
    await handleError(res);
    return res.json();
}

/**
 * 文件上传
 */
async function apiUpload(endpoint, file) {
    const token = localStorage.getItem('admin_token');
    const formData = new FormData();
    formData.append('file', file);

    const res = await fetch(API_BASE + endpoint, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` },
        body: formData
    });

    await handleError(res);
    return res.json();
}

// 错误处理
async function handleError(res) {
    if (!res.ok) {
        let errorData;
        try {
            errorData = await res.json();
        } catch {
            errorData = { error: '请求失败' };
        }
        
        // Token过期处理
        if (errorData.code === 'TOKEN_EXPIRED' || errorData.code === 'AUTH_REQUIRED') {
            localStorage.removeItem('admin_token');
            localStorage.removeItem('admin_user');
            
            if (confirm('登录已过期，请重新登录')) {
                window.location.href = '/admin/login.html';
            }
            throw new Error(errorData.error);
        }
        
        throw new Error(errorData.error || '请求失败');
    }
}

// ====== 工具函数 ======

/**
 * HTML转义（防XSS）
 */
function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

/**
 * 格式化时间
 */
function formatTime(dateStr) {
    if (!dateStr) return '';
    const date = new Date(dateStr);
    const now = new Date();
    const diffMs = now - date;
    const diffMin = Math.floor(diffMs / 60000);
    const diffHour = Math.floor(diffMs / 3600000);

    if (diffMin < 1) return '刚刚';
    if (diffMin < 60) return `${diffMin}分钟前`;
    if (diffHour < 24) return `${diffHour}小时前`;

    return date.toLocaleDateString('zh-CN', {
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * 显示提示消息（Toast）
 */
let toastTimer = null;

function showToast(message, type = 'success') {
    // 移除已有的toast
    const existing = document.querySelector('.toast-msg');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = `toast-msg toast-${type}`;
    
    const icon = type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ';
    
    toast.innerHTML = `<span class="toast-icon">${icon}</span> ${escapeHtml(message)}`;
    document.body.appendChild(toast);
    
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });

    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 2500);
}

/**
 * 确认对话框
 */
function confirmDialog(title, message, onConfirm) {
    const overlay = document.createElement('div');
    overlay.className = 'dialog-overlay';
    overlay.innerHTML = `
        <div class="dialog-box">
            <h3 class="dialog-title">${escapeHtml(title)}</h3>
            <p class="dialog-message">${escapeHtml(message)}</p>
            <div class="dialog-buttons">
                <button class="btn-dialog-cancel" id="dlgCancel">取消</button>
                <button class="btn-dialog-confirm" id="dlgConfirm">确认</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    requestAnimationFrame(() => overlay.classList.add('show'));
    
    document.getElementById('dlgCancel').onclick = () => overlay.remove();
    document.getElementById('dlgConfirm').onclick = () => {
        overlay.remove();
        onConfirm?.();
    };
}
