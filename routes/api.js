/**
 * 后台管理API路由（适配sql.js纯JS实现）
 * 所有接口需要认证，使用参数化查询防SQL注入
 */
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const { getDb, saveDb, queryOne, queryAll, runSql, getLastInsertRowId, getChangesCount, transaction, logAction } = require('../database');
const { authenticate } = require('../middleware/auth');
const {
    loginRules,
    configUpdateRules,
    quoteCreateRules,
    quoteUpdateRules,
    quoteDeleteRules,
    passwordChangeRules,
    sanitizeHtml
} = require('../middleware/validate');
const { upload, handleUploadError } = require('../middleware/upload');
const { generateToken } = require('../middleware/auth');
const fs = require('fs');

// ====== 认证API ======

router.post('/auth/login', loginRules, (req, res) => {
    const { username, password } = req.body;

    const user = queryOne('SELECT * FROM users WHERE username = ?', [username]);
    
    if (!user) {
        return res.status(401).json({ error: '用户名或密码错误', code: 'LOGIN_FAILED' });
    }

    if (!user.is_active) {
        return res.status(403).json({ error: '账号已被禁用', code: 'ACCOUNT_DISABLED' });
    }

    if (!bcrypt.compareSync(password, user.password_hash)) {
        return res.status(401).json({ error: '用户名或密码错误', code: 'LOGIN_FAILED' });
    }

    runSql("UPDATE users SET last_login = datetime('now'), login_count = login_count + 1 WHERE id = ?", [user.id]);

    logAction(user.id, 'LOGIN', 'user', String(user.id), '管理员登录', req.ip);
    saveDb();

    res.json({
        success: true,
        token: generateToken({ userId: user.id, username: user.username }),
        user: {
            id: user.id,
            username: user.username,
            displayName: user.display_name || user.username,
            avatar: user.avatar
        }
    });
});

router.get('/auth/me', authenticate, (req, res) => {
    const user = queryOne(
        'SELECT id, username, display_name, avatar, created_at, last_login, login_count FROM users WHERE id = ?',
        [req.user.userId]
    );

    if (!user) return res.status(404).json({ error: '用户不存在' });

    res.json({ user });
});

// ====== 需要认证的API ======
router.use(authenticate);

router.put('/auth/password', passwordChangeRules, (req, res) => {
    const { current_password, new_password } = req.body;
    
    const user = queryOne('SELECT id, password_hash FROM users WHERE id = ?', [req.user.userId]);
    if (!bcrypt.compareSync(current_password, user.password_hash)) {
        return res.status(400).json({ error: '当前密码不正确' });
    }

    runSql('UPDATE users SET password_hash = ? WHERE id = ?', [bcrypt.hashSync(new_password, 12), user.id]);
    logAction(req.user.userId, 'CHANGE_PASSWORD', 'user', String(user.id), null, req.ip);
    saveDb();
    res.json({ success: true, message: '密码修改成功' });
});

router.post('/auth/logout', (req, res) => {
    logAction(req.user.userId, 'LOGOUT', 'user', String(req.user.userId), null, req.ip);
    saveDb();
    res.json({ success: true });
});

// ====== 网站配置 API ======

router.get('/config', (req, res) => {
    const configs = queryAll('SELECT key, value FROM site_config');
    const configObj = {};
    configs.forEach(c => { configObj[c.key] = c.value; });
    res.json(configObj);
});

router.put('/config/:key', configUpdateRules, (req, res) => {
    let value = sanitizeHtml(req.body.value ?? '');
    
    runSql(`
        INSERT INTO site_config (key, value, updated_at, updated_by)
        VALUES (?, ?, datetime('now'), ?)
        ON CONFLICT(key) DO UPDATE SET value=?, updated_at=datetime('now'), updated_by=?
    `, [req.params.key, value, req.user.userId, value, req.user.userId]);
    
    logAction(req.user.userId, 'UPDATE_CONFIG', 'config', req.params.key, `修改配置:${req.params.key}`, req.ip);
    saveDb();
    res.json({ success: true, key: req.params.key, value });
});

router.put('/config/batch', (req, res) => {
    const configs = req.body;
    if (!configs || typeof configs !== 'object') return res.status(400).json({ error: '无效数据' });

    for (const [key, rawValue] of Object.entries(configs)) {
        runSql(
            "INSERT INTO site_config (key, value, updated_at, updated_by) VALUES (?, ?, datetime('now'), ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now'), updated_by=excluded.updated_by",
            [key, sanitizeHtml(String(rawValue)), req.user.userId]
        );
    }

    logAction(req.user.userId, 'BATCH_UPDATE_CONFIG', 'config', '', `批量修改${Object.keys(configs).length}项`, req.ip);
    saveDb();
    res.json({ success: true });
});

// ====== 名言管理 API ======

router.get('/quotes', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(50, parseInt(req.query.limit) || 20);
    const offset = (page - 1) * limit;

    const quotes = queryAll(
        'SELECT id, text, source, highlight_word, is_active, sort_order, created_at FROM quotes ORDER BY sort_order ASC, id DESC LIMIT ? OFFSET ?',
        [limit, offset]
    );

    const totalResult = getDb().exec('SELECT COUNT(*) as cnt FROM quotes');
    const total = totalResult[0]?.values?.[0]?.[0] || quotes.length;

    res.json({ data: quotes, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
});

router.post('/quotes', quoteCreateRules, (req, res) => {
    const cleanText = sanitizeHtml(req.body.text);
    const cleanSource = sanitizeHtml(req.body.source || '');
    const cleanHighlight = sanitizeHtml(req.body.highlight_word || '');

    runSql(
        "INSERT INTO quotes (text, source, highlight_word, sort_order, is_active) VALUES (?, ?, ?, (SELECT COALESCE(MAX(sort_order),0)+1 FROM quotes), 1)",
        [cleanText, cleanSource, cleanHighlight]
    );

    const id = getLastInsertRowId();
    logAction(req.user.userId, 'CREATE_QUOTE', 'quote', String(id), '创建名言', req.ip);
    saveDb();
    res.status(201).json({ success: true, id });
});

router.put('/quotes/:id', quoteUpdateRules, (req, res) => {
    const id = parseInt(req.params.id);

    const existing = queryOne('SELECT id FROM quotes WHERE id = ?', [id]);
    if (!existing) return res.status(404).json({ error: '名言不存在' });

    const updates = [];
    const params = [];

    if (req.body.text !== undefined) { updates.push('text=?'); params.push(sanitizeHtml(req.body.text)); }
    if (req.body.source !== undefined) { updates.push('source=?'); params.push(sanitizeHtml(req.body.source)); }
    if (req.body.highlight_word !== undefined) { updates.push('highlight_word=?'); params.push(sanitizeHtml(req.body.highlight_word)); }
    if (req.body.is_active !== undefined) { updates.push('is_active=?'); params.push(Number(req.body.is_active)); }
    if (req.body.sort_order !== undefined) { updates.push('sort_order=?'); params.push(Number(req.body.sort_order)); }

    params.push(id);
    runSql(`UPDATE quotes SET ${updates.join(',')} WHERE id=?`, params);

    logAction(req.user.userId, 'UPDATE_QUOTE', 'quote', String(id), `修改名言ID:${id}`, req.ip);
    saveDb();
    res.json({ success: true });
});

router.delete('/quotes/:id', quoteDeleteRules, (req, res) => {
    const id = parseInt(req.params.id);
    
    runSql('DELETE FROM quotes WHERE id = ?', [id]);
    
    if (getChangesCount() === 0) return res.status(404).json({ error: '名言不存在' });

    logAction(req.user.userId, 'DELETE_QUOTE', 'quote', String(id), `删除名言ID:${id}`, req.ip);
    saveDb();
    res.json({ success: true });
});

// ====== 文件上传 API ======

router.post('/upload/image', upload('image'), handleUploadError, (req, res) => {
    if (!req.file) return res.status(400).json({ error: '没有上传文件' });

    const relPath = `uploads/image/${req.file.filename}`;
    
    runSql(
        "INSERT INTO media (filename, original_name, mime_type, size, category, uploaded_by) VALUES (?, ?, ?, ?, 'image', ?)",
        [relPath, req.file.originalname, req.file.mimetype, req.file.size, req.user.userId]
    );

    logAction(req.user.userId, 'UPLOAD_IMAGE', 'media', '', `上传图片:${req.file.originalname}`, req.ip);
    saveDb();
    
    res.json({ success: true, url: `/${relPath}`, filename: req.file.filename, originalName: req.file.originalname, size: req.file.size });
});

router.post('/upload/video', upload('video'), handleUploadError, (req, res) => {
    if (!req.file) return res.status(400).json({ error: '没有上传文件' });

    const relPath = `uploads/video/${req.file.filename}`;
    
    runSql(
        "INSERT INTO media (filename, original_name, mime_type, size, category, uploaded_by) VALUES (?, ?, ?, ?, 'video', ?)",
        [relPath, req.file.originalname, req.file.mimetype, req.file.size, req.user.userId]
    );

    logAction(req.user.userId, 'UPLOAD_VIDEO', 'media', '', `上传视频:${req.file.originalname}`, req.ip);
    saveDb();
    
    res.json({ success: true, url: `/${relPath}`, filename: req.file.filename });
});

// ====== 访问统计 API ======

router.get('/stats/visits', (req, res) => {
    const days = Math.min(90, parseInt(req.query.days) || 30);

    const totalVisitsResult = getDb().exec(`SELECT COUNT(*) as cnt FROM visits WHERE visited_at > datetime('now','-${days} days')`);
    const totalVisits = totalVisitsResult[0]?.values?.[0]?.[0] || 0;

    const todayVisitsResult = getDb().exec("SELECT COUNT(*) as cnt FROM visits WHERE date(visited_at)=date('now')");
    const todayVisits = todayVisitsResult[0]?.values?.[0]?.[0] || 0;

    // 每日统计
    const dailyStatsRaw = getDb().exec(`SELECT date(visited_at) as d, COUNT(*) as v FROM visits WHERE visited_at > datetime('now','-${days} days') GROUP BY date(visited_at) ORDER BY d`);
    const dailyStats = (dailyStatsRaw[0]?.values || []).map(row => ({ date: row[0], visits: row[1] }));

    // 热门页面
    const topPagesRaw = getDb().exec(`SELECT path, COUNT(*) as v FROM visits WHERE visited_at > datetime('now','-${days} days') GROUP BY path ORDER BY v DESC LIMIT 10`);
    const topPages = (topPagesRaw[0]?.values || []).map(row => ({ path: row[0], visits: row[1] }));

    res.json({ totalVisits, todayVisits, dailyStats, topPages });
});

router.get('/stats/recent', (req, res) => {
    const limit = Math.min(100, parseInt(req.query.limit) || 20);
    const recentRaw = getDb().exec(`SELECT ip, path, user_agent, visited_at FROM visits ORDER BY id DESC LIMIT ${limit}`);
    const recent = (recentRaw[0]?.values || []).map(r => ({
        ip: r[0].replace(/\.\d+$/, '.***'),
        path: r[1],
        user_agent: r[2],
        visited_at: r[3]
    }));
    res.json(recent);
});

// ====== 操作日志 API ======

router.get('/logs', (req, res) => {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, parseInt(req.query.limit) || 30);

    const logsRaw = getDb().exec(`
        SELECT l.*, COALESCE(u.username,'system') as username
        FROM admin_logs l LEFT JOIN users u ON l.user_id=u.id
        ORDER BY l.id DESC LIMIT ${limit} OFFSET ${(page - 1) * limit}
    `);
    
    const logs = (logsRaw[0]?.values || []).map((row, i) => {
        const cols = logsRaw[0].columns;
        const obj = {};
        cols.forEach((c, idx) => obj[c] = row[idx]);
        return obj;
    });

    const totalRaw = getDb().exec('SELECT COUNT(*) as cnt FROM admin_logs');
    const total = totalRaw[0]?.values?.[0]?.[0] || 0;

    res.json({ data: logs, pagination: { page, limit, total, pages: Math.ceil(total / limit) } });
});

module.exports = router;
