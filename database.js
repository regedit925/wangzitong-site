/**
 * SQLite数据库模块 - 安全设计（使用sql.js纯JS实现）
 * 所有查询使用参数化绑定，防止SQL注入
 */
const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

let db = null;
// Render 免费版文件系统只读，数据库存入 /tmp；本地开发使用 ./data/
const isRender = process.env.RENDER === 'true';
const dbPath = isRender
    ? '/tmp/data/site.db'
    : path.join(__dirname, 'data', 'site.db');

function getDb() {
    if (!db) throw new Error('数据库未初始化');
    return db;
}

async function init() {
    try {
        // 确保data目录存在
        const dataDir = path.dirname(dbPath);
        if (!fs.existsSync(dataDir)) {
            fs.mkdirSync(dataDir, { recursive: true });
        }

        // 初始化SQL.js
        const SQL = await initSqlJs();

        // 尝试加载已有数据库
        if (fs.existsSync(dbPath)) {
            const buffer = fs.readFileSync(dbPath);
            db = new SQL.Database(buffer);
        } else {
            // 创建新数据库
            db = new SQL.Database();
            saveDb();
        }

        // ====== 创建表结构 ======
        
        // 1. 管理员用户表
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                display_name TEXT DEFAULT '',
                avatar TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now')),
                last_login TEXT,
                login_count INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1
            )
        `);

        // 2. 网站配置表（键值对）
        db.run(`
            CREATE TABLE IF NOT EXISTS site_config (
                key TEXT PRIMARY KEY NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT DEFAULT (datetime('now')),
                updated_by INTEGER
            )
        `);

        // 3. 名言库
        db.run(`
            CREATE TABLE IF NOT EXISTS quotes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL,
                source TEXT DEFAULT '',
                highlight_word TEXT DEFAULT '',
                is_active INTEGER DEFAULT 1,
                sort_order INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now'))
            )
        `);

        // 4. 访问记录
        db.run(`
            CREATE TABLE IF NOT EXISTS visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT DEFAULT '',
                user_agent TEXT DEFAULT '',
                path TEXT DEFAULT '/',
                visited_at TEXT DEFAULT (datetime('now'))
            )
        `);

        // 5. 媒体文件记录
        db.run(`
            CREATE TABLE IF NOT EXISTS media (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                original_name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER DEFAULT 0,
                category TEXT DEFAULT 'other',
                uploaded_at TEXT DEFAULT (datetime('now')),
                uploaded_by INTEGER
            )
        `);

        // 6. 操作日志
        db.run(`
            CREATE TABLE IF NOT EXISTS admin_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                target_type TEXT DEFAULT '',
                target_id TEXT DEFAULT '',
                details TEXT DEFAULT '',
                ip TEXT DEFAULT '',
                created_at TEXT DEFAULT (datetime('now'))
            )
        `);

        // ====== 初始化默认数据 ======
        initDefaultData();

        console.log(`✅ 数据库初始化成功: ${dbPath}`);
    } catch (err) {
        throw err;
    }
}

// 保存数据库到文件
function saveDb() {
    if (!db) return;
    const data = db.export();
    const buffer = Buffer.from(data);
    
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(dbPath, buffer);
}

// 查询辅助函数
function queryOne(sql, params = []) {
    const stmt = db.prepare(sql);
    if (params && params.length) stmt.bind(params);
    
    if (stmt.step()) {
        return stmt.getAsObject();
    }
    return undefined;
}

function queryAll(sql, params = []) {
    const stmt = db.prepare(sql);
    if (params && params.length) stmt.bind(params);
    
    const results = [];
    while (stmt.step()) {
        results.push(stmt.getAsObject());
    }
    return results;
}

function runSql(sql, params = []) {
    db.run(sql, params || []);
}

function getLastInsertRowId() {
    return db.exec("SELECT last_insert_rowid() as id")[0]?.values[0][0] || -1;
}

function getChangesCount() {
    return db.exec("SELECT changes() as cnt")[0]?.values[0][0] || 0;
}

// 事务支持
function transaction(fn) {
    db.run('BEGIN TRANSACTION');
    try {
        fn();
        db.run('COMMIT');
        saveDb();
    } catch (e) {
        db.run('ROLLBACK');
        throw e;
    }
}

function initDefaultData() {
    // 创建默认管理员账号（密码: admin123）
    const adminExists = queryOne('SELECT id FROM users WHERE username = ?', ['admin']);
    
    if (!adminExists) {
        const hash = bcrypt.hashSync('admin123', 12); // 12轮盐值
        runSql(
            "INSERT INTO users (username, password_hash, display_name) VALUES (?, ?, ?)",
            ['admin', hash, '管理员']
        );
        logAction(null, 'SYSTEM', 'user', '1', '创建默认管理员账号');
        saveDb();
    }

    // 初始化网站配置
    const defaultConfig = {
        site_name: '王梓桐的个人主页',
        name: '王梓桐',
        status: '准八年级 · 未来程序员',
        about_me: '别被年级骗了——我从小学就开始折腾电脑了。',
        greeting: '你好呀',
        bgm_file: 'bgm.mp3'
    };

    for (const [key, value] of Object.entries(defaultConfig)) {
        const exists = queryOne('SELECT key FROM site_config WHERE key = ?', [key]);
        if (!exists) {
            runSql(
                'INSERT OR IGNORE INTO site_config (key, value) VALUES (?, ?)',
                [key, value]
            );
        }
    }

    // 初始化默认名言
    const quoteCount = queryOne('SELECT COUNT(*) as cnt FROM quotes')?.cnt || 0;
    
    if (quoteCount === 0) {
        const defaultQuotes = [
            { text: '雨纷纷，旧故里草木深<br>我听闻，你始终<em>一个人</em>', source: '方文山 · 青花瓷', highlight: '一个人', order: 1 },
            { text: '一路向北<br>离开有你的<em>季节</em>', source: '周杰伦 · 一路向北', highlight: '季节', order: 2 },
            { text: '生活就像一首歌<br>有快乐也有悲伤<br>但音乐让我学会<em>享受每一刻</em>', source: '互联网', highlight: '享受每一刻', order: 3 }
        ];

        for (const q of defaultQuotes) {
            runSql(
                'INSERT INTO quotes (text, source, highlight_word, sort_order) VALUES (?, ?, ?, ?)',
                [q.text, q.source, q.highlight, q.order]
            );
        }

        logAction(null, 'SYSTEM', 'quote', '', '创建3条默认名言');
    }

    // 清理30天前的访问记录
    runSql("DELETE FROM visits WHERE visited_at < datetime('now', '-30 days')");
    
    saveDb();
}

// 日志记录
function logAction(userId, action, targetType, targetId, details, ip) {
    try {
        runSql(`
            INSERT INTO admin_logs (user_id, action, target_type, target_id, details, ip)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [userId, action, targetType, targetId, details?.slice(0, 1000), ip]);
        saveDb();
    } catch (e) {
        console.error('日志记录失败:', e.message);
    }
}

module.exports = {
    getDb, init, saveDb,
    queryOne, queryAll, runSql,
    getLastInsertRowId, getChangesCount,
    transaction, logAction
};
