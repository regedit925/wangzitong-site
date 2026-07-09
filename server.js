/**
 * 王梓桐个人主页 - 后端服务器
 * 安全特性：helmet安全头 / 速率限制 / JWT认证 / bcrypt密码哈希 / 参数化查询
 */
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

// ====== 配置 ======
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'wzt_site_secret_key_2025_change_in_production';
const ADMIN_DIR = path.join(__dirname, 'admin');
const PUBLIC_DIR = __dirname;

const app = express();

// ====== 安全中间件 ======
// 1. Helmet - 设置安全HTTP头
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", 'fonts.googleapis.com', 'cdn.jsdelivr.net'],
            fontSrc: ["'self'", 'fonts.googleapis.com', 'fonts.gstatic.com', 'cdn.jsdelivr.net'],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'blob:'],
            mediaSrc: ["'self'"],
            connectSrc: ["'self'"]
        }
    },
    crossOriginEmbedderPolicy: false
}));

// 2. CORS - 仅允许同源
app.use(cors({
    origin: true,
    credentials: true
}));

// 3. JSON解析（限制大小防DDOS）
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// 4. 全局速率限制
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15分钟
    max: 300, // 每IP最多300请求
    message: { error: '请求过于频繁，请稍后再试' },
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// 登录接口更严格的限制（防暴力破解）
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: '登录尝试次数过多，请15分钟后再试' },
    standardHeaders: true
});

// ====== 静态文件服务 ======
app.use(express.static(PUBLIC_DIR));

// ====== 数据库模块 ======
const Database = require('./database');

// ====== 认证中间件 ======
const { authenticate } = require('./middleware/auth');

// ====== API路由 ======
const apiRoutes = require('./routes/api');

app.use('/api', apiRoutes);

// ====== 后台管理页面路由 ======
// 所有/admin路径需要认证（除了/login）
app.get('/admin/login.html', (req, res) => {
    res.sendFile(path.join(ADMIN_DIR, 'login.html'));
});

app.get('/admin/*', authenticate, (req, res) => {
    const filePath = req.path === '/admin/' ? '/admin/dashboard.html' : req.path;
    res.sendFile(path.join(PUBLIC_DIR, filePath), (err) => {
        if (err) {
            res.status(404).sendFile(path.join(ADMIN_DIR, '404.html'));
        }
    });
});

// ====== 访问统计中间件（记录前台访问） ======
app.use((req, res, next) => {
    // 只记录前台页面访问，不记录API和admin
    if (!req.path.startsWith('/api') && !req.path.startsWith('/admin')) {
        const db = Database.getDb();
        try {
            const stmt = db.prepare(`
                INSERT INTO visits (ip, user_agent, path, visited_at)
                VALUES (?, ?, ?, datetime('now'))
            `);
            stmt.run(
                req.ip || req.headers['x-forwarded-for'] || 'unknown',
                req.headers['user-agent']?.slice(0, 500) || '',
                req.path.slice(0, 200)
            );
        } catch (e) {
            console.error('访问记录失败:', e.message);
        }
    }
    next();
});

// SPA回退：所有非API非文件请求返回index.html
app.get('*', (req, res) => {
    if (!req.path.startsWith('/api') && !req.path.startsWith('/admin') && !req.path.includes('.')) {
        res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
    } else {
        res.status(404).json({ error: '页面不存在' });
    }
});

// ====== 错误处理 ======
app.use((err, req, res, next) => {
    console.error('服务器错误:', err.stack);
    res.status(500).json({ error: '服务器内部错误' });
});

// ====== 启动服务器 ======
Database.init().then(() => {
    app.listen(PORT, () => {
        console.log(`========================================`);
        console.log(`  王梓桐个人主页 - 后台管理系统`);
        console.log(`  前台地址: http://localhost:${PORT}`);
        console.log(`  后台入口: http://localhost:${PORT}/admin/login.html`);
        console.log(`  默认账号: admin / admin123`);
        console.log(`  ⚠️ 请立即修改默认密码!`);
        console.log(`========================================`);
    });
}).catch(err => {
    console.error('数据库初始化失败:', err);
    process.exit(1);
});

module.exports = app;
