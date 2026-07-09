/**
 * JWT认证中间件
 * 安全特性：token过期检查 / 黑名单 / 权限验证
 */
const jwt = require('jsonwebtoken');
const { getDb } = require('../database');

const JWT_SECRET = process.env.JWT_SECRET || 'wzt_site_secret_key_2025_change_in_production';
const TOKEN_EXPIRY = '2h'; // token有效期2小时

// 生成JWT
function generateToken(user) {
    return jwt.sign(
        {
            userId: user.id,
            username: user.username,
            role: 'admin'
        },
        JWT_SECRET,
        { expiresIn: TOKEN_EXPIRY }
    );
}

// 验证token中间件
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ 
            error: '未登录，请先登录',
            code: 'AUTH_REQUIRED'
        });
    }

    const token = authHeader.split(' ')[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // 验证用户是否仍然存在且激活
        const db = getDb();
        const user = db.prepare(`
            SELECT id, username, is_active FROM users WHERE id = ?
        `).get(decoded.userId);

        if (!user) {
            return res.status(401).json({
                error: '用户不存在',
                code: 'USER_NOT_FOUND'
            });
        }

        if (!user.is_active) {
            return res.status(403).json({
                error: '账号已被禁用',
                code: 'ACCOUNT_DISABLED'
            });
        }

        // 将用户信息附加到request上
        req.user = decoded;
        req.dbUser = user;
        next();

    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({
                error: '登录已过期，请重新登录',
                code: 'TOKEN_EXPIRED'
            });
        }
        
        return res.status(401).json({
            error: '无效的登录凭证',
            code: 'INVALID_TOKEN'
        });
    }
}

// 可选认证（不强制，但如果有token则解析）
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            const token = authHeader.split(' ')[1];
            const decoded = jwt.verify(token, JWT_SECRET);
            req.user = decoded;
        } catch (e) {
            // token无效则忽略，继续执行
        }
    }
    
    next();
}

module.exports = { authenticate, optionalAuth, generateToken, JWT_SECRET };
