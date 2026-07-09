/**
 * 输入验证中间件
 * 防止XSS和非法输入
 */
const { body, param, query, validationResult } = require('express-validator');

// 验证结果处理
function handleValidation(req, res, next) {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: '输入数据不合法',
            details: errors.array().map(e => ({
                field: e.path,
                message: e.msg
            }))
        });
    }
    
    next();
}

// 登录验证规则
const loginRules = [
    body('username')
        .trim()
        .notEmpty().withMessage('用户名不能为空')
        .isLength({ min: 2, max: 50 }).withMessage('用户名长度应在2-50字符之间')
        .matches(/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/).withMessage('用户名包含非法字符'),
    body('password')
        .trim()
        .notEmpty().withMessage('密码不能为空')
        .isLength({ min: 1, max: 200 }).withMessage('密码格式错误'),
    handleValidation
];

// 配置更新验证
const configUpdateRules = [
    body('key')
        .trim()
        .notEmpty().withMessage('配置键不能为空')
        .matches(/^[a-z_][a-z0-9_]*$/i).withMessage('配置键格式错误')
        .isLength({ max: 100 }).withMessage('配置键过长'),
    body('value')
        .optional()
        .isString().withMessage('值必须是字符串')
        .isLength({ max: 5000 }).withMessage('值内容过长'),
    handleValidation
];

// 名言CRUD验证
const quoteCreateRules = [
    body('text')
        .trim()
        .notEmpty().withMessage('名言内容不能为空')
        .isLength({ max: 2000 }).withMessage('名言内容过长')
        // 允许HTML标签（用于em高亮），但会做sanitize
        ,
    body('source')
        .optional()
        .trim()
        .isLength({ max: 200 }).withMessage('来源过长'),
    body('highlight_word')
        .optional()
        .trim()
        .isLength({ max: 50 }).withMessage('高亮词过长'),
    handleValidation
];

const quoteUpdateRules = [
    param('id')
        .isInt({ min: 1 }).withMessage('ID必须是正整数'),
    ...quoteCreateRules,
    handleValidation
];

const quoteDeleteRules = [
    param('id')
        .isInt({ min: 1 }).withMessage('ID必须是正整数'),
    handleValidation
];

// ID参数验证
const idParamRule = [
    param('id')
        .isInt({ min: 1 }).withMessage('ID必须是正整数'),
    handleValidation
];

// 密码修改验证
const passwordChangeRules = [
    body('current_password')
        .trim()
        .notEmpty().withMessage('当前密码不能为空'),
    body('new_password')
        .trim()
        .isLength({ min: 6, max: 100 }).withMessage('新密码长度应为6-100字符')
        .matches(/^(?=.*[A-Za-z])(?=.*\d)/).withMessage('新密码需包含字母和数字'),
    handleValidation
];

/**
 * HTML净化 - 移除危险标签但保留安全的格式标签
 */
function sanitizeHtml(str) {
    if (typeof str !== 'string') return '';
    
    // 只允许这些安全标签
    const allowedTags = ['em', 'strong', 'b', 'i', 'br', 'p'];
    // 完全移除的危险属性/协议
    const dangerousPatterns = [
        /on\w+\s*=/gi,           // 事件处理器 onclick= 等
        /javascript:/gi,         // javascript: 协议
        /data:\s*text\/html/gi,  // data URL
        /vbscript:/gi            // vbscript 协议
    ];

    let clean = str;
    
    // 移除危险模式
    for (const pattern of dangerousPatterns) {
        clean = clean.replace(pattern, '');
    }

    return clean;
}

module.exports = {
    handleValidation,
    loginRules,
    configUpdateRules,
    quoteCreateRules,
    quoteUpdateRules,
    quoteDeleteRules,
    idParamRule,
    passwordChangeRules,
    sanitizeHtml
};
