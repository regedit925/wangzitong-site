/**
 * 文件上传中间件 - 安全配置
 * 限制文件类型/大小/数量，防止恶意上传
 */
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

// 允许的MIME类型
const ALLOWED_MIME_TYPES = {
    image: ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'],
    video: ['video/mp4', 'video/webm'],
    audio: ['audio/mpeg', 'audio/wav', 'audio/mp3', 'audio/ogg']
};

// 最大文件大小（字节）
const MAX_FILE_SIZE = {
    image: 5 * 1024 * 1024,   // 5MB
    video: 50 * 1024 * 1024,  // 50MB
    audio: 10 * 1024 * 1024   // 10MB
};

// 上传目录
const UPLOAD_DIR = path.join(__dirname, '..', 'uploads');

function getStorage(category) {
    return multer.diskStorage({
        destination: (req, file, cb) => {
            const dir = path.join(UPLOAD_DIR, category || 'other');
            require('fs').mkdirSync(dir, { recursive: true });
            cb(null, dir);
        },
        filename: (req, file, cb) => {
            // 使用UUID重命名，防止路径遍历和文件名冲突
            const ext = path.extname(file.originalname).toLowerCase();
            const safeName = `${Date.now()}_${uuidv4()}${ext}`;
            cb(null, safeName);
        }
    });
}

function getFileFilter(category) {
    return (req, file, cb) => {
        const allowedTypes = ALLOWED_MIME_TYPES[category] || [];
        
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error(`不支持的文件类型: ${file.mimetype}。允许的类型: ${allowedTypes.join(', ')}`), false);
        }
        
        cb(null, true);
    };
}

/**
 * 创建multer实例
 * @param {string} category - 文件类别: image/video/audio
 */
function upload(category) {
    const maxSize = MAX_FILE_SIZE[category] || MAX_FILE_SIZE.image;
    
    return multer({
        storage: getStorage(category),
        fileFilter: getFileFilter(category),
        limits: {
            fileSize: maxSize,
            files: 1 // 单次只允许一个文件
        }
    }).single('file');
}

/**
 * 错误处理中间件（配合upload使用）
 */
function handleUploadError(err, req, res, next) {
    if (err instanceof multer.MulterError) {
        // Multer错误
        let message;
        
        switch (err.code) {
            case 'LIMIT_FILE_SIZE':
                message = '文件大小超出限制';
                break;
            case 'LIMIT_FILE_COUNT':
                message = '一次只能上传一个文件';
                break;
            case 'LIMIT_UNEXPECTED_FILE':
                message = '不允许上传此类型的字段';
                break;
            default:
                message = `上传错误: ${err.message}`;
        }
        
        return res.status(400).json({ error: message, code: 'UPLOAD_ERROR' });
    }
    
    if (err) {
        return res.status(400).json({ 
            error: err.message || '文件上传失败',
            code: 'UPLOAD_FAILED'
        });
    }
    
    next();
}

module.exports = { upload, handleUploadError, UPLOAD_DIR, ALLOWED_MIME_TYPES };
