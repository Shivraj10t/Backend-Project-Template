# Backend-Project-Template

// .env
PORT=5000
MONGODB_URI=mongodb://localhost:27017/backend-template
JWT_SECRET=your-secret-key
JWT_EXPIRE=30d
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-email-password
NODE_ENV=development

// package.json
{
  "name": "backend-template",
  "version": "1.0.0",
  "description": "Backend template with common functionalities",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "express-rate-limit": "^6.7.0",
    "joi": "^17.9.2",
    "jsonwebtoken": "^9.0.0",
    "mongoose": "^7.0.3",
    "multer": "^1.4.5-lts.1",
    "nodemailer": "^6.9.1",
    "winston": "^3.8.2"
  },
  "devDependencies": {
    "nodemon": "^2.0.22"
  }
}

// src/config/db.js
const mongoose = require('mongoose');
const logger = require('../utils/logger');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    logger.info(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    logger.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

module.exports = connectDB;

// src/config/env.js
require('dotenv').config();

module.exports = {
  port: process.env.PORT || 5000,
  mongoUri: process.env.MONGODB_URI,
  jwtSecret: process.env.JWT_SECRET,
  jwtExpire: process.env.JWT_EXPIRE,
  emailHost: process.env.EMAIL_HOST,
  emailPort: process.env.EMAIL_PORT,
  emailUser: process.env.EMAIL_USER,
  emailPass: process.env.EMAIL_PASS,
  nodeEnv: process.env.NODE_ENV
};

// src/models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, 'Please add a name'],
    trim: true
  },
  email: {
    type: String,
    required: [true, 'Please add an email'],
    unique: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please add a valid email']
  },
  password: {
    type: String,
    required: [true, 'Please add a password'],
    minlength: 6,
    select: false
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  verificationToken: String,
  resetPasswordToken: String,
  resetPasswordExpire: Date,
  createdAt: {
    type: Date,
    default: Date.now
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

module.exports = mongoose.model('User', userSchema);

// src/utils/validators.js
const Joi = require('joi');

const registerValidator = Joi.object({
  name: Joi.string().required().min(3),
  email: Joi.string().email().required(),
  password: Joi.string().required().min(6),
  role: Joi.string().valid('user', 'admin')
});

const loginValidator = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

module.exports = {
  registerValidator,
  loginValidator
};

// src/utils/email.js
const nodemailer = require('nodemailer');
const config = require('../config/env');
const logger = require('./logger');

const transporter = nodemailer.createTransport({
  host: config.emailHost,
  port: config.emailPort,
  auth: {
    user: config.emailUser,
    pass: config.emailPass
  }
});

const sendEmail = async (options) => {
  try {
    const message = {
      from: `${config.emailUser}`,
      to: options.email,
      subject: options.subject,
      text: options.message
    };

    await transporter.sendMail(message);
    logger.info('Email sent successfully');
  } catch (error) {
    logger.error('Email send error:', error);
    throw new Error('Email could not be sent');
  }
};

module.exports = sendEmail;

// src/utils/logger.js
const winston = require('winston');

const logger = winston.createLogger({
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}

module.exports = logger;

// src/middlewares/authMiddleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const config = require('../config/env');

const protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    const decoded = jwt.verify(token, config.jwtSecret);
    req.user = await User.findById(decoded.id);
    next();
  } catch (error) {
    res.status(401).json({ message: 'Not authorized' });
  }
};

module.exports = { protect };

// src/middlewares/roleMiddleware.js
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        message: 'Not authorized to access this route' 
      });
    }
    next();
  };
};

module.exports = { authorize };

// src/controllers/authController.js
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const config = require('../config/env');
const sendEmail = require('../utils/email');
const { registerValidator, loginValidator } = require('../utils/validators');

const register = async (req, res) => {
  try {
    // Validate input
    const { error } = registerValidator.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { name, email, password } = req.body;

    // Check if user exists
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Create verification token
    const verificationToken = jwt.sign(
      { email },
      config.jwtSecret,
      { expiresIn: '1d' }
    );

    // Create user
    user = await User.create({
      name,
      email,
      password,
      verificationToken
    });

    // Send verification email
    await sendEmail({
      email: user.email,
      subject: 'Email Verification',
      message: `Please verify your email by clicking: http://yourapp.com/verify/${verificationToken}`
    });

    // Create JWT token
    const token = jwt.sign({ id: user._id }, config.jwtSecret, {
      expiresIn: config.jwtExpire
    });

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

const login = async (req, res) => {
  try {
    // Validate input
    const { error } = loginValidator.validate(req.body);
    if (error) {
      return res.status(400).json({ message: error.details[0].message });
    }

    const { email, password } = req.body;

    // Check user exists
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    // Create token
    const token = jwt.sign({ id: user._id }, config.jwtSecret, {
      expiresIn: config.jwtExpire
    });

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  register,
  login
};

// src/routes/authRoutes.js
const express = require('express');
const router = express.Router();
const { register, login } = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);

module.exports = router;

// src/app.js
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/authRoutes');
const errorHandler = require('./middlewares/errorHandler');
const logger = require('./utils/logger');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Routes
app.use('/api/auth', authRoutes);

// Error handling
app.use(errorHandler);

module.exports = app;

// src/server.js
const app = require('./app');
const connectDB = require('./config/db');
const config = require('./config/env');
const logger = require('./utils/logger');

// Connect to database
connectDB();

const server = app.listen(config.port, () => {
  logger.info(`Server running in ${config.nodeEnv} mode on port ${config.port}`);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  logger.error(`Error: ${err.message}`);
  server.close(() => process.exit(1));
});

-------------------------222-------------

// src/middlewares/fileUpload.js
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|pdf/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error('Only .jpeg, .jpg, .png and .pdf format allowed!'), false);
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 1024 * 1024 * 5 }, // 5MB
  fileFilter: fileFilter
});

module.exports = upload;

// src/controllers/authController.js (Additional methods)
const crypto = require('crypto');

// ... (previous code remains the same)

const forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(20).toString('hex');
    user.resetPasswordToken = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    user.resetPasswordExpire = Date.now() + 10 * 60 * 1000; // 10 minutes

    await user.save();

    // Send email
    const resetUrl = `http://yourapp.com/reset-password/${resetToken}`;
    await sendEmail({
      email: user.email,
      subject: 'Password Reset Request',
      message: `You requested a password reset. Please click: ${resetUrl}`
    });

    res.json({ message: 'Email sent' });
  } catch (error) {
    res.status(500).json({ message: 'Email could not be sent' });
  }
};

const resetPassword = async (req, res) => {
  try {
    const resetPasswordToken = crypto
      .createHash('sha256')
      .update(req.params.resetToken)
      .digest('hex');

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;

    await user.save();

    res.json({ message: 'Password updated' });
  } catch (error) {
    res.status(500).json({ message: 'Could not reset password' });
  }
};

const verifyEmail = async (req, res) => {
  try {
    const decoded = jwt.verify(req.params.token, config.jwtSecret);
    const user = await User.findOne({ email: decoded.email });

    if (!user) {
      return res.status(400).json({ message: 'Invalid verification token' });
    }

    user.isEmailVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.json({ message: 'Email verified successfully' });
  } catch (error) {
    res.status(400).json({ message: 'Invalid verification token' });
  }
};

module.exports = {
  // ... (previous exports)
  forgotPassword,
  resetPassword,
  verifyEmail
};

// src/controllers/userController.js
const User = require('../models/User');
const upload = require('../middlewares/fileUpload');

const getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

const updateProfile = async (req, res) => {
  try {
    const fieldsToUpdate = {
      name: req.body.name,
      email: req.body.email
    };

    const user = await User.findByIdAndUpdate(
      req.user.id,
      fieldsToUpdate,
      {
        new: true,
        runValidators: true
      }
    );

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

const uploadAvatar = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'Please upload a file' });
    }

    const user = await User.findByIdAndUpdate(
      req.user.id,
      { avatar: req.file.filename },
      { new: true }
    );

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

// Admin Controllers
const getAllUsers = async (req, res) => {
  try {
    const page = parseInt(req.query.page, 10) || 1;
    const limit = parseInt(req.query.limit, 10) || 10;
    const startIndex = (page - 1) * limit;

    const total = await User.countDocuments();
    const users = await User.find()
      .skip(startIndex)
      .limit(limit);

    res.json({
      success: true,
      count: users.length,
      pagination: {
        current: page,
        pages: Math.ceil(total / limit),
        total
      },
      data: users
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

const updateUser = async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      req.body,
      {
        new: true,
        runValidators: true
      }
    );

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      success: true,
      data: user
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

const deleteUser = async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      success: true,
      data: {}
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  getProfile,
  updateProfile,
  uploadAvatar,
  getAllUsers,
  updateUser,
  deleteUser
};

// src/routes/authRoutes.js (Updated)
const express = require('express');
const router = express.Router();
const {
  register,
  login,
  forgotPassword,
  resetPassword,
  verifyEmail
} = require('../controllers/authController');

router.post('/register', register);
router.post('/login', login);
router.post('/forgot-password', forgotPassword);
router.put('/reset-password/:resetToken', resetPassword);
router.get('/verify-email/:token', verifyEmail);

module.exports = router;

// src/routes/userRoutes.js
const express = require('express');
const router = express.Router();
const {
  getProfile,
  updateProfile,
  uploadAvatar,
  getAllUsers,
  updateUser,
  deleteUser
} = require('../controllers/userController');
const { protect } = require('../middlewares/authMiddleware');
const { authorize } = require('../middlewares/roleMiddleware');
const upload = require('../middlewares/fileUpload');

// User routes
router.get('/profile', protect, getProfile);
router.put('/profile', protect, updateProfile);
router.post('/avatar', protect, upload.single('avatar'), uploadAvatar);

// Admin routes
router.get('/users', protect, authorize('admin'), getAllUsers);
router.put('/users/:id', protect, authorize('admin'), updateUser);
router.delete('/users/:id', protect, authorize('admin'), deleteUser);

module.exports = router;

// src/utils/pagination.js
const paginate = (query, pageSize = 10, pageNumber = 1) => {
  const skip = (pageNumber - 1) * pageSize;
  return query.skip(skip).limit(pageSize);
};

module.exports = paginate;

// Update app.js to include new routes
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const errorHandler = require('./middlewares/errorHandler');
const logger = require('./utils/logger');

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Static folder
app.use('/uploads', express.static('public/uploads'));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Error handling
app.use(errorHandler);

module.exports = app;
------------------------------------------------33333333333-------------------


// docker-compose.yml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - NODE_ENV=development
      - MONGODB_URI=mongodb://mongo:27017/backend-template
      - REDIS_URI=redis://redis:6379
    depends_on:
      - mongo
      - redis
    volumes:
      - ./:/usr/src/app
      - /usr/src/app/node_modules
    command: npm run dev

  mongo:
    image: mongo:latest
    ports:
      - "27017:27017"
    volumes:
      - mongodata:/data/db

  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
    volumes:
      - redisdata:/data

volumes:
  mongodata:
  redisdata:

// Dockerfile
FROM node:18-alpine

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 5000

CMD ["npm", "start"]

// src/config/redis.js
const Redis = require('ioredis');
const logger = require('../utils/logger');

const redis = new Redis(process.env.REDIS_URI);

redis.on('error', (err) => {
  logger.error('Redis Client Error:', err);
});

redis.on('connect', () => {
  logger.info('Redis Client Connected');
});

module.exports = redis;

// src/middlewares/cache.js
const redis = require('../config/redis');

const cache = (duration) => {
  return async (req, res, next) => {
    const key = `cache:${req.originalUrl}`;

    try {
      const cachedResponse = await redis.get(key);
      
      if (cachedResponse) {
        return res.json(JSON.parse(cachedResponse));
      }

      res.sendResponse = res.json;
      res.json = (body) => {
        redis.setex(key, duration, JSON.stringify(body));
        res.sendResponse(body);
      };

      next();
    } catch (error) {
      next(error);
    }
  };
};

module.exports = cache;

// src/middlewares/rateLimiter.js
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('../config/redis');

const createRateLimiter = (options = {}) => {
  return rateLimit({
    store: new RedisStore({
      client: redis,
      prefix: 'rate-limit:'
    }),
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
    max: options.max || 100,
    message: options.message || 'Too many requests, please try again later.',
    ...options
  });
};

module.exports = createRateLimiter;

// src/docs/swagger.js
const swaggerJsdoc = require('swagger-jsdoc');

const options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Backend API Template',
      version: '1.0.0',
      description: 'A template REST API with common features',
    },
    servers: [
      {
        url: 'http://localhost:5000/api',
        description: 'Development server',
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
  },
  apis: ['./src/routes/*.js'], // Path to the API routes
};

module.exports = swaggerJsdoc(options);

// Example swagger documentation in routes/authRoutes.js
/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - name
 *               - email
 *               - password
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Invalid input
 */

// tests/setup.js
const mongoose = require('mongoose');
const { MongoMemoryServer } = require('mongodb-memory-server');

let mongoServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  await mongoose.connect(mongoUri);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});

// tests/auth.test.js
const request = require('supertest');
const app = require('../src/app');
const User = require('../src/models/User');

describe('Auth Endpoints', () => {
  beforeEach(async () => {
    await User.deleteMany();
  });

  describe('POST /api/auth/register', () => {
    it('should register a new user', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'test@test.com',
          password: 'password123'
        });

      expect(res.statusCode).toBe(201);
      expect(res.body).toHaveProperty('token');
      expect(res.body.user).toHaveProperty('email', 'test@test.com');
    });

    it('should not register user with existing email', async () => {
      await User.create({
        name: 'Existing User',
        email: 'test@test.com',
        password: 'password123'
      });

      const res = await request(app)
        .post('/api/auth/register')
        .send({
          name: 'Test User',
          email: 'test@test.com',
          password: 'password123'
        });

      expect(res.statusCode).toBe(400);
      expect(res.body).toHaveProperty('message', 'User already exists');
    });
  });
});

// tests/user.test.js
const request = require('supertest');
const app = require('../src/app');
const User = require('../src/models/User');
const jwt = require('jsonwebtoken');
const config = require('../src/config/env');

describe('User Endpoints', () => {
  let token;
  let user;

  beforeEach(async () => {
    await User.deleteMany();
    
    user = await User.create({
      name: 'Test User',
      email: 'test@test.com',
      password: 'password123'
    });

    token = jwt.sign({ id: user._id }, config.jwtSecret);
  });

  describe('GET /api/users/profile', () => {
    it('should get user profile', async () => {
      const res = await request(app)
        .get('/api/users/profile')
        .set('Authorization', `Bearer ${token}`);

      expect(res.statusCode).toBe(200);
      expect(res.body).toHaveProperty('email', 'test@test.com');
    });

    it('should not get profile without token', async () => {
      const res = await request(app)
        .get('/api/users/profile');

      expect(res.statusCode).toBe(401);
    });
  });
});

// Update package.json with new dependencies and scripts
{
  // ... (previous content remains)
  "scripts": {
    "start": "node src/server.js",
    "dev": "nodemon src/server.js",
    "test": "jest --detectOpenHandles",
    "test:watch": "jest --watch",
    "docker:up": "docker-compose up",
    "docker:down": "docker-compose down",
    "docs": "swagger-ui-express"
  },
  "dependencies": {
    // ... (previous dependencies)
    "ioredis": "^5.3.2",
    "rate-limit-redis": "^3.0.1",
    "swagger-jsdoc": "^6.2.8",
    "swagger-ui-express": "^4.6.2"
  },
  "devDependencies": {
    // ... (previous devDependencies)
    "jest": "^29.5.0",
    "mongodb-memory-server": "^8.12.2",
    "supertest": "^6.3.3"
  },
  "jest": {
    "testEnvironment": "node",
    "setupFilesAfterEnv": ["./tests/setup.js"],
    "testTimeout": 10000
  }
}

// Update app.js to include Swagger and updated rate limiting
const express = require('express');
const cors = require('cors');
const swaggerUi = require('swagger-ui-express');
const swaggerSpec = require('./docs/swagger');
const createRateLimiter = require('./middlewares/rateLimiter');
// ... (previous imports)

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// API Documentation
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Rate limiting with Redis
app.use('/api/', createRateLimiter());
app.use('/api/auth/', createRateLimiter({ 
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many accounts created, please try again later.'
}));

// ... (rest of the configuration)

module.exports = app;

--------------------------------------------4444444444-----------------------


// .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2
    
    - name: Setup Node.js
      uses: actions/setup-node@v2
      with:
        node-version: '18'
        
    - name: Install dependencies
      run: npm ci
      
    - name: Run tests
      run: npm test
      
    - name: Run linter
      run: npm run lint

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
    - name: Deploy to production
      uses: digitalocean/action-doctl@v2
      with:
        token: ${{ secrets.DIGITALOCEAN_ACCESS_TOKEN }}
        
    - name: Deploy to Docker Hub
      uses: docker/build-push-action@v2
      with:
        push: true
        tags: user/app:latest

// src/config/apm.js
const apm = require('elastic-apm-node');

if (process.env.NODE_ENV === 'production') {
  apm.start({
    serviceName: 'backend-template',
    secretToken: process.env.ELASTIC_APM_SECRET_TOKEN,
    serverUrl: process.env.ELASTIC_APM_SERVER_URL,
    environment: process.env.NODE_ENV
  });
}

module.exports = apm;

// src/graphql/schema.js
const { gql } = require('apollo-server-express');

const typeDefs = gql`
  type User {
    id: ID!
    name: String!
    email: String!
    role: String!
    isEmailVerified: Boolean!
    createdAt: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type Query {
    me: User
    users(page: Int, limit: Int): [User]!
    user(id: ID!): User
  }

  type Mutation {
    register(name: String!, email: String!, password: String!): AuthPayload!
    login(email: String!, password: String!): AuthPayload!
    updateProfile(name: String, email: String): User!
    deleteUser(id: ID!): Boolean!
  }

  type Subscription {
    userCreated: User
    userUpdated: User
  }
`;

module.exports = typeDefs;

// src/graphql/resolvers.js
const User = require('../models/User');
const jwt = require('jsonwebtoken');
const { AuthenticationError, UserInputError } = require('apollo-server-express');
const { PubSub } = require('graphql-subscriptions');

const pubsub = new PubSub();

const resolvers = {
  Query: {
    me: (_, __, { user }) => {
      if (!user) throw new AuthenticationError('Not authenticated');
      return User.findById(user.id);
    },
    users: async (_, { page = 1, limit = 10 }, { user }) => {
      if (!user || user.role !== 'admin') {
        throw new AuthenticationError('Not authorized');
      }
      return User.find()
        .skip((page - 1) * limit)
        .limit(limit);
    },
    user: (_, { id }, { user }) => {
      if (!user || user.role !== 'admin') {
        throw new AuthenticationError('Not authorized');
      }
      return User.findById(id);
    }
  },
  Mutation: {
    register: async (_, { name, email, password }) => {
      // Implementation similar to REST controller
    },
    login: async (_, { email, password }) => {
      // Implementation similar to REST controller
    },
    updateProfile: async (_, args, { user }) => {
      // Implementation similar to REST controller
    }
  },
  Subscription: {
    userCreated: {
      subscribe: () => pubsub.asyncIterator(['USER_CREATED'])
    },
    userUpdated: {
      subscribe: () => pubsub.asyncIterator(['USER_UPDATED'])
    }
  }
};

module.exports = resolvers;

// src/websocket/server.js
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const config = require('../config/env');

const setupWebSocket = (server) => {
  const wss = new WebSocket.Server({ server });

  wss.on('connection', async (ws, req) => {
    try {
      // Extract token from query string
      const token = new URL(req.url, 'ws://localhost').searchParams.get('token');
      if (!token) {
        ws.close(4001, 'Authentication failed');
        return;
      }

      const decoded = jwt.verify(token, config.jwtSecret);
      ws.userId = decoded.id;

      // Send welcome message
      ws.send(JSON.stringify({ type: 'connection', message: 'Connected successfully' }));

      ws.on('message', async (message) => {
        try {
          const data = JSON.parse(message);
          
          // Handle different message types
          switch (data.type) {
            case 'ping':
              ws.send(JSON.stringify({ type: 'pong' }));
              break;
            // Add more message handlers here
          }
        } catch (error) {
          ws.send(JSON.stringify({ type: 'error', message: 'Invalid message format' }));
        }
      });
    } catch (error) {
      ws.close(4001, 'Authentication failed');
    }
  });

  // Broadcast to all connected clients
  wss.broadcast = (data) => {
    wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(data));
      }
    });
  };

  return wss;
};

module.exports = setupWebSocket;

// src/db/migrations/20250121000001_create_users.js
const mongoose = require('mongoose');

module.exports = {
  async up() {
    const collections = await mongoose.connection.db.collections();
    
    if (!collections.find(c => c.collectionName === 'users')) {
      await mongoose.connection.db.createCollection('users', {
        validator: {
          $jsonSchema: {
            bsonType: 'object',
            required: ['name', 'email', 'password'],
            properties: {
              name: {
                bsonType: 'string',
                description: 'must be a string and is required'
              },
              email: {
                bsonType: 'string',
                pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$',
                description: 'must be a valid email and is required'
              }
            }
          }
        }
      });
    }
  },

  async down() {
    await mongoose.connection.db.dropCollection('users');
  }
};

// src/db/seeds/users.js
const User = require('../../models/User');
const logger = require('../../utils/logger');

const seedUsers = async () => {
  try {
    await User.deleteMany({});

    const users = [
      {
        name: 'Admin User',
        email: 'admin@example.com',
        password: 'admin123',
        role: 'admin',
        isEmailVerified: true
      },
      {
        name: 'Test User',
        email: 'user@example.com',
        password: 'user123',
        role: 'user',
        isEmailVerified: true
      }
    ];

    await User.create(users);
    logger.info('Database seeded successfully');
  } catch (error) {
    logger.error('Error seeding database:', error);
    process.exit(1);
  }
};

module.exports = seedUsers;

// Update server.js to include new features
const app = require('./app');
const { ApolloServer } = require('apollo-server-express');
const { execute, subscribe } = require('graphql');
const { SubscriptionServer } = require('subscriptions-transport-ws');
const { makeExecutableSchema } = require('@graphql-tools/schema');
const typeDefs = require('./graphql/schema');
const resolvers = require('./graphql/resolvers');
const setupWebSocket = require('./websocket/server');
require('./config/apm');

const schema = makeExecutableSchema({ typeDefs, resolvers });

const startServer = async () => {
  const apolloServer = new ApolloServer({
    schema,
    context: ({ req }) => {
      const token = req.headers.authorization || '';
      // Add user authentication logic here
      return { user: null };
    },
  });

  await apolloServer.start();
  apolloServer.applyMiddleware({ app });

  const server = app.listen(config.port, () => {
    logger.info(`Server running on port ${config.port}`);
    
    // Set up WebSocket server
    const wss = setupWebSocket(server);
    
    // Set up GraphQL subscriptions
    SubscriptionServer.create(
      { schema, execute, subscribe },
      { server, path: '/graphql' }
    );
  });
};

startServer();

// Update package.json with new dependencies
{
  // ... (previous content)
  "scripts": {
    // ... (previous scripts)
    "migrate": "node src/db/migrate.js",
    "seed": "node src/db/seed.js"
  },
  "dependencies": {
    // ... (previous dependencies)
    "apollo-server-express": "^3.12.0",
    "elastic-apm-node": "^3.42.0",
    "graphql": "^16.6.0",
    "graphql-subscriptions": "^2.0.0",
    "subscriptions-transport-ws": "^0.11.0",
    "ws": "^8.13.0"
  }
}