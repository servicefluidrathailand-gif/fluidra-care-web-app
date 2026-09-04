
// ============================================
// FLUIDRA CARE - Backend Server v1.0.0
// ============================================

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import http from 'http';
import { Server as SocketIOServer } from 'socket.io';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import winston from 'winston';

// Load environment variables
dotenv.config();

// ============== LOGGER SETUP ==============
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
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

// ============== EXPRESS APP SETUP ==============
const app = express();
const server = http.createServer(app);

// Socket.IO Configuration
const io = new SocketIOServer(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// ============== MIDDLEWARE ==============
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP'
});
app.use('/api/', limiter);

// ============== JWT AUTHENTICATION MIDDLEWARE ==============
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// ============== DATABASE CONNECTION ==============
import pkg from 'pg';
const { Pool } = pkg;

const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME
});

pool.on('error', (err) => {
  logger.error('Unexpected error on idle client', err);
});

// ============== ROUTES ==============

// 1. AUTHENTICATION ROUTES
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const result = await pool.query(
      'SELECT * FROM admin_users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    
    // In production, use bcrypt for password comparison
    if (user.password_hash !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      {
        user_id: user.admin_id,
        email: user.email,
        role: user.role,
        center_id: user.center_id
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        user_id: user.admin_id,
        email: user.email,
        role: user.role,
        center_id: user.center_id,
        name: user.name
      }
    });

    logger.info(`User logged in: ${email}`);
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', authenticateToken, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// 2. LINE OA WEBHOOK
app.post('/api/webhook/line', async (req, res) => {
  try {
    const { events } = req.body;

    for (const event of events) {
      if (event.type === 'message' && event.message.type === 'text') {
        const userId = event.source.userId;
        const messageText = event.message.text;
        const replyToken = event.replyToken;

        logger.info(`LINE Message: ${userId} - ${messageText}`);

        // Check if customer has active case
        const caseResult = await pool.query(
          `SELECT * FROM line_cases 
           WHERE line_user_id = $1 AND status IN ('open', 'in_progress', 'waiting_customer')
           ORDER BY opened_at DESC LIMIT 1`,
          [userId]
        );

        if (caseResult.rows.length > 0) {
          // Route to existing case
          const activeCase = caseResult.rows[0];
          await pool.query(
            `INSERT INTO line_messages (case_id, sender_type, sender_id, message_text)
             VALUES ($1, $2, $3, $4)`,
            [activeCase.case_id, 'customer', userId, messageText]
          );

          // Notify staff via Socket.IO
          io.to(`center_${activeCase.center_id}`).emit('new_message', {
            case_id: activeCase.case_id,
            message: messageText,
            timestamp: new Date()
          });
        } else {
          // Show service center selection
          const centersResult = await pool.query(
            'SELECT center_id, center_name FROM service_centers WHERE status = $1',
            ['active']
          );

          const centers = centersResult.rows;
          // Send FlexMessage with center buttons to LINE
          sendLineFlexMessage(replyToken, centers);
        }
      } else if (event.type === 'postback') {
        const userId = event.source.userId;
        const data = new URLSearchParams(event.postback.data);
        const action = data.get('action');
        const centerId = data.get('center');

        if (action === 'select_center') {
          // Create new case
          const caseId = `CASE_${Date.now()}`;
          const result = await pool.query(
            `INSERT INTO line_cases (case_id, line_user_id, center_id, status)
             VALUES ($1, $2, $3, $4)
             RETURNING *`,
            [caseId, userId, centerId, 'open']
          );

          // Reply to user
          await sendLineMessage(event.replyToken, 
            `✅ เลือกศูนย์บริการสำเร็จ (${centerId})\nกรุณารอเจ้าหน้าที่ติดต่อกลับ`
          );

          // Notify staff
          io.to(`center_${centerId}`).emit('new_case', {
            case_id: caseId,
            user_id: userId,
            timestamp: new Date()
          });

          logger.info(`Case created: ${caseId} for center: ${centerId}`);
        }
      }
    }

    res.json({ success: true });
  } catch (err) {
    logger.error('Webhook error:', err);
    res.status(500).json({ error: 'Webhook processing failed' });
  }
});

// 3. CASES MANAGEMENT
app.get('/api/cases', authenticateToken, async (req, res) => {
  try {
    const { user_id, center_id } = req.user;

    const result = await pool.query(
      `SELECT * FROM line_cases 
       WHERE center_id = $1 
       ORDER BY opened_at DESC`,
      [center_id]
    );

    res.json(result.rows);
  } catch (err) {
    logger.error('Get cases error:', err);
    res.status(500).json({ error: 'Failed to fetch cases' });
  }
});

app.get('/api/cases/:case_id', authenticateToken, async (req, res) => {
  try {
    const { case_id } = req.params;
    const { center_id } = req.user;

    const caseResult = await pool.query(
      'SELECT * FROM line_cases WHERE case_id = $1 AND center_id = $2',
      [case_id, center_id]
    );

    if (caseResult.rows.length === 0) {
      return res.status(403).json({ error: 'CROSS_CENTER_ACCESS_DENIED' });
    }

    const messagesResult = await pool.query(
      'SELECT * FROM line_messages WHERE case_id = $1 ORDER BY created_at ASC',
      [case_id]
    );

    res.json({
      case: caseResult.rows[0],
      messages: messagesResult.rows
    });
  } catch (err) {
    logger.error('Get case details error:', err);
    res.status(500).json({ error: 'Failed to fetch case' });
  }
});

app.patch('/api/cases/:case_id', authenticateToken, async (req, res) => {
  try {
    const { case_id } = req.params;
    const { status } = req.body;
    const { center_id } = req.user;

    const result = await pool.query(
      `UPDATE line_cases 
       SET status = $1, updated_at = NOW() 
       WHERE case_id = $2 AND center_id = $3
       RETURNING *`,
      [status, case_id, center_id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'CROSS_CENTER_ACCESS_DENIED' });
    }

    res.json(result.rows[0]);
    logger.info(`Case ${case_id} updated to status: ${status}`);
  } catch (err) {
    logger.error('Update case error:', err);
    res.status(500).json({ error: 'Failed to update case' });
  }
});

// 4. SEND REPLY TO LINE
app.post('/api/line/send-message', authenticateToken, async (req, res) => {
  try {
    const { case_id, message } = req.body;
    const { center_id, user_id } = req.user;

    // Verify access
    const caseResult = await pool.query(
      'SELECT * FROM line_cases WHERE case_id = $1 AND center_id = $2',
      [case_id, center_id]
    );

    if (caseResult.rows.length === 0) {
      return res.status(403).json({ error: 'CROSS_CENTER_ACCESS_DENIED' });
    }

    const lineUserId = caseResult.rows[0].line_user_id;

    // Save to database
    await pool.query(
      `INSERT INTO line_messages (case_id, sender_type, sender_id, message_text)
       VALUES ($1, $2, $3, $4)`,
      [case_id, 'staff', user_id, message]
    );

    // Send to LINE
    await sendLineMessage(lineUserId, message);

    res.json({ success: true });
    logger.info(`Message sent to case ${case_id}`);
  } catch (err) {
    logger.error('Send message error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// 5. SERIAL NUMBER SEARCH (PUBLIC - NO AUTH)
app.get('/api/products/search-serial/:serial_number', async (req, res) => {
  try {
    const { serial_number } = req.params;

    const result = await pool.query(
      `SELECT 
        pi.serial_number,
        p.product_name,
        p.model,
        pi.warranty_end_date,
        CASE 
          WHEN pi.warranty_end_date >= CURRENT_DATE THEN 'Active'
          ELSE 'Expired'
        END as warranty_status,
        (SELECT COUNT(*) FROM service_history WHERE instance_id = pi.instance_id) as service_count,
        (SELECT MAX(service_date) FROM service_history WHERE instance_id = pi.instance_id) as last_service_date
       FROM product_instances pi
       JOIN products p ON pi.product_id = p.product_id
       WHERE pi.serial_number = $1`,
      [serial_number]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Serial number not found' });
    }

    res.json(result.rows[0]);
    logger.info(`Serial search: ${serial_number}`);
  } catch (err) {
    logger.error('Serial search error:', err);
    res.status(500).json({ error: 'Search failed' });
  }
});

// 6. HEALTH CHECK
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// ============== SOCKET.IO EVENTS ==============
io.on('connection', (socket) => {
  logger.info('Client connected:', socket.id);

  socket.on('join_center', (data) => {
    const { center_id } = data;
    socket.join(`center_${center_id}`);
    logger.info(`Socket joined center: ${center_id}`);
  });

  socket.on('disconnect', () => {
    logger.info('Client disconnected:', socket.id);
  });
});

// ============== HELPER FUNCTIONS ==============
async function sendLineMessage(userId, message) {
  try {
    const response = await fetch('https://api.line.biz/v1/bot/message/push', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.LINE_CHANNEL_ACCESS_TOKEN}`
      },
      body: JSON.stringify({
        to: userId,
        messages: [{
          type: 'text',
          text: message
        }]
      })
    });
    return response.ok;
  } catch (err) {
    logger.error('LINE API error:', err);
    return false;
  }
}

async function sendLineFlexMessage(replyToken, centers) {
  const buttons = centers.map((center, idx) => ({
    type: 'button',
    style: 'primary',
    action: {
      type: 'postback',
      label: `🏢 ${center.center_name}`,
      data: `action=select_center&center=${center.center_id}`
    }
  }));

  try {
    await fetch('https://api.line.biz/v1/bot/message/reply', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.LINE_CHANNEL_ACCESS_TOKEN}`
      },
      body: JSON.stringify({
        replyToken,
        messages: [{
          type: 'flex',
          altText: 'เลือกศูนย์บริการ',
          contents: {
            type: 'bubble',
            body: {
              type: 'box',
              layout: 'vertical',
              contents: [
                {
                  type: 'text',
                  text: 'เลือกศูนย์บริการ',
                  weight: 'bold',
                  size: 'xl'
                },
                ...buttons
              ]
            }
          }
        }]
      })
    });
  } catch (err) {
    logger.error('Send FlexMessage error:', err);
  }
}

// ============== SERVER STARTUP ==============
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  logger.info(`🚀 Fluidra Care Backend running on port ${PORT}`);
});

process.on('SIGINT', () => {
  logger.info('Shutting down gracefully...');
  server.close(() => {
    pool.end();
    process.exit(0);
  });
});

export default app;
