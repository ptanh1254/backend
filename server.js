const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const multer = require('multer');

require('dotenv').config();

const app = express();
const server = http.createServer(app);

// CORS Configuration
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:3000,http://localhost:5173,http://192.168.1.87:5173')
  .split(',')
  .map(origin => origin.trim())
  .filter(origin => {
    if (/\s/.test(origin)) return false;
    return true;
  });

if (!allowedOrigins.includes('http://localhost:5000')) {
  allowedOrigins.push('http://localhost:5000');
}

// Function to check if origin is from local network
const isLocalNetworkOrigin = (origin) => {
  if (!origin) return true;
  // Allow localhost
  if (origin.includes('localhost') || origin.includes('127.0.0.1') || origin.includes('::1')) return true;
  // Allow 192.168.x.x (private network)
  if (/https?:\/\/192\.168\.\d+\.\d+/.test(origin)) return true;
  // Allow 10.x.x.x (private network)
  if (/https?:\/\/10\.\d+\.\d+\.\d+/.test(origin)) return true;
  // Allow 172.16-31.x.x (private network)
  if (/https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/.test(origin)) return true;
  return allowedOrigins.includes(origin);
};

const io = new Server(server, {
  cors: {
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (isLocalNetworkOrigin(origin)) {
        return callback(null, true);
      } else {
        return callback(new Error('Not allowed by CORS'));
      }
    },
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true
  }
});

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "http:", "https:", "*"],
    }
  }
}));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (isLocalNetworkOrigin(origin)) {
      return callback(null, true);
    } else {
      console.log(`🚫 CORS blocked: ${origin}`);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200
}));

app.use(express.json({ limit: '10kb' }));

// Custom sanitization middleware
app.use((req, res, next) => {
  // Sanitize request body
  if (req.body) {
    Object.keys(req.body).forEach(key => {
      if (typeof req.body[key] === 'string') {
        // Remove potentially dangerous characters
        req.body[key] = req.body[key].replace(/[$<>]/g, '');
      }
    });
  }
  
  // Sanitize query parameters
  if (req.query) {
    Object.keys(req.query).forEach(key => {
      if (typeof req.query[key] === 'string') {
        req.query[key] = req.query[key].replace(/[$<>]/g, '');
      }
    });
  }
  next();
});

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Quá nhiều request, vui lòng thử lại sau',
  standardHeaders: true,
  legacyHeaders: false
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true,
  message: 'Quá nhiều lần thử đăng nhập, vui lòng thử lại sau'
});

app.use('/api/', limiter);
app.use('/api/login', authLimiter);
app.use('/api/login1', authLimiter); 

// Serve static files từ uploads folder - PHẢI ĐẶT TRƯỚC ROUTES
if (!fs.existsSync('uploads')){
    fs.mkdirSync('uploads');
}
app.use('/uploads', express.static('uploads', {
  maxAge: '1d',
  etag: false,
  setHeaders: (res, path) => {
    res.set('Cross-Origin-Resource-Policy', 'cross-origin');
    res.set('Access-Control-Allow-Origin', '*');
  }
}));

// MongoDB Connection - Đã sửa lỗi options không được hỗ trợ
const MONGO_URI = process.env.MONGO_URI;
if (!MONGO_URI) {
  console.error('❌ Lỗi: MONGO_URI chưa được set trong .env file');
  process.exit(1);
}

// Đã xóa useNewUrlParser và useUnifiedTopology vì không cần thiết trong mongoose 6+
mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: 5000
})
  .then(() => console.log('✅ Đã kết nối MongoDB Atlas'))
  .catch(err => console.error('❌ Lỗi kết nối MongoDB:', err.message));

// Schemas
const SettingSchema = new mongoose.Schema({
  restaurantName: { type: String, default: 'Mr Duc' },
  address: { type: String, default: '21 Thôn 12 Hoà Phú, BMT' },
  phone: { type: String, default: '0357975610' },
  wifiPass: { type: String, default: '12345678' },
  receiptFooter: { type: String, default: 'Cảm ơn quý khách!' },
  receiptLine1: { type: String, default: '' },
  receiptLine2: { type: String, default: '' },
  receiptLine3: { type: String, default: '' },
  lateThreshold: { type: Number, default: 15 },
  standardStartTime: { type: String, default: '09:00' },
  standardEndTime: { type: String, default: '18:00' }
});

const CategorySchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Tên danh mục là bắt buộc'] },
  order: { type: Number, default: 0 }
});

const MenuSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Tên món là bắt buộc'] },
  price: { type: Number, required: [true, 'Giá là bắt buộc'], min: [0, 'Giá không thể âm'] },
  categoryId: { type: mongoose.Schema.Types.ObjectId, ref: 'Category' },
  categoryName: String,
  image: String,
  status: { type: String, default: 'active', enum: ['active', 'inactive'] }
});

const TableSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Tên bàn là bắt buộc'] },
  capacity: { type: Number, required: [true, 'Sức chứa là bắt buộc'], min: [1, 'Sức chứa tối thiểu là 1'] },
  zone: { type: String, default: 'Tầng 1' }
});

const StaffSchema = new mongoose.Schema({
  name: { type: String, required: [true, 'Tên nhân viên là bắt buộc'] },
  username: { 
    type: String, 
    required: [true, 'Username là bắt buộc'], 
    unique: true,
    minlength: [3, 'Username phải có ít nhất 3 ký tự']
  },
  password: { 
    type: String, 
    required: [true, 'Password là bắt buộc'],
    minlength: [6, 'Password phải có ít nhất 6 ký tự']
  },
  role: { type: String, default: 'staff', enum: ['admin', 'staff'] }
});

const AttendanceSchema = new mongoose.Schema({
  staffId: { type: mongoose.Schema.Types.ObjectId, ref: 'Staff', required: true },
  staffName: { type: String, required: true },
  date: { type: Date, required: true },
  checkInTime: Date,
  checkOutTime: Date,
  ipAddress: String,
  status: { type: String, enum: ['present', 'absent', 'late'], default: 'absent' },
  createdAt: { type: Date, default: Date.now }
});

AttendanceSchema.index({ staffId: 1, date: 1 }, { unique: true });

const RevenueSchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  month: { type: String, required: true },
  dailyRevenue: { type: Number, default: 0, min: 0 },
  monthlyRevenue: { type: Number, default: 0, min: 0 },
  totalRevenue: { type: Number, default: 0, min: 0 },
  dailyOrders: { type: Number, default: 0, min: 0 },
  monthlyOrders: { type: Number, default: 0, min: 0 },
  totalOrders: { type: Number, default: 0, min: 0 },
  updatedAt: { type: Date, default: Date.now }
});

const OrderSchema = new mongoose.Schema({
  tableId: String,
  tableName: String,
  staffName: String,
  items: [{
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    name: String,
    price: { type: Number, min: 0 },
    quantity: { type: Number, min: 1 },
    status: { type: String, default: 'new', enum: ['new', 'cooking', 'served'] }
  }],
  note: String,
  status: { type: String, default: 'new', enum: ['new', 'cooking', 'served', 'paid'] },
  paymentMethod: String,
  finalTotal: { type: Number, min: 0 },
  createdAt: { type: Date, default: Date.now },
  paidAt: Date
});

// Cart Schema - Lưu giỏ hàng tạm thời
const CartSchema = new mongoose.Schema({
  sessionId: { type: String, required: true, unique: true },
  tableId: String,
  items: [{
    _id: { type: mongoose.Schema.Types.ObjectId, auto: true },
    name: String,
    price: { type: Number, min: 0 },
    quantity: { type: Number, min: 1 }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Models
const Setting = mongoose.model('Setting', SettingSchema);
const Category = mongoose.model('Category', CategorySchema);
const Menu = mongoose.model('Menu', MenuSchema);
const Table = mongoose.model('Table', TableSchema);
const Staff = mongoose.model('Staff', StaffSchema);
const Attendance = mongoose.model('Attendance', AttendanceSchema);
const Revenue = mongoose.model('Revenue', RevenueSchema);
const Order = mongoose.model('Order', OrderSchema);
const Cart = mongoose.model('Cart', CartSchema);

// Seed Data
const seedData = async () => {
  try {
    const settingCount = await Setting.countDocuments();
    if (settingCount === 0) {
      await Setting.create({});
      console.log('✅ Đã tạo cài đặt mặc định');
    }

    const staffCount = await Staff.countDocuments();
    if (staffCount === 0) {
      const defaultPassword = process.env.ADMIN_PASSWORD || 'Ptuananh1254';
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(defaultPassword, salt);
      await Staff.create({
        name: 'Quản Lý',
        username: 'admin',
        password: hashedPassword,
        role: 'admin'
      });
      console.log('🛡️ Đã tạo tài khoản admin mặc định');
    }
  } catch (e) {
    console.log('Seed error:', e.message);
  }
};

mongoose.connection.once('open', seedData);

// Helper Functions
const validateInput = (data) => {
  if (!data.username || typeof data.username !== 'string' || data.username.length < 3) {
    return 'Username phải có ít nhất 3 ký tự';
  }
  if (!data.password || typeof data.password !== 'string' || data.password.length < 6) {
    return 'Password phải có ít nhất 6 ký tự';
  }
  return null;
};

// Hàm xử lý lỗi Mongoose validation
const handleValidationError = (error) => {
  if (error.name === 'ValidationError') {
    const messages = Object.values(error.errors).map(err => err.message);
    return messages.join(', ');
  }
  if (error.code === 11000) {
    return 'Dữ liệu đã tồn tại';
  }
  return null;
};

// Hàm xác thực ObjectId
const validateObjectId = (id) => mongoose.Types.ObjectId.isValid(id);

// Hàm trả về error response chuẩn
const errorResponse = (res, statusCode, message) => {
  res.status(statusCode).json({ success: false, message });
};

const updateRevenue = async (order) => {
  try {
    const paidDate = new Date(order.paidAt);
    paidDate.setHours(0, 0, 0, 0);
    const monthStr = `${paidDate.getFullYear()}-${String(paidDate.getMonth() + 1).padStart(2, '0')}`;

    // Update revenue cho ngày cụ thể
    const revenue = await Revenue.findOne({ date: paidDate });
    if (revenue) {
      revenue.dailyRevenue += order.finalTotal;
      revenue.dailyOrders += 1;
      revenue.month = monthStr;
      revenue.updatedAt = new Date();
      await revenue.save();
    } else {
      await Revenue.create({
        date: paidDate,
        month: monthStr,
        dailyRevenue: order.finalTotal,
        dailyOrders: 1,
        updatedAt: new Date()
      });
    }

    // Update revenue cho tháng - tính lại từ tất cả ngày trong tháng
    const startOfMonth = new Date(paidDate.getFullYear(), paidDate.getMonth(), 1);
    const endOfMonth = new Date(paidDate.getFullYear(), paidDate.getMonth() + 1, 0);
    
    const monthlyOrders = await Order.find({
      status: 'paid',
      paidAt: { $gte: startOfMonth, $lte: endOfMonth }
    });
    
    const monthlyRevenue = monthlyOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);
    
    // Cập nhật tất cả revenue records trong tháng
    await Revenue.updateMany(
      { month: monthStr },
      { monthlyRevenue: monthlyRevenue, monthlyOrders: monthlyOrders.length }
    );

    // Update revenue tổng cộng
    const totalOrders = await Order.find({ status: 'paid' });
    const totalRevenue = totalOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);
    
    await Revenue.updateMany(
      {},
      { totalRevenue: totalRevenue, totalOrders: totalOrders.length }
    );

  } catch (error) {
    console.error('Revenue update error:', error);
  }
};

// Login function (reusable)
const handleLogin = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Input validation
    if (!username || !password) {
      return errorResponse(res, 400, 'Vui lòng nhập username và password');
    }

    const user = await Staff.findOne({ username });
    if (!user) {
      return errorResponse(res, 401, 'Tài khoản hoặc mật khẩu không đúng');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return errorResponse(res, 401, 'Tài khoản hoặc mật khẩu không đúng');
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        role: user.role,
        username: user.username
      }
    });
  } catch (e) {
    console.error('Login error:', e);
    errorResponse(res, 500, 'Lỗi server');
  }
};

// Routes

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running', timestamp: new Date() });
});

// Login - Chính thức
app.post('/api/login', handleLogin);

// Login - Dự phòng (cho các client cũ)
app.post('/api/login1', handleLogin);

// Init Data
app.get('/api/init', async (req, res) => {
  try {
    const [tables, menu, categories, activeOrders, settings] = await Promise.all([
      Table.find().sort({ name: 1 }),
      Menu.find(),
      Category.find().sort({ order: 1 }),
      Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 }),
      Setting.findOne()
    ]);
    
    res.json({ tables, menu, categories, activeOrders, settings });
  } catch (e) {
    console.error('Init error:', e);
    errorResponse(res, 500, 'Lỗi khi tải dữ liệu');
  }
});

// CRUD Generator - ĐÃ TỐI ƯU
const createCrud = (Model, routeName, excludeRoutes = []) => {
  // GET all
  if (!excludeRoutes.includes('GET')) {
    app.get(`/api/${routeName}`, async (req, res) => {
      try {
        const data = await Model.find();
        res.json(data);
      } catch (e) {
        console.error(`Get ${routeName} error:`, e);
        errorResponse(res, 500, `Lỗi khi tải ${routeName}`);
      }
    });
  }

  // POST create
  if (!excludeRoutes.includes('POST')) {
    app.post(`/api/${routeName}`, async (req, res) => {
      try {
        if (!req.body || Object.keys(req.body).length === 0) {
          return errorResponse(res, 400, 'Dữ liệu không hợp lệ');
        }
        
        const n = new Model(req.body);
        await n.save();
        
        // Emit socket event for real-time updates
        io.emit(`${routeName}_updated`, await Model.find());
        
        res.status(201).json(n);
      } catch (e) {
        console.error(`Create ${routeName} error:`, e);
        const validationError = handleValidationError(e);
        if (validationError) return errorResponse(res, 400, validationError);
        errorResponse(res, 500, `Lỗi khi tạo ${routeName}`);
      }
    });
  }

  // PUT update
  if (!excludeRoutes.includes('PUT')) {
    app.put(`/api/${routeName}/:id`, async (req, res) => {
      try {
        if (!validateObjectId(req.params.id)) {
          return errorResponse(res, 400, 'ID không hợp lệ');
        }
        
        const updated = await Model.findByIdAndUpdate(
          req.params.id, 
          req.body, 
          { new: true, runValidators: true }
        );
        
        if (!updated) {
          return errorResponse(res, 404, 'Không tìm thấy dữ liệu');
        }
        
        io.emit(`${routeName}_updated`, await Model.find());
        res.json({ success: true, data: updated });
      } catch (e) {
        console.error(`Update ${routeName} error:`, e);
        const validationError = handleValidationError(e);
        if (validationError) return errorResponse(res, 400, validationError);
        errorResponse(res, 500, `Lỗi khi cập nhật ${routeName}`);
      }
    });
  }

  // DELETE
  if (!excludeRoutes.includes('DELETE')) {
    app.delete(`/api/${routeName}/:id`, async (req, res) => {
      try {
        if (!validateObjectId(req.params.id)) {
          return errorResponse(res, 400, 'ID không hợp lệ');
        }
        
        const deleted = await Model.findByIdAndDelete(req.params.id);
        
        if (!deleted) {
          return errorResponse(res, 404, 'Không tìm thấy dữ liệu');
        }
        
        io.emit(`${routeName}_updated`, await Model.find());
        res.json({ success: true, message: 'Đã xóa thành công' });
      } catch (e) {
        console.error(`Delete ${routeName} error:`, e);
        errorResponse(res, 500, `Lỗi khi xóa ${routeName}`);
      }
    });
  }
};

// Apply CRUD routes - Quay về thuật toán cũ đơn giản
createCrud(Menu, 'menu');
createCrud(Table, 'tables');
createCrud(Category, 'categories');

// THÊM CHỨC NĂNG GET MENU BY ID ĐỂ TEST
app.get('/api/menu/:id', async (req, res) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return errorResponse(res, 400, 'ID không hợp lệ');
    }
    
    const menuItem = await Menu.findById(req.params.id);
    if (!menuItem) {
      return errorResponse(res, 404, 'Không tìm thấy món ăn');
    }
    
    res.json(menuItem);
  } catch (e) {
    console.error('Get menu item error:', e);
    errorResponse(res, 500, 'Lỗi khi tải món ăn');
  }
});

// Staff Management
app.get('/api/staff', async (req, res) => {
  try {
    const staff = await Staff.find().select('-password');
    res.json(staff);
  } catch (e) {
    console.error('Get staff error:', e);
    errorResponse(res, 500, 'Lỗi khi tải nhân viên');
  }
});

app.post('/api/staff', async (req, res) => {
  try {
    const { username, password, name, role } = req.body;

    // Validation
    if (!username || !password || !name) {
      return errorResponse(res, 400, 'Thiếu thông tin bắt buộc');
    }

    // Check for existing username
    const existing = await Staff.findOne({ username });
    if (existing) {
      return errorResponse(res, 400, 'Username đã tồn tại');
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create staff
    const staff = new Staff({
      username,
      password: hashedPassword,
      name,
      role: role || 'staff'
    });

    await staff.save();
    
    // Return without password
    const staffResponse = staff.toObject();
    delete staffResponse.password;
    
    res.status(201).json(staffResponse);
  } catch (e) {
    console.error('Create staff error:', e);
    const validationError = handleValidationError(e);
    if (validationError) return errorResponse(res, 400, validationError);
    errorResponse(res, 500, 'Lỗi khi tạo nhân viên');
  }
});

app.put('/api/staff/:id', async (req, res) => {
  try {
    const { username, password, name, role } = req.body;

    if (!validateObjectId(req.params.id)) {
      return errorResponse(res, 400, 'ID không hợp lệ');
    }

    const updateData = { name, role: role || 'staff' };

    // If username is being updated, check for duplicates
    if (username) {
      const existing = await Staff.findOne({ username, _id: { $ne: req.params.id } });
      if (existing) {
        return errorResponse(res, 400, 'Username đã tồn tại');
      }
      updateData.username = username;
    }

    // If password is provided, hash it
    if (password && password.length > 0) {
      const salt = await bcrypt.genSalt(10);
      updateData.password = await bcrypt.hash(password, salt);
    }

    const updated = await Staff.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updated) {
      return errorResponse(res, 404, 'Không tìm thấy nhân viên');
    }

    res.json({ success: true, data: updated });
  } catch (e) {
    console.error('Update staff error:', e);
    const validationError = handleValidationError(e);
    if (validationError) return errorResponse(res, 400, validationError);
    errorResponse(res, 500, 'Lỗi khi cập nhật nhân viên');
  }
});

app.delete('/api/staff/:id', async (req, res) => {
  try {
    if (!validateObjectId(req.params.id)) {
      return errorResponse(res, 400, 'ID không hợp lệ');
    }

    // Don't allow deleting the last admin
    const staffToDelete = await Staff.findById(req.params.id);
    if (staffToDelete && staffToDelete.role === 'admin') {
      const adminCount = await Staff.countDocuments({ role: 'admin' });
      if (adminCount <= 1) {
        return errorResponse(res, 400, 'Không được xóa quản lý duy nhất');
      }
    }

    await Staff.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Đã xóa nhân viên' });
  } catch (e) {
    console.error('Delete staff error:', e);
    errorResponse(res, 500, 'Lỗi khi xóa nhân viên');
  }
});

// Attendance Routes
const ALLOWED_IPS = (process.env.ALLOWED_IPS || '192.168.1.87,127.0.0.1,localhost').split(',');

const getClientIp = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    'unknown';
};

const isIpAllowed = (ip) => {
  return ALLOWED_IPS.some(allowed => {
    if (allowed === 'localhost') return ip === '::1' || ip === '127.0.0.1';
    return ip.includes(allowed.trim());
  });
};

app.post('/api/attendance/checkin', async (req, res) => {
  try {
    const { staffId } = req.body;

    if (!staffId || !validateObjectId(staffId)) {
      return errorResponse(res, 400, 'ID nhân viên không hợp lệ');
    }

    const clientIp = getClientIp(req);
    console.log(`Check-in attempt from IP: ${clientIp}`);
    
    if (!isIpAllowed(clientIp)) {
      return errorResponse(res, 403, 'Chỉ được điểm danh tại quán');
    }

    const staff = await Staff.findById(staffId);
    if (!staff) {
      return errorResponse(res, 404, 'Nhân viên không tồn tại');
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    let attendance = await Attendance.findOne({
      staffId,
      date: { $gte: today, $lt: tomorrow }
    });

    if (!attendance) {
      attendance = new Attendance({
        staffId,
        staffName: staff.name,
        date: new Date(),
        checkInTime: new Date(),
        ipAddress: clientIp,
        status: 'present'
      });
    } else if (attendance.checkInTime) {
      return errorResponse(res, 400, 'Bạn đã điểm danh hôm nay rồi');
    } else {
      attendance.checkInTime = new Date();
      attendance.status = 'present';
      attendance.ipAddress = clientIp;
    }

    await attendance.save();
    
    // Populate staff info for response
    await attendance.populate('staffId', 'name username');
    
    res.json({ 
      success: true, 
      message: 'Điểm danh thành công', 
      data: attendance 
    });
  } catch (e) {
    console.error('Check-in error:', e);
    errorResponse(res, 500, 'Lỗi khi điểm danh');
  }
});

app.post('/api/attendance/checkout', async (req, res) => {
  try {
    const { staffId } = req.body;

    if (!staffId || !validateObjectId(staffId)) {
      return errorResponse(res, 400, 'ID nhân viên không hợp lệ');
    }

    const clientIp = getClientIp(req);
    if (!isIpAllowed(clientIp)) {
      return errorResponse(res, 403, 'Chỉ được điểm danh tại quán');
    }

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const attendance = await Attendance.findOne({
      staffId,
      date: { $gte: today, $lt: tomorrow }
    });

    if (!attendance) {
      return errorResponse(res, 404, 'Chưa điểm danh hôm nay');
    }

    attendance.checkOutTime = new Date();
    await attendance.save();
    
    await attendance.populate('staffId', 'name username');

    res.json({ 
      success: true, 
      message: 'Kết thúc ca làm việc', 
      data: attendance 
    });
  } catch (e) {
    console.error('Check-out error:', e);
    errorResponse(res, 500, 'Lỗi khi kết thúc ca');
  }
});

app.get('/api/attendance/today', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    const attendance = await Attendance.find({
      date: { $gte: today, $lt: tomorrow }
    }).populate('staffId', 'name username role');

    res.json(attendance);
  } catch (e) {
    console.error('Get attendance error:', e);
    errorResponse(res, 500, 'Lỗi khi lấy dữ liệu điểm danh');
  }
});

// Lịch sử điểm danh theo tháng
app.get('/api/attendance/month', async (req, res) => {
  try {
    const { year, month } = req.query;
    
    if (!year || !month) {
      return errorResponse(res, 400, 'Cần cung cấp year và month');
    }

    const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
    const endDate = new Date(parseInt(year), parseInt(month), 1);

    const attendance = await Attendance.find({
      date: { $gte: startDate, $lt: endDate }
    }).populate('staffId', 'name username role').sort({ date: -1, staffId: 1 });

    res.json(attendance);
  } catch (e) {
    console.error('Get monthly attendance error:', e);
    errorResponse(res, 500, 'Lỗi khi lấy lịch sử điểm danh');
  }
});

// Thống kê chi tiết nhân viên theo tháng
app.get('/api/attendance/stats/monthly', async (req, res) => {
  try {
    const { year, month } = req.query;
    
    if (!year || !month) {
      return errorResponse(res, 400, 'Cần cung cấp year và month');
    }

    const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
    const endDate = new Date(parseInt(year), parseInt(month), 1);

    const attendance = await Attendance.find({
      date: { $gte: startDate, $lt: endDate }
    }).populate('staffId', 'name username role');

    // Tính toán thống kê
    const stats = {};
    const daysInMonth = new Date(parseInt(year), parseInt(month), 0).getDate();

    // Lấy tất cả nhân viên
    const allStaff = await Staff.find().select('_id name username role');
    
    allStaff.forEach(staff => {
      const staffAttendance = attendance.filter(a => a.staffId._id.toString() === staff._id.toString());
      
      const present = staffAttendance.filter(a => a.status === 'present').length;
      const absent = daysInMonth - staffAttendance.length;
      const late = staffAttendance.filter(a => a.status === 'late').length;
      
      const totalHours = staffAttendance.reduce((sum, a) => {
        if (a.checkInTime && a.checkOutTime) {
          return sum + (a.checkOutTime - a.checkInTime) / (1000 * 60 * 60);
        }
        return sum;
      }, 0);

      stats[staff._id] = {
        staffId: staff._id,
        name: staff.name,
        username: staff.username,
        role: staff.role,
        present,
        absent,
        late,
        totalHours: Math.round(totalHours * 10) / 10,
        attendanceRate: Math.round((present / daysInMonth) * 100) + '%'
      };
    });

    res.json({
      month: `${month}/${year}`,
      daysInMonth,
      stats: Object.values(stats)
    });
  } catch (e) {
    console.error('Get attendance stats error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tính toán thống kê' });
  }
});

// Thống kê chi tiết từng nhân viên
app.get('/api/attendance/stats/staff/:staffId', async (req, res) => {
  try {
    const { staffId } = req.params;
    const { year, month } = req.query;

    if (!staffId || !mongoose.Types.ObjectId.isValid(staffId)) {
      return res.status(400).json({ success: false, message: 'ID nhân viên không hợp lệ' });
    }

    const staff = await Staff.findById(staffId).select('name username role');
    if (!staff) {
      return res.status(404).json({ success: false, message: 'Nhân viên không tồn tại' });
    }

    let query = { staffId };
    
    if (year && month) {
      const startDate = new Date(parseInt(year), parseInt(month) - 1, 1);
      const endDate = new Date(parseInt(year), parseInt(month), 1);
      query.date = { $gte: startDate, $lt: endDate };
    }

    const attendance = await Attendance.find(query).sort({ date: -1 });

    const stats = {
      staffId: staff._id,
      name: staff.name,
      username: staff.username,
      role: staff.role,
      totalDays: attendance.length,
      present: attendance.filter(a => a.status === 'present').length,
      absent: attendance.filter(a => a.status === 'absent').length,
      late: attendance.filter(a => a.status === 'late').length,
      totalHours: Math.round(
        attendance.reduce((sum, a) => {
          if (a.checkInTime && a.checkOutTime) {
            return sum + (a.checkOutTime - a.checkInTime) / (1000 * 60 * 60);
          }
          return sum;
        }, 0) * 10
      ) / 10,
      details: attendance
    };

    res.json(stats);
  } catch (e) {
    console.error('Get staff stats error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi lấy thống kê nhân viên' });
  }
});

// Orders
app.post('/api/orders', async (req, res) => {
  try {
    const { tableId, items, ...otherData } = req.body;

    if (!tableId || !items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ success: false, message: 'Dữ liệu đơn hàng không hợp lệ' });
    }

    // Validate items
    for (const item of items) {
      if (!item.name || !item.price || !item.quantity) {
        return res.status(400).json({ success: false, message: 'Thông tin mặt hàng không hợp lệ' });
      }
      if (typeof item.price !== 'number' || item.price < 0) {
        return res.status(400).json({ success: false, message: 'Giá mặt hàng không hợp lệ' });
      }
      if (typeof item.quantity !== 'number' || item.quantity < 1) {
        return res.status(400).json({ success: false, message: 'Số lượng mặt hàng không hợp lệ' });
      }
    }

    const itemsWithStatus = items.map(item => ({
      ...item,
      _id: item._id || new mongoose.Types.ObjectId(),
      status: item.status || 'new'
    }));

    // Delete empty orders for this table first
    await Order.deleteMany({ 
      tableId: tableId, 
      items: { $size: 0 },
      status: { $in: ['new', 'cooking', 'served'] }
    });

    const existingOrder = await Order.findOne({ 
      tableId: tableId, 
      status: { $in: ['new', 'cooking', 'served'] } 
    });

    if (existingOrder) {
      existingOrder.items = [...existingOrder.items, ...itemsWithStatus];
      if (otherData.note) {
        existingOrder.note = existingOrder.note ? `${existingOrder.note}, ${otherData.note}` : otherData.note;
      }
      await existingOrder.save();
      
      const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
      io.emit('orders_updated', updatedOrders);
      
      res.json(existingOrder);
    } else {
      const newOrder = new Order({ 
        tableId, 
        items: itemsWithStatus, 
        ...otherData 
      });
      
      await newOrder.save();
      
      const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
      io.emit('orders_updated', updatedOrders);
      
      res.status(201).json(newOrder);
    }
  } catch (e) {
    console.error('Create order error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tạo đơn hàng' });
  }
});

// Update order items
app.put('/api/orders/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;
    const { items, status } = req.body;

    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(400).json({ success: false, message: 'Order ID không hợp lệ' });
    }

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy đơn hàng' });
    }

    // If items is empty, delete the order
    if (Array.isArray(items) && items.length === 0) {
      await Order.findByIdAndDelete(orderId);
      const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
      io.emit('orders_updated', updatedOrders);
      return res.json({ success: true, message: 'Đơn hàng đã được xóa' });
    }

    // Update items - bảo đảm tất cả items có _id
    if (Array.isArray(items)) {
      order.items = items.map(item => ({
        ...item,
        _id: item._id || new mongoose.Types.ObjectId()
      }));
    }

    // Update status if provided
    if (status) {
      order.status = status;
    }

    await order.save();

    const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
    io.emit('orders_updated', updatedOrders);

    res.json({ success: true, data: order });
  } catch (e) {
    console.error('Update order error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi cập nhật đơn hàng' });
  }
});

// Delete order
app.delete('/api/orders/:orderId', async (req, res) => {
  try {
    const { orderId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(400).json({ success: false, message: 'Order ID không hợp lệ' });
    }

    const deleted = await Order.findByIdAndDelete(orderId);
    if (!deleted) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy đơn hàng' });
    }

    const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
    io.emit('orders_updated', updatedOrders);

    res.json({ success: true, message: 'Đơn hàng đã được xóa' });
  } catch (e) {
    console.error('Delete order error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi xóa đơn hàng' });
  }
});

app.put('/api/orders/:orderId/items/:itemIdx', async (req, res) => {
  try {
    const { orderId, itemIdx } = req.params;
    const { status } = req.body;

    if (!mongoose.Types.ObjectId.isValid(orderId)) {
      return res.status(400).json({ success: false, message: 'Order ID không hợp lệ' });
    }
    
    if (!['new', 'cooking', 'served'].includes(status)) {
      return res.status(400).json({ success: false, message: 'Trạng thái không hợp lệ' });
    }

    const order = await Order.findById(orderId);
    if (!order) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy đơn hàng' });
    }
    
    if (!order.items[itemIdx]) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy mặt hàng' });
    }

    order.items[itemIdx].status = status;
    
    // Check if all items are served
    const allItemsServed = order.items.every(item => item.status === 'served');
    if (allItemsServed) {
      order.status = 'served';
    }
    
    await order.save();
    
    const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
    io.emit('orders_updated', updatedOrders);
    
    res.json({ success: true });
  } catch (e) {
    console.error('Update order item error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi cập nhật mặt hàng' });
  }
});

// Payment
app.post('/api/pay', async (req, res) => {
  try {
    let { orderIds, paymentMethod } = req.body;

    if (!orderIds || !Array.isArray(orderIds) || orderIds.length === 0) {
      return res.status(400).json({ success: false, message: 'Dữ liệu thanh toán không hợp lệ' });
    }

    // Payment method mapping
    const methodMap = {
      'cash': 'Tiền mặt',
      'card': 'Chuyển khoản',
      'bank_transfer': 'Chuyển khoản',
      'Tiền mặt': 'Tiền mặt',
      'Chuyển khoản': 'Chuyển khoản'
    };

    if (!methodMap[paymentMethod]) {
      return res.status(400).json({ success: false, message: 'Phương thức thanh toán không hợp lệ' });
    }

    paymentMethod = methodMap[paymentMethod];

    // Process each order
    for (const orderId of orderIds) {
      if (!mongoose.Types.ObjectId.isValid(orderId)) {
        return res.status(400).json({ success: false, message: 'Order ID không hợp lệ' });
      }

      const order = await Order.findById(orderId);
      if (order) {
        const total = order.items.reduce((acc, item) => acc + (item.price * item.quantity), 0);
        order.status = 'paid';
        order.paymentMethod = paymentMethod;
        order.paidAt = new Date();
        order.finalTotal = total;
        await order.save();

        // Update revenue
        await updateRevenue(order);
      }
    }

    const updatedOrders = await Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 });
    io.emit('orders_updated', updatedOrders);
    
    res.json({ success: true, message: 'Thanh toán thành công' });
  } catch (e) {
    console.error('Payment error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi xử lý thanh toán' });
  }
});

// Cart Management
app.get('/api/cart/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    if (!sessionId) return res.status(400).json({ success: false, message: 'SessionId không hợp lệ' });

    let cart = await Cart.findOne({ sessionId });
    if (!cart) {
      cart = await Cart.create({ sessionId, items: [] });
    }
    res.json(cart);
  } catch (e) {
    console.error('Get cart error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tải giỏ hàng' });
  }
});

app.post('/api/cart/:sessionId/add', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { item } = req.body;

    if (!sessionId || !item) return res.status(400).json({ success: false, message: 'Dữ liệu không hợp lệ' });

    let cart = await Cart.findOne({ sessionId });
    if (!cart) {
      cart = new Cart({ sessionId, items: [] });
    }

    // Kiểm tra item đã có trong giỏ
    const existingItem = cart.items.find(i => i._id?.toString() === item._id?.toString());
    if (existingItem) {
      existingItem.quantity += (item.quantity || 1);
    } else {
      cart.items.push({
        _id: item._id,
        name: item.name,
        price: item.price,
        quantity: item.quantity || 1
      });
    }

    cart.updatedAt = new Date();
    await cart.save();
    res.json({ success: true, data: cart });
  } catch (e) {
    console.error('Add to cart error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi thêm vào giỏ hàng' });
  }
});

app.put('/api/cart/:sessionId/update/:itemId', async (req, res) => {
  try {
    const { sessionId, itemId } = req.params;
    const { quantity } = req.body;

    if (!sessionId || !itemId || !quantity) return res.status(400).json({ success: false, message: 'Dữ liệu không hợp lệ' });

    const cart = await Cart.findOne({ sessionId });
    if (!cart) return res.status(404).json({ success: false, message: 'Giỏ hàng không tồn tại' });

    const item = cart.items.find(i => i._id?.toString() === itemId);
    if (!item) return res.status(404).json({ success: false, message: 'Mục không tồn tại' });

    item.quantity = quantity;
    if (item.quantity <= 0) {
      cart.items = cart.items.filter(i => i._id?.toString() !== itemId);
    }

    cart.updatedAt = new Date();
    await cart.save();
    res.json({ success: true, data: cart });
  } catch (e) {
    console.error('Update cart error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi cập nhật giỏ hàng' });
  }
});

app.delete('/api/cart/:sessionId/remove/:itemId', async (req, res) => {
  try {
    const { sessionId, itemId } = req.params;

    if (!sessionId || !itemId) return res.status(400).json({ success: false, message: 'Dữ liệu không hợp lệ' });

    const cart = await Cart.findOne({ sessionId });
    if (!cart) return res.status(404).json({ success: false, message: 'Giỏ hàng không tồn tại' });

    cart.items = cart.items.filter(i => i._id?.toString() !== itemId);
    cart.updatedAt = new Date();
    await cart.save();
    res.json({ success: true, data: cart });
  } catch (e) {
    console.error('Remove from cart error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi xóa khỏi giỏ hàng' });
  }
});

app.delete('/api/cart/:sessionId/clear', async (req, res) => {
  try {
    const { sessionId } = req.params;

    if (!sessionId) return res.status(400).json({ success: false, message: 'SessionId không hợp lệ' });

    await Cart.deleteOne({ sessionId });
    res.json({ success: true, message: 'Giỏ hàng đã được xóa' });
  } catch (e) {
    console.error('Clear cart error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi xóa giỏ hàng' });
  }
});

// Reports
app.get('/api/reports', async (req, res) => {
  try {
    const { from, to } = req.query;
    const query = { status: 'paid' };

    if (from && to) {
      const fromDate = new Date(from);
      const toDate = new Date(to);
      
      if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
        return res.status(400).json({ success: false, message: 'Định dạng ngày không hợp lệ' });
      }
      
      toDate.setHours(23, 59, 59, 999);
      query.paidAt = { $gte: fromDate, $lte: toDate };
    }

    const reports = await Order.find(query)
      .sort({ paidAt: -1 })
      .limit(100);

    res.json(reports);
  } catch (e) {
    console.error('Reports error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tải báo cáo' });
  }
});

// Revenue Endpoints
app.get('/api/revenue/today', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const monthStr = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}`;

    const revenue = await Revenue.findOne({ date: today });
    
    if (revenue) {
      res.json(revenue);
    } else {
      // Calculate from orders if no revenue record exists
      const dailyOrders = await Order.find({
        status: 'paid',
        paidAt: { $gte: today, $lt: new Date(today.getTime() + 86400000) }
      });
      const dailyRevenue = dailyOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);

      const startOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
      const endOfMonth = new Date(today.getFullYear(), today.getMonth() + 1, 0);
      const monthlyOrders = await Order.find({
        status: 'paid',
        paidAt: { $gte: startOfMonth, $lte: endOfMonth }
      });
      const monthlyRevenue = monthlyOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);

      const totalOrders = await Order.find({ status: 'paid' });
      const totalRevenue = totalOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);

      res.json({
        date: today,
        month: monthStr,
        dailyRevenue,
        dailyOrders: dailyOrders.length,
        monthlyRevenue,
        monthlyOrders: monthlyOrders.length,
        totalRevenue,
        totalOrders: totalOrders.length
      });
    }
  } catch (e) {
    console.error('Revenue error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tải doanh thu' });
  }
});

app.get('/api/revenue/month', async (req, res) => {
  try {
    const { month } = req.query;
    
    if (!month || !/^\d{4}-\d{2}$/.test(month)) {
      return res.status(400).json({ success: false, message: 'Định dạng tháng không hợp lệ (YYYY-MM)' });
    }

    const [year, monthNum] = month.split('-');
    const startOfMonth = new Date(parseInt(year), parseInt(monthNum) - 1, 1);
    const endOfMonth = new Date(parseInt(year), parseInt(monthNum), 0);

    const monthlyOrders = await Order.find({
      status: 'paid',
      paidAt: { $gte: startOfMonth, $lte: endOfMonth }
    });
    const monthlyRevenue = monthlyOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);

    const totalOrders = await Order.find({ status: 'paid' });
    const totalRevenue = totalOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);

    res.json({
      month,
      monthlyRevenue,
      monthlyOrders: monthlyOrders.length,
      totalRevenue,
      totalOrders: totalOrders.length
    });
  } catch (e) {
    console.error('Monthly revenue error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tải doanh thu tháng' });
  }
});

app.get('/api/revenue/total', async (req, res) => {
  try {
    const totalOrders = await Order.find({ status: 'paid' });
    const totalRevenue = totalOrders.reduce((sum, o) => sum + (o.finalTotal || 0), 0);

    res.json({
      totalRevenue,
      totalOrders: totalOrders.length
    });
  } catch (e) {
    console.error('Total revenue error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi tải tổng doanh thu' });
  }
});

// Configure Upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/')
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname))
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Chỉ chấp nhận file ảnh'));
    }
  }
});

// Upload endpoint
app.post('/api/upload', upload.single('image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, error: 'Chưa chọn file ảnh' });
  }
  
  try {
    const protocol = req.protocol;
    const host = req.get('host');
    const imageUrl = `${protocol}://${host}/uploads/${req.file.filename}`;
    res.json({ success: true, url: imageUrl });
  } catch (e) {
    console.error('Upload error:', e);
    res.status(500).json({ success: false, error: 'Lỗi upload ảnh' });
  }
});

// Settings
app.post('/api/settings', async (req, res) => {
  try {
    // Validate phone number
    if (req.body.phone && !/^\d+$/.test(req.body.phone)) {
      return res.status(400).json({ success: false, message: 'Số điện thoại không hợp lệ' });
    }

    const settings = await Setting.findOneAndUpdate(
      {}, 
      req.body, 
      { 
        upsert: true, 
        new: true, 
        runValidators: true 
      }
    );

    io.emit('settings_updated', settings);
    res.json({ success: true, data: settings });
  } catch (e) {
    console.error('Settings error:', e);
    res.status(500).json({ success: false, message: 'Lỗi khi cập nhật cài đặt' });
  }
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Socket.IO
io.on('connection', (socket) => {
  console.log('🔌 Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });

  socket.on('error', (error) => {
    console.error('Socket error:', error);
  });

  // Optional: Send initial data on connection
  socket.on('request_data', async () => {
    try {
      const [orders, menu, tables] = await Promise.all([
        Order.find({ status: { $ne: 'paid' } }).sort({ createdAt: 1 }),
        Menu.find(),
        Table.find().sort({ name: 1 })
      ]);
      
      socket.emit('initial_data', { orders, menu, tables });
    } catch (error) {
      console.error('Error sending initial data:', error);
    }
  });
});

// Error Handlers
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File quá lớn (tối đa 5MB)' });
    }
    return res.status(400).json({ error: 'Lỗi upload file' });
  }
  
  if (err) {
    console.error('Unhandled error:', err);
    return res.status(500).json({ error: 'Lỗi server nội bộ' });
  }
  
  next();
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint không tồn tại' });
});

// Process Handlers
process.on('uncaughtException', (e) => {
  console.error('CRITICAL ERROR:', e);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
const NODE_ENV = process.env.NODE_ENV || 'development';

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server đang chạy tại cổng ${PORT}`);
  console.log(`📋 Môi trường: ${NODE_ENV}`);
  console.log(`🔐 CORS origins: ${allowedOrigins.join(', ')}`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`📁 Upload folder: ${path.join(process.cwd(), 'uploads')}`);
});

// Graceful Shutdown
const gracefulShutdown = () => {
  console.log('🔄 Nhận tín hiệu shutdown, đang đóng kết nối...');
  
  server.close(async () => {
    console.log('✅ Server đã đóng');
    
    try {
      await mongoose.connection.close();
      console.log('✅ MongoDB connection đã đóng');
      process.exit(0);
    } catch (err) {
      console.error('Lỗi đóng MongoDB:', err);
      process.exit(1);
    }
  });

  // Force close after 10 seconds
  setTimeout(() => {
    console.error('❌ Buộc đóng do timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);