import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import dotenv from 'dotenv';
import axios from 'axios';
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Cloudinary Configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Multer configuration for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: (req, file) => ({
    folder: "skin-sugar",
    format: "png",
    allowed_formats: ["jpg", "jpeg", "png"],
    transformation: [{ width: 500, height: 500, crop: "limit" }],
    public_id: file.originalname.split(".")[0], // optional: use original name
  }),
});
const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

// MongoDB Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection failed:', error.message);
    process.exit(1);
  }
};

connectDB();

// Models
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  createdAt: { type: Date, default: Date.now }
}));

const Category = mongoose.model('Category', new mongoose.Schema({
  name: { type: String, required: true, unique: true },
  description: String,
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const Subcategory = mongoose.model('Subcategory', new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
}));

const Product = mongoose.model('Product', new mongoose.Schema({
  name: { type: String, required: true },
  price: { type: Number, required: true },
  originalPrice: Number,
  category: { type: mongoose.Schema.Types.ObjectId, ref: 'Category', required: true },
  subcategory: { type: mongoose.Schema.Types.ObjectId, ref: 'Subcategory', required: true },
  rating: { type: Number, default: 0 },
  reviews: { type: Number, default: 0 },
  image: { type: String, required: true },
  images: [String],
  description: String,
  ingredients: [String],
  inStock: { type: Boolean, default: true },
  featured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
}));

const Order = mongoose.model('Order', new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
    quantity: { type: Number, required: true },
    price: { type: Number, required: true },
    basket: { type: Number, default: 1 } // Add basket field for gift basket items
  }],
  totalAmount: { type: Number, required: true },
  shippingInfo: {
    address: { type: String, required: true },
    city: { type: String, required: true },
    state: { type: String, required: true },
    pincode: { type: String, required: true },
    phone: { type: String, required: true },
    recipientName: String, // Add for gift baskets
    giftMessage: String    // Add for gift baskets
  },
  status: {
    type: String,
    enum: ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'],
    default: 'pending'
  },
  paymentStatus: {
    type: String,
    enum: ['pending', 'paid', 'failed', 'refunded'],
    default: 'pending'
  },
  orderType: {
    type: String,
    enum: ['regular', 'gift_basket'],
    default: 'regular'
  },
  selectedBasket: {
    type: String,
    default: ''
  },
  baskets: [{ // Add baskets array for gift basket orders
    basketNumber: { type: Number, required: true },
    items: [{
      product: { type: mongoose.Schema.Types.ObjectId, ref: 'Product' },
      quantity: { type: Number, required: true },
      price: { type: Number, required: true }
    }],
    total: { type: Number, required: true }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}));;

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Admin access required' });
  }
  next();
};

// Utility Functions
const calculateDashboardStats = async () => {
  const totalUsers = await User.countDocuments();
  const totalProducts = await Product.countDocuments();
  const totalOrders = await Order.countDocuments();
  const totalRevenue = await Order.aggregate([
    { $match: { paymentStatus: 'paid' } },
    { $group: { _id: null, total: { $sum: '$totalAmount' } } }
  ]);

  const categoryStats = await Product.aggregate([
    {
      $lookup: {
        from: 'categories',
        localField: 'category',
        foreignField: '_id',
        as: 'categoryInfo'
      }
    },
    { $unwind: '$categoryInfo' },
    {
      $group: {
        _id: '$categoryInfo.name',
        count: { $sum: 1 },
        revenue: {
          $sum: {
            $cond: [{ $eq: ['$paymentStatus', 'paid'] }, '$totalAmount', 0]
          }
        }
      }
    }
  ]);
  const monthlyRevenue = await Order.aggregate([
    {
      $match: {
        status: "delivered", // only delivered orders should count
        paymentStatus: { $ne: "pending" } // optional: count only paid ones
      }
    },
    {
      $group: {
        _id: { $month: "$createdAt" },
        revenue: { $sum: "$totalAmount" }
      }
    },
    { $sort: { "_id": 1 } }
  ]);

  const monthNames = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  ];

  const monthlyRevenueFormatted = monthlyRevenue.map((item) => ({
    month: monthNames[item._id - 1],
    revenue: item.revenue
  }));


  const recentOrders = await Order.find()
    .populate('user', 'name email')
    .sort({ createdAt: -1 })
    .limit(5);

  return {
    totalUsers,
    totalProducts,
    totalOrders,
    totalRevenue: totalRevenue[0]?.total || 0,
    categoryStats,
    monthlyRevenue: monthlyRevenueFormatted,
    recentOrders
  };
};

// Routes
app.get('/', (req, res) => {
  res.json({ message: 'API is running' });
});


// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user
    });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Admin Dashboard Routes
app.get('/api/admin/dashboard', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const stats = await calculateDashboardStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching dashboard data', error: error.message });
  }
});

// Category Management Routes
app.get('/api/admin/categories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const categories = await Category.find().sort({ createdAt: -1 });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching categories', error: error.message });
  }
});

app.post('/api/admin/categories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const category = new Category({ name, description });
    await category.save();
    res.status(201).json({ message: 'Category created successfully', category });
  } catch (error) {
    res.status(500).json({ message: 'Error creating category', error: error.message });
  }
});

app.put('/api/admin/categories/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, description, isActive } = req.body;
    const category = await Category.findByIdAndUpdate(
      req.params.id,
      { name, description, isActive },
      { new: true }
    );
    res.json({ message: 'Category updated successfully', category });
  } catch (error) {
    res.status(500).json({ message: 'Error updating category', error: error.message });
  }
});

app.delete('/api/admin/categories/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting category', error: error.message });
  }
});

// Subcategory Management Routes
app.get('/api/admin/subcategories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const subcategories = await Subcategory.find()
      .populate('category', 'name')
      .sort({ createdAt: -1 });
    res.json(subcategories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subcategories', error: error.message });
  }
});

app.post('/api/admin/subcategories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, description, category } = req.body;
    const subcategory = new Subcategory({ name, description, category });
    await subcategory.save();
    await subcategory.populate('category', 'name');
    res.status(201).json({ message: 'Subcategory created successfully', subcategory });
  } catch (error) {
    res.status(500).json({ message: 'Error creating subcategory', error: error.message });
  }
});

app.put('/api/admin/subcategories/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, description, category, isActive } = req.body;
    const subcategory = await Subcategory.findByIdAndUpdate(
      req.params.id,
      { name, description, category, isActive },
      { new: true }
    ).populate('category', 'name');
    res.json({ message: 'Subcategory updated successfully', subcategory });
  } catch (error) {
    res.status(500).json({ message: 'Error updating subcategory', error: error.message });
  }
});

app.delete('/api/admin/subcategories/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Subcategory.findByIdAndDelete(req.params.id);
    res.json({ message: 'Subcategory deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting subcategory', error: error.message });
  }
});
app.get("/api/admin/categories/:categoryId/subcategories", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const subcategories = await Subcategory.find({ category: req.params.categoryId })
      .populate('category', 'name')
      .sort({ createdAt: -1 });
    res.json(subcategories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subcategories', error: error.message });
  }
});
// Product Management Routes
// GET /admin/products with pagination and filtering
app.get('/api/admin/products', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5; // Make sure this matches your frontend
    const skip = (page - 1) * limit;
    const query = {};
    if (req.query.category) {
      query.category = req.query.category;
    }
    if (req.query.subcategory) {
      query.subcategory = req.query.subcategory;
    }

    // Get total count for pagination
    const totalCount = await Product.countDocuments(query);

    // Get products with pagination, populate, and CONSISTENT sorting
    const products = await Product.find(query)
      .populate('category', 'name')
      .populate('subcategory', 'name')
      .sort({ createdAt: -1, _id: 1 }) // Primary sort by createdAt, secondary by _id
      .skip(skip)
      .limit(limit);

    const totalPages = Math.ceil(totalCount / limit);

    res.json({
      products,
      currentPage: page,
      totalPages,
      totalCount,
      hasNext: page < totalPages,
      hasPrev: page > 1
    });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/products', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const productData = {
      ...req.body,
      price: parseFloat(req.body.price),
      originalPrice: parseFloat(req.body.originalPrice) || null,
      rating: parseFloat(req.body.rating) || 0,
      reviews: parseInt(req.body.reviews) || 0,
      inStock: req.body.inStock === 'true',
      featured: req.body.featured === 'true',
      ingredients: req.body.ingredients ? JSON.parse(req.body.ingredients) : []
    };

    if (req.file) {
      productData.image = req.file.path;
    }

    const product = new Product(productData);
    await product.save();
    await product.populate('category', 'name');
    await product.populate('subcategory', 'name');

    res.status(201).json({ message: 'Product created successfully', product });
  } catch (error) {
    res.status(500).json({ message: 'Error creating product', error: error.message });
  }
});

app.put('/api/admin/products/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const updateData = { ...req.body };

    if (req.file) {
      updateData.image = req.file.path;
    }

    if (updateData.ingredients) {
      updateData.ingredients = JSON.parse(updateData.ingredients);
    }

    const product = await Product.findByIdAndUpdate(
      req.params.id,
      updateData,
      { new: true }
    )
      .populate('category', 'name')
      .populate('subcategory', 'name');

    res.json({ message: 'Product updated successfully', product });
  } catch (error) {
    res.status(500).json({ message: 'Error updating product', error: error.message });
  }
});

app.delete('/api/admin/products/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting product', error: error.message });
  }
});

// Order Management Routes
app.get('/api/admin/orders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('user', 'name email')
      .populate('items.product', 'name image')
      .populate('baskets.items.product', 'name image')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

app.put('/api/admin/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    )
      .populate('user', 'name email')
      .populate('items.product', 'name image');

    res.json({ message: 'Order updated successfully', order });
  } catch (error) {
    res.status(500).json({ message: 'Error updating order', error: error.message });
  }
});


app.put('/api/admin/orders/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    )
      .populate('user', 'name email')
      .populate('items.product', 'name image');

    res.json({ message: 'Order status updated successfully', order });
  } catch (error) {
    res.status(500).json({ message: 'Error updating order status', error: error.message });
  }
});

app.put('/api/admin/orders/:id/payment-status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { paymentStatus } = req.body;
    const order = await Order.findByIdAndUpdate(
      req.params.id,
      { paymentStatus },
      { new: true }
    )
      .populate('user', 'name email')
      .populate('items.product', 'name image');

    res.json({ message: 'Order payment status updated successfully', order });
  } catch (error) {
    res.status(500).json({ message: 'Error updating order payment status', error: error.message });
  }
});

app.delete('/api/admin/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(
      req.params.id,
      { new: true }
    )
      .populate('user', 'name email')
      .populate('items.product', 'name image');

    res.json({ message: 'Order deleted successfully', order });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting order', error: error.message });
  }
});


// User Management Routes
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});

app.post('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();
    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

app.put('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, email, role, password } = req.body;
    const updateData = { name, email, role };
    if (password) {
      updateData.password = await bcrypt.hash(password, 12);
    }
    const user = await User.findByIdAndUpdate(req.params.id, updateData, { new: true }).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User updated successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const user = await User.findByIdAndDelete(req.params.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting user', error: error.message });
  }
});

// Public Routes (for frontend)
app.get('/api/categories', async (req, res) => {
  try {
    const categories = await Category.find({ isActive: true });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching categories', error: error.message });
  }
});

app.get("/api/subcategories", async (req, res) => {
  try {
    const subcategories = await Subcategory.find({ isActive: true });
    res.json(subcategories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subcategories', error: error.message });
  }
})

app.get('/api/products', async (req, res) => {
  try {
    const { category, subcategory, featured } = req.query;
    let filter = { inStock: true };

    if (category) filter.category = category;
    if (subcategory) filter.subcategory = subcategory;
    if (featured === 'true') filter.featured = true;

    const products = await Product.find(filter)
      .populate('category', 'name')
      .populate('subcategory', 'name');

    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});
app.get('/api/products/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const product = await Product.findById(id)
      .populate('category', 'name')
      .populate('subcategory', 'name');

    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching products', error: error.message });
  }
});

// Create Order (C)
app.post('/api/orders', async (req, res) => {
  try {
    const {
      user,
      items,
      totalAmount,
      shippingInfo,
      orderType = 'regular',
      selectedBasket,
      baskets = []
    } = req.body;

    // Validate required fields
    if (!user || !items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: 'User and items are required' });
    }

    // Validate shipping info
    if (!shippingInfo || !shippingInfo.address || !shippingInfo.city ||
      !shippingInfo.state || !shippingInfo.pincode || !shippingInfo.phone) {
      return res.status(400).json({ message: 'Complete shipping information is required' });
    }

    // Validate phone number
    const phoneRegex = /^[6-9]\d{9}$/;
    if (!phoneRegex.test(shippingInfo.phone)) {
      return res.status(400).json({ message: 'Please enter a valid 10-digit phone number' });
    }

    // Validate pincode
    const pincodeRegex = /^\d{6}$/;
    if (!pincodeRegex.test(shippingInfo.pincode)) {
      return res.status(400).json({ message: 'Please enter a valid 6-digit pincode' });
    }

    // For gift basket orders, validate recipient name
    if (orderType === 'gift_basket' && (!shippingInfo.recipientName || shippingInfo.recipientName.trim() === '')) {
      return res.status(400).json({ message: 'Recipient name is required for gift baskets' });
    }

    // Calculate totalAmount if not provided or invalid
    let calculatedTotal = totalAmount;
    if (typeof totalAmount !== 'number' || isNaN(totalAmount)) {
      const productIds = items.map(i => i.product);
      const products = await Product.find({ _id: { $in: productIds } });
      const productMap = products.reduce((acc, p) => ({ ...acc, [p._id.toString()]: p.price }), {});

      calculatedTotal = items.reduce((sum, item) => {
        const productPrice = productMap[item.product.toString()] || item.price || 0;
        return sum + (item.quantity * productPrice);
      }, 0);
    }

    // For gift basket orders, calculate basket totals
    let basketData = [];
    if (orderType === 'gift_basket' && baskets.length > 0) {
      basketData = baskets.map(basket => ({
        basketNumber: basket.basketNumber,
        items: basket.items,
        total: basket.total || basket.items.reduce((sum, item) => sum + (item.quantity * item.price), 0),
      }));
    } else if (orderType === 'gift_basket') {
      // Auto-generate baskets from items if not provided
      const basketNumbers = [...new Set(items.map(item => item.basket || 1))];
      basketData = basketNumbers.map(basketNum => {
        const basketItems = items.filter(item => (item.basket || 1) === basketNum);
        return {
          basketNumber: basketNum,
          items: basketItems,
          total: basketItems.reduce((sum, item) => sum + (item.quantity * item.price), 0)
        };
      });
    }

    // Create order object
    const orderData = {
      user,
      items: items.map(item => ({
        product: item.product,
        quantity: item.quantity,
        price: item.price,
        ...(orderType === 'gift_basket' && { basket: item.basket || 1 })
      })),
      totalAmount: calculatedTotal,
      shippingInfo: {
        address: shippingInfo.address,
        city: shippingInfo.city,
        state: shippingInfo.state,
        pincode: shippingInfo.pincode,
        phone: shippingInfo.phone,
        ...(orderType === 'gift_basket' && {
          recipientName: shippingInfo.recipientName,
          giftMessage: shippingInfo.giftMessage || ''
        })
      },
      orderType,
      selectedBasket,
      ...(orderType === 'gift_basket' && { baskets: basketData }),
      status: 'pending',
      paymentStatus: 'pending'
    };
    
    const order = new Order(orderData);
    await order.save();

    // Populate the order with product and user details
    await order.populate('user', 'name email');
    await order.populate('items.product', 'name image price');
    if (orderType === 'gift_basket') {
      await order.populate('baskets.items.product', 'name image price');
    }

    res.status(201).json({
      message: 'Order created successfully',
      order
    });

  } catch (error) {
    console.error('Order creation error:', error);
    res.status(500).json({
      message: 'Error creating order',
      error: error.message
    });
  }
});

// Get All Orders (R)
app.get('/api/orders', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const orders = await Order.find({ user: userId })
      .populate('user', 'name email')
      .populate('items.product', 'name image price')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

// Get Single Order by ID (R)
app.get('/api/orders/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const order = await Order.findById(req.params.id)
      .populate('user', 'name email')
      .populate('items.product', 'name image price');
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    if (order.user._id.toString() !== userId) {
      return res.status(403).json({ message: 'Not authorized to view this order' });
    }
    res.json(order);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching order', error: error.message });
  }
});

// Update Order (U)
app.put('/api/orders/:id', async (req, res) => {
  try {
    const { items, totalAmount, shippingInfo, status, paymentStatus } = req.body;

    const updateData = {};
    if (items) updateData.items = items;
    if (typeof totalAmount === 'number') updateData.totalAmount = totalAmount;
    if (shippingInfo) updateData.shippingInfo = shippingInfo;
    if (status) updateData.status = status;
    if (paymentStatus) updateData.paymentStatus = paymentStatus;

    const order = await Order.findByIdAndUpdate(req.params.id, updateData, { new: true })
      .populate('user', 'name email')
      .populate('items.product', 'name image price');

    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }

    res.json({ message: 'Order updated successfully', order });
  } catch (error) {
    res.status(500).json({ message: 'Error updating order', error: error.message });
  }
});

// Delete Order (D)
app.delete('/api/orders/:id', async (req, res) => {
  try {
    const order = await Order.findByIdAndDelete(req.params.id);
    if (!order) {
      return res.status(404).json({ message: 'Order not found' });
    }
    res.json({ message: 'Order deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting order', error: error.message });
  }
});
app.get('/api/orders/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    const orders = await Order.find({ user: userId })
      .populate('items.product', 'name image')
      .populate('baskets.items.product', 'name image')
      .sort({ createdAt: -1 });

    res.json({ orders });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

//calacuate the shipping charges
const DELHIVERY_API_URL = process.env.DELHIVERY_API_URL;
const DELHIVERY_API_KEY = process.env.DELHIVERY_API_KEY;
const headers = {
  Authorization: `Token ${DELHIVERY_API_KEY}`,
  "Content-Type": "application/json",
};

app.get("/api/pincode-check/:pincode", async (req, res) => {
  try {
    const { pincode } = req.params;
    const { data } = await axios.get(`${DELHIVERY_API_URL}/kinko/v1/invoice/charges/.json?md=E&ss=Delivered&d_pin=452016&o_pin=${pincode}&cgm=10&pt=Pre-paid`, {
      headers
    });
    res.json(data);
  } catch (error) {
    res.status(500).json({ message: 'Error checking pincode', error: error.message });
  }
});
app.post("/api/delhivery/create", async (req, res) => {
  try {
    const order = req.body; // Pass full order object
    const payload = {
      shipments: [
        {
          add: order.shippingInfo.address,
          phone: order.shippingInfo.phone,
          name: order.shippingInfo.recipientName || order.user.name,
          order: order._id,
          payment_mode: order.paymentStatus === "pending" ? "COD" : "Prepaid",
          cod_amount: order.paymentStatus === "pending" ? order.totalAmount : 0,
          products_desc: order.orderType === 'gift_basket' ? "Gift Basket" : "regular",
          // you can pass pickup location if you have multiple
        }
      ],
      pickup_location: {
        name: "Skin Sugar",
        add: "Your Warehouse Address",
        city: "Indore",
        state: "Madhya Pradesh",
        country: "India",
        pin: "452001",
        phone: "9999999999"
      }
    };

    const { data } = await axios.post(
      `${DELHIVERY_API_URL}/cmu/create.json`,
      payload,
      {
        headers
      }
    );

    res.json({
      success: true,
      data: data,
    });
  } catch (err) {
    console.error("Delhivery Create Error:", err.response?.data || err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get label
app.get("/api/delhivery/label/:waybill", async (req, res) => {
  try {
    const { waybill } = req.params;
    const { data } = await axios.get(
      `${DELHIVERY_API_URL}/p/packing_slip?wbns=${waybill}`,
      { headers }
    );
    res.json({
      success: true,
      label: data,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Track shipment
app.get("/api/delhivery/track/:waybill", async (req, res) => {
  try {
    const { waybill } = req.params;
    const { data } = await axios.get(
      `${DELHIVERY_API_URL}/v1/packages/json/?waybill=${waybill}`,
      { headers }
    );
    res.json({
      success: true,
      data: data,
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});
// Error handling middleware
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ message: 'File too large' });
    }
  }
  res.status(500).json({ message: error.message });
});

export default app;