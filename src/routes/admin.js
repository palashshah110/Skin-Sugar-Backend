// api/routes/admin.js
const express = require('express');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const { authenticateToken, requireAdmin } = require('../middleware/auth');
const { User, Category, Subcategory, Product, Order } = require('../models');

const router = express.Router();

// Multer configuration for Cloudinary
const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'skin-sugars',
    format: async (req, file) => 'png',
    public_id: (req, file) => {
      const timestamp = Date.now();
      return `product-${timestamp}`;
    },
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed!'), false);
    }
  }
});

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
      $match: { status: { $in: ["delivered", "paid"] } }
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

// Admin Dashboard Routes
router.get('/dashboard', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const stats = await calculateDashboardStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching dashboard data', error: error.message });
  }
});

// Category Management Routes
router.get('/categories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const categories = await Category.find().sort({ createdAt: -1 });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching categories', error: error.message });
  }
});

router.post('/categories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, description } = req.body;
    const category = new Category({ name, description });
    await category.save();
    res.status(201).json({ message: 'Category created successfully', category });
  } catch (error) {
    res.status(500).json({ message: 'Error creating category', error: error.message });
  }
});

router.put('/categories/:id', authenticateToken, requireAdmin, async (req, res) => {
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

router.delete('/categories/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Category.findByIdAndDelete(req.params.id);
    res.json({ message: 'Category deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting category', error: error.message });
  }
});

// Subcategory Management Routes
router.get('/subcategories', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const subcategories = await Subcategory.find()
      .populate('category', 'name')
      .sort({ createdAt: -1 });
    res.json(subcategories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subcategories', error: error.message });
  }
});

router.post('/subcategories', authenticateToken, requireAdmin, async (req, res) => {
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

router.put('/subcategories/:id', authenticateToken, requireAdmin, async (req, res) => {
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

router.delete('/subcategories/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Subcategory.findByIdAndDelete(req.params.id);
    res.json({ message: 'Subcategory deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting subcategory', error: error.message });
  }
});

router.get("/categories/:categoryId/subcategories", authenticateToken, requireAdmin, async (req, res) => {
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
router.get('/products', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const skip = (page - 1) * limit;
    const query = {};
    
    if (req.query.category) {
      query.category = req.query.category;
    }
    if (req.query.subcategory) {
      query.subcategory = req.query.subcategory;
    }

    const totalCount = await Product.countDocuments(query);
    const products = await Product.find(query)
      .populate('category', 'name')
      .populate('subcategory', 'name')
      .sort({ createdAt: -1, _id: 1 })
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

router.post('/products', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
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

router.put('/products/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
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

router.delete('/products/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    await Product.findByIdAndDelete(req.params.id);
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting product', error: error.message });
  }
});

// Order Management Routes
router.get('/orders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const orders = await Order.find()
      .populate('user', 'name email')
      .populate('items.product', 'name image')
      .sort({ createdAt: -1 });
    res.json(orders);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching orders', error: error.message });
  }
});

router.put('/orders/:id', authenticateToken, requireAdmin, async (req, res) => {
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

router.put('/orders/:id/status', authenticateToken, requireAdmin, async (req, res) => {
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

// User Management Routes
router.get('/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await User.find().select('-password').sort({ createdAt: -1 });
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});

router.post('/users', authenticateToken, requireAdmin, async (req, res) => {
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

router.put('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
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

router.delete('/users/:id', authenticateToken, requireAdmin, async (req, res) => {
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

module.exports = router;