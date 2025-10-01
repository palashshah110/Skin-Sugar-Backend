// api/index.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
require('dotenv').config();
const serverless = require("serverless-http");

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
  params: {
    folder: 'skin-sugars',
    format: async (req, file) => 'png',
    public_id: (req, file) => {
      const timestamp = Date.now();
      return `product-${timestamp}`;
    },
  },
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

const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const publicRoutes = require('./routes/public');
const orderRoutes = require('./routes/orders');

// Use routes
app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api', publicRoutes);
app.use('/api/orders', orderRoutes);
app.get("/api/pincode-check/:pincode", async (req, res) => {
  const { pincode } = req.params;
  try {
    const response = await fetch(
      `https://track.delhivery.com/api/kinko/v1/invoice/charges/.json?md=E&ss=Delivered&d_pin=${pincode}&o_pin=450331&cgm=10&pt=COD`,
      {
        headers: {
          Authorization: "Token 34893d8057bd273c9820309963ce7cf4e284804b",
          "Content-Type": "application/json",
        },
      }
    );
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error("Delhivery API error:", error);
    res.status(500).json({ error: "Something went wrong" });
  }
});
// Root route
app.get('/', (req, res) => {
  res.json({ message: 'API is running' });
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

module.exports = app;
module.exports.handler = serverless(app);