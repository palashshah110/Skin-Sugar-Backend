// api/routes/orders.js
const express = require('express');
const { authenticateToken } = require('../middleware/auth');
const { Order, Product } = require('../models');

const router = express.Router();

// Create Order
router.post('/', async (req, res) => {
  try {
    const { user, items, totalAmount, shippingInfo } = req.body;

    if (!user || !items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: 'User and items are required' });
    }

    let calculatedTotal = totalAmount;
    if (typeof totalAmount !== 'number') {
      const productIds = items.map(i => i.product);
      const products = await Product.find({ _id: { $in: productIds } });
      const productMap = products.reduce((acc, p) => ({ ...acc, [p._id]: p.price }), {});
      calculatedTotal = items.reduce((sum, item) => sum + (item.quantity * productMap[item.product]), 0);
    }

    const order = new Order({
      user,
      items,
      totalAmount: calculatedTotal,
      shippingInfo: shippingInfo || {},
      status: 'pending',
      paymentStatus: 'pending'
    });

    await order.save();
    await order.populate('user', 'name email');
    await order.populate('items.product', 'name image');

    res.status(201).json({ message: 'Order created successfully', order });
  } catch (error) {
    res.status(500).json({ message: 'Error creating order', error: error.message });
  }
});

// Get All Orders for authenticated user
router.get('/', authenticateToken, async (req, res) => {
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

// Get Single Order by ID
router.get('/:id', authenticateToken, async (req, res) => {
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

// Update Order
router.put('/:id', async (req, res) => {
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

// Delete Order
router.delete('/:id', async (req, res) => {
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

module.exports = router;