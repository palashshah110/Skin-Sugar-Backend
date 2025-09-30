// api/routes/public.js
const express = require('express');
const { Category, Subcategory, Product } = require('../models');

const router = express.Router();

router.get('/categories', async (req, res) => {
  try {
    const categories = await Category.find({ isActive: true });
    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching categories', error: error.message });
  }
});

router.get("/subcategories", async (req, res) => {
  try {
    const subcategories = await Subcategory.find({ isActive: true });
    res.json(subcategories);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching subcategories', error: error.message });
  }
});

router.get('/products', async (req, res) => {
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

router.get('/products/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const product = await Product.findById(id)
      .populate('category', 'name')
      .populate('subcategory', 'name');

    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching product', error: error.message });
  }
});

module.exports = router;