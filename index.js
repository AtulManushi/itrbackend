const express = require("express");
const Razorpay = require("razorpay");
const cors = require("cors");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const crypto = require("crypto");
const Contact = require("./models/contactModel");
const { type } = require("os");
require("dotenv").config();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Admin = require("./models/adminModel");


const app = express();
app.use(cors());
app.use(bodyParser.json());

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.log("MongoDB error:", err));

// Schema
const OrderSchema = new mongoose.Schema({
  orderId: String,
  plan: String,
  tenure: String,
  amount: Number,
  name: String,
  isPaymentComplete:{type:Boolean, default:false},
  email: String,
  contact: String,
  location: String,
  status: { type: String, default: "pending" },
  createdAt: { type: Date, default: Date.now }
});

const Order = mongoose.model("Order", OrderSchema);

// Razorpay instance
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// 1️⃣ Create order and store user data
app.post("/create-order", async (req, res) => {
  try {
    const { amount, plan, tenure, name, email, contact, location } = req.body;

    const options = {
      amount: amount * 100, // in paise
      currency: "INR",
      receipt: `receipt_${Date.now()}`,
      notes: { plan, tenure, name, email, contact, location },
    };

    const order = await razorpay.orders.create(options);

    // Save order + user details to DB
    const newOrder = new Order({
      orderId: order.id,
      plan,
      tenure,
      amount,
      name,
      email,
      contact,
      location,
      status: "pending",
    });
    await newOrder.save();

    res.json({ id: order.id, currency: order.currency, amount: order.amount });
  } catch (err) {
    console.error("Error creating order:", err);
    res.status(500).send("Server Error");
  }
});

// 2️⃣ Verify Payment
app.post("/verify-payment", async (req, res) => {
  const { order_id, payment_id, signature } = req.body;

  const generated_signature = crypto
    .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
    .update(order_id + "|" + payment_id)
    .digest("hex");

  if (generated_signature === signature) {
    await Order.findOneAndUpdate(
    { orderId: order_id },
    { status: "paid", isPaymentComplete: true },
    { new: true }
  );
    res.json({ success: true });
  } else {
    await Order.findOneAndUpdate({ orderId: order_id }, { status: "failed" });
    res.status(400).json({ success: false });
  }
});

app.post("/contact", async (req, res) => {
  try {
    const { name, contact, email, city } = req.body;

    if (!name || !contact || !email || !city) {
      return res.status(400).json({ success: false, message: "All fields required" });
    }

    const newEntry = new Contact({ name, contact, email, city });
    await newEntry.save();

    res.json({ success: true, message: "Contact saved successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server Error" });
  }
});

// -------------- ADMIN AUTH ----------------

// Auto-create admin if not exists
(async () => {
  const adminEmail = "admin@gmail.com";
  const adminPassword = "123456";

  const existing = await Admin.findOne({ email: adminEmail });
  if (!existing) {
    const hashed = await bcrypt.hash(adminPassword, 10);
    await Admin.create({ email: adminEmail, password: hashed });
    console.log("✅ Default admin created: admin@gmail.com / 123456");
  } else {
    console.log("ℹ️ Admin already exists");
  }
})();

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret123");
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Admin login
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  const admin = await Admin.findOne({ email });
  if (!admin) return res.status(400).json({ message: "Admin not found" });

  const isMatch = await bcrypt.compare(password, admin.password);
  if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

  const token = jwt.sign(
    { id: admin._id, email: admin.email },
    process.env.JWT_SECRET || "secret123",
    { expiresIn: "1d" }
  );

  res.json({ message: "Login successful", token });
});


// Change password
app.post("/admin/change-password", verifyToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
console.log("ddd", oldPassword, "new", newPassword)
  const admin = await Admin.findById(req.admin.id);
  if (!admin) return res.status(404).json({ message: "Admin not found" });

  const isMatch = await bcrypt.compare(oldPassword, admin.password);
  if (!isMatch) return res.status(400).json({ message: "Incorrect old password" });

  const hashed = await bcrypt.hash(newPassword, 10);
  admin.password = hashed;
  await admin.save();

  res.json({ message: "Password updated successfully" });
});


// ============================
// 🔹 ADMIN DASHBOARD ROUTES 🔹
// ============================

app.get("/admin/contacts/count", verifyToken, async (req, res) => {
  try {
    const count = await Contact.countDocuments();
    res.json(count);
  } catch (err) {
    console.error("Error fetching contacts count:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

app.get("/admin/orders/count",verifyToken, async (req, res) => {
  try {
    const count = await Order.countDocuments();
    res.json(count);
  } catch (err) {
    console.error("Error fetching orders count:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

app.get("/admin/orders/paid/count",verifyToken, async (req, res) => {
  try {
    const count = await Order.countDocuments({
      isPaymentComplete: true,
      status: "paid",
    });
    res.json(count);
  } catch (err) {
    console.error("Error fetching paid orders count:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

app.get("/admin/orders/unpaid",verifyToken, async (req, res) => {
  try {
    const count = await Order.countDocuments({
      $or: [{ isPaymentComplete: false }, { status: { $ne: "paid" } }],
    });
    res.json(count);
  } catch (err) {
    console.error("Error fetching unpaid orders count:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

app.get("/admin/contacts",verifyToken, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: "Failed to fetch contacts" });
  }
});

app.get("/admin/orders",verifyToken, async (req, res) => {
  try {
    const orders = await Order.find().sort({ createdAt: -1 });
    res.json(orders);
  } catch (err) {
    console.error("Error fetching orders:", err);
    res.status(500).json({ error: "Server Error" });
  }
});

app.get("/admin/orders/paid", verifyToken, async (req, res) => {
  try {
    const orders = await Order.find({
      isPaymentComplete: true,
      status: "paid",
    }).sort({ createdAt: -1 }); // latest first

    res.json(orders);
  } catch (err) {
    console.error("Error fetching paid orders:", err);
    res.status(500).json({ error: "Server Error" });
  }
});


app.get("/admin/orders/pending", verifyToken, async (req, res) => {
  try {
    const pendingOrders = await Order.find({
      isPaymentComplete: false,
    }).sort({ createdAt: -1 }); // latest first

    res.json(pendingOrders);
  } catch (err) {
    console.error("Error fetching pending orders:", err);
    res.status(500).json({ error: "Server Error" });
  }
});


app.listen(process.env.PORT, () =>
  console.log(`🚀 Server running on http://localhost:${process.env.PORT}`)
);
