const mongoose = require("mongoose");

const contactSchema = new mongoose.Schema({
  name: String,
  contact: String,
  email: String,
  city: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Contact", contactSchema);
