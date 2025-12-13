const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const nodemailer = require("nodemailer");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Razorpay = require("razorpay");
const crypto = require("crypto");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

mongoose
  .connect("mongodb://localhost:27017/mern-app")
  .then(() => console.log("MongoDB connected successfully...."))
  .catch((err) => console.log("MongoDB connection failed..", err));

const regsSchema = new mongoose.Schema({
  name: String,
  phonenumber: String,
  email: String,
  webType: String,
  description: String,
});
const regsModel = mongoose.model("WebRegDatas", regsSchema);

const usersSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
});
const usersModel = mongoose.model("User", usersSchema);

// Payment Schema
const paymentSchema = new mongoose.Schema({
  orderId: String,
  paymentId: String,
  razorpaySignature: String,
  amount: Number,
  currency: String,
  status: {
    type: String,
    enum: ['pending', 'paid', 'failed'],
    default: 'pending'
  },
  userEmail: String,
  userName: String,
  createdAt: { type: Date, default: Date.now },
  paidAt: Date
});
const paymentModel = mongoose.model("Payment", paymentSchema);

const JWT_SECRET = process.env.JWT_SECRET || "supersecret123";

// Initialize Razorpay
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

const authenticateToken = (req, res, next) => {
  const header = req.headers["authorization"];
  const token = header && header.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Please login to access web registration",
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: "Invalid or expired token. Please login again",
      });
    }
    req.user = user;
    next();
  });
};

app.post("/Signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await usersModel.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User with this email already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await usersModel.create({
      name,
      email,
      password: hashedPassword,
    });

    res.status(201).json({
      success: true,
      message: "Signup successful. Please login.",
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
      },
    });
  } catch (err) {
    console.error("Signup Error:", err);
    res.status(500).json({
      success: false,
      message: "Signup failed",
      error: err.message,
    });
  }
});

app.post("/Login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await usersModel.findOne({ email });
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Email not found",
      });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password);

    if (!isPasswordMatch) {
      return res.status(401).json({
        success: false,
        message: "Incorrect password",
      });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.error("Login Error:", err);
    res.status(500).json({
      success: false,
      message: "Login failed",
      error: err.message,
    });
  }
});

app.post("/reqst", authenticateToken, async (req, res) => {
  try {
    const { name, phonenumber, email, webType, description } = req.body;

    const transporter = nodemailer.createTransport({
      host: "smtp.gmail.com",
      port: 587,
      secure: false,
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
      },
    });

    const mailOption = {
      from: "webrequesting@gmail.com",
      replyTo: email,
      to: "webrequesting@gmail.com",
      subject: "WEB REQUESTING PLATFORM",
      html: `
        <h2>Name: ${name}</h2>
        <h2>Phone: ${phonenumber}</h2>
        <h2>Email: ${email}</h2>
        <h2>Website Type: ${webType}</h2>
        <h2>Description: ${description}</h2>
      `,
    };

    await transporter.sendMail(mailOption);

    const webReg = new regsModel({
      name,
      phonenumber,
      email,
      webType,
      description,
    });

    await webReg.save();

    res.status(201).json({
      success: true,
      message: "Web registration successful! Email sent.",
      data: webReg,
    });
  } catch (err) {
    console.error("Web Registration Error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to process web registration",
      error: err.message,
    });
  }
});

app.delete("/delete-account", authenticateToken, async (req, res) => {
  try {
    const { userId, email } = req.body;

    if (req.user.userId !== userId && req.user.email !== email) {
      return res.status(403).json({
        success: false,
        message: "Unauthorized - You can only delete your own account",
      });
    }

    const deletedUser = await usersModel.findByIdAndDelete(userId);

    if (!deletedUser) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    await regsModel.deleteMany({ email: email });

    res.status(200).json({
      success: true,
      message: "Account and all associated data deleted successfully",
    });
  } catch (err) {
    console.error("Delete Account Error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to delete account",
      error: err.message,
    });
  }
});

app.get("/protected", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Access granted",
    user: req.user,
  });
});

async function getDataFromdB() {
  const users = await usersModel.find();

  return users.map((u) => ({
    Name: u.name,
    Email: u.email,
  }));
}

app.get("/users", async (req, res) => {
  try {
    const data = await getDataFromdB();
    res.json(data);
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({
      success: false,
      message: "Failed to fetch users",
      error: err.message,
    });
  }
});



app.post("/payment/create-order", async (req, res) => {
  try {
    const { amount, currency, userEmail, userName } = req.body;

    const options = {
      amount: Math.round(amount * 100), 
      currency: currency || 'INR',
      receipt: `receipt_${Date.now()}`,
      payment_capture: 1,
    };

    const order = await razorpay.orders.create(options);
    
  
    const payment = new paymentModel({
      orderId: order.id,
      amount: amount,
      currency: order.currency,
      status: 'pending',
      userEmail: userEmail,
      userName: userName,
    });
    
    await payment.save();

    console.log('Payment order created:', order.id);
    
    res.json({
      success: true,
      id: order.id,
      currency: order.currency,
      amount: order.amount,
    });
  } catch (error) {
    console.error('Create order error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to create order',
      message: error.message 
    });
  }
});

app.post("/payment/verify-payment", async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.bod
    const sign = razorpay_order_id + '|' + razorpay_payment_id;
    const expectedSign = crypto
      .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
      .update(sign.toString())
      .digest('hex')
    if (razorpay_signature === expectedSign) {
      console.log('Payment verified successfully');
      console.log('Payment ID:', razorpay_payment_id);
      console.log('Order ID:', razorpay_order_id);

      await paymentModel.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { 
          status: 'paid',
          paymentId: razorpay_payment_id,
          razorpaySignature: razorpay_signature,
          paidAt: new Date()
        }
      );

      res.json({ 
        success: true, 
        message: 'Payment verified successfully',
        paymentId: razorpay_payment_id,
        orderId: razorpay_order_id
      });
    } else {
      console.log('Payment verification failed - Invalid signature');
      
      
      await paymentModel.findOneAndUpdate(
        { orderId: razorpay_order_id },
        { status: 'failed' }
      );
      
      res.status(400).json({ 
        success: false, 
        message: 'Invalid signature' 
      });
    }
  } catch (error) {
    console.error('Verify payment error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Payment verification failed',
      message: error.message 
    });
  }
});


app.get("/payment/:paymentId", async (req, res) => {
  try {
    const payment = await razorpay.payments.fetch(req.params.paymentId);
    res.json({
      success: true,
      payment: payment
    });
  } catch (error) {
    console.error('Fetch payment error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch payment details',
      message: error.message 
    });
  }
});

app.get("/payments", authenticateToken, async (req, res) => {
  try {
    const payments = await paymentModel.find().sort({ createdAt: -1 });
    res.json({
      success: true,
      payments: payments
    });
  } catch (error) {
    console.error('Fetch payments error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch payments',
      message: error.message 
    });
  }
});


app.get("/my-payments", authenticateToken, async (req, res) => {
  try {
    const payments = await paymentModel
      .find({ userEmail: req.user.email })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      payments: payments
    });
  } catch (error) {
    console.error('Fetch user payments error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch payment history',
      message: error.message 
    });
  }
});


const PORT = 8000;
app.listen(PORT, () =>
  console.log(`Server running on http://localhost:${PORT}`)
);