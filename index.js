import express from 'express'
import mongoose from 'mongoose'
import path from 'path'
import cookieParser from 'cookie-parser'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

const app = express()

// Middleware
app.use(express.static(path.join(path.resolve(), 'public')))
app.use(express.urlencoded({ extended: true }))
app.use(cookieParser())

// Setting engine
app.set('view engine', 'ejs')

// Database connection
mongoose
  .connect('mongodb://127.0.0.1:27017', {
    dbName: 'Auth',
  })
  .then(() => console.log('Connected to MongoDB'))
  .catch((e) => console.log(e))

// Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
})

// Model
const User = mongoose.model('User', userSchema)

// handler for authentication
const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies

  if (token) {
    const decoded = jwt.verify(token, 'secretkey')
    req.user = await User.findById(decoded._id)
    next()
  } else {
    res.render('login')
  }
}

// Routes
app.get('/', isAuthenticated, (req, res) => {
  console.log(req.user)
  res.render('logout', { name: req.user.name })
})

app.get('/register', (req, res) => {
  res.render('register')
})

app.post('/login', async (req, res) => {
  const { email, password } = req.body

  const user = await User.findOne({ email })

  if (!user) {
    return res.redirect('/register')
  }

  // comparing the hashed password 
  const isMatch = await bcrypt.compare(password, user.password);
  //if not match
  if (!isMatch) {
    return res.render('login', { message: 'incorrect email or password' })
  }

  const token = jwt.sign({ _id: user._id }, 'secretKey')

  res.cookie('token', token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  })
  res.render('logout', { name: user.name })
})

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body

  // if user already exists then login page
  const user = await User.findOne({ email })
  if (user) {
   return  res.redirect('/login')
  }
  // hashing the password 
  const hashedPassword = await bcrypt.hash(password, 10);

  user = await User.create({ name, email, password: hashedPassword })

  const token = jwt.sign({ _id: user._id }, 'secretKey')
  res.cookie('token', token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  })

  res.redirect('/')
})

app.get('/login', (req, res) => {
  res.render('login')
})

app.post('/login', async (req, res) => {
  const { name, email } = req.body
  let user = await User.findOne({ email })

  // if user is not available then redirect to register
  if (!user) {
    return res.redirect('/register')
  }
  user = await User.create({ name, email })

  // Creating token using jwt token
  const token = jwt.sign({ _id: user._id }, 'secretkey')

  res.cookie('token', token, {
    httpOnly: true,
    expires: new Date(Date.now() + 60 * 1000),
  })
  res.redirect('/')
})

// Listening
app.listen(5000, () => {
  console.log('server is running!')
})
