const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'super_secret_jwt_key_2026';

const users = [];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const verifyToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ error: 'Необхідна автентифікація' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Недійсний токен' });
  }
};

app.get('/', (req, res) => {
  const theme = req.cookies.theme || 'light';
  res.render('index.pug', { theme });
});

app.post('/set-theme', (req, res) => {
  const { theme } = req.body;
  if (theme) {
    res.cookie('theme', theme, { maxAge: 90000000, httpOnly: false });
  }
  res.redirect('/');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ error: 'Користувач вже існує' });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });
  res.status(201).json({ message: 'Користувач успішно зареєстрований' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Невірні облікові дані' });
  }
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true, maxAge: 3600000 });
  res.json({ message: 'Успішний вхід' });
});

app.get('/dashboard', verifyToken, (req, res) => {
  const theme = req.cookies.theme || 'light';
  res.render('dashboard.ejs', { username: req.user.username, theme });
});

app.post('/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ message: 'Вихід успішний' });
});

app.listen(PORT, () => {
  console.log(`Сервер запущено на http://localhost:${PORT}`);
});
