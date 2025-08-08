require('dotenv').config();
const express = require('express');
const path = require('path');
const pool = require("./db"); // PostgreSQL connection
const session = require('express-session');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const fs = require('fs');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const uploadDir = path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const unique = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, unique + path.extname(file.originalname));
  }
});
const upload = multer({ storage });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'geheim',
  resave: false,
  saveUninitialized: false
}));

app.use((req, res, next) => {
  res.locals.user = req.session.username || null;
  next();
});

// Reviews JSON-bestand helpers
const reviewsFile = path.join(__dirname, 'data', 'reviews.json');
function readReviews() {
  if (!fs.existsSync(reviewsFile)) return [];
  try {
    const data = fs.readFileSync(reviewsFile, 'utf-8');
    return JSON.parse(data);
  } catch (err) {
    console.error("Fout bij lezen reviews.json:", err);
    return [];
  }
}
function saveReviews(reviews) {
  try {
    fs.writeFileSync(reviewsFile, JSON.stringify(reviews, null, 2));
  } catch (err) {
    console.error("Fout bij schrijven reviews.json:", err);
  }
}

// --- Routes ---

app.get('/reviews/send', (req, res) => {
  res.render('reviews/send/index');
});

app.get('/', (req, res) => res.render('index'));
app.get('/register', (req, res) => res.render('register'));
app.get('/login', (req, res) => res.render('login'));
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const exists = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  if (exists.rows.length > 0) return res.send("Gebruiker bestaat al");
  await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [username, hashed]);
  res.redirect('/login');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
  if (result.rows.length === 0) return res.send("Gebruiker niet gevonden");
  const match = await bcrypt.compare(password, result.rows[0].password);
  if (!match) return res.send("Wachtwoord onjuist");
  req.session.username = username;
  res.redirect('/dashboard');
});

app.get('/dashboard', async (req, res) => {
  if (!req.session.username) return res.redirect('/login');
  const me = (await pool.query("SELECT * FROM users WHERE username = $1", [req.session.username])).rows[0];
  const friendsResult = await pool.query(`
    SELECT u.username FROM users u
    JOIN friendships f ON (f.user1 = u.username OR f.user2 = u.username)
    WHERE (f.user1 = $1 OR f.user2 = $1) AND u.username != $1
  `, [me.username]);
  const friends = friendsResult.rows.map(r => r.username);
  const requests = (await pool.query("SELECT sender FROM friend_requests WHERE receiver = $1", [me.username])).rows.map(r => r.sender);
  const messages = await pool.query(`
    SELECT from_user, COUNT(*) AS count FROM messages
    WHERE to_user = $1
    GROUP BY from_user
  `, [me.username]);
  const newMessageCounts = {};
  messages.rows.forEach(m => newMessageCounts[m.from_user] = m.count);
  res.render('dashboard', {
    username: me.username,
    friends,
    requests,
    newMessageCounts,
    error: null
  });
});

app.post('/friend-request', async (req, res) => {
  const sender = req.session.username;
  const receiver = req.body.receiver;
  if (sender === receiver) return res.redirect('/dashboard');
  const exists = await pool.query("SELECT * FROM users WHERE username = $1", [receiver]);
  const already = await pool.query("SELECT * FROM friend_requests WHERE sender = $1 AND receiver = $2", [sender, receiver]);
  const alreadyFriends = await pool.query("SELECT * FROM friendships WHERE (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)", [sender, receiver]);
  if (exists.rows.length > 0 && already.rows.length === 0 && alreadyFriends.rows.length === 0) {
    await pool.query("INSERT INTO friend_requests (sender, receiver) VALUES ($1, $2)", [sender, receiver]);
  }
  res.redirect('/dashboard');
});

app.post('/accept-friend', async (req, res) => {
  const receiver = req.session.username;
  const sender = req.body.sender;
  await pool.query("DELETE FROM friend_requests WHERE sender = $1 AND receiver = $2", [sender, receiver]);
  await pool.query("INSERT INTO friendships (user1, user2) VALUES ($1, $2)", [sender, receiver]);
  res.redirect('/dashboard');
});

app.post('/decline-friend', async (req, res) => {
  const receiver = req.session.username;
  const sender = req.body.sender;
  await pool.query("DELETE FROM friend_requests WHERE sender = $1 AND receiver = $2", [sender, receiver]);
  res.redirect('/dashboard');
});

app.get('/chat/:friend', async (req, res) => {
  const me = req.session.username;
  const friend = req.params.friend;
  const friendship = await pool.query(`
    SELECT * FROM friendships WHERE 
    (user1 = $1 AND user2 = $2) OR (user1 = $2 AND user2 = $1)
  `, [me, friend]);
  if (friendship.rows.length === 0) return res.send("Geen toegang");
  const messages = await pool.query(`
    SELECT * FROM messages
    WHERE (from_user = $1 AND to_user = $2) OR (from_user = $2 AND to_user = $1)
    ORDER BY time ASC
  `, [me, friend]);
  res.render('chat', { friend, messages: messages.rows });
});

app.get('/messages/:friend', async (req, res) => {
  const me = req.session.username;
  const friend = req.params.friend;
  const messages = await pool.query(`
    SELECT * FROM messages
    WHERE (from_user = $1 AND to_user = $2) OR (from_user = $2 AND to_user = $1)
    ORDER BY time ASC
  `, [me, friend]);
  const html = messages.rows.map(m =>
    `<p><strong>${m.from_user}:</strong> ${m.text || `<a href="${m.file}" target="_blank">Bestand</a>`} 
     <small>(${new Date(m.time).toLocaleTimeString()})</small></p>`
  ).join('');
  res.send(html);
});

app.post('/upload', upload.single('file'), (req, res) => {
  res.send({ file: `/uploads/${req.file.filename}` });
});

app.get('/verrassing', (req, res) => {
  if (!req.session.username) return res.redirect('/login');
  const verrassingen = [
    "Citroenfeit: Citroenen drijven omdat ze een dikke schil met luchtzakjes hebben.",
    "Limonademop: Waarom hield de limonade een speech? Omdat hij bruisend was!",
    "Citroenfeit: In de Middeleeuwen dacht men dat citroen gif kon tegengaan.",
    "Limonademop: Wat zegt de citroen tegen de limonade? Jij bent té zoet!",
    "Citroenfeit: Citroenen bevatten meer suiker dan aardbeien!",
    "Limonademop: Wat doet een citroen in de sportschool? Zich uitpersen!"
  ];
  const today = new Date().getDate();
  const verrassing = verrassingen[today % verrassingen.length];
  res.render('verrassing', { verrassing });
});

app.get('/reviews', (req, res) => {
  const reviews = readReviews();
  res.render('reviews/index', { reviews });
});

app.post('/reviews', (req, res) => {
  const { name, rating, message } = req.body;
  if (!name || !rating || !message) return res.status(400).send("Alle velden zijn verplicht");
  const reviews = readReviews();
  reviews.unshift({
    id: Date.now(),
    name,
    rating: Number(rating),
    message,
    time: new Date().toISOString()
  });
  saveReviews(reviews);
  res.redirect('/reviews');
});

app.get(/^\/(?!.*\.(ejs|json|js|css|png|jpg|jpeg|ico|webmanifest|svg|woff|ttf)$).*$/, (req, res) => {
  const viewPath = req.path === '/' ? 'index' : req.path.slice(1);
  res.render(viewPath, (err, html) => {
    if (!err) return res.send(html);
    res.render(`${viewPath}/index`, (err2, html2) => {
      if (err2) return res.status(404).send("Pagina niet gevonden");
      res.send(html2);
    });
  });
});

// Socket.IO authenticatie en events
io.use((socket, next) => {
  const username = socket.handshake.auth.username;
  if (!username) return next(new Error("Geen gebruikersnaam opgegeven"));
  socket.username = username;
  next();
});

io.on('connection', (socket) => {
  console.log(`${socket.username} verbonden`);
  socket.on('private message', async ({ content, to, file }) => {
    await pool.query(`
      INSERT INTO messages (from_user, to_user, text, file, time)
      VALUES ($1, $2, $3, $4, NOW())
    `, [socket.username, to, content || null, file || null]);
    for (const [id, s] of io.of("/").sockets) {
      if (s.username === to) {
        s.emit("private message", {
          from: socket.username,
          content,
          file,
          time: new Date().toISOString()
        });
      }
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server gestart op poort ${PORT}`));
