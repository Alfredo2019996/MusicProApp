// Importar dependencias
const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session');
const mysql = require('mysql2');
require('dotenv').config(); // Cargar variables de entorno desde el archivo .env
const app = express();
const port = 3000;

// Configurar la base de datos con variables de entorno
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Alfredo201904', // Usa la contraseña configurada en el archivo .env
  database: 'musicpro',
});

db.connect((err) => {
  if (err) {
    console.error('Error de conexión a la base de datos:', err);
    return;
  }
  console.log('Conexión a la base de datos establecida');
});

// Configurar el motor de plantillas
app.set('view engine', 'ejs');

// Configurar la carpeta pública para archivos estáticos (CSS, imágenes, JS)
app.use(express.static('public'));

// Middleware para manejar datos de formularios
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Middleware de sesión
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'el_secreto', // Usa un secreto de sesión seguro
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Cambiar a true en producción con HTTPS
  })
);

// Middleware para verificar sesión de usuario
function loginRequired(req, res, next) {
  console.log('Middleware loginRequired - Sesión:', req.session);
  if (!req.session.userId) {
    return res.redirect('/login');
  }
  next();
}


app.get('/', (req, res) => {
  res.render('index');
});


// Ruta principal
app.get('/login', (req, res) => {
  res.render('login');
});

// Ruta para el registro
app.get('/register', (req, res) => {
  res.render('register');
});

// Ruta para el menú (protegida)
app.get('/menu', loginRequired, (req, res) => {
  try {
    res.render('menu', { username: req.session.username });
  } catch (error) {
    console.error('Error al renderizar el menú:', error);
    res.status(500).send('Error al cargar el menú.');
  }
});

// Ruta para manejar el formulario de inicio de sesión
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Por favor, ingresa ambos campos.' });
  }
  
  // Consultamos la base de datos para verificar si el email existe
  const query = 'SELECT * FROM usuarios WHERE email = ?';
  db.query(query, [email], (err, results) => {
    if (err) {
      console.error('Error al buscar el usuario:', err);
      return res.status(500).json({ error: 'Hubo un problema en el servidor.' });
    }

    if (results.length === 0) {
      return res.status(400).json({ error: 'Correo electrónico no encontrado.' });
    }

    const user = results[0];
    console.log(user)
    // Verificamos la contraseña
    bcrypt.compare(password, user.contraseña, (err, isMatch) => {
      if (err) {
        console.error('Error al comparar contraseñas:', err);
        return res.status(500).json({ error: 'Error en el servidor.' });
      }

      if (!isMatch) {
        return res.status(400).json({ error: 'Contraseña incorrecta.' });
      }

      // Creamos una sesión para el usuario
      req.session.userId = user.id; // Guardamos el ID del usuario en la sesión
      req.session.username = user.nombre; // Guardamos el nombre del usuario (opcional)

      // Redirigimos al menú
      console.log('Redirigiendo al menú');
      res.redirect('/menu');
    });
  });
});

// Ruta para el registro de usuarios
const saltRounds = 10; // Número de rondas de sal para el hashing
app.post('/register', (req, res) => {
  const { username, email, password, date } = req.body;

  if (!username || !email || !password || !date) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  const checkEmailQuery = 'SELECT email FROM usuarios WHERE email = ?';
  db.query(checkEmailQuery, [email], (err, results) => {
    if (err) {
      console.error('Error al verificar el email:', err);
      return res.status(500).json({
        error: 'Hubo un problema al verificar tu correo. Por favor intenta más tarde.',
      });
    }

    if (results.length > 0) {
      return res.status(400).json({
        error: 'El email ya está registrado. Por favor utiliza otro correo.',
      });
    }

    bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
      if (err) {
        console.error('Error al hashear la contraseña:', err);
        return res.status(500).json({ error: 'Error en el servidor' });
      }

      const insertUserQuery =
        'INSERT INTO usuarios (nombre, email, contraseña, fecha_registro) VALUES (?, ?, ?, ?)';
      db.query(insertUserQuery, [username, email, hashedPassword, date], (err, results) => {
        if (err) {
          console.error('Error al registrar el usuario:', err);
          return res.status(500).json({ error: 'Error al registrar el usuario' });
        }
        return res.redirect('/login')

      });
    });
  });
});

// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error al cerrar sesión:', err);
      res.status(500).send('Error al cerrar sesión');
    } else {
      res.redirect('/'); // Redirige al inicio después de cerrar sesión
    }
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
