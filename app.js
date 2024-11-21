const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const session = require('express-session'); 
const db = require('./db'); // Importar la conexión a la base de datos
const app = express();
const port = 3000;

// Configurar el motor de plantillas
app.set('view engine', 'ejs');

// Middleware para manejar datos de formularios
app.use(bodyParser.urlencoded({ extended: true }));

// Middleware de sesión
app.use(session({
    secret: 'el_secreto',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Cambiar a true en producción con HTTPS
}));

// Servir archivos estáticos
app.use(express.static('public'));

// Middleware para verificar si el usuario está autenticado
function loginRequired(req, res, next) {
    if (req.session && req.session.userId) {
        return next();
    } else {
        res.redirect('/');
    }
}

// Ruta principal
app.get('/', (req, res) => {
    res.render('index');
});

// Ruta para el registro
app.get('/register', (req, res) => {
    res.render('register');
});

// Ruta para el menú (protegida)
app.get('/menu', loginRequired, (req, res) => {
    res.render('menu');
});

// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error al cerrar sesión:', err);
            res.status(500).send('Error al cerrar sesión');
        } else {
            res.redirect('/');
        }
    });
});

// Ruta para el inicio de sesión
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const query = 'SELECT id_usuario, nombre, email, contraseña FROM usuarios WHERE email = ?';

    db.query(query, [email], (err, results) => {
        if (err) {
            console.error('Error al iniciar sesión:', err);
            res.status(500).send('Error al iniciar sesión');
        } else if (results.length === 0) {
            res.status(401).send('Email o contraseña incorrectos');
        } else {
            const hashedPassword = results[0].contraseña;
            bcrypt.compare(password, hashedPassword, (err, isMatch) => {
                if (err) {
                    console.error('Error al comparar la contraseña:', err);
                    res.status(500).send('Error al iniciar sesión');
                } else if (!isMatch) {
                    res.status(401).send('Email o contraseña incorrectos');
                } else {
                    req.session.userId = results[0].id_usuario;
                    res.redirect('/menu');
                }
            });
        }
    });
});

// Ruta para el registro de usuarios
const saltRounds = 10; // Número de rondas de sal para el hashing
app.post('/register', (req, res) => {
    const { username, email, password, date } = req.body;

    // Verificar si el email ya existe
    const checkEmailQuery = 'SELECT email FROM usuarios WHERE email = ?';
    db.query(checkEmailQuery, [email], (err, results) => {
        if (err) {
            console.error('Error al verificar el email:', err);
            res.status(500).json({ error: 'Error al registrar el usuario' });
        } else if (results.length > 0) {
            res.status(400).json({ error: 'El email ya está registrado' });
        } else {
            // Hashear la contraseña
            bcrypt.hash(password, saltRounds, (err, hashedPassword) => {
                if (err) {
                    console.error('Error al hashear la contraseña:', err);
                    res.status(500).json({ error: 'Error al registrar el usuario' });
                } else {
                    const insertUserQuery = 'INSERT INTO usuarios (nombre, email, contraseña, fecha_registro) VALUES (?, ?, ?, ?)';
                    db.query(insertUserQuery, [username, email, hashedPassword, date], (err, results) => {
                        if (err) {
                            console.error('Error al registrar el usuario:', err);
                            res.status(500).json({ error: 'Error al registrar el usuario, el usuario ya existe.' });
                        } else {
                            res.status(200).json({ success: 'Usuario registrado exitosamente' });
                        }
                    });
                }
            });
        }
    });
});



// Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
});
