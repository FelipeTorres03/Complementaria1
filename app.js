const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');  
require('dotenv').config();

const app = express();
app.use(express.json());

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Token no proporcionado' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Token inválido' });
        req.userId = decoded.id;
        next();
    });
};

app.post('/acceso', (req, res) => {
    const { usuario, clave } = req.body;

    pool.query('SELECT * FROM usuarios WHERE usuario = ?', [usuario], (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor' });
        if (results.length === 0) return res.status(404).json({ message: 'Usuario no encontrado' });

        const user = results[0];
        const passwordIsValid = bcrypt.compareSync(clave, user.clave);

        if (!passwordIsValid) {
            return res.status(401).json({ token: null, message: 'Clave incorrecta' });
        }

        const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
            expiresIn: 86400 // 24 horas
        });
        res.status(200).json({ token });
    });
});

app.get('/data', verifyToken, (req, res) => {
    pool.query('SELECT * FROM data', (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor' });
        res.status(200).json({ data: results, message: '' });
    });
});

app.post('/data', verifyToken, (req, res) => {
    const newData = req.body;
    pool.query('INSERT INTO data SET ?', newData, (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor' });
        res.status(201).json({ insertID: results.insertId, message: 'Registro insertado' });
    });
});

app.patch('/data/:id', verifyToken, (req, res) => {
    const id = req.params.id;
    const updatedData = req.body;

    pool.query('UPDATE data SET ? WHERE id = ?', [updatedData, id], (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor' });
        res.status(200).json({ data: results, message: 'Registro actualizado' });
    });
});

app.delete('/data/:id', verifyToken, (req, res) => {
    const id = req.params.id;

    pool.query('DELETE FROM data WHERE id = ?', [id], (err, results) => {
        if (err) return res.status(500).json({ message: 'Error en el servidor' });
        res.status(200).json({ data: results, message: 'Registro eliminado' });
    });
});

app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});
