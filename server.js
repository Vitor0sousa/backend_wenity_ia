// server.js
const express = require('express');
const mariadb = require('mariadb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const auth = require('./middleware/auth');

const app = express();
app.use(express.json()); 
app.use(cors()); 


const pool = mariadb.createPool({
     host: 'localhost', 
     user: 'root',
     password: 'admin',
     database: 'wenetyia',
     connectionLimit: 5
});


const JWT_SECRET = 'chave_secreta';


app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;

    // Validação básica
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }

    let conn;
    try {
        conn = await pool.getConnection();

        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        
        const result = await conn.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );

        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: String(result.insertId) });

    } catch (error) {
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Este email já está em uso.' });
        }
        console.error(error);
        res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
    } finally {
        if (conn) conn.release(); 
    }
});


app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }

    let conn;
    try {
        conn = await pool.getConnection();

        // 1. Buscar o usuário pelo email
        const users = await conn.query("SELECT * FROM users WHERE email = ?", [email]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Credenciais inválidas.' }); // Email não encontrado
        }
        const user = users[0];

        // 2. Comparar a senha enviada com a senha hasheada no banco
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas.' }); // Senha incorreta
        }

        // 3. Se as credenciais estiverem corretas, criar um token JWT
        const payload = {
            user: {
                id: user.id,
                email: user.email
            }
        };

        jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Erro no servidor.' });
    } finally {
        if (conn) conn.release();
    }
});


app.post('/api/chat', async (req, res) => {
    const { message } = req.body;
    
    // URL do seu Webhook do n8n
    // Cole a URL que você obteve do nó "Webhook" no n8n aqui
    const n8nWebhookUrl = 'https://v0sousa.app.n8n.cloud/webhook-test/189d6f04-7ace-4770-92c0-ed1ab8559e56'; 
    
    if (!message) {
        return res.status(400).json({ message: 'Mensagem não pode ser vazia.' });
    }

    try {
        // Envia a mensagem do usuário para o n8n via POST
        const response = await axios.post(n8nWebhookUrl, {
            message: message
        });
        
        // Retorna a resposta que veio do n8n (que é a resposta da IA)
        // O `response.data` contém a resposta final da IA
        res.status(200).json(response.data);

    } catch (error) {
        console.error('Erro ao comunicar com o webhook do n8n:', error.message);
        res.status(500).json({ message: 'Erro ao processar a mensagem.' });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));