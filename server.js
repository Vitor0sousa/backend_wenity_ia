// server.js
const express = require('express');
const mariadb = require('mariadb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const auth = require('./middleware/auth');
const multer = require('multer');
const FormData = require('form-data'); // Certifique-se de que a biblioteca está instalada

const app = express();
app.use(express.json());
app.use(cors());

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

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
            "INSERT INTO users (name, email, hashedPassword) VALUES (?, ?, ?)",
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

    const n8nWebhookUrl = 'https://v0sousa.app.n8n.cloud/webhook-test/189d6f04-7ace-4770-92c0-ed1ab8559e56';

    if (!message) {
        return res.status(400).json({ message: 'Mensagem não pode ser vazia.' });
    }

    try {
        const response = await axios.post(n8nWebhookUrl, {
            message: message
        });

        let finalResponse = { reply: 'Ocorreu um erro ao processar a mensagem.' };

        if (typeof response.data === 'string') {
            finalResponse.reply = response.data;
        } else if (response.data && response.data.reply) {
            finalResponse.reply = response.data.reply;
        } else {
            console.error('Formato de resposta do n8n inesperado:', response.data);
            finalResponse.reply = 'Ocorreu um erro ao processar a mensagem, formato inesperado.';
        }

        res.status(200).json(finalResponse);

    } catch (error) {
        console.error('Erro detalhado ao comunicar com o webhook do n8n:', error.message);
        res.status(500).json({ reply: 'Erro no servidor: Falha na comunicação com a API externa.' });
    }
});


app.post('/api/analyze', upload.single('curriculo'), async (req, res) => {
    // URL do seu webhook do n8n para análise de PDF
    const n8nWebhookUrl = 'https://vitor9sousa.app.n8n.cloud/webhook-test/189d6f04-7ace-4770-92c0-ed1ab8559e56'; // Substitua por sua URL de webhook de PDF

    if (!req.file) {
        return res.status(400).json({ message: 'Nenhum arquivo enviado.' });
    }

    try {
        const formData = new FormData();
        // O nome 'curriculo' deve ser o mesmo usado no seu frontend
        formData.append('curriculo', req.file.buffer, {
            filename: req.file.originalname,
            contentType: req.file.mimetype,
        });

        const response = await axios.post(n8nWebhookUrl, formData, {
            headers: formData.getHeaders(),
        });

        if (response.data && response.data.reply) {
            res.status(200).json({ reply: response.data.reply });
        } else if (typeof response.data === 'string') {
            // Caso a resposta seja uma string, ajusta aqui
            res.status(200).json({ reply: response.data.toString() });
        }
        else {
            res.status(500).json({ reply: 'Ocorreu um erro ao processar a mensagem, formato de resposta inesperado.' });
        }


    } catch (error) {
        console.error('Erro ao comunicar com o webhook do n8n para análise de PDF:');
        console.error('Nome do erro:', error.name);
        console.error('Mensagem do erro:', error.message);
        if (error.response) {
            console.error('Status da resposta:', error.response.status);
            console.error('Dados da resposta:', error.response.data);
        }
        res.status(500).json({ message: 'Erro interno do servidor ao analisar o documento.' });
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));