// server.js
require('dotenv').config();
const express = require('express');
const mariadb = require('mariadb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const auth = require('./middleware/auth');
const multer = require('multer');
const FormData = require('form-data');
const pdf = require('pdf-parse/lib/pdf-parse.js');

// --- ADICIONADO: Dependências para recuperação de senha ---
const nodemailer = require('nodemailer');
const crypto = require('crypto');
// ----------------------------------------------------

// Importa a biblioteca do Gemini
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();

// --- Middleware ---
app.use(express.json());
app.use(cors()); // [cite: 22]

// Configuração do Multer
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// --- Configuração do Banco de Dados ---
const pool = mariadb.createPool({
    host: 'localhost',
    user: 'root',
    password: 'root',
    database: 'wenetyia',
    connectionLimit: 5
}); // [cite: 23]

// --- Configuração de Variáveis de Ambiente ---
const JWT_SECRET = process.env.JWT_SECRET; // [cite: 24]

// --- ADICIONADO: Armazenamento de tokens de reset ---
// Isso estava faltando no código do estagiário e causaria erros.
const resetTokens = new Map();
// --------------------------------------------------

// --- Configuração da API do Gemini ---
let model;
try {
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" }); // [cite: 26]
    console.log("Modelo do Gemini inicializado com sucesso.");
} catch (error) {
    console.error("ERRO ao inicializar o modelo do Gemini:", error); // [cite: 27]
    model = null;
}

// =================================
//     FUNÇÕES AUXILIARES
// =================================

// --- Função para gerar tokens JWT ---
function generateTokens(user) {
    const accessTokenPayload = {
        user: {
            id: user.id,
            email: user.email
        }
    }; // [cite: 18]
    // Access token (1 hora)
    const accessToken = jwt.sign(
        accessTokenPayload,
        process.env.JWT_SECRET,
        { expiresIn: '1h' }
    ); // [cite: 19]
    // Refresh token (7 dias)
    const refreshToken = jwt.sign(
        accessTokenPayload,
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
    ); // [cite: 20]
    return { accessToken, refreshToken }; // [cite: 21]
}

// --- ADICIONADO: Função para enviar email de recuperação ---
async function sendResetEmail(email, token) {
    const publicUrl = process.env.FRONT_URL || 'http://localhost:4200'; // 
    const resetLink = `${publicUrl}/trocar-senha/${token}`; // 

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    }); // [cite: 3]

    const mailOptions = {
        from: `"Wenity IA" <${process.env.EMAIL_USER}>`, // 
        to: email, // 
        subject: 'Recuperação de senha - Wenity IA', // 
        html: `
          <h2>Recuperação de senha</h2>
          <p>Você solicitou a redefinição de sua senha.</p>
          <p>Clique no link abaixo para criar uma nova senha:</p>
          <p><a href="${resetLink}" target="_blank">${resetLink}</a></p>
          <p>Este link expira em 15 minutos.</p>
        ` // HTML corrigido para enviar o link
    };

    await transporter.sendMail(mailOptions); // [cite: 5]
    console.log(`✅ E-mail enviado para ${email} com link: ${resetLink}`);
}
// -------------------------------------------------------


// =================================
//        ROTAS DE AUTENTICAÇÃO
// =================================

// Rota de Registro
app.post('/api/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }
    let conn;
    try {
        conn = await pool.getConnection();
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt); // [cite: 29]
        const result = await conn.query(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            [name, email, hashedPassword]
        );
        res.status(201).json({ message: 'Usuário cadastrado com sucesso!', userId: String(result.insertId) });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') { // [cite: 30]
            return res.status(409).json({ message: 'Este email já está em uso.' });
        }
        console.error(error); // [cite: 31]
        res.status(500).json({ message: 'Erro ao cadastrar usuário.' });
    } finally {
        if (conn) conn.release(); // [cite: 32]
    }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }
    let conn;
    try {
        conn = await pool.getConnection();
        const users = await conn.query("SELECT * FROM users WHERE email = ?", [email]); // [cite: 34]
        if (users.length === 0) {
            return res.status(401).json({ message: 'Credenciais inválidas.' }); // [cite: 34]
        }
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas.' }); // [cite: 35]
        }
        const { accessToken, refreshToken } = generateTokens(user);
        await conn.query(
            "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
            [user.id, refreshToken]
        ); // [cite: 36]
        res.json({
            token: accessToken,
            refreshToken: refreshToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        }); // [cite: 37, 38]
    } catch (error) {
        console.error('Erro no login:', error); // [cite: 39]
        res.status(500).json({ message: 'Erro no servidor.' }); // [cite: 40]
    } finally {
        if (conn) conn.release();
    }
});

// --- ADICIONADO: Rota para solicitar recuperação de senha ---
app.post('/api/recuperar-senha', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'E-mail é obrigatório.' });

    let conn;
    try {
        conn = await pool.getConnection();
        const users = await conn.query('SELECT * FROM users WHERE email = ?', [email]);

        if (users.length === 0) {
            // Não expõe se o e-mail existe ou não
            return res.json({ message: 'Se o e-mail existir, um link de recuperação foi enviado.' });
        }

        const token = crypto.randomBytes(32).toString('hex'); // [cite: 7]
        const expires = Date.now() + 15 * 60 * 1000; // 15 minutos
        resetTokens.set(token, { email, expires });

        await sendResetEmail(email, token);

        res.json({
            message: 'E-mail enviado com sucesso!',
            // [cite: 6] (removido o redirectTo que estava no original, 
            // pois o link agora vai por email)
        });
    } catch (error) {
        console.error('❌ Erro ao enviar e-mail:', error);
        res.status(500).json({ message: 'Erro ao enviar o e-mail.' }); // [cite: 8]
    } finally {
        if (conn) conn.release();
    }
});
// ---------------------------------------------------------

// --- ADICIONADO: Rota para trocar a senha com o token ---
app.post('/api/trocar-senha', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ message: 'Token e nova senha são obrigatórios.' });
    }

    const tokenData = resetTokens.get(token);
    if (!tokenData) return res.status(400).json({ message: 'Token inválido ou expirado.' });

    const { email, expires } = tokenData;
    if (Date.now() > expires) {
        resetTokens.delete(token);
        return res.status(400).json({ message: 'Token expirado.' });
    }

    let conn;
    try {
        conn = await pool.getConnection();

        const saltRounds = 10; // [cite: 10]
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds); // [cite: 10]

        await conn.query('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email]);

        resetTokens.delete(token); // Invalida o token após o uso

        res.json({ message: 'Senha alterada com sucesso!' });
    } catch (error) {
        console.error('❌ Erro ao trocar senha:', error);
        res.status(500).json({ message: 'Erro ao trocar a senha.' }); // [cite: 11]
    } finally {
        if (conn) conn.release();
    }
});
// ------------------------------------------------------

// Rota para renovar o token
app.post('/api/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token não fornecido.' });
    }
    let conn;
    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        conn = await pool.getConnection(); // [cite: 89]
        const tokens = await conn.query(
            "SELECT * FROM refresh_tokens WHERE token = ? AND user_id = ? AND expires_at > NOW() AND revoked = 0",
            [refreshToken, decoded.user.id]
        ); // [cite: 90]
        if (tokens.length === 0) {
            return res.status(401).json({ message: 'Refresh token inválido ou expirado.' });
        }
        const users = await conn.query("SELECT * FROM users WHERE id = ?", [decoded.user.id]);
        if (users.length === 0) {
            return res.status(401).json({ message: 'Usuário não encontrado.' }); // [cite: 91]
        }
        const user = users[0]; // [cite: 92]
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user); // [cite: 93]
        await conn.query(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?",
            [refreshToken]
        ); // [cite: 94]
        await conn.query(
            "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
            [user.id, newRefreshToken]
        ); // [cite: 95]
        res.json({
            token: accessToken,
            refreshToken: newRefreshToken
        }); // [cite: 96]
    } catch (error) {
        if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Refresh token inválido.' }); // [cite: 97]
        }
        console.error('Erro ao renovar token:', error); // [cite: 98]
        res.status(500).json({ message: 'Erro no servidor.' });
    } finally {
        if (conn) conn.release(); // [cite: 99]
    }
});

// Rota de Logout
app.post('/api/logout', auth, async (req, res) => {
    const { refreshToken } = req.body;
    let conn;
    try {
        conn = await pool.getConnection();
        if (refreshToken) {
            await conn.query(
                "UPDATE refresh_tokens SET revoked = 1 WHERE token = ? AND user_id = ?",
                [refreshToken, req.user.id]
            ); // [cite: 101]
        } else {
            await conn.query(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
                [req.user.id]
            ); // [cite: 102]
        }
        res.json({ message: 'Logout realizado com sucesso.' });
    } catch (error) {
        console.error('Erro no logout:', error);
        res.status(500).json({ message: 'Erro ao fazer logout.' }); // [cite: 103]
    } finally {
        if (conn) conn.release();
    }
});


// =================================
//        ROTAS DA APLICAÇÃO (IA)
// =================================

// Rota de Chat Gemini (protegida)
app.post('/api/chat', auth, async (req, res) => {
    if (!model) {
        return res.status(503).json({ error: "O modelo de IA não está disponível no momento." });
    }
    let conn; // [cite: 43]
    try {
        const { message, history } = req.body;
        if (!message) {
            return res.status(400).json({ error: 'Nenhuma mensagem foi fornecida.' }); // [cite: 44]
        }
        const userId = req.user.id; // [cite: 45]
        const chat = model.startChat({
            history: history || [],
        });
        const result = await chat.sendMessage(message); // [cite: 46]
        const response = result.response; // [cite: 47]
        const modelResponseText = response.text();

        conn = await pool.getConnection();
        await conn.query(
            "INSERT INTO chat_history (user_id, role, message_text) VALUES (?, ?, ?)",
            [userId, 'user', message]
        ); // [cite: 48]
        await conn.query(
            "INSERT INTO chat_history (user_id, role, message_text) VALUES (?, ?, ?)",
            [userId, 'model', modelResponseText]
        ); // [cite: 49]
        console.log(`Conversa salva para o usuário com ID: ${userId}`); // [cite: 50]
        res.json({ response: modelResponseText });
    } catch (error) {
        console.error("Erro na rota /api/chat:", error); // [cite: 51]
        res.status(500).json({ error: 'Ocorreu um erro ao processar sua mensagem.' }); // [cite: 52]
    } finally {
        if (conn) { // [cite: 55]
            conn.release(); // [cite: 54]
        }
    }
});

// Rota para carregar histórico do chat (protegida)
app.get('/api/chat/history', auth, async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); // [cite: 56]
    let conn;
    try {
        conn = await pool.getConnection();
        const userId = req.user.id;
        const rows = await conn.query(
            "SELECT role, message_text FROM chat_history WHERE user_id = ? ORDER BY created_at ASC",
            [userId]
        ); // [cite: 57]
        const history = rows.map(row => ({
            role: row.role,
            parts: [{ text: row.message_text }]
        })); // [cite: 58]
        res.json(history);
    } catch (error) {
        console.error("Erro ao buscar histórico do chat:", error);
        res.status(500).json({ message: 'Erro ao buscar histórico.' }); // [cite: 59]
    } finally {
        if (conn) conn.release(); // [cite: 60]
    }
});

// Rota para Analisar Currículo (protegida)
app.post('/api/analyze-resume', auth, upload.single('resume'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo de currículo foi enviado.' });
    }
    try {
        const data = await pdf(req.file.buffer);
        const resumeText = data.text;
        const userPrompt = req.body.prompt || "Faça uma análise geral deste currículo."; // [cite: 61]
        const fullPrompt = `
            Você é um assistente de RH especialista em recrutamento técnico...
            Instrução do recrutador: "${userPrompt}"
            --- CONTEÚDO DO CURRÍCULO ---
            ${resumeText}
            --- FIM DO CURRÍCULO ---
            ...forneça uma análise clara e objetiva...
        `; // [cite: 62, 63]
        const result = await model.generateContent(fullPrompt);
        const response = result.response;
        const analysisText = response.text();
        res.json({ response: analysisText });
    } catch (error) {
        console.error("Erro ao analisar o currículo:", error); // [cite: 64]
        res.status(500).json({ error: 'Ocorreu um erro ao processar o arquivo PDF.' }); // [cite: 65]
    }
});

// Rota para Histórico de Contratação (protegida)
app.get('/api/hiring/history', auth, async (req, res) => {
    let conn;
    try {
        conn = await pool.getConnection();
        const userId = req.user.id;
        const rows = await conn.query(
            "SELECT job_title, job_requirements, analysis_result, resumes_count, created_at FROM resume_analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT 5",
            [userId]
        ); // [cite: 66]
        const history = rows.map(row => ({
            jobOpening: { id: '', title: row.job_title },
            requirements: JSON.parse(row.job_requirements || '{}'),
            bestCandidate: "Análise Salva",
            analyzedResumesCount: row.resumes_count,
            analysisDate: row.created_at,
            analysisText: row.analysis_result
        })); // [cite: 67, 68]
        res.json(history);
    } catch (error) {
        console.error("Erro ao buscar histórico de análises:", error); // [cite: 69]
        res.status(500).json({ message: 'Erro ao buscar histórico.' }); // [cite: 70]
    } finally {
        if (conn) conn.release(); // [cite: 71]
    }
});

// Rota para Analisar Múltiplos Currículos (protegida)
app.post('/api/hiring/analyze', auth, upload.array('resumes'), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: 'Nenhum currículo foi enviado.' });
    }
    if (!model) {
        return res.status(503).json({ error: "O modelo de IA não está disponível." });
    }
    let conn;
    try {
        const jobOpening = JSON.parse(req.body.jobOpening);
        const requirements = JSON.parse(req.body.requirements);
        const userId = req.user.id; // [cite: 72]
        let allResumesText = "";
        for (const file of req.files) { // [cite: 73]
            const data = await pdf(file.buffer);
            allResumesText += `\n\n--- INÍCIO DO CURRÍCULO: ${file.originalname} ---\n`;
            allResumesText += data.text; // [cite: 74]
            allResumesText += `\n--- FIM DO CURRÍCULO: ${file.originalname} ---\n`;
        } // [cite: 75]
        const fullPrompt = `
            Você é um especialista de RH sênior.
            Sua tarefa é analisar um lote de currículos para uma vaga específica.
            VAGA: ${jobOpening.title}
            REQUISITOS DA VAGA:
            - Nível de Experiência: ${requirements.experienceLevel}
            - Habilidades Obrigatórias: ${requirements.requiredSkills.join(', ')}
            - Habilidades Desejáveis: ${requirements.niceToHaveSkills.join(', ')}
            - Requisitos Adicionais: ${requirements.specificRequirements || 'Nenhum'}
            --- CONTEÚDO DOS CURRÍCULOS ---
            ${allResumesText}
            --- FIM DOS CURRÍCULOS ---
            ...forneça uma análise comparativa...
        `; // [cite: 76, 77, 78, 79]
        const result = await model.generateContent(fullPrompt);
        const response = result.response; // [cite: 80]
        const analysisText = response.text();

        conn = await pool.getConnection();
        const insertQuery = `
            INSERT INTO resume_analyses 
                (user_id, job_title, job_requirements, analysis_result, resumes_count) 
            VALUES (?, ?, ?, ?, ?)
        `; // [cite: 81]
        await conn.query(insertQuery, [
            userId,
            jobOpening.title,
            JSON.stringify(requirements),
            analysisText,
            req.files.length
        ]); // [cite: 82]
        console.log(`Análise salva para o usuário ${userId}`); // [cite: 83]
        res.json({
            jobOpening: jobOpening,
            requirements: requirements,
            bestCandidate: "Análise da IA (verifique o texto)",
            analyzedResumesCount: req.files.length, // [cite: 84]
            analysisDate: new Date(),
            analysisText: analysisText
        });
    } catch (error) {
        console.error("Erro em /api/hiring/analyze:", error); // [cite: 85]
        res.status(500).json({ error: 'Ocorreu um erro ao processar os currículos.' }); // [cite: 86]
    } finally {
        if (conn) conn.release(); // [cite: 87]
    }
});


// =================================
//        INICIALIZAÇÃO DO SERVIDOR
// =================================

const PORT = process.env.PORT || 3000; // [cite: 104]
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));