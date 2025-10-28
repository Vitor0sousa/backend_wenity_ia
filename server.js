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

// --- ADICIONADO ---
// Carrega as variáveis de ambiente do arquivo .env

// Importa a biblioteca do Gemini
const { GoogleGenerativeAI } = require('@google/generative-ai');
// ------------------
// Armazena o arquivo na memória como um Buffer

// ----------------------------------------------------------------


const app = express();

function generateTokens(user) {
    const accessTokenPayload = {
        user: {
            id: user.id,
            email: user.email
        }
    };
    
    // Access token com duração curta (1 hora)
    const accessToken = jwt.sign(
        accessTokenPayload, 
        process.env.JWT_SECRET, 
        { expiresIn: '1h' }
    );
    
    // Refresh token com duração longa (7 dias)
    const refreshToken = jwt.sign(
        accessTokenPayload, 
        process.env.JWT_SECRET, 
        { expiresIn: '7d' }
    );
    
    return { accessToken, refreshToken };
}



app.use((req, res, next) => {
  console.log('--- NOVA REQUISIÇÃO ---');
  console.log('Rota:', req.method, req.originalUrl);
  console.log('Cabeçalhos:', req.headers);
  console.log('-------------------------');
  next(); // Passa a requisição para a próxima rota
});

app.use(express.json());
app.use(cors());

const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

const pool = mariadb.createPool({
     host: 'localhost',
     user: 'root',
     password: 'root',
     database: 'wenetyia',
     connectionLimit: 5
});


// --- MODIFICADO ---
// Agora a chave secreta é lida do arquivo .env
const JWT_SECRET = process.env.JWT_SECRET;
// ------------------


// --- ADICIONADO: Configuração da API do Gemini ---
let model;
try {
  const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
  model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
  console.log("Modelo do Gemini inicializado com sucesso.");
} catch (error) {
  console.error("ERRO ao inicializar o modelo do Gemini:", error);
  model = null;
}
// ------------------------------------------------


// Rota de Registro (seu código original, sem alterações)
app.post('/api/register', async (req, res) => {
    // ... seu código de registro aqui ...
    const { name, email, password } = req.body;
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


// Rota de Login (seu código original, modificado para usar a nova JWT_SECRET)
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }
    
    let conn;
    try {
        conn = await pool.getConnection();
        const users = await conn.query("SELECT * FROM users WHERE email = ?", [email]);
        
        if (users.length === 0) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }
        
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }
        
        // Gera ambos os tokens
        const { accessToken, refreshToken } = generateTokens(user);
        
        // Salva o refresh token no banco (recomendado para poder revogar)
        await conn.query(
            "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
            [user.id, refreshToken]
        );
        
        // Retorna ambos os tokens e dados do usuário
        res.json({ 
            token: accessToken,
            refreshToken: refreshToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro no servidor.' });
    } finally {
        if (conn) conn.release();
    }
});


// --- ADICIONADO: Nova Rota do Chat Gemini ---
// A rota está protegida pelo middleware 'auth', ou seja,
// apenas usuários logados podem usá-la.
// Rota de Chat, agora com consulta à IA e salvamento no banco de dados
app.post('/api/chat', auth, async (req, res) => {
    // 'auth' é o middleware que já rodou. Ele verificou o token
    // e adicionou os dados do usuário em 'req.user'.

    // 1. Verifica se o modelo de IA foi inicializado corretamente
    if (!model) {
        return res.status(503).json({ error: "O modelo de IA não está disponível no momento." });
    }

    // Declara a variável de conexão aqui para que o bloco 'finally' possa acessá-la
    let conn; 

    try {
        // 2. Pega a mensagem e o histórico enviados pelo frontend
        const { message, history } = req.body;

        // Valida se uma mensagem foi de fato enviada
        if (!message) {
            return res.status(400).json({ error: 'Nenhuma mensagem foi fornecida.' });
        }

        // 3. Pega o ID do usuário que está fazendo a requisição.
        // O middleware 'auth' colocou essa informação em 'req.user' para nós.
        const userId = req.user.id;

        // 4. Seção de Interação com a API do Gemini
        // Inicia uma sessão de chat com o histórico da conversa
        const chat = model.startChat({
            history: history || [],
        });

        // Envia a nova mensagem do usuário para o Gemini e aguarda a resposta
        const result = await chat.sendMessage(message);
        const response = result.response;
        const modelResponseText = response.text();

        // 5. Seção para Salvar a Conversa no Banco de Dados
        // Obtém uma conexão do nosso pool de conexões MariaDB
        conn = await pool.getConnection();

        // Salva a mensagem ENVIADA pelo usuário
        await conn.query(
            "INSERT INTO chat_history (user_id, role, message_text) VALUES (?, ?, ?)",
            [userId, 'user', message]
        );
        
        // Salva a mensagem RECEBIDA do modelo (IA)
        await conn.query(
            "INSERT INTO chat_history (user_id, role, message_text) VALUES (?, ?, ?)",
            [userId, 'model', modelResponseText]
        );
        
        console.log(`Conversa salva para o usuário com ID: ${userId}`);

        // 6. Envia a resposta do Gemini de volta para o frontend
        res.json({ response: modelResponseText });

    } catch (error) {
        // 7. Tratamento de Erros
        // Se qualquer coisa nos blocos 'try' der errado, o código pula para cá
        console.error("Erro na rota /api/chat:", error);
        res.status(500).json({ error: 'Ocorreu um erro ao processar sua mensagem.' });

    } finally {
        // 8. Libera a Conexão
        // Este bloco SEMPRE roda, quer tenha dado erro ou não.
        // É crucial para devolver a conexão ao pool e evitar sobrecarga do banco.
        if (conn) {
            conn.release();
        }
    }
});
// ------------------------------------------
// ROTA PARA CARREGAR O HISTÓRICO DO CHAT
app.get('/api/chat/history', auth, async (req, res) => {
    // --- ADICIONADO: CABEÇALHO PARA IMPEDIR O CACHE DO NAVEGADOR ---
    res.setHeader('Cache-Control', 'no-store');
    // -----------------------------------------------------------

    let conn;
    try {
        conn = await pool.getConnection();
        const userId = req.user.id; // ID do usuário vem do token (via middleware auth)

        const rows = await conn.query(
            "SELECT role, message_text FROM chat_history WHERE user_id = ? ORDER BY created_at ASC",
            [userId]
        );

        // Formata os dados para o formato que o Gemini e o frontend esperam
        const history = rows.map(row => ({
            role: row.role,
            parts: [{ text: row.message_text }]
        }));

        res.json(history);

    } catch (error) {
        console.error("Erro ao buscar histórico do chat:", error);
        res.status(500).json({ message: 'Erro ao buscar histórico.' });
    } finally {
        if (conn) conn.release();
    }
});


// --- ADICIONADO: Rota para Analisar Currículo via Gemini ---

app.post('/api/analyze-resume', auth, upload.single('resume'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: 'Nenhum arquivo de currículo foi enviado.' });
    }

    try {
       

        // Extrai o texto do PDF que está na memória (req.file.buffer)
        const data = await pdf(req.file.buffer);
        const resumeText = data.text;

        // Pega a instrução específica do usuário
        const userPrompt = req.body.prompt || "Faça uma análise geral deste currículo.";

        // Montagem do Prompt para o Gemini
        const fullPrompt = `
            Você é um assistente de RH especialista em recrutamento técnico. Sua tarefa é analisar o currículo a seguir.

            Instrução do recrutador: "${userPrompt}"

            --- CONTEÚDO DO CURRÍCULO ---
            ${resumeText}
            --- FIM DO CURRÍCULO ---

            Com base na instrução do recrutador, forneça uma análise clara e objetiva do currículo.
        `;

        const result = await model.generateContent(fullPrompt);
        const response = result.response;
        const analysisText = response.text();

        res.json({ response: analysisText });

    } catch (error) {
        console.error("Erro ao analisar o currículo:", error);
        res.status(500).json({ error: 'Ocorreu um erro ao processar o arquivo PDF.' });
    }
});
// Rota para renovar o token usando o refresh token

app.post('/api/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token não fornecido.' });
    }
    
    let conn;
    try {
        // Verifica se o token é válido
        const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);
        
        conn = await pool.getConnection();
        
        // Verifica se o refresh token existe no banco e não expirou
        const tokens = await conn.query(
            "SELECT * FROM refresh_tokens WHERE token = ? AND user_id = ? AND expires_at > NOW() AND revoked = 0",
            [refreshToken, decoded.user.id]
        );
        
        if (tokens.length === 0) {
            return res.status(401).json({ message: 'Refresh token inválido ou expirado.' });
        }
        
        // Busca dados atualizados do usuário
        const users = await conn.query("SELECT * FROM users WHERE id = ?", [decoded.user.id]);
        
        if (users.length === 0) {
            return res.status(401).json({ message: 'Usuário não encontrado.' });
        }
        
        const user = users[0];
        
        // Gera novos tokens
        const { accessToken, refreshToken: newRefreshToken } = generateTokens(user);
        
        // Revoga o refresh token antigo
        await conn.query(
            "UPDATE refresh_tokens SET revoked = 1 WHERE token = ?",
            [refreshToken]
        );
        
        // Salva o novo refresh token
        await conn.query(
            "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))",
            [user.id, newRefreshToken]
        );
        
        res.json({ 
            token: accessToken,
            refreshToken: newRefreshToken 
        });
        
    } catch (error) {
        if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Refresh token inválido.' });
        }
        console.error('Erro ao renovar token:', error);
        res.status(500).json({ message: 'Erro no servidor.' });
    } finally {
        if (conn) conn.release();
    }
});

app.post('/api/logout', auth, async (req, res) => {
    const { refreshToken } = req.body;
    let conn;
    
    try {
        conn = await pool.getConnection();
        
        if (refreshToken) {
            // Revoga o refresh token específico
            await conn.query(
                "UPDATE refresh_tokens SET revoked = 1 WHERE token = ? AND user_id = ?",
                [refreshToken, req.user.id]
            );
        } else {
            // Revoga todos os refresh tokens do usuário
            await conn.query(
                "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?",
                [req.user.id]
            );
        }
        
        res.json({ message: 'Logout realizado com sucesso.' });
        
    } catch (error) {
        console.error('Erro no logout:', error);
        res.status(500).json({ message: 'Erro ao fazer logout.' });
    } finally {
        if (conn) conn.release();
    }
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));