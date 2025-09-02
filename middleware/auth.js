// middleware/auth.js
const jwt = require('jsonwebtoken');

// IMPORTANTE: Use a mesma chave secreta do seu server.js
const JWT_SECRET = 'chave_secreta'; 

module.exports = function(req, res, next) {
    // Pega o token do cabeçalho de autorização (que vem do frontend)
    const token = req.header('x-auth-token');

    // Se não houver token, o acesso é negado
    if (!token) {
        return res.status(401).json({ message: 'Nenhum token, autorização negada.' });
    }

    try {
        // Verifica se o token é válido
        const decoded = jwt.verify(token, JWT_SECRET);

        // Adiciona a informação do usuário à requisição
        req.user = decoded.user;
        next(); // Continua para a próxima função (sua rota de chat/dashboard)

    } catch (error) {
        res.status(401).json({ message: 'Token não é válido.' });
    }
};