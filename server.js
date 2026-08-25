const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // ssl: { rejectUnauthorized: false } // Descomente caso use nuvem com SSL obrigatório (Supabase/Render)
});

const JWT_SECRET = process.env.JWT_SECRET || 'rps_super_secret_jwt_key_2026';

// Middleware de Autenticação JWT
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Sessão inválida ou expirada.' });
        req.user = user;
        next();
    });
}

// Middleware para verificar perfil Administrador
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Acesso restrito a administradores.' });
    }
    next();
}

// Função auxiliar para Auditoria
async function logAudit(clientOrPool, userId, action) {
    try {
        await clientOrPool.query(
            'INSERT INTO audit_logs (user_id, action_description) VALUES ($1, $2)',
            [userId, action]
        );
    } catch (e) {
        console.error('Erro ao registrar log:', e);
    }
}

// --- ROTAS DE AUTENTICAÇÃO ---
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1 AND is_active = TRUE', [username]);
        if (result.rows.length === 0) {
            return res.status(400).json({ error: 'Usuário ou senha inválidos.' });
        }
        const user = result.rows[0];
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(400).json({ error: 'Usuário ou senha inválidos.' });
        }

        await pool.query('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = $1', [user.id]);
        
        const token = jwt.sign({ id: user.id, username: user.username, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '8h' });
        
        res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- ROTAS DE USUÁRIOS (ADMIN) ---
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, name, email, username, role, is_active, created_at, last_login FROM users ORDER BY id ASC');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users', authenticateToken, requireAdmin, async (req, res) => {
    const { name, email, username, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (name, email, username, password_hash, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, username, role',
            [name, email, username, hashedPassword, role || 'user']
        );
        await logAudit(pool, req.user.id, `Criou o usuário ${username} (${role})`);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: 'Erro ao cadastrar usuário. Verifique se o e-mail ou usuário já existem.' });
    }
});

// --- ROTAS DO SISTEMA (DADOS COMPARTILHADOS) ---
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const clients = await pool.query('SELECT * FROM clients ORDER BY id ASC');
        const docTypes = await pool.query('SELECT * FROM doc_types ORDER BY id ASC');
        const configs = await pool.query('SELECT * FROM configs ORDER BY id ASC');
        const statuses = await pool.query('SELECT * FROM statuses ORDER BY id ASC');

        res.json({
            clients: clients.rows,
            docTypes: docTypes.rows,
            configs: configs.rows,
            statuses: statuses.rows
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Cadastrar Empresa
app.post('/api/clients', authenticateToken, async (req, res) => {
    const { name, cnpj } = req.body;
    try {
        const result = await pool.query('INSERT INTO clients (name, cnpj) VALUES ($1, $2) RETURNING *', [name, cnpj]);
        await logAudit(pool, req.user.id, `Cadastrou a empresa ${name}`);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Salvar / Editar Regra de Documento
app.post('/api/configs', authenticateToken, async (req, res) => {
    const { client_id, doc_id, custom_doc_name, entity, due_day, months } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO configs (client_id, doc_id, custom_doc_name, entity, due_day, months) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [client_id, doc_id, custom_doc_name, entity, due_day, months]
        );
        await logAudit(pool, req.user.id, `Adicionou regra de documento para a empresa ID ${client_id}`);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/configs/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM configs WHERE id = $1', [id]);
        await logAudit(pool, req.user.id, `Excluiu a regra de documento ID ${id}`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Alternar Status de Documento (Recebido / Pendente)
app.post('/api/statuses/toggle', authenticateToken, async (req, res) => {
    const { config_id, month } = req.body;
    try {
        const existing = await pool.query('SELECT * FROM statuses WHERE config_id = $1 AND month = $2', [config_id, month]);
        
        if (existing.rows.length > 0) {
            await pool.query('DELETE FROM statuses WHERE config_id = $1 AND month = $2', [config_id, month]);
            await logAudit(pool, req.user.id, `Removeu status de recebido da regra ID ${config_id} no mês ${month}`);
            res.json({ status: 'Pendente' });
        } else {
            await pool.query('INSERT INTO statuses (config_id, month, status) VALUES ($1, $2, $3)', [config_id, month, 'Recebido']);
            await logAudit(pool, req.user.id, `Marcou como Recebido a regra ID ${config_id} no mês ${month}`);
            res.json({ status: 'Recebido' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));