// ===================================
// IMPORTAÇÕES DAS BIBLIOTECAS
// ===================================
require('dotenv').config();               // ✅ CARREGAR VARIÁVEIS DE AMBIENTE
const express = require('express');        // Framework web
const mongoose = require('mongoose');      // Banco de dados MongoDB
const cors = require('cors');              // Permitir requisições de outros domínios
const multer = require('multer');          // Upload de arquivos
const XLSX = require('xlsx');              // Ler arquivos Excel
const path = require('path');              // Trabalhar com caminhos de arquivos
const bcrypt = require('bcryptjs');        // Criptografar senhas
const session = require('express-session'); // Gerenciar sessões de login
const MongoStore = require('connect-mongo'); // Salvar sessões no MongoDB

// ===================================
// CONFIGURAÇÃO INICIAL
// ===================================
const app = express();
const PORT = process.env.PORT || 3000;

// ===================================
// MIDDLEWARES (Configurações que rodam antes das rotas)
// ===================================
app.use(cors());                    // Permitir requisições AJAX
app.use(express.json());            // Ler dados JSON do corpo das requisições
app.use(express.static('public'));  // Servir arquivos estáticos (HTML, CSS, JS)

// Configuração de sessão (para lembrar quem está logado)
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',  // ✅ VARIÁVEL DE AMBIENTE
  resave: false,                        // Não salvar sessão se não modificada
  saveUninitialized: false,             // Não criar sessão vazia
  store: MongoStore.create({            // Salvar sessões no MongoDB
    mongoUrl: process.env.MONGODB_URI   // ✅ VARIÁVEL DE AMBIENTE
  }),
  cookie: {
    secure: false,        // true apenas com HTTPS
    httpOnly: true,       // Cookie não acessível via JavaScript (segurança)
    maxAge: 24 * 60 * 60 * 1000  // 24 horas em milissegundos
  }
}));

// Configuração do multer para upload de arquivos Excel
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// ===================================
// CONEXÃO COM BANCO DE DADOS
// ===================================
mongoose.connect(process.env.MONGODB_URI, {  // ✅ VARIÁVEL DE AMBIENTE
  useNewUrlParser: true,
  useUnifiedTopology: true
});

mongoose.connection.on('connected', () => {
  console.log('✅ Conectado ao MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.log('❌ Erro na conexão com MongoDB:', err);
});

// ===================================
// MODELOS DO BANCO DE DADOS (Schemas)
// ===================================

// Modelo para CLIENTES da barbearia (apenas dados - não fazem login)
const clienteSchema = new mongoose.Schema({
  nome: {
    type: String,
    required: true,
    trim: true
  },
  ddi: {
    type: String,
    required: true,
    trim: true,
    default: '55' // DDI padrão do Brasil SEM +
  },
  telefone: {
    type: String,
    required: true,
    trim: true
  },
  dataNascimento: {
    type: Date,
    required: false,  // ✅ AGORA OPCIONAL para clientes vindos do histórico
    default: null
  },
  unidade: {
    type: String,
    required: false,  // ✅ OPCIONAL - nem todos os clientes têm unidade definida
    trim: true,
    default: null     // ✅ SEM UNIDADE POR PADRÃO
  },
  // ✅ NOVO: Histórico de serviços
  historicoServicos: [{
    servico: {
      type: String,
      required: true,
      trim: true
    },
    profissional: {
      type: String,
      required: true,
      trim: true
    },
    dataServico: {
      type: Date,
      required: true
    },
    adicionadoEm: {
      type: Date,
      default: Date.now
    }
  }],
  criadoEm: {
    type: Date,
    default: Date.now
  }
});

// Modelo para ADMIN (você e funcionários - fazem login no sistema)
const adminSchema = new mongoose.Schema({
  nome: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,        // Email único
    trim: true,
    lowercase: true      // Converter para minúsculo
  },
  senha: {
    type: String,
    required: true
  },
  tipo: {
    type: String,
    enum: ['admin', 'funcionario'],  // Apenas estes valores
    default: 'admin'
  },
  ativo: {
    type: Boolean,
    default: true        // Para desativar funcionários se necessário
  },
  criadoEm: {
    type: Date,
    default: Date.now
  }
});

// MIDDLEWARE DO SCHEMA: Criptografar senha antes de salvar
adminSchema.pre('save', async function(next) {
  // Se a senha não foi modificada, pular
  if (!this.isModified('senha')) return next();
  
  // Criptografar a senha
  this.senha = await bcrypt.hash(this.senha, 12);
  next();
});

// MÉTODO DO SCHEMA: Verificar se senha está correta
adminSchema.methods.verificarSenha = async function(senhaCandidata) {
  return await bcrypt.compare(senhaCandidata, this.senha);
};

// Modelo para COMUNICAÇÕES (histórico de mensagens enviadas via WhatsApp)
const comunicacaoSchema = new mongoose.Schema({
  titulo: {
    type: String,
    required: true,
    trim: true
  },
  totalClientes: {
    type: Number,
    required: true,
    default: 0
  },
  clientesEncontrados: {
    type: Number,
    required: true,
    default: 0
  },
  clientesNaoEncontrados: {
    type: Number,
    required: true,
    default: 0
  },
  clientes: [{
    numeroOriginal: {
      type: String,
      required: true,
      trim: true
    },
    encontrado: {
      type: Boolean,
      required: true,
      default: false
    },
    clienteId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Cliente',
      required: false
    },
    cliente: {
      type: Object,
      required: false
    }
  }],
  realizados: [{
    clienteId: {
      type: String, // Pode ser ObjectId ou índice do array para clientes não encontrados
      required: true
    },
    realizado: {
      type: Boolean,
      default: true
    },
    dataRealizacao: {
      type: Date,
      default: Date.now
    }
  }],
  criadoEm: {
    type: Date,
    default: Date.now
  }
});

// ===================================
// 🆕 NOVO MODELO: ESTATÍSTICAS DE MOVIMENTOS
// ===================================
const estatisticasMovimentoSchema = new mongoose.Schema({
  ultimaImportacao: {
    type: Date,
    default: null
  },
  totalMovimentos: {
    type: Number,
    default: 0
  },
  movimentosEsteMes: {
    type: Number,
    default: 0
  },
  mesReferencia: {
    type: String, // YYYY-MM formato
    default: () => {
      const now = new Date();
      return `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
    }
  },
  ultimoArquivoImportado: {
    type: String,
    default: null
  },
  atualizadoEm: {
    type: Date,
    default: Date.now
  }
});

// ===================================
// 🆕 NOVO MODELO: ESTATÍSTICAS DE CADASTRO
// ===================================
const estatisticasCadastroSchema = new mongoose.Schema({
  ultimaImportacao: {
    type: Date,
    default: null
  },
  totalClientes: {
    type: Number,
    default: 0
  },
  clientesEsteMes: {
    type: Number,
    default: 0
  },
  mesReferencia: {
    type: String, // YYYY-MM formato
    default: () => {
      const now = new Date();
      return `${now.getFullYear()}-${(now.getMonth() + 1).toString().padStart(2, '0')}`;
    }
  },
  ultimoArquivoImportado: {
    type: String,
    default: null
  },
  atualizadoEm: {
    type: Date,
    default: Date.now
  }
});

// ===================================
// 🆕 NOVO MODELO: HISTÓRICO DE IMPORTAÇÕES DE MOVIMENTO
// ===================================
const historicoMovimentoSchema = new mongoose.Schema({
  dataImportacao: {
    type: Date,
    default: Date.now
  },
  nomeArquivo: {
    type: String,
    required: true
  },
  servicosAdicionados: {
    type: Number,
    default: 0
  },
  clientesAtualizados: {
    type: Number,
    default: 0
  },
  clientesNovos: {
    type: Number,
    default: 0
  },
  totalLinhasProcessadas: {
    type: Number,
    default: 0
  },
  totalErros: {
    type: Number,
    default: 0
  },
  usuarioImportacao: {
    type: String,
    required: true
  }
});

// ===================================
// 🆕 NOVO MODELO: HISTÓRICO DE IMPORTAÇÕES DE CADASTRO
// ===================================
const historicoCadastroSchema = new mongoose.Schema({
  dataImportacao: {
    type: Date,
    default: Date.now
  },
  nomeArquivo: {
    type: String,
    required: true
  },
  clientesAdicionados: {
    type: Number,
    default: 0
  },
  clientesJaExistiam: {
    type: Number,
    default: 0
  },
  totalLinhasProcessadas: {
    type: Number,
    default: 0
  },
  totalErros: {
    type: Number,
    default: 0
  },
  usuarioImportacao: {
    type: String,
    required: true
  }
});

// Criar os modelos
const Cliente = mongoose.model('Cliente', clienteSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Comunicacao = mongoose.model('Comunicacao', comunicacaoSchema);
const EstatisticasMovimento = mongoose.model('EstatisticasMovimento', estatisticasMovimentoSchema);
const EstatisticasCadastro = mongoose.model('EstatisticasCadastro', estatisticasCadastroSchema);
const HistoricoMovimento = mongoose.model('HistoricoMovimento', historicoMovimentoSchema);
const HistoricoCadastro = mongoose.model('HistoricoCadastro', historicoCadastroSchema);

// ===================================
// MIDDLEWARE DE AUTENTICAÇÃO
// ===================================

// Verificar se usuário está logado
const verificarLogin = async (req, res, next) => {
  try {
    // Verificar se existe ID do admin na sessão
    if (!req.session.adminId) {
      return res.status(401).json({ erro: 'Acesso negado. Faça login primeiro.' });
    }

    // Buscar admin no banco
    const admin = await Admin.findById(req.session.adminId);
    if (!admin || !admin.ativo) {
      req.session.destroy(); // Destruir sessão inválida
      return res.status(401).json({ erro: 'Admin não encontrado ou desativado.' });
    }

    req.admin = admin; // Adicionar admin na requisição
    next(); // Continuar para próxima função
  } catch (error) {
    res.status(401).json({ erro: 'Erro de autenticação.' });
  }
};

// ===================================
// ROTAS DE PÁGINAS (HTML)
// ===================================

// Página inicial: Login ou Dashboard
app.get('/', (req, res) => {
  // Se já está logado, ir para dashboard
  if (req.session.adminId) {
    return res.redirect('/dashboard');
  }
  
  // Se não está logado, mostrar login
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Dashboard (área restrita)
app.get('/dashboard', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Página de Atualizar Dados
app.get('/atualizar-dados', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'atualizar-dados.html'));
});

// Página de Consultar Dados
app.get('/consultar-dados', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'consultar-dados.html'));
});

// ✅ NOVA: Página de Detalhes do Cliente
app.get('/cliente-detalhes', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'cliente-detalhes.html'));
});

// ✅ NOVA: Página de Comunicação Clientes
app.get('/comunicacao-clientes', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'comunicacao-clientes.html'));
});

// ✅ NOVA: Página de Detalhes da Comunicação
app.get('/comunicacao-detalhes', (req, res) => {
  if (!req.session.adminId) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'comunicacao-detalhes.html'));
});

// ===================================
// ROTAS DA API - AUTENTICAÇÃO
// ===================================

// Fazer login
app.post('/api/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ erro: 'Email e senha são obrigatórios.' });
    }

    // Buscar admin por email
    const admin = await Admin.findOne({ email, ativo: true });
    if (!admin || !(await admin.verificarSenha(senha))) {
      return res.status(401).json({ erro: 'Email ou senha incorretos.' });
    }

    // Criar sessão
    req.session.adminId = admin._id;

    res.json({
      mensagem: 'Login realizado com sucesso!',
      admin: {
        nome: admin.nome,
        email: admin.email,
        tipo: admin.tipo
      }
    });
  } catch (error) {
    res.status(500).json({ erro: 'Erro no login.' });
  }
});

// Fazer logout
app.post('/api/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ erro: 'Erro ao fazer logout.' });
    }
    res.json({ mensagem: 'Logout realizado com sucesso!' });
  });
});

// Verificar se está logado
app.get('/api/auth-status', async (req, res) => {
  try {
    if (!req.session.adminId) {
      return res.json({ logado: false });
    }

    const admin = await Admin.findById(req.session.adminId);
    if (!admin || !admin.ativo) {
      req.session.destroy();
      return res.json({ logado: false });
    }

    res.json({
      logado: true,
      admin: {
        nome: admin.nome,
        email: admin.email,
        tipo: admin.tipo
      }
    });
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao verificar autenticação.' });
  }
});

// ===================================
// ROTAS DA API - GESTÃO DE ADMINS (PROTEGIDAS)
// ===================================

// Listar admins (apenas para admin principal)
app.get('/api/admins', verificarLogin, async (req, res) => {
  try {
    // Verificar se é admin principal
    if (req.admin.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const admins = await Admin.find({}, '-senha').sort({ nome: 1 });
    res.json(admins);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar admins.' });
  }
});

// Criar novo admin (apenas para admin principal)
app.post('/api/admins', verificarLogin, async (req, res) => {
  try {
    // Verificar se é admin principal
    if (req.admin.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Apenas o administrador principal pode criar novos usuários.' });
    }

    const { nome, email, senha, tipo } = req.body;
    
    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Nome, email e senha são obrigatórios.' });
    }

    if (senha.length < 6) {
      return res.status(400).json({ erro: 'A senha deve ter pelo menos 6 caracteres.' });
    }

    // Verificar se email já existe
    const adminExistente = await Admin.findOne({ email });
    if (adminExistente) {
      return res.status(400).json({ erro: 'Este email já está sendo usado.' });
    }

    const novoAdmin = new Admin({
      nome,
      email,
      senha, // Será criptografada automaticamente
      tipo: tipo || 'funcionario'
    });

    await novoAdmin.save();

    res.status(201).json({
      mensagem: 'Admin criado com sucesso!',
      admin: {
        nome: novoAdmin.nome,
        email: novoAdmin.email,
        tipo: novoAdmin.tipo
      }
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ erro: 'Este email já está sendo usado.' });
    }
    res.status(500).json({ erro: 'Erro ao criar admin.' });
  }
});

// Atualizar admin
app.put('/api/admins/:id', verificarLogin, async (req, res) => {
  try {
    if (req.admin.tipo !== 'admin') {
      return res.status(403).json({ erro: 'Acesso negado.' });
    }

    const { nome, email, ativo } = req.body;
    
    const adminAtualizado = await Admin.findByIdAndUpdate(
      req.params.id,
      { nome, email, ativo },
      { new: true, select: '-senha' }
    );

    if (!adminAtualizado) {
      return res.status(404).json({ erro: 'Admin não encontrado.' });
    }

    res.json(adminAtualizado);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao atualizar admin.' });
  }
});

// ===================================
// 🆕 ROTAS DA API - ESTATÍSTICAS DE MOVIMENTO (PROTEGIDAS)
// ===================================

// Buscar estatísticas de movimento
app.get('/api/estatisticas-movimento', verificarLogin, async (req, res) => {
  try {
    let stats = await EstatisticasMovimento.findOne();
    
    if (!stats) {
      // Criar estatísticas iniciais se não existir
      stats = new EstatisticasMovimento();
      await stats.save();
    }
    
    // Verificar se mudou o mês (resetar contador mensal)
    const mesAtual = new Date().toISOString().slice(0, 7); // YYYY-MM
    if (stats.mesReferencia !== mesAtual) {
      stats.mesReferencia = mesAtual;
      stats.movimentosEsteMes = 0;
      await stats.save();
    }
    
    res.json(stats);
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ erro: 'Erro ao buscar estatísticas de movimento.' });
  }
});

// 🆕 NOVA ROTA: Buscar histórico completo de movimento
app.get('/api/historico-movimento', verificarLogin, async (req, res) => {
  try {
    const historico = await HistoricoMovimento.find()
      .sort({ dataImportacao: -1 })
      .limit(50); // Últimas 50 importações
    
    // Calcular estatísticas do histórico
    const totalMovimentos = await HistoricoMovimento.aggregate([
      { $group: { _id: null, total: { $sum: "$servicosAdicionados" } } }
    ]);
    
    const ultimaImportacao = historico.length > 0 ? historico[0] : null;
    
    res.json({
      historico,
      estatisticas: {
        ultimaImportacao: ultimaImportacao ? ultimaImportacao.dataImportacao : null,
        totalMovimentos: totalMovimentos.length > 0 ? totalMovimentos[0].total : 0,
        totalImportacoes: historico.length
      }
    });
  } catch (error) {
    console.error('Erro ao buscar histórico de movimento:', error);
    res.status(500).json({ erro: 'Erro ao buscar histórico de movimento.' });
  }
});

// 🆕 NOVA ROTA: Buscar histórico completo de cadastro
app.get('/api/historico-cadastro', verificarLogin, async (req, res) => {
  try {
    const historico = await HistoricoCadastro.find()
      .sort({ dataImportacao: -1 })
      .limit(50); // Últimas 50 importações
    
    // Calcular estatísticas do histórico
    const totalClientes = await HistoricoCadastro.aggregate([
      { $group: { _id: null, total: { $sum: "$clientesAdicionados" } } }
    ]);
    
    const ultimaImportacao = historico.length > 0 ? historico[0] : null;
    
    res.json({
      historico,
      estatisticas: {
        ultimaImportacao: ultimaImportacao ? ultimaImportacao.dataImportacao : null,
        totalClientes: totalClientes.length > 0 ? totalClientes[0].total : 0,
        totalImportacoes: historico.length
      }
    });
  } catch (error) {
    console.error('Erro ao buscar histórico de cadastro:', error);
    res.status(500).json({ erro: 'Erro ao buscar histórico de cadastro.' });
  }
});

// ===================================
// 🆕 ROTAS DA API - ESTATÍSTICAS DE CADASTRO (PROTEGIDAS)
// ===================================

// Buscar estatísticas de cadastro
app.get('/api/estatisticas-cadastro', verificarLogin, async (req, res) => {
  try {
    let stats = await EstatisticasCadastro.findOne();
    
    if (!stats) {
      // Criar estatísticas iniciais se não existir
      const totalClientesAtual = await Cliente.countDocuments();
      stats = new EstatisticasCadastro({
        totalClientes: totalClientesAtual
      });
      await stats.save();
    }
    
    // Verificar se mudou o mês (resetar contador mensal)
    const mesAtual = new Date().toISOString().slice(0, 7); // YYYY-MM
    if (stats.mesReferencia !== mesAtual) {
      stats.mesReferencia = mesAtual;
      stats.clientesEsteMes = 0;
      await stats.save();
    }
    
    // Sempre atualizar o total com a contagem real
    const totalClientesAtual = await Cliente.countDocuments();
    if (stats.totalClientes !== totalClientesAtual) {
      stats.totalClientes = totalClientesAtual;
      await stats.save();
    }
    
    res.json(stats);
  } catch (error) {
    console.error('Erro ao buscar estatísticas de cadastro:', error);
    res.status(500).json({ erro: 'Erro ao buscar estatísticas de cadastro.' });
  }
});

// ===================================
// ROTAS DA API - CLIENTES (PROTEGIDAS)
// ===================================

// Listar todos os clientes
app.get('/api/clientes', verificarLogin, async (req, res) => {
  try {
    const clientes = await Cliente.find().sort({ nome: 1 });
    res.json(clientes);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar clientes.' });
  }
});

// Buscar cliente por ID
app.get('/api/clientes/:id', verificarLogin, async (req, res) => {
  try {
    const cliente = await Cliente.findById(req.params.id);
    if (!cliente) {
      return res.status(404).json({ erro: 'Cliente não encontrado.' });
    }
    res.json(cliente);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar cliente.' });
  }
});

// Criar novo cliente
app.post('/api/clientes', verificarLogin, async (req, res) => {
  try {
    const { nome, ddi, telefone, dataNascimento } = req.body;
    
    // Validar dados obrigatórios
    if (!nome || !ddi || !telefone || !dataNascimento) {
      return res.status(400).json({ erro: 'Nome, DDI, telefone e data de nascimento são obrigatórios.' });
    }
    
    // 🔧 CORREÇÃO: Limpar DDI removendo + se houver e definir padrão
    let ddiLimpo = ddi.toString().trim().replace(/^\+/, ''); // Remove + do início
    if (!ddiLimpo || ddiLimpo === '') {
      ddiLimpo = '55'; // Padrão Brasil se vazio
    }
    
    // ✅ NOVO: Formatar telefone no padrão (xx) xxxxx-xxxx
    const telefoneLimpo = formatarTelefone(telefone.toString().trim());
    
    // VERIFICAR SE TELEFONE JÁ EXISTE (DDI + Telefone)
    const telefoneCompleto = `${ddiLimpo} ${telefoneLimpo}`;
    console.log(`🔍 Verificando duplicata para telefone completo: "${telefoneCompleto}"`);
    
    // Primeira verificação: DDI + telefone exato
    let clienteExistente = await Cliente.findOne({ 
      ddi: ddiLimpo, 
      telefone: telefoneLimpo 
    });
    
    // Segunda verificação: apenas números do telefone (para compatibilidade)
    if (!clienteExistente) {
      const telefoneApenasNumeros = telefoneLimpo.replace(/\D/g, '');
      console.log(`🔍 Verificando também apenas números: "${telefoneApenasNumeros}"`);
      
      clienteExistente = await Cliente.findOne({ 
        telefone: { $regex: telefoneApenasNumeros, $options: 'i' } 
      });
    }
    
    if (clienteExistente) {
      console.log(`❌ Telefone já existe para cliente: ${clienteExistente.nome}`);
      return res.status(400).json({ 
        erro: `Telefone "${telefoneCompleto}" já está cadastrado para o cliente: ${clienteExistente.nome}` 
      });
    }
    
    console.log(`✅ Telefone "${telefoneCompleto}" é novo, pode adicionar`);
    
    // Criar cliente
    const novoCliente = new Cliente({
      nome: nome.trim(),
      ddi: ddiLimpo,
      telefone: telefoneLimpo,
      dataNascimento: new Date(dataNascimento)
    });
    
    await novoCliente.save();
    console.log(`✅ Cliente "${nome}" adicionado com sucesso`);
    
    res.status(201).json(novoCliente);
  } catch (error) {
    console.error('❌ Erro ao criar cliente:', error);
    res.status(400).json({ erro: 'Erro ao criar cliente.' });
  }
});

// Atualizar cliente
app.put('/api/clientes/:id', verificarLogin, async (req, res) => {
  try {
    const { nome, ddi, telefone, dataNascimento, unidade } = req.body;
    
    // ✅ CORREÇÃO: Data de nascimento agora é opcional
    if (!nome || !ddi || !telefone) {
      return res.status(400).json({ erro: 'Nome, DDI e telefone são obrigatórios. Data de nascimento e unidade são opcionais.' });
    }
    
    // 🔧 CORREÇÃO: Limpar DDI removendo + se houver e definir padrão
    let ddiLimpo = ddi.toString().trim().replace(/^\+/, ''); // Remove + do início
    if (!ddiLimpo || ddiLimpo === '') {
      ddiLimpo = '55'; // Padrão Brasil se vazio
    }
    
    // ✅ NOVO: Formatar telefone no padrão (xx) xxxxx-xxxx
    const telefoneLimpo = formatarTelefone(telefone.toString().trim());
    const unidadeLimpa = unidade && unidade.toString().trim() !== '' ? unidade.toString().trim() : null;
    
    // ✅ PROCESSAR DATA DE NASCIMENTO (PODE SER NULL)
    let dataConvertida = null;
    if (dataNascimento && dataNascimento.toString().trim() !== '') {
      try {
        dataConvertida = new Date(dataNascimento);
        // Validar se a data é válida
        if (isNaN(dataConvertida.getTime())) {
          dataConvertida = null;
        }
      } catch (error) {
        dataConvertida = null;
      }
    }
    
    // VERIFICAR SE TELEFONE JÁ EXISTE (exceto para o próprio cliente)
    const telefoneCompleto = `${ddiLimpo} ${telefoneLimpo}`;
    console.log(`🔍 Verificando duplicata para telefone: "${telefoneCompleto}" (editando cliente ${req.params.id})`);
    
    // Primeira verificação: DDI + telefone exato
    let clienteExistente = await Cliente.findOne({ 
      ddi: ddiLimpo,
      telefone: telefoneLimpo,
      _id: { $ne: req.params.id } // Excluir o próprio cliente da busca
    });
    
    // Segunda verificação: apenas números
    if (!clienteExistente) {
      const telefoneApenasNumeros = telefoneLimpo.replace(/\D/g, '');
      
      clienteExistente = await Cliente.findOne({ 
        telefone: { $regex: telefoneApenasNumeros, $options: 'i' },
        _id: { $ne: req.params.id } // Excluir o próprio cliente da busca
      });
    }
    
    if (clienteExistente) {
      console.log(`❌ Telefone já existe para outro cliente: ${clienteExistente.nome}`);
      return res.status(400).json({ 
        erro: `Telefone "${telefoneCompleto}" já está cadastrado para outro cliente: ${clienteExistente.nome}` 
      });
    }
    
    // Atualizar cliente
    const clienteAtualizado = await Cliente.findByIdAndUpdate(
      req.params.id,
      {
        nome: nome.trim(),
        ddi: ddiLimpo,
        telefone: telefoneLimpo,
        dataNascimento: dataConvertida, // ✅ PODE SER NULL
        unidade: unidadeLimpa // ✅ NOVO: Incluir unidade na atualização
      },
      { new: true }
    );
    
    if (!clienteAtualizado) {
      return res.status(404).json({ erro: 'Cliente não encontrado.' });
    }
    
    console.log(`✅ Cliente "${nome}" atualizado com sucesso (unidade: ${unidadeLimpa || 'N/A'})`);
    res.json(clienteAtualizado);
  } catch (error) {
    console.error('❌ Erro ao atualizar cliente:', error);
    res.status(400).json({ erro: 'Erro ao atualizar cliente.' });
  }
});

// Deletar cliente
app.delete('/api/clientes/:id', verificarLogin, async (req, res) => {
  try {
    const clienteDeletado = await Cliente.findByIdAndDelete(req.params.id);
    
    if (!clienteDeletado) {
      return res.status(404).json({ erro: 'Cliente não encontrado.' });
    }
    
    res.json({ mensagem: 'Cliente deletado com sucesso.' });
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao deletar cliente.' });
  }
});

// ===================================
// UPLOAD DE EXCEL - VERSÃO CORRIGIDA E MELHORADA
// ===================================
app.post('/api/upload-excel', verificarLogin, upload.single('excel'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ erro: 'Nenhum arquivo enviado.' });
    }
    
    // Ler arquivo Excel
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    
    // Converter para JSON
    const dados = XLSX.utils.sheet_to_json(worksheet);
    
    if (dados.length === 0) {
      return res.status(400).json({ erro: 'Arquivo Excel está vazio ou não possui dados válidos.' });
    }
    
    let clientesInseridos = 0;
    let clientesJaExistem = 0;
    let erros = [];
    let sucessos = [];
    
    console.log(`📊 Processando ${dados.length} linhas do Excel...`);
    
    // DEBUG: Mostrar estrutura da primeira linha para diagnóstico
    console.log('📋 Estrutura da primeira linha:', dados[0]);
    console.log('📋 Chaves disponíveis:', Object.keys(dados[0]));
    
    // DEBUG: Mostrar todos os telefones já cadastrados
    const telefonesExistentes = await Cliente.find({}, 'nome telefone ddi').lean();
    console.log(`📱 Telefones já cadastrados no banco:`, telefonesExistentes.map(c => `${c.nome}: ${c.ddi || '+55'} ${c.telefone}`));
    
    for (let i = 0; i < dados.length; i++) {
      const linha = dados[i];
      const numeroLinha = i + 2; // +2 porque linha 1 é cabeçalho e arrays começam em 0
      
      try {
        // 🔧 MAPEAMENTO MELHORADO DE COLUNAS
        // Buscar nome
        const nome = linha.Nome || linha.nome || linha.NOME || 
                    linha['Nome Completo'] || linha.name || linha.Name || 
                    linha['NOME COMPLETO'] || linha['Nome completo'] || null;
        
        // Buscar DDI (com valor padrão SEM +)
        const ddi = linha.DDI || linha.ddi || linha['Código País'] || 
                   linha['CODIGO PAIS'] || linha.country_code || '55';
        
        // Buscar telefone
        const telefone = linha.Telefone || linha.telefone || linha.TELEFONE || 
                        linha.phone || linha.celular || linha.Celular || 
                        linha.CELULAR || linha['Número'] || linha.numero || null;
        
        // Buscar data de nascimento
        const dataNascimento = linha['Data de Nascimento'] || linha.dataNascimento || 
                              linha['DATA DE NASCIMENTO'] || linha.nascimento || 
                              linha.birthday || linha.birth || linha.Nascimento ||
                              linha['Data Nascimento'] || linha['DATA_NASCIMENTO'] || null;
        
        // ✅ NOVO: Buscar data de cadastro da planilha
        const dataCadastro = linha.Cadastro || linha.cadastro || linha.CADASTRO || 
                           linha['Data Cadastro'] || linha['DATA CADASTRO'] || 
                           linha['Data de Cadastro'] || linha['DATA DE CADASTRO'] || null;
        
        // 🔧 VALIDAÇÃO CORRIGIDA - APENAS TELEFONE É OBRIGATÓRIO
        const telefoneValido = telefone && telefone.toString().trim() !== '' && telefone.toString().toLowerCase() !== 'vazio';
        
        // Debug detalhado para linha com problema
        if (!telefoneValido) {
          console.log(`🚨 LINHA ${numeroLinha} - DEBUG:`);
          console.log(`   Nome encontrado: "${nome || 'N/A'}"`);
          console.log(`   Telefone encontrado: "${telefone}" | Válido: ${telefoneValido}`);
          console.log(`   Data encontrada: "${dataNascimento || 'N/A'}"`);
          console.log(`   Objeto completo:`, linha);
        }
        
        // APENAS TELEFONE É OBRIGATÓRIO
        if (!telefoneValido) {
          erros.push(`Linha ${numeroLinha}: Telefone obrigatório está vazio ou inválido - Telefone: "${telefone || 'VAZIO'}"`);
          continue;
        }
        
        // 🔧 LIMPEZA E VALIDAÇÃO MELHORADA DO DDI
        const nomeLimpo = nome ? nome.toString().trim() : 'Cliente sem nome'; // ✅ PADRÃO se vazio
        let ddiLimpo = ddi ? ddi.toString().trim() : '55'; // ✅ PADRÃO se vazio
        // 🔧 REMOVER + DO DDI SE HOUVER
        ddiLimpo = ddiLimpo.replace(/^\+/, ''); // Remove + do início
        if (!ddiLimpo || ddiLimpo === '') {
          ddiLimpo = '55'; // Padrão Brasil se ficar vazio
        }
        
        // ✅ NOVO: Formatar telefone no padrão (xx) xxxxx-xxxx
        const telefoneLimpo = formatarTelefone(telefone.toString().trim());
        
        // Validar tamanho mínimo do telefone
        const telefoneApenasNumeros = telefoneLimpo.replace(/\D/g, '');
        if (telefoneApenasNumeros.length < 8) {
          erros.push(`Linha ${numeroLinha}: Telefone "${telefoneLimpo}" parece inválido (muito curto: ${telefoneApenasNumeros.length} dígitos)`);
          continue;
        }
        
        // 🔧 VERIFICAÇÃO DE DUPLICATA MELHORADA
        console.log(`🔍 Verificando duplicata para: "${ddiLimpo} ${telefoneLimpo}"`);
        
        // Buscar por DDI + telefone exato
        let clienteExistente = await Cliente.findOne({ 
          ddi: ddiLimpo, 
          telefone: telefoneLimpo 
        });
        
        // Se não encontrou, buscar apenas por números do telefone (compatibilidade)
        if (!clienteExistente) {
          console.log(`🔍 Verificando também apenas números: "${telefoneApenasNumeros}"`);
          
          clienteExistente = await Cliente.findOne({ 
            $or: [
              { telefone: { $regex: telefoneApenasNumeros, $options: 'i' } },
              { telefone: telefoneLimpo },
              { telefone: telefoneApenasNumeros }
            ]
          });
        }
        
        if (clienteExistente) {
          clientesJaExistem++;
          console.log(`❌ Telefone "${ddiLimpo} ${telefoneLimpo}" já existe para cliente: ${clienteExistente.nome}`);
          erros.push(`Linha ${numeroLinha}: Cliente "${nomeLimpo}" não foi adicionado - telefone "${ddiLimpo} ${telefoneLimpo}" já cadastrado para: ${clienteExistente.nome}`);
          continue;
        }
        
        console.log(`✅ Telefone "${ddiLimpo} ${telefoneLimpo}" é novo, pode adicionar`);
        
        // 🔧 VALIDAÇÃO DE DATA MELHORADA - OPCIONAL (PODE SER NULL)
        let dataConvertida = null; // ✅ AGORA SERÁ NULL SE NÃO INFORMADA
        
        if (dataNascimento && dataNascimento.toString().trim() !== '' && dataNascimento.toString().toLowerCase() !== 'vazio') {
          try {
            const dataString = dataNascimento.toString().trim();
            
            // Diferentes formatos possíveis
            if (dataString.includes('/')) {
              // Formato brasileiro DD/MM/YYYY
              const partes = dataString.split('/');
              if (partes.length === 3) {
                const [dia, mes, ano] = partes;
                dataConvertida = new Date(`${ano}-${mes.padStart(2, '0')}-${dia.padStart(2, '0')}`);
              }
            } else if (dataString.includes('-')) {
              // Formato DD-MM-YYYY ou YYYY-MM-DD
              const partes = dataString.split('-');
              if (partes.length === 3) {
                if (partes[0].length === 4) {
                  // YYYY-MM-DD
                  dataConvertida = new Date(dataString);
                } else {
                  // DD-MM-YYYY
                  const [dia, mes, ano] = partes;
                  dataConvertida = new Date(`${ano}-${mes.padStart(2, '0')}-${dia.padStart(2, '0')}`);
                }
              }
            } else {
              // Tentar conversão direta
              dataConvertida = new Date(dataString);
            }
            
            // Validar se a data é válida
            if (isNaN(dataConvertida.getTime())) {
              console.log(`⚠️ Linha ${numeroLinha}: Data "${dataString}" inválida, deixando sem data de nascimento`);
              dataConvertida = null; // ✅ NULL EM VEZ DE DATA PADRÃO
            } else {
              // Verificar se a data faz sentido
              const anoNascimento = dataConvertida.getFullYear();
              const anoAtual = new Date().getFullYear();
              if (anoNascimento < 1900 || anoNascimento > anoAtual) {
                console.log(`⚠️ Linha ${numeroLinha}: Ano ${anoNascimento} suspeito, deixando sem data de nascimento`);
                dataConvertida = null; // ✅ NULL EM VEZ DE DATA PADRÃO
              }
            }
            
          } catch (error) {
            console.log(`⚠️ Linha ${numeroLinha}: Erro ao processar data "${dataNascimento}", deixando sem data de nascimento`);
            dataConvertida = null; // ✅ NULL EM VEZ DE DATA PADRÃO
          }
        } else {
          console.log(`ℹ️ Linha ${numeroLinha}: Data de nascimento não informada, deixando como "Não Informado"`);
        }
        
        // ✅ NOVO: PROCESSAR DATA DE CADASTRO DA PLANILHA
        let dataCadastroConvertida = new Date(); // Data atual como padrão
        
        if (dataCadastro && dataCadastro.toString().trim() !== '' && dataCadastro.toString().toLowerCase() !== 'vazio') {
          try {
            const cadastroString = dataCadastro.toString().trim();
            console.log(`📅 Linha ${numeroLinha}: Processando data de cadastro: "${cadastroString}"`);
            
            // Diferentes formatos possíveis para data de cadastro
            if (cadastroString.includes('/')) {
              // Formato brasileiro DD/MM/YYYY ou DD/MM/YYYY HH:MM
              const partes = cadastroString.split(' ');
              const dataPartes = partes[0].split('/');
              
              if (dataPartes.length === 3) {
                const [dia, mes, ano] = dataPartes;
                // Usar apenas a data, ignorando a hora (meio-dia para evitar problemas de timezone)
                dataCadastroConvertida = new Date(`${ano}-${mes.padStart(2, '0')}-${dia.padStart(2, '0')}T12:00:00.000Z`);
              }
            } else if (cadastroString.includes('-')) {
              // Formato YYYY-MM-DD ou similar
              const partes = cadastroString.split(' ');
              const dataPartes = partes[0].split('-');
              
              if (dataPartes.length === 3) {
                if (dataPartes[0].length === 4) {
                  // YYYY-MM-DD
                  dataCadastroConvertida = new Date(`${dataPartes[0]}-${dataPartes[1].padStart(2, '0')}-${dataPartes[2].padStart(2, '0')}T12:00:00.000Z`);
                } else {
                  // DD-MM-YYYY
                  const [dia, mes, ano] = dataPartes;
                  dataCadastroConvertida = new Date(`${ano}-${mes.padStart(2, '0')}-${dia.padStart(2, '0')}T12:00:00.000Z`);
                }
              }
            } else {
              // Tentar conversão direta
              dataCadastroConvertida = new Date(cadastroString);
              // Se tem horário, manter apenas a data
              if (!isNaN(dataCadastroConvertida.getTime())) {
                dataCadastroConvertida = new Date(dataCadastroConvertida.getFullYear(), dataCadastroConvertida.getMonth(), dataCadastroConvertida.getDate(), 12, 0, 0, 0);
              }
            }
            
            // Validar se a data é válida
            if (isNaN(dataCadastroConvertida.getTime())) {
              console.log(`⚠️ Linha ${numeroLinha}: Data de cadastro "${cadastroString}" inválida, usando data atual`);
              dataCadastroConvertida = new Date();
            } else {
              // Verificar se a data faz sentido (não pode ser futura nem muito antiga)
              const anoAtual = new Date().getFullYear();
              const anoCadastro = dataCadastroConvertida.getFullYear();
              if (anoCadastro < 2020 || anoCadastro > anoAtual) {
                console.log(`⚠️ Linha ${numeroLinha}: Ano de cadastro ${anoCadastro} suspeito, usando data atual`);
                dataCadastroConvertida = new Date();
              } else {
                console.log(`✅ Linha ${numeroLinha}: Data de cadastro processada: ${dataCadastroConvertida.toISOString().split('T')[0]}`);
              }
            }
            
          } catch (error) {
            console.log(`⚠️ Linha ${numeroLinha}: Erro ao processar data de cadastro "${dataCadastro}", usando data atual`);
            dataCadastroConvertida = new Date();
          }
        } else {
          console.log(`ℹ️ Linha ${numeroLinha}: Data de cadastro não informada, usando data atual`);
        }
        
        // 🔧 CRIAR NOVO CLIENTE COM DATA DE CADASTRO DA PLANILHA
        const novoCliente = new Cliente({
          nome: nomeLimpo,
          ddi: ddiLimpo,
          telefone: telefoneLimpo,
          dataNascimento: dataConvertida,
          unidade: null,  // ✅ SEM UNIDADE - será definida depois manualmente
          criadoEm: dataCadastroConvertida  // ✅ USAR DATA DA PLANILHA AO INVÉS DA ATUAL
        });
        
        await novoCliente.save();
        clientesInseridos++;
        sucessos.push(`✅ ${nomeLimpo} - ${ddiLimpo} ${telefoneLimpo}`);
        
        console.log(`✅ Cliente ${clientesInseridos}: ${nomeLimpo} adicionado com sucesso`);
        
      } catch (error) {
        erros.push(`Linha ${numeroLinha}: Erro ao salvar - ${error.message}`);
        console.error(`❌ Erro na linha ${numeroLinha}:`, error);
      }
    }
    
        // 🆕 NOVO: SALVAR NO HISTÓRICO DE CADASTRO
    if (clientesInseridos > 0 || erros.length > 0) {
      try {
        // Criar registro no histórico
        const novoHistorico = new HistoricoCadastro({
          dataImportacao: new Date(),
          nomeArquivo: req.file.originalname || 'Arquivo Excel',
          clientesAdicionados: clientesInseridos,
          clientesJaExistiam: clientesJaExistem,
          totalLinhasProcessadas: dados.length,
          totalErros: erros.length,
          usuarioImportacao: req.admin.nome || 'Admin'
        });
        
        await novoHistorico.save();
        
        // Atualizar estatísticas existentes (compatibilidade)
        let stats = await EstatisticasCadastro.findOne();
        if (!stats) {
          stats = new EstatisticasCadastro();
        }
        
        const mesAtual = new Date().toISOString().slice(0, 7);
        if (stats.mesReferencia !== mesAtual) {
          stats.mesReferencia = mesAtual;
          stats.clientesEsteMes = 0;
        }
        
        stats.ultimaImportacao = new Date();
        stats.totalClientes += clientesInseridos;
        stats.clientesEsteMes += clientesInseridos;
        stats.ultimoArquivoImportado = req.file.originalname || 'Arquivo Excel';
        stats.atualizadoEm = new Date();
        
        await stats.save();
        
        console.log(`✅ Histórico e estatísticas de cadastro atualizados: +${clientesInseridos} clientes`);
        
      } catch (error) {
        console.log('⚠️ Erro ao atualizar histórico de cadastro (não crítico):', error);
      }
    }
    
    // 🔧 RESPOSTA DETALHADA MELHORADA
    const mensagem = `📊 Processamento concluído! 
${clientesInseridos} clientes adicionados, 
${clientesJaExistem} já existiam, 
${erros.length} erros encontrados.`;
    
    const resultado = {
      mensagem,
      totalLinhas: dados.length,
      clientesInseridos,
      clientesJaExistem,
      totalErros: erros.length,
      erros: erros.length > 0 ? erros : null,
      sucessos: sucessos.length > 0 ? sucessos.slice(0, 10) : null,
      // Adicionar informações de debug
      primeiraLinhaExemplo: dados[0] ? Object.keys(dados[0]) : null
    };
    
    console.log('📋 Resultado final:', resultado);
    
    res.json(resultado);
    
  } catch (error) {
    console.error('❌ Erro geral no upload:', error);
    res.status(500).json({ 
      erro: 'Erro ao processar arquivo Excel.',
      detalhes: error.message 
    });
  }
});

// ===================================
// NOVA ROTA: UPLOAD DE HISTÓRICO DE SERVIÇOS - COM ESTATÍSTICAS PERSISTENTES
// ===================================
app.post('/api/upload-servicos', verificarLogin, upload.single('excel'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ erro: 'Nenhum arquivo enviado.' });
    }
    
    // Ler arquivo Excel
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    
    // Converter para JSON
    const dados = XLSX.utils.sheet_to_json(worksheet);
    
    if (dados.length === 0) {
      return res.status(400).json({ erro: 'Arquivo Excel está vazio ou não possui dados válidos.' });
    }
    
    let servicosAdicionados = 0;
    let clientesNovos = 0;
    let clientesAtualizados = 0;
    let erros = [];
    let sucessos = [];
    
    console.log(`📊 Processando ${dados.length} linhas do histórico de serviços...`);
    
    // DEBUG: Mostrar estrutura da primeira linha
    console.log('📋 Estrutura da primeira linha:', dados[0]);
    console.log('📋 Chaves disponíveis:', Object.keys(dados[0]));
    
    for (let i = 0; i < dados.length; i++) {
      const linha = dados[i];
      const numeroLinha = i + 2; // +2 porque linha 1 é cabeçalho
      
      try {
        // 🔧 MAPEAMENTO DAS COLUNAS DO HISTÓRICO
        const servico = linha.Serviço || linha.servico || linha.SERVIÇO || 
                       linha.Servico || linha.SERVICE || linha.service || null;
        
        const cliente = linha.Cliente || linha.cliente || linha.CLIENTE || 
                       linha.Nome || linha.nome || linha.NOME || null;
        
        const telefone = linha.Telefone || linha.telefone || linha.TELEFONE || 
                        linha.phone || linha.celular || linha.Celular || null;
        
        const profissional = linha.Profissional || linha.profissional || linha.PROFISSIONAL ||
                            linha.Barbeiro || linha.barbeiro || linha.BARBEIRO ||
                            linha.Funcionario || linha.funcionario || null;
        
        const dataServico = linha.Data || linha.data || linha.DATA ||
                           linha['Data Serviço'] || linha['Data do Serviço'] ||
                           linha.date || linha.Date || null;
        
        // 🔧 VALIDAÇÃO DOS CAMPOS OBRIGATÓRIOS
        const telefoneValido = telefone && telefone.toString().trim() !== '' && telefone.toString().toLowerCase() !== 'vazio';
        const servicoValido = servico && servico.toString().trim() !== '' && servico.toString().toLowerCase() !== 'vazio';
        const profissionalValido = profissional && profissional.toString().trim() !== '' && profissional.toString().toLowerCase() !== 'vazio';
        const dataValida = dataServico && dataServico.toString().trim() !== '' && dataServico.toString().toLowerCase() !== 'vazio';
        
        if (!telefoneValido) {
          erros.push(`Linha ${numeroLinha}: Telefone obrigatório está vazio - Telefone: "${telefone || 'VAZIO'}"`);
          continue;
        }
        
        if (!servicoValido || !profissionalValido || !dataValida) {
          erros.push(`Linha ${numeroLinha}: Dados incompletos - Serviço: "${servico || 'VAZIO'}", Profissional: "${profissional || 'VAZIO'}", Data: "${dataServico || 'VAZIO'}"`);
          continue;
        }
        
        // 🔧 LIMPEZA DOS DADOS COM FORMATAÇÃO DE TELEFONE
        const telefoneLimpo = formatarTelefone(telefone.toString().trim()); // ✅ FORMATADO
        const servicoLimpo = servico.toString().trim();
        const profissionalLimpo = profissional.toString().trim();
        const clienteLimpo = cliente ? cliente.toString().trim() : 'Cliente';
        
        // 🔧 VALIDAÇÃO DE DATA DO SERVIÇO
        let dataServicoConvertida;
        try {
          const dataString = dataServico.toString().trim();
          
          if (dataString.includes('/')) {
            // Formato brasileiro DD/MM/YYYY
            const partes = dataString.split(' ')[0].split('/');
            if (partes.length === 3) {
              const [dia, mes, ano] = partes;
              dataServicoConvertida = new Date(`${ano}-${mes.padStart(2, '0')}-${dia.padStart(2, '0')}T12:00:00.000Z`);
            }
          } else if (dataString.includes('-')) {
            // Formato YYYY-MM-DD ou DD-MM-YYYY
            const partes = dataString.split(' ')[0].split('-');
            if (partes.length === 3) {
              if (partes[0].length === 4) {
                dataServicoConvertida = new Date(`${partes[0]}-${partes[1].padStart(2, '0')}-${partes[2].padStart(2, '0')}T12:00:00.000Z`);
              } else {
                const [dia, mes, ano] = partes;
                dataServicoConvertida = new Date(`${ano}-${mes.padStart(2, '0')}-${dia.padStart(2, '0')}T12:00:00.000Z`);
              }
            }
          } else {
            dataServicoConvertida = new Date(dataString);
          }
          
          if (isNaN(dataServicoConvertida.getTime())) {
            erros.push(`Linha ${numeroLinha}: Data do serviço "${dataString}" está em formato inválido`);
            continue;
          }
          
        } catch (error) {
          erros.push(`Linha ${numeroLinha}: Erro ao processar data "${dataServico}"`);
          continue;
        }
        
        // 🔍 BUSCAR CLIENTE EXISTENTE POR TELEFONE
        const telefoneApenasNumeros = telefoneLimpo.replace(/\D/g, '');
        let clienteExistente = await Cliente.findOne({
          $or: [
            { telefone: telefoneLimpo },
            { telefone: { $regex: telefoneApenasNumeros, $options: 'i' } }
          ]
        });
        
        // Objeto do novo serviço
        const novoServico = {
          servico: servicoLimpo,
          profissional: profissionalLimpo,
          dataServico: dataServicoConvertida
        };
        
        if (clienteExistente) {
          // ✅ CLIENTE EXISTE - VERIFICAR NOME E ADICIONAR SERVIÇO
          console.log(`🔍 Cliente encontrado: ${clienteExistente.nome} | Telefone: ${clienteExistente.telefone}`);
          
          // Verificar se o nome confere (opcional, mas registra diferenças)
          if (clienteExistente.nome.toLowerCase() !== clienteLimpo.toLowerCase()) {
            console.log(`⚠️ Linha ${numeroLinha}: Nome diferente - Banco: "${clienteExistente.nome}" vs Planilha: "${clienteLimpo}"`);
          }
          
          // ✅ CHECAR SE JÁ EXISTE SERVIÇO IGUAL NA MESMA DATA
          const jaTemServico = clienteExistente.historicoServicos && clienteExistente.historicoServicos.some(s =>
            s.servico.toLowerCase() === servicoLimpo.toLowerCase() &&
            new Date(s.dataServico).toISOString().split('T')[0] === dataServicoConvertida.toISOString().split('T')[0]
          );
          if (jaTemServico) {
            erros.push(`Linha ${numeroLinha}: Serviço "${servicoLimpo}" já existe para o cliente "${clienteExistente.nome}" na data ${dataServicoConvertida.toISOString().split('T')[0]}`);
            continue;
          }
          
          // Adicionar serviço ao histórico
          if (!clienteExistente.historicoServicos) {
            clienteExistente.historicoServicos = [];
          }
          
          clienteExistente.historicoServicos.push(novoServico);
          
          // Garantir que tem unidade JSP
          if (!clienteExistente.unidade) {
            clienteExistente.unidade = 'JSP';
          }
          
          await clienteExistente.save();
          clientesAtualizados++;
          servicosAdicionados++;
          
          sucessos.push(`✅ ${clienteExistente.nome}: ${servicoLimpo} (${profissionalLimpo})`);
          console.log(`✅ Serviço adicionado ao cliente existente: ${clienteExistente.nome}`);
          
        } else {
          // ❌ CLIENTE NÃO EXISTE - CRIAR NOVO
          console.log(`➕ Criando novo cliente: ${clienteLimpo} | Telefone: ${telefoneLimpo}`);
          
          const novoCliente = new Cliente({
            nome: clienteLimpo,
            ddi: '55',  // DDI padrão SEM +
            telefone: telefoneLimpo, // ✅ JÁ FORMATADO
            dataNascimento: null,  // Será preenchido manualmente depois
            unidade: 'JSP',
            historicoServicos: [novoServico],
            criadoEm: new Date()
          });
          
          await novoCliente.save();
          clientesNovos++;
          servicosAdicionados++;
          
          sucessos.push(`➕ NOVO: ${clienteLimpo}: ${servicoLimpo} (${profissionalLimpo})`);
          console.log(`✅ Novo cliente criado: ${clienteLimpo}`);
        }
        
      } catch (error) {
        erros.push(`Linha ${numeroLinha}: Erro ao processar - ${error.message}`);
        console.error(`❌ Erro na linha ${numeroLinha}:`, error);
      }
    }

   // 🆕 NOVO: SALVAR NO HISTÓRICO DE MOVIMENTO
    if (servicosAdicionados > 0 || erros.length > 0) {
      try {
        // Criar registro no histórico
        const novoHistorico = new HistoricoMovimento({
          dataImportacao: new Date(),
          nomeArquivo: req.file.originalname || 'Arquivo Excel',
          servicosAdicionados: servicosAdicionados,
          clientesAtualizados: clientesAtualizados,
          clientesNovos: clientesNovos,
          totalLinhasProcessadas: dados.length,
          totalErros: erros.length,
          usuarioImportacao: req.admin.nome || 'Admin'
        });
        
        await novoHistorico.save();
        
        // Atualizar estatísticas existentes (compatibilidade)
        let stats = await EstatisticasMovimento.findOne();
        if (!stats) {
          stats = new EstatisticasMovimento();
        }
        
        const mesAtual = new Date().toISOString().slice(0, 7);
        if (stats.mesReferencia !== mesAtual) {
          stats.mesReferencia = mesAtual;
          stats.movimentosEsteMes = 0;
        }
        
        stats.ultimaImportacao = new Date();
        stats.totalMovimentos += servicosAdicionados;
        stats.movimentosEsteMes += servicosAdicionados;
        stats.ultimoArquivoImportado = req.file.originalname || 'Arquivo Excel';
        stats.atualizadoEm = new Date();
        
        await stats.save();
        
        console.log(`✅ Histórico e estatísticas de movimento atualizados: +${servicosAdicionados} movimentos`);
        
      } catch (error) {
        console.log('⚠️ Erro ao atualizar histórico de movimento (não crítico):', error);
      }
    }
    
    // 🔧 RESPOSTA DETALHADA
    const mensagem = `📊 Histórico processado! 
${servicosAdicionados} serviços adicionados, 
${clientesAtualizados} clientes atualizados, 
${clientesNovos} clientes novos criados, 
${erros.length} erros encontrados.`;
    
    const resultado = {
      mensagem,
      totalLinhas: dados.length,
      servicosAdicionados,
      clientesAtualizados,
      clientesNovos,
      totalErros: erros.length,
      erros: erros.length > 0 ? erros : null,
      sucessos: sucessos.length > 0 ? sucessos.slice(0, 10) : null,
      primeiraLinhaExemplo: dados[0] ? Object.keys(dados[0]) : null
    };
    
    console.log('📋 Resultado final do histórico:', resultado);
    
    res.json(resultado);
    
  } catch (error) {
    console.error('❌ Erro geral no upload do histórico:', error);
    res.status(500).json({ 
      erro: 'Erro ao processar arquivo de histórico.',
      detalhes: error.message 
    });
  }
});

// ===================================
// ROTAS DA API - COMUNICAÇÕES (PROTEGIDAS)
// ===================================

// Listar todas as comunicações
app.get('/api/comunicacoes', verificarLogin, async (req, res) => {
  try {
    const comunicacoes = await Comunicacao.find()
      .sort({ criadoEm: -1 })
      .select('-clientes'); // Não incluir dados dos clientes na listagem
    
    // Adicionar contagem de realizados para cada comunicação
    const comunicacoesComRealizados = comunicacoes.map(comunicacao => {
      const realizados = comunicacao.realizados ? 
        comunicacao.realizados.filter(item => item.realizado).length : 0;
      
      return {
        ...comunicacao.toObject(),
        clientesRealizados: realizados
      };
    });
    
    res.json(comunicacoesComRealizados);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar comunicações.' });
  }
});

// Buscar comunicação por ID (com clientes)
app.get('/api/comunicacoes/:id', verificarLogin, async (req, res) => {
  try {
    const comunicacao = await Comunicacao.findById(req.params.id);
    if (!comunicacao) {
      return res.status(404).json({ erro: 'Comunicação não encontrada.' });
    }
    res.json(comunicacao);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar comunicação.' });
  }
});

// Criar nova comunicação (processar arquivo do Wasender)
app.post('/api/comunicacoes', verificarLogin, upload.single('excel'), async (req, res) => {
  try {
    const { titulo } = req.body;
    
    if (!req.file) {
      return res.status(400).json({ erro: 'Arquivo Excel é obrigatório.' });
    }
    
    if (!titulo || titulo.trim() === '') {
      return res.status(400).json({ erro: 'Título da comunicação é obrigatório.' });
    }
    
    // Ler arquivo Excel
    const workbook = XLSX.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    
    // Converter para JSON - pegar dados a partir da linha 2
    const dados = XLSX.utils.sheet_to_json(worksheet); // Processa todas as linhas
    
    if (dados.length === 0) {
      return res.status(400).json({ erro: 'Arquivo Excel está vazio ou não possui dados válidos.' });
    }
    
    console.log(`📊 Processando comunicação "${titulo}" com ${dados.length} números...`);
    
    // Buscar todos os clientes para comparação
    const todosClientes = await Cliente.find({}, 'nome telefone ddi unidade').lean();
    console.log(`📱 Total de clientes no banco: ${todosClientes.length}`);
    
    let clientesEncontrados = 0;
    let clientesNaoEncontrados = 0;
    const clientesResultado = [];
    
    for (let i = 0; i < dados.length; i++) {
      const linha = dados[i];
      
      // Pegar número da primeira coluna (coluna A)
      const numeroOriginal = linha[Object.keys(linha)[0]]; // Primeira coluna
      
      if (!numeroOriginal || numeroOriginal.toString().trim() === '') {
        console.log(`⚠️ Linha ${i + 2}: Número vazio, pulando`);
        continue;
      }
      
      const numeroLimpo = numeroOriginal.toString().trim();
      console.log(`🔍 Processando número: ${numeroLimpo}`);
      
      // Extrair DDI e telefone do número completo
      let ddiExtraido = '';
      let telefoneExtraido = '';
      
      if (numeroLimpo.startsWith('55') && numeroLimpo.length >= 12) {
        // Número brasileiro: 5511994338072
        ddiExtraido = '55';
        telefoneExtraido = numeroLimpo.slice(2); // Remove DDI 55
      } else if (numeroLimpo.startsWith('1') && numeroLimpo.length >= 11) {
        // Número americano: 15126354104
        ddiExtraido = '1';
        telefoneExtraido = numeroLimpo.slice(1); // Remove DDI 1
      } else {
        // Outros países - tentar detectar automaticamente
        // Verificar DDIs comuns de 2-3 dígitos
        const ddisComuns = ['55', '1', '44', '33', '49', '39', '34', '351', '52', '54'];
        let encontrouDDI = false;
        
        for (const ddi of ddisComuns) {
          if (numeroLimpo.startsWith(ddi)) {
            ddiExtraido = ddi;
            telefoneExtraido = numeroLimpo.slice(ddi.length);
            encontrouDDI = true;
            break;
          }
        }
        
        if (!encontrouDDI) {
          // Assumir que é número brasileiro sem DDI ou formato desconhecido
          ddiExtraido = '55';
          telefoneExtraido = numeroLimpo;
        }
      }
      
      // Formatar telefone extraído
      const telefoneFormatado = formatarTelefone(telefoneExtraido);
      console.log(`📞 Extraído - DDI: ${ddiExtraido}, Telefone: ${telefoneFormatado}`);
      
      // Buscar cliente no banco de dados
      const telefoneApenasNumeros = telefoneExtraido.replace(/\D/g, '');
      
      const clienteEncontrado = todosClientes.find(cliente => {
        const clienteDDI = cliente.ddi || '55';
        const clienteTelefoneNumeros = cliente.telefone.replace(/\D/g, '');
        
        // Comparar DDI + telefone (apenas números)
        return clienteDDI === ddiExtraido && clienteTelefoneNumeros === telefoneApenasNumeros;
      });
      
      if (clienteEncontrado) {
        clientesEncontrados++;
        clientesResultado.push({
          numeroOriginal: numeroLimpo,
          encontrado: true,
          clienteId: clienteEncontrado._id,
          cliente: clienteEncontrado
        });
        console.log(`✅ Cliente encontrado: ${clienteEncontrado.nome}`);
      } else {
        clientesNaoEncontrados++;
        clientesResultado.push({
          numeroOriginal: numeroLimpo,
          encontrado: false,
          clienteId: null,
          cliente: null
        });
        console.log(`❌ Cliente não encontrado para: ${ddiExtraido} ${telefoneFormatado}`);
      }
    }
    
    // Criar comunicação no banco
    const novaComunicacao = new Comunicacao({
      titulo: titulo.trim(),
      totalClientes: dados.length,
      clientesEncontrados,
      clientesNaoEncontrados,
      clientes: clientesResultado
    });
    
    await novaComunicacao.save();
    
    const taxaSucesso = Math.round((clientesEncontrados / dados.length) * 100);
    
    const mensagem = `✅ Comunicação "${titulo}" processada com sucesso! 
${clientesEncontrados} clientes encontrados (${taxaSucesso}%), 
${clientesNaoEncontrados} não encontrados.`;
    
    console.log(`📊 Comunicação salva - ID: ${novaComunicacao._id}`);
    
    res.json({
      mensagem,
      comunicacaoId: novaComunicacao._id,
      totalProcessados: dados.length,
      clientesEncontrados,
      clientesNaoEncontrados,
      taxaSucesso: `${taxaSucesso}%`
    });
    
  } catch (error) {
    console.error('❌ Erro ao processar comunicação:', error);
    res.status(500).json({ 
      erro: 'Erro ao processar comunicação.',
      detalhes: error.message 
    });
  }
});

// Buscar comunicações de um cliente específico
app.get('/api/clientes/:id/comunicacoes', verificarLogin, async (req, res) => {
  try {
    const clienteId = req.params.id;
    
    // Buscar comunicações onde este cliente foi encontrado
    const comunicacoes = await Comunicacao.find({
      'clientes.clienteId': clienteId,
      'clientes.encontrado': true
    })
    .sort({ criadoEm: -1 })
    .select('titulo criadoEm totalClientes clientesEncontrados realizados _id')
    .limit(10); // Limitar às 10 mais recentes
    
    // Adicionar informação se este cliente específico foi marcado como realizado
    const comunicacoesComStatus = comunicacoes.map(comunicacao => {
      const foiRealizado = comunicacao.realizados ? 
        comunicacao.realizados.some(item => item.clienteId === clienteId && item.realizado) : false;
      
      const totalRealizados = comunicacao.realizados ? 
        comunicacao.realizados.filter(item => item.realizado).length : 0;
      
      return {
        ...comunicacao.toObject(),
        clienteRealizado: foiRealizado,
        totalRealizados: totalRealizados
      };
    });
    
    res.json(comunicacoesComStatus);
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao buscar comunicações do cliente.' });
  }
});

// Deletar comunicação
app.delete('/api/comunicacoes/:id', verificarLogin, async (req, res) => {
  try {
    const comunicacaoDeletada = await Comunicacao.findByIdAndDelete(req.params.id);
    
    if (!comunicacaoDeletada) {
      return res.status(404).json({ erro: 'Comunicação não encontrada.' });
    }
    
    res.json({ mensagem: 'Comunicação deletada com sucesso.' });
  } catch (error) {
    res.status(500).json({ erro: 'Erro ao deletar comunicação.' });
  }
});

// ===================================
// ROTAS DA API - REALIZADOS (PROTEGIDAS)
// ===================================

// Buscar status de realizados de uma comunicação
app.get('/api/comunicacoes/:id/realizados', verificarLogin, async (req, res) => {
  try {
    const comunicacao = await Comunicacao.findById(req.params.id).select('realizados');
    
    if (!comunicacao) {
      return res.status(404).json({ erro: 'Comunicação não encontrada.' });
    }
    
    // Retornar array de clienteIds realizados para compatibilidade
    const clientesRealizados = comunicacao.realizados
      .filter(item => item.realizado)
      .map(item => item.clienteId);
    
    res.json({ clientesRealizados });
  } catch (error) {
    console.error('❌ Erro ao buscar realizados:', error);
    res.status(500).json({ erro: 'Erro ao buscar status de realizados.' });
  }
});

// Atualizar status de realizado de um cliente específico
app.put('/api/comunicacoes/:id/realizados/:clienteId', verificarLogin, async (req, res) => {
  try {
    const { id, clienteId } = req.params;
    const { realizado } = req.body;
    
    const comunicacao = await Comunicacao.findById(id);
    
    if (!comunicacao) {
      return res.status(404).json({ erro: 'Comunicação não encontrada.' });
    }
    
    // Procurar se já existe um registro para este cliente
    const indiceExistente = comunicacao.realizados.findIndex(
      item => item.clienteId === clienteId
    );
    
    if (indiceExistente >= 0) {
      // Atualizar registro existente
      comunicacao.realizados[indiceExistente].realizado = realizado;
      comunicacao.realizados[indiceExistente].dataRealizacao = new Date();
    } else {
      // Criar novo registro
      comunicacao.realizados.push({
        clienteId: clienteId,
        realizado: realizado,
        dataRealizacao: new Date()
      });
    }
    
    await comunicacao.save();
    
    res.json({ 
      mensagem: `Cliente ${realizado ? 'marcado como realizado' : 'desmarcado'} com sucesso.`,
      clienteId,
      realizado,
      dataRealizacao: new Date()
    });
    
  } catch (error) {
    console.error('❌ Erro ao atualizar realizado:', error);
    res.status(500).json({ erro: 'Erro ao atualizar status de realizado.' });
  }
});

// Atualizar status de realizados em massa
app.put('/api/comunicacoes/:id/realizados', verificarLogin, async (req, res) => {
  try {
    const { id } = req.params;
    const { clienteIds, realizado } = req.body;
    
    if (!Array.isArray(clienteIds) || clienteIds.length === 0) {
      return res.status(400).json({ erro: 'Lista de cliente IDs é obrigatória.' });
    }
    
    const comunicacao = await Comunicacao.findById(id);
    
    if (!comunicacao) {
      return res.status(404).json({ erro: 'Comunicação não encontrada.' });
    }
    
    const dataAtual = new Date();
    let atualizados = 0;
    
    // Processar cada cliente ID
    clienteIds.forEach(clienteId => {
      const indiceExistente = comunicacao.realizados.findIndex(
        item => item.clienteId === clienteId
      );
      
      if (indiceExistente >= 0) {
        // Atualizar registro existente
        comunicacao.realizados[indiceExistente].realizado = realizado;
        comunicacao.realizados[indiceExistente].dataRealizacao = dataAtual;
      } else {
        // Criar novo registro
        comunicacao.realizados.push({
          clienteId: clienteId,
          realizado: realizado,
          dataRealizacao: dataAtual
        });
      }
      atualizados++;
    });
    
    await comunicacao.save();
    
    res.json({ 
      mensagem: `${atualizados} clientes ${realizado ? 'marcados como realizados' : 'desmarcados'} com sucesso.`,
      atualizados,
      realizado,
      dataRealizacao: dataAtual
    });
    
  } catch (error) {
    console.error('❌ Erro ao atualizar realizados em massa:', error);
    res.status(500).json({ erro: 'Erro ao atualizar status de realizados em massa.' });
  }
});

// ===================================
// FUNÇÃO PARA CRIAR ADMIN INICIAL (APENAS PARA DESENVOLVIMENTO)
// ===================================
async function criarAdminInicial() {
  try {
    const adminExistente = await Admin.findOne();
    if (!adminExistente) {
      const adminInicial = new Admin({
        nome: 'Admin Principal',
        email: 'admin@barbearia.com',
        senha: '123456',
        tipo: 'admin'
      });
      
      await adminInicial.save();
      console.log('🔑 Admin inicial criado!');
      console.log('📧 Email: admin@barbearia.com');
      console.log('🔒 Senha: 123456');
      console.log('⚠️  ALTERE ESTA SENHA NO PRIMEIRO LOGIN!');
    }
  } catch (error) {
    console.log('Erro ao criar admin inicial:', error);
  }
}

// ===================================
// FUNÇÃO AUXILIAR: FORMATAÇÃO DE TELEFONE
// ===================================
function formatarTelefone(telefone) {
  if (!telefone) return '';
  
  // Remove tudo que não é número
  const apenasNumeros = telefone.toString().replace(/\D/g, '');
  
  // Se tem 11 dígitos (celular com DDD)
  if (apenasNumeros.length === 11) {
    return `(${apenasNumeros.slice(0, 2)}) ${apenasNumeros.slice(2, 7)}-${apenasNumeros.slice(7)}`;
  }
  // Se tem 10 dígitos (fixo com DDD)  
  else if (apenasNumeros.length === 10) {
    return `(${apenasNumeros.slice(0, 2)}) ${apenasNumeros.slice(2, 6)}-${apenasNumeros.slice(6)}`;
  }
  // Se tem 9 dígitos (celular sem DDD)
  else if (apenasNumeros.length === 9) {
    return `${apenasNumeros.slice(0, 5)}-${apenasNumeros.slice(5)}`;
  }
  // Se tem 8 dígitos (fixo sem DDD)
  else if (apenasNumeros.length === 8) {
    return `${apenasNumeros.slice(0, 4)}-${apenasNumeros.slice(4)}`;
  }
  // Para outros tamanhos, retorna apenas os números
  else {
    return apenasNumeros;
  }
}

// ===================================
// INICIAR SERVIDOR
// ===================================
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
  console.log(`📱 Acesse: http://localhost:${PORT}`);
  
  // Criar admin inicial se não existir
  criarAdminInicial();
});