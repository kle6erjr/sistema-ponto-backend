import "dotenv/config";
import express from "express";
import cors from "cors";
import pkg from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const { PrismaClient } = pkg;

const app = express();
const prisma = new PrismaClient();

// 🔧 CORS CONFIGURADO PARA PRODUÇÃO E DESENVOLVIMENTO
app.use(cors({
  origin: [
    'http://localhost:5173',           // Frontend Ponto (local)
    'http://localhost:5174',           // Frontend Admin (local)
    'https://sistema-ponto-frontend.vercel.app',  // Frontend Ponto (produção)
    'https://sistema-ponto-admin.vercel.app'      // Frontend Admin (produção)
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const PORT = 3000;
const SECRET = "segredo_super_secreto";

/* =========================
   ROTA RAIZ (TESTE)
========================= */
app.get("/", (req, res) => {
  res.json({
    mensagem: "API do Sistema de Ponto está rodando!",
    rotas: [
      "POST /login",
      "POST /funcionarios",
      "GET /funcionarios",
      "GET /funcionarios/:id",
      "PUT /funcionarios/:id",
      "DELETE /funcionarios/:id",
      "POST /registros",
      "GET /registros/dia",
      "GET /registros",
      "GET /registros/filtro",
      "GET /dashboard/estatisticas"
    ]
  });
});

/* =========================
   MIDDLEWARE AUTENTICAÇÃO
========================= */
function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ erro: "Token não fornecido" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ erro: "Token inválido" });
    }

    req.user = user;
    next();
  });
}

/* =========================
   MIDDLEWARE AUTORIZAÇÃO
========================= */
function autorizarAdmin(req, res, next) {
  if (req.user.tipo !== "admin") {
    return res.status(403).json({ erro: "Acesso negado: apenas admin" });
  }
  next();
}

/* =========================
   CRIAR FUNCIONÁRIO (COM CRIPTOGRAFIA)
========================= */
app.post("/funcionarios", async (req, res) => {
  try {
    const { nome, matricula, cargo, senha, tipo } = req.body;

    // 🔐 CRIPTOGRAFAR SENHA
    const senhaHash = await bcrypt.hash(senha, 10);

    const funcionario = await prisma.funcionario.create({
      data: {
        nome,
        matricula,
        cargo,
        senha: senhaHash,
        tipo,
      },
    });

    res.status(201).json(funcionario);

  } catch (error) {
    console.error(error);

    // 🔥 erro de duplicidade (matricula única)
    if (error.code === "P2002") {
      return res.status(400).json({
        erro: "Matrícula já cadastrada"
      });
    }

    // erro genérico
    res.status(500).json({
      erro: "Erro ao criar funcionário"
    });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/login", async (req, res) => {
  try {
    const { matricula, senha } = req.body;

    const funcionario = await prisma.funcionario.findFirst({
      where: { matricula },
    });

    if (!funcionario) {
      return res.status(401).json({ erro: "Credenciais inválidas" });
    }

    const senhaValida = await bcrypt.compare(senha, funcionario.senha);

    if (!senhaValida) {
      return res.status(401).json({ erro: "Credenciais inválidas" });
    }

    const token = jwt.sign(
      {
        id: funcionario.id,
        tipo: funcionario.tipo,
      },
      SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      mensagem: "Login realizado com sucesso",
      token,
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro no login" });
  }
});

/* =========================
   LISTAR FUNCIONÁRIOS (ADMIN)
========================= */
app.get("/funcionarios", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const funcionarios = await prisma.funcionario.findMany();
    res.json(funcionarios);
  } catch (error) {
    res.status(500).json({ erro: "Erro ao buscar funcionários" });
  }
});

/* =========================
   BUSCAR FUNCIONÁRIO POR ID (ADMIN)
========================= */
app.get("/funcionarios/:id", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const funcionario = await prisma.funcionario.findUnique({
      where: { id: parseInt(id) },
    });
    
    if (!funcionario) {
      return res.status(404).json({ erro: "Funcionário não encontrado" });
    }
    
    // Remove a senha por segurança
    const { senha, ...funcionarioSemSenha } = funcionario;
    res.json(funcionarioSemSenha);
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar funcionário" });
  }
});

/* =========================
   ATUALIZAR FUNCIONÁRIO (ADMIN)
========================= */
app.put("/funcionarios/:id", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { nome, matricula, cargo, senha, tipo } = req.body;
    
    // Verifica se funcionário existe
    const funcionarioExistente = await prisma.funcionario.findUnique({
      where: { id: parseInt(id) },
    });
    
    if (!funcionarioExistente) {
      return res.status(404).json({ erro: "Funcionário não encontrado" });
    }
    
    // Prepara dados para atualização
    const dadosAtualizacao = {
      nome,
      matricula,
      cargo,
      tipo,
    };
    
    // Se senha foi fornecida, criptografa
    if (senha && senha.trim() !== "") {
      dadosAtualizacao.senha = await bcrypt.hash(senha, 10);
    }
    
    const funcionarioAtualizado = await prisma.funcionario.update({
      where: { id: parseInt(id) },
      data: dadosAtualizacao,
    });
    
    // Remove senha da resposta
    const { senha: _, ...funcionarioSemSenha } = funcionarioAtualizado;
    res.json(funcionarioSemSenha);
    
  } catch (error) {
    console.error(error);
    
    if (error.code === "P2002") {
      return res.status(400).json({ erro: "Matrícula já cadastrada" });
    }
    
    res.status(500).json({ erro: "Erro ao atualizar funcionário" });
  }
});

/* =========================
   EXCLUIR FUNCIONÁRIO (ADMIN)
========================= */
app.delete("/funcionarios/:id", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Verifica se funcionário existe
    const funcionario = await prisma.funcionario.findUnique({
      where: { id: parseInt(id) },
    });
    
    if (!funcionario) {
      return res.status(404).json({ erro: "Funcionário não encontrado" });
    }
    
    // Não permite excluir o próprio admin logado
    if (funcionario.id === req.user.id) {
      return res.status(400).json({ erro: "Não é possível excluir seu próprio usuário" });
    }
    
    // Exclui registros de ponto do funcionário primeiro
    await prisma.registro.deleteMany({
      where: { funcionarioId: parseInt(id) },
    });
    
    // Exclui o funcionário
    await prisma.funcionario.delete({
      where: { id: parseInt(id) },
    });
    
    res.json({ mensagem: "Funcionário excluído com sucesso" });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao excluir funcionário" });
  }
});

/* =========================
   REGISTRAR PONTO (4 BATIDAS)
========================= */
app.post("/registros", autenticarToken, async (req, res) => {
  try {
    const { tipo } = req.body;
    const funcionarioId = req.user.id;

    // Lista de tipos válidos para 4 batidas
    const tiposValidos = [
      "ENTRADA_MANHA",
      "SAIDA_MANHA",
      "ENTRADA_TARDE",
      "SAIDA_NOITE"
    ];

    // Validação: tipo deve ser válido
    if (!tipo || !tiposValidos.includes(tipo.toUpperCase())) {
      return res.status(400).json({
        erro: "Tipo inválido",
        mensagem: `Deve ser: ${tiposValidos.join(", ")}`
      });
    }

    // Busca registros do dia atual
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    
    const amanha = new Date(hoje);
    amanha.setDate(amanha.getDate() + 1);

    const registrosHoje = await prisma.registro.findMany({
      where: {
        funcionarioId,
        dataHora: {
          gte: hoje,
          lt: amanha
        }
      },
      orderBy: { dataHora: "asc" }
    });

    const tiposRegistrados = registrosHoje.map(r => r.tipo);
    const ordemCorreta = ["ENTRADA_MANHA", "SAIDA_MANHA", "ENTRADA_TARDE", "SAIDA_NOITE"];

    // REGRA 1: Verifica limite de 4 registros
    if (registrosHoje.length >= 4) {
      return res.status(400).json({
        erro: "Limite diário atingido",
        mensagem: "Você já registrou os 4 pontos do dia"
      });
    }

    // REGRA 2: Verifica se está tentando pular ordem
    const proximoEsperado = ordemCorreta[registrosHoje.length];
    
    if (tipo.toUpperCase() !== proximoEsperado) {
      return res.status(400).json({
        erro: "Ordem incorreta",
        mensagem: `Próximo registro esperado: ${proximoEsperado}`,
        registrado: tipo.toUpperCase(),
        esperado: proximoEsperado
      });
    }

    // REGRA 3: Não pode registrar o mesmo tipo duas vezes
    if (tiposRegistrados.includes(tipo.toUpperCase())) {
      return res.status(400).json({
        erro: "Registro duplicado",
        mensagem: `${tipo.toUpperCase()} já foi registrado hoje`
      });
    }

    // Cria o registro
    const registro = await prisma.registro.create({
      data: {
        funcionarioId,
        tipo: tipo.toUpperCase(),
        dataHora: new Date()
      },
      include: {
        funcionario: {
          select: {
            nome: true,
            matricula: true
          }
        }
      }
    });

    // Calcula próximo registro esperado
    const proximo = ordemCorreta[registrosHoje.length + 1] || "NENHUM (jornada finalizada)";
    
    res.status(201).json({
      mensagem: `${tipo.toUpperCase()} registrada com sucesso`,
      registro,
      proximoEsperado: proximo,
      registrosHoje: registrosHoje.length + 1,
      totalEsperado: 4
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao registrar ponto" });
  }
});

/* =========================
   VER REGISTROS DO DIA (funcionário logado)
========================= */
app.get("/registros/dia", autenticarToken, async (req, res) => {
  try {
    const funcionarioId = req.user.id;
    
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    
    const amanha = new Date(hoje);
    amanha.setDate(amanha.getDate() + 1);

    const registrosHoje = await prisma.registro.findMany({
      where: {
        funcionarioId,
        dataHora: {
          gte: hoje,
          lt: amanha
        }
      },
      orderBy: { dataHora: "asc" }
    });

    const ordemCorreta = ["ENTRADA_MANHA", "SAIDA_MANHA", "ENTRADA_TARDE", "SAIDA_NOITE"];
    
    // Mapeia quais registros já foram feitos
    const status = ordemCorreta.map(tipo => ({
      tipo,
      registrado: registrosHoje.some(r => r.tipo === tipo),
      horario: registrosHoje.find(r => r.tipo === tipo)?.dataHora || null
    }));

    res.json({
      data: new Date().toLocaleDateString("pt-BR"),
      totalRegistros: registrosHoje.length,
      registros: registrosHoje,
      status,
      proximoEsperado: ordemCorreta[registrosHoje.length] || "Jornada finalizada"
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar registros do dia" });
  }
});

/* =========================
   LISTAR TODOS REGISTROS (ADMIN)
========================= */
app.get("/registros", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const registros = await prisma.registro.findMany({
      include: {
        funcionario: {
          select: {
            nome: true,
            matricula: true,
            cargo: true
          }
        }
      },
      orderBy: { dataHora: "desc" }
    });

    res.json(registros);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao listar registros" });
  }
});

/* =========================
   LISTAR REGISTROS COM FILTRO (ADMIN)
========================= */
app.get("/registros/filtro", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const { dataInicio, dataFim, funcionarioId } = req.query;
    
    let where = {};
    
    // Filtro por funcionário
    if (funcionarioId) {
      where.funcionarioId = parseInt(funcionarioId);
    }
    
    // Filtro por data
    if (dataInicio || dataFim) {
      where.dataHora = {};
      
      if (dataInicio) {
        const inicio = new Date(dataInicio);
        inicio.setHours(0, 0, 0, 0);
        where.dataHora.gte = inicio;
      }
      
      if (dataFim) {
        const fim = new Date(dataFim);
        fim.setHours(23, 59, 59, 999);
        where.dataHora.lte = fim;
      }
    }
    
    const registros = await prisma.registro.findMany({
      where,
      include: {
        funcionario: {
          select: {
            nome: true,
            matricula: true,
            cargo: true
          }
        }
      },
      orderBy: { dataHora: "desc" }
    });
    
    res.json(registros);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao listar registros com filtro" });
  }
});

/* =========================
   ESTATÍSTICAS DO DASHBOARD (ADMIN)
========================= */
app.get("/dashboard/estatisticas", autenticarToken, autorizarAdmin, async (req, res) => {
  try {
    const hoje = new Date();
    hoje.setHours(0, 0, 0, 0);
    
    const amanha = new Date(hoje);
    amanha.setDate(amanha.getDate() + 1);
    
    const inicioMes = new Date(hoje.getFullYear(), hoje.getMonth(), 1);
    const fimMes = new Date(hoje.getFullYear(), hoje.getMonth() + 1, 0, 23, 59, 59);
    
    // Total de funcionários
    const totalFuncionarios = await prisma.funcionario.count();
    
    // Registros hoje
    const registrosHoje = await prisma.registro.count({
      where: {
        dataHora: {
          gte: hoje,
          lt: amanha
        }
      }
    });
    
    // Registros do mês
    const registrosMes = await prisma.registro.count({
      where: {
        dataHora: {
          gte: inicioMes,
          lte: fimMes
        }
      }
    });
    
    // Registros por tipo (últimos 30 dias)
    const trintaDiasAtras = new Date();
    trintaDiasAtras.setDate(trintaDiasAtras.getDate() - 30);
    
    const registrosPorTipo = await prisma.registro.groupBy({
      by: ['tipo'],
      where: {
        dataHora: {
          gte: trintaDiasAtras
        }
      },
      _count: {
        tipo: true
      }
    });
    
    // Registros por dia (últimos 7 dias)
    const ultimos7Dias = [];
    for (let i = 6; i >= 0; i--) {
      const dia = new Date();
      dia.setDate(dia.getDate() - i);
      dia.setHours(0, 0, 0, 0);
      
      const diaSeguinte = new Date(dia);
      diaSeguinte.setDate(diaSeguinte.getDate() + 1);
      
      const count = await prisma.registro.count({
        where: {
          dataHora: {
            gte: dia,
            lt: diaSeguinte
          }
        }
      });
      
      ultimos7Dias.push({
        data: dia.toLocaleDateString("pt-BR"),
        registros: count
      });
    }
    
    // Top funcionários que mais registraram
    const topFuncionarios = await prisma.registro.groupBy({
      by: ['funcionarioId'],
      where: {
        dataHora: {
          gte: inicioMes,
          lte: fimMes
        }
      },
      _count: {
        funcionarioId: true
      },
      orderBy: {
        _count: {
          funcionarioId: 'desc'
        }
      },
      take: 5
    });
    
    // Buscar nomes dos funcionários
    const funcionariosIds = topFuncionarios.map(f => f.funcionarioId);
    const funcionariosInfo = await prisma.funcionario.findMany({
      where: {
        id: { in: funcionariosIds }
      },
      select: {
        id: true,
        nome: true
      }
    });
    
    const topFuncionariosComNomes = topFuncionarios.map(f => ({
      nome: funcionariosInfo.find(ff => ff.id === f.funcionarioId)?.nome || "N/A",
      total: f._count.funcionarioId
    }));
    
    // Função para formatar tipos
    const tiposMap = {
      ENTRADA_MANHA: "Entrada Manhã",
      SAIDA_MANHA: "Saída Manhã",
      ENTRADA_TARDE: "Entrada Tarde",
      SAIDA_NOITE: "Saída Noite"
    };
    
    const registrosPorTipoFormatado = registrosPorTipo.map(r => ({
      tipo: tiposMap[r.tipo] || r.tipo,
      total: r._count.tipo
    }));
    
    res.json({
      totalFuncionarios,
      registrosHoje,
      registrosMes,
      registrosPorTipo: registrosPorTipoFormatado,
      registrosPorDia: ultimos7Dias,
      topFuncionarios: topFuncionariosComNomes
    });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: "Erro ao buscar estatísticas" });
  }
});

/* =========================
   INICIAR SERVIDOR
========================= */
app.listen(PORT, () => {
  console.log(`🔥 SERVIDOR RODANDO`);
  console.log(`🚀 http://localhost:${PORT}`);
});