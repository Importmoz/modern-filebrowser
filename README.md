# 🚀 NovaDrive — File Manager Moderno

> Gerenciador de arquivos web feito do zero com design moderno, dark mode e PT-BR.

![NovaDrive](https://img.shields.io/badge/status-ativo-success)

## ✨ Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| 🎨 **Design Moderno** | Dark theme, glassmorphism e navegação ágil otimizada para VPS |
| ⚡ **Navegação Instantânea** | Entrada imediata em pastas sem atraso de animações |
| 🖼️ **Miniaturas Reais** | Thumbnails gerados sob demanda em WebP com cache para imagens na grade |
| ⚡ **Ações em Lote (Bulk)** | Barra flutuante para download ZIP em massa, mover, copiar e apagar múltiplos arquivos |
| 🗑️ **Lixeira com Restauração** | Histórico com metadados de exclusão e restauração em 1 clique para a pasta de origem |
| 📝 **Editor com Syntax Highlighting** | Destaque de código com Prism.js (Python, JS, HTML, CSS, Bash, JSON, SQL, Docker, YAML), indentação Tab e atalho `Ctrl+S` |
| 🎵 **Player de Áudio Persistente** | Dock flutuante no rodapé com vinil animado para ouvir áudios enquanto navega livremente |
| 📊 **Monitor de Recursos da VPS** | Dashboard em tempo real com telemetria de CPU, Memória RAM, Disco, Uptime e RSS do container |
| 👥 **Gestão de Usuários (Admin)** | Painel administrativo completo para criar, editar escopos de pastas, alterar senhas e remover usuários |
| 📤 **Upload com Progresso Real** | Barra dinâmica de progresso com porcentagem, total em MB e velocidade de transferência (MB/s) |
| 🔍 **Busca Recursiva & Filtros** | Busca instantânea em toda a árvore de diretórios com filtros por tipo de arquivo |
| 📊 **Analisador de Disco** | Gráficos visuais mostrando quais pastas e arquivos ocupam mais espaço no servidor |
| 📱 **PWA (Progressive Web App)** | Instalável no smartphone ou desktop com Service Worker e ícone oficial |
| 🔐 **Autenticação Segura** | Sessões JWT com proteção de rotas de sistema e escopo por usuário |
| 🇧🇷 **PT-BR** | Interface completa 100% em português |

## 🚀 Deploy Rápido

```bash
# Clone
git clone https://github.com/Importmoz/modern-filebrowser.git
cd modern-filebrowser

# Configure
cp .env.example .env
# Edite ROOT_PATH para o diretório que quer gerenciar

# Suba
docker compose up -d --build
```

Acesse: **http://SEU_IP:8090**

**Login padrão:** `admin` / `admin`

## ☁️ Deploy no Coolify

1. **New Resource → Docker Compose**
2. Cole o conteúdo do `docker-compose.yaml`
3. Configure:
   - `ROOT_PATH`: diretório a gerenciar
   - `PORT`: 8090
4. Aponte um domínio (Coolify faz SSL automaticamente)
5. **Force rebuild** na primeira vez

## 🖥️ Desenvolvimento Local

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8090

# Frontend (só abrir o HTML)
# O FastAPI serve o frontend em http://localhost:8090
```

## 📁 Estrutura

```
modern-filebrowser/
├── backend/
│   ├── main.py              # FastAPI completo
│   └── requirements.txt
├── frontend/
│   ├── index.html           # SPA moderno dark/glass
│   ├── manifest.json        # PWA Web App Manifest
│   ├── icon.svg             # Ícone do aplicativo
│   └── sw.js                # Service Worker para cache e PWA
├── Dockerfile
├── docker-compose.yaml
├── .env.example
└── README.md
```

## 🔧 Comandos Úteis

```bash
# Logs
docker logs novadrive -f

# Parar
docker compose down

# Atualizar
docker compose build --pull && docker compose up -d

# Criar admin
# Já criado automaticamente no primeiro start

# Acessar container
docker exec -it novadrive sh
```

## 🐛 Troubleshooting

| Problema | Solução |
|---|---|
| Login não funciona | Delete `data/users.json` e reinicie |
| Upload muito grande | Aumente `MAX_FILE_SIZE` no .env |
| Porta ocupada | Mude `PORT` no .env |
| Permissão negada | `chown -R 1000:1000 /caminho/do/seu/diretorio` |

---

<p align="center">Feito com ☕ — Modern File Browser</p>
