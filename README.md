# 🚀 NovaDrive — File Manager Moderno

> Gerenciador de arquivos web feito do zero com design moderno, dark mode e PT-BR.

![NovaDrive](https://img.shields.io/badge/status-ativo-success)

## ✨ Funcionalidades

| Funcionalidade | Descrição |
|---|---|
| 🎨 **Design Moderno** | Dark theme, glassmorphism, animações suaves |
| 🔐 **Autenticação** | Login com JWT, multi-usuário com permissões |
| 📂 **Navegação** | Breadcrumbs, navegação por pastas |
| 📤 **Upload** | Drag & drop ou clique, múltiplos arquivos |
| 📥 **Download** | Arquivo único ou pasta em ZIP |
| ✏️ **Editor** | Visualize e edite arquivos de texto no navegador |
| 🖼️ **Preview** | Imagens, vídeos, áudio, PDF |
| 🔍 **Busca** | Filtro instantâneo por nome |
| 📋 **Copiar/Mover** | Ctrl+C / Ctrl+V entre pastas |
| 🗑️ **Lixeira** | Recupere arquivos excluídos |
| 👥 **Multi-usuário** | Admin e usuários com escopo |
| 📊 **Armazenamento** | Barra de uso do disco |
| 📱 **Responsivo** | Funciona em desktop e mobile |
| 🇧🇷 **PT-BR** | Interface completa em português |

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

Acesse: **http://SEU_IP:8000**

**Login padrão:** `admin` / `admin`

## ☁️ Deploy no Coolify

1. **New Resource → Docker Compose**
2. Cole o conteúdo do `docker-compose.yml`
3. Configure:
   - `ROOT_PATH`: diretório a gerenciar
   - `PORT`: 8000
4. Aponte um domínio (Coolify faz SSL automaticamente)
5. **Force rebuild** na primeira vez

## 🖥️ Desenvolvimento Local

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend (só abrir o HTML)
# O FastAPI serve o frontend em http://localhost:8000
```

## 📁 Estrutura

```
modern-filebrowser/
├── backend/
│   ├── main.py              # FastAPI completo
│   └── requirements.txt
├── frontend/
│   └── index.html           # SPA moderno dark/glass
├── Dockerfile
├── docker-compose.yml
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
