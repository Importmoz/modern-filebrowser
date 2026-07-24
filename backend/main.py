# Modern File Browser
# Backend - FastAPI
#
# Dependências:
#   pip install fastapi uvicorn python-multipart pyjwt aiofiles
#
# Para rodar:
#   uvicorn main:app --host 0.0.0.0 --port 8090

import os
import json
import shutil
import zipfile
import hashlib
import uuid
import mimetypes
import io
import datetime
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query, Request
from fastapi.responses import StreamingResponse, JSONResponse, FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import jwt

# =============================================================================
# Configuração
# =============================================================================

ROOT_PATH = os.environ.get("ROOT_PATH", "/data")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-to-a-secure-random-string")
JWT_ALGO = "HS256"
JWT_EXPIRATION_HOURS = 24
USERS_FILE = os.environ.get("USERS_FILE", "/app/data/users.json")
PORT = int(os.environ.get("PORT", 8090))
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 500 * 1024 * 1024))  # 500MB

app = FastAPI(title="NovaDrive", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Utilitários
# =============================================================================

def load_users():
    """Carrega usuários do arquivo JSON."""
    default_users = {
        "admin": {
            "password": hashlib.sha256("admin".encode()).hexdigest(),
            "name": "Administrador",
            "role": "admin",
            "scope": "/",
            "created_at": datetime.datetime.now().isoformat()
        }
    }
    if not os.path.exists(USERS_FILE):
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)
        return default_users
    
    try:
        with open(USERS_FILE, "r") as f:
            data = json.load(f)
            if not data or not isinstance(data, dict):
                raise ValueError("JSON de usuários inválido")
            return data
    except Exception as e:
        # Se o arquivo estiver corrompido ou vazio, re-cria com o usuário admin padrão
        print(f"⚠️ Erro ao ler {USERS_FILE} ({e}). Recriando com usuário admin...")
        with open(USERS_FILE, "w") as f:
            json.dump(default_users, f, indent=2)
        return default_users

def save_users(users):
    """Salva usuários no arquivo JSON."""
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

def verify_password(password, hashed):
    """Verifica senha contra hash SHA256."""
    return hashlib.sha256(password.encode()).hexdigest() == hashed

def hash_password(password):
    """Gera hash SHA256 da senha."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(username):
    """Cria JWT token."""
    payload = {
        "sub": username,
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        "jti": str(uuid.uuid4())
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token):
    """Decodifica JWT token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(401, "Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Token inválido")

def get_current_user(request: Request):
    """Obtém usuário atual do token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Não autenticado")
    token = auth[7:]
    username = decode_token(token)
    users = load_users()
    if username not in users:
        raise HTTPException(401, "Usuário não encontrado")
    return {**users[username], "username": username}

def sanitize_path(path: str) -> str:
    """Normaliza e valida o caminho."""
    # Remove caracteres perigosos e normaliza
    path = path.replace("..", "").lstrip("/")
    return path

def get_full_path(user_path: str) -> Path:
    """Resolve o caminho absoluto seguro."""
    safe = sanitize_path(user_path)
    full = Path(ROOT_PATH) / safe
    full = full.resolve()
    # Garante que está dentro de ROOT_PATH
    if not str(full).startswith(str(Path(ROOT_PATH).resolve())):
        raise HTTPException(403, "Acesso negado")
    return full

def format_size(size_bytes: int) -> str:
    """Formata tamanho em bytes para formato legível."""
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.1f} {units[i]}"

def get_file_icon(filename: str, is_dir: bool = False) -> str:
    """Retorna tipo de ícone baseado na extensão."""
    if is_dir:
        return "folder"
    ext = Path(filename).suffix.lower()
    icons = {
        ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
        ".svg": "image", ".webp": "image", ".ico": "image",
        ".mp4": "video", ".avi": "video", ".mkv": "video", ".mov": "video",
        ".webm": "video",
        ".mp3": "audio", ".wav": "audio", ".flac": "audio", ".ogg": "audio",
        ".pdf": "pdf",
        ".doc": "document", ".docx": "document", ".odt": "document",
        ".xls": "spreadsheet", ".xlsx": "spreadsheet", ".csv": "spreadsheet",
        ".zip": "archive", ".rar": "archive", ".7z": "archive", ".tar": "archive",
        ".gz": "archive", ".bz2": "archive",
        ".py": "code", ".js": "code", ".ts": "code", ".html": "code",
        ".css": "code", ".json": "code", ".xml": "code", ".yaml": "code",
        ".yml": "code", ".sh": "code", ".bat": "code", ".sql": "code",
        ".txt": "text", ".md": "text", ".log": "text",
        ".exe": "binary", ".dll": "binary", ".so": "binary",
        ".iso": "disc", ".img": "disc",
        ".torrent": "download",
    }
    return icons.get(ext, "file")

# =============================================================================
# Rotas de Autenticação
# =============================================================================

@app.post("/api/auth/login")
async def login(
    request: Request,
    username: Optional[str] = Form(None),
    password: Optional[str] = Form(None)
):
    """Login do usuário (aceita JSON ou Form)."""
    if not username or not password:
        try:
            body = await request.json()
            username = username or body.get("username")
            password = password or body.get("password")
        except Exception:
            pass

    if not username or not password:
        raise HTTPException(400, "Usuário e senha são obrigatórios")

    users = load_users()
    if username not in users or not verify_password(password, users[username]["password"]):
        raise HTTPException(401, "Usuário ou senha inválidos")
    
    token = create_token(username)
    user = users[username]
    return {
        "token": token,
        "user": {
            "username": username,
            "name": user.get("name", username),
            "role": user.get("role", "user")
        }
    }

@app.get("/api/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Retorna dados do usuário atual."""
    return {
        "username": current_user["username"],
        "name": current_user.get("name", current_user["username"]),
        "role": current_user.get("role", "user")
    }

# =============================================================================
# Rotas de Arquivos
# =============================================================================

@app.get("/api/files")
async def list_files(
    path: str = Query("/", description="Caminho do diretório"),
    search: Optional[str] = Query(None, description="Termo de busca"),
    current_user: dict = Depends(get_current_user)
):
    """Lista arquivos e pastas em um diretório."""
    full_path = get_full_path(path)
    
    if not full_path.exists():
        raise HTTPException(404, "Diretório não encontrado")
    if not full_path.is_dir():
        raise HTTPException(400, "Caminho não é um diretório")
    
    items = []
    
    try:
        raw_entries = list(full_path.iterdir())
        entries = sorted(raw_entries, key=lambda x: (not (x.is_dir() if hasattr(x, 'is_dir') else False), x.name.lower()))
    except PermissionError:
        raise HTTPException(403, "Permissão negada ao ler diretório")
    except Exception as e:
        raise HTTPException(500, f"Erro ao acessar diretório: {str(e)}")
    
    for entry in entries:
        try:
            # Pula arquivos ocultos de sistema (.trash etc.)
            if entry.name.startswith(".") and entry.name not in [".", ".."]:
                continue
            
            is_dir = False
            try:
                is_dir = entry.is_dir()
            except Exception:
                pass
            
            stat_size = 0
            stat_mtime = 0
            try:
                stat = entry.stat()
                stat_size = stat.st_size
                stat_mtime = stat.st_mtime
            except Exception:
                pass
            
            # Filtro de busca (opcional)
            if search and search.lower() not in entry.name.lower():
                continue
            
            try:
                rel = str(entry.relative_to(ROOT_PATH))
                rel_path = "/" + rel.lstrip("/") if rel != "." else "/"
            except Exception:
                rel_path = "/" + entry.name
            
            items.append({
                "name": entry.name,
                "path": rel_path,
                "is_dir": is_dir,
                "size": stat_size if not is_dir else 0,
                "size_formatted": format_size(stat_size) if not is_dir else "",
                "modified": datetime.datetime.fromtimestamp(stat_mtime).isoformat() if stat_mtime else "",
                "icon": get_file_icon(entry.name, is_dir),
                "extension": Path(entry.name).suffix.lower() if not is_dir else "",
            })
        except Exception:
            continue
    
    # Informações do diretório atual
    breadcrumbs = []
    rel_path = Path(sanitize_path(path))
    parts = rel_path.parts
    
    for i, part in enumerate(parts):
        if part:
            breadcrumbs.append({
                "name": part,
                "path": "/" + "/".join(parts[:i+1])
            })
    
    return {
        "items": items,
        "breadcrumbs": breadcrumbs,
        "current_path": path,
        "total": len(items),
        "directory": full_path.name if full_path.name else "/"
    }

@app.get("/api/files/info")
async def file_info(
    path: str = Query(..., description="Caminho do arquivo"),
    current_user: dict = Depends(get_current_user)
):
    """Retorna informações detalhadas de um arquivo/pasta."""
    full_path = get_full_path(path)
    
    if not full_path.exists():
        raise HTTPException(404, "Arquivo ou pasta não encontrado")
    
    stat = full_path.stat()
    is_dir = full_path.is_dir()
    
    return {
        "name": full_path.name,
        "path": path,
        "is_dir": is_dir,
        "size": stat.st_size if not is_dir else 0,
        "size_formatted": format_size(stat.st_size) if not is_dir else "",
        "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "created": datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
        "icon": get_file_icon(full_path.name, is_dir),
        "extension": full_path.suffix.lower() if not is_dir else "",
        "permissions": oct(stat.st_mode)[-3:],
        "mime_type": mimetypes.guess_type(str(full_path))[0] or "application/octet-stream"
    }

@app.post("/api/files/upload")
async def upload_file(
    path: str = Form("/"),
    files: List[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user)
):
    """Upload de um ou múltiplos arquivos."""
    upload_dir = get_full_path(path)
    
    if not upload_dir.exists():
        raise HTTPException(404, "Diretório não encontrado")
    if not upload_dir.is_dir():
        raise HTTPException(400, "Caminho não é um diretório")
    
    uploaded = []
    errors = []
    
    for file in files:
        try:
            content = await file.read()
            
            if len(content) > MAX_FILE_SIZE:
                errors.append({"name": file.filename, "error": "Arquivo excede o tamanho máximo"})
                continue
            
            file_path = upload_dir / file.filename
            
            # Evita sobrescrever: adiciona (1), (2) etc.
            if file_path.exists():
                base = file_path.stem
                ext = file_path.suffix
                counter = 1
                while file_path.exists():
                    file_path = upload_dir / f"{base} ({counter}){ext}"
                    counter += 1
            
            with open(file_path, "wb") as f:
                f.write(content)
            
            uploaded.append(file.filename)
        except Exception as e:
            errors.append({"name": file.filename, "error": str(e)})
    
    return {
        "uploaded": uploaded,
        "errors": errors,
        "total": len(uploaded),
        "failed": len(errors)
    }

@app.post("/api/files/folder")
async def create_folder(
    path: str = Form("/"),
    name: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Cria uma nova pasta."""
    parent = get_full_path(path)
    
    if not parent.exists():
        raise HTTPException(404, "Diretório pai não encontrado")
    if not parent.is_dir():
        raise HTTPException(400, "Caminho não é um diretório")
    
    new_folder = parent / name
    
    if new_folder.exists():
        raise HTTPException(409, "Já existe uma pasta com este nome")
    
    new_folder.mkdir(parents=True, exist_ok=True)
    
    return {
        "name": name,
        "path": str(new_folder.relative_to(ROOT_PATH)),
        "created": True
    }

@app.put("/api/files/rename")
async def rename_file(
    path: str = Form(...),
    new_name: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Renomeia arquivo ou pasta."""
    old_path = get_full_path(path)
    
    if not old_path.exists():
        raise HTTPException(404, "Arquivo não encontrado")
    
    new_path = old_path.parent / new_name
    
    if new_path.exists():
        raise HTTPException(409, "Já existe um arquivo com este nome")
    
    old_path.rename(new_path)
    
    return {
        "old_name": old_path.name,
        "new_name": new_name,
        "renamed": True
    }

@app.delete("/api/files")
async def delete_file(
    path: str = Query(...),
    permanent: bool = Query(False),
    current_user: dict = Depends(get_current_user)
):
    """Exclui arquivo ou pasta (move para lixeira ou exclui permanentemente)."""
    full_path = get_full_path(path)
    
    if not full_path.exists():
        raise HTTPException(404, "Arquivo não encontrado")
    
    if permanent:
        # Exclusão permanente
        if full_path.is_dir():
            shutil.rmtree(full_path)
        else:
            full_path.unlink()
        return {"deleted": True, "permanent": True}
    else:
        # Move para lixeira
        trash_dir = Path(ROOT_PATH) / ".trash"
        trash_dir.mkdir(parents=True, exist_ok=True)
        
        # Evita sobrescrever na lixeira
        trash_path = trash_dir / full_path.name
        if trash_path.exists():
            base = full_path.stem
            ext = full_path.suffix if not full_path.is_dir() else ""
            counter = 1
            while trash_path.exists():
                trash_path = trash_dir / f"{base}_{counter}{ext}"
                counter += 1
        
        shutil.move(str(full_path), str(trash_path))
        return {"deleted": True, "permanent": False, "trash_path": str(trash_path.relative_to(ROOT_PATH))}

@app.get("/api/files/download")
async def download_file(
    path: str = Query(...),
    current_user: dict = Depends(get_current_user)
):
    """Download de arquivo ou pasta (ZIP se for pasta)."""
    full_path = get_full_path(path)
    
    if not full_path.exists():
        raise HTTPException(404, "Arquivo não encontrado")
    
    if full_path.is_file():
        # Download de arquivo único
        mime_type, _ = mimetypes.guess_type(str(full_path))
        return FileResponse(
            path=str(full_path),
            filename=full_path.name,
            media_type=mime_type or "application/octet-stream"
        )
    else:
        # Download de pasta como ZIP
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(full_path):
                for file in files:
                    file_path = Path(root) / file
                    arcname = str(file_path.relative_to(full_path.parent))
                    zf.write(file_path, arcname)
        
        zip_buffer.seek(0)
        return StreamingResponse(
            zip_buffer,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{full_path.name}.zip"'
            }
        )

@app.post("/api/files/copy")
async def copy_file(
    path: str = Form(...),
    destination: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Copia arquivo ou pasta para outro local."""
    src = get_full_path(path)
    dst_parent = get_full_path(destination)
    
    if not src.exists():
        raise HTTPException(404, "Arquivo não encontrado")
    if not dst_parent.exists() or not dst_parent.is_dir():
        raise HTTPException(404, "Diretório destino não encontrado")
    
    dst = dst_parent / src.name
    
    if dst.exists():
        base = src.stem
        ext = src.suffix if not src.is_dir() else ""
        counter = 1
        while dst.exists():
            dst = dst_parent / f"{base} (cópia {counter}){ext}"
            counter += 1
    
    if src.is_dir():
        shutil.copytree(src, dst)
    else:
        shutil.copy2(src, dst)
    
    return {
        "copied": True,
        "source": path,
        "destination": str(dst.relative_to(ROOT_PATH))
    }

@app.post("/api/files/move")
async def move_file(
    path: str = Form(...),
    destination: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Move arquivo ou pasta para outro local."""
    src = get_full_path(path)
    dst_parent = get_full_path(destination)
    
    if not src.exists():
        raise HTTPException(404, "Arquivo não encontrado")
    if not dst_parent.exists() or not dst_parent.is_dir():
        raise HTTPException(404, "Diretório destino não encontrado")
    
    dst = dst_parent / src.name
    
    if dst.exists():
        raise HTTPException(409, "Já existe um arquivo com este nome no destino")
    
    shutil.move(str(src), str(dst))
    
    return {
        "moved": True,
        "source": path,
        "destination": str(dst.relative_to(ROOT_PATH))
    }

@app.get("/api/files/preview")
async def preview_file(
    path: str = Query(...),
    current_user: dict = Depends(get_current_user)
):
    """Retorna conteúdo de arquivo de texto para preview."""
    full_path = get_full_path(path)
    
    if not full_path.exists() or not full_path.is_file():
        raise HTTPException(404, "Arquivo não encontrado")
    
    try:
        # Tenta verificar se é um arquivo binário checando nulos iniciais
        with open(full_path, 'rb') as f:
            chunk = f.read(4096)
            if b'\0' in chunk:
                raise HTTPException(400, "Arquivo binário")
                
        content = full_path.read_text(encoding="utf-8", errors="replace")
        ext = full_path.suffix.lower()
        return {"content": content, "name": full_path.name, "language": ext.lstrip(".") or "text"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Erro ao ler arquivo: {str(e)}")

@app.put("/api/files/save")
async def save_file(
    path: str = Form(...),
    content: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Salva conteúdo em arquivo de texto."""
    full_path = get_full_path(path)
    
    if not full_path.exists():
        raise HTTPException(404, "Arquivo não encontrado")
    
    try:
        full_path.write_text(content, encoding="utf-8")
        return {"saved": True, "path": path}
    except Exception as e:
        raise HTTPException(500, f"Erro ao salvar arquivo: {str(e)}")

@app.get("/api/files/trash")
async def list_trash(current_user: dict = Depends(get_current_user)):
    """Lista arquivos na lixeira."""
    trash_dir = Path(ROOT_PATH) / ".trash"
    
    if not trash_dir.exists():
        return {"items": [], "total": 0}
    
    items = []
    for entry in sorted(trash_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = entry.stat()
        is_dir = entry.is_dir()
        
        items.append({
            "name": entry.name,
            "path": f"/.trash/{entry.name}",
            "is_dir": is_dir,
            "size": stat.st_size if not is_dir else 0,
            "size_formatted": format_size(stat.st_size) if not is_dir else "",
            "deleted_at": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "icon": get_file_icon(entry.name, is_dir),
        })
    
    return {"items": items, "total": len(items)}

@app.post("/api/files/trash/restore")
async def restore_file(
    path: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    """Restaura arquivo da lixeira."""
    trash_path = get_full_path(path)
    
    if not trash_path.exists():
        raise HTTPException(404, "Arquivo não encontrado na lixeira")
    
    # Tenta restaurar para o local original
    original_path = Path(ROOT_PATH) / trash_path.name
    
    if original_path.exists():
        # Se o original existe, coloca na raiz com sufixo
        base = trash_path.stem
        ext = trash_path.suffix if not trash_path.is_dir() else ""
        counter = 1
        while original_path.exists():
            original_path = Path(ROOT_PATH) / f"{base}_restaurado_{counter}{ext}"
            counter += 1
    
    shutil.move(str(trash_path), str(original_path))
    
    return {
        "restored": True,
        "name": original_path.name,
        "path": str(original_path.relative_to(ROOT_PATH))
    }

@app.delete("/api/files/trash/empty")
async def empty_trash(current_user: dict = Depends(get_current_user)):
    """Esvazia a lixeira."""
    trash_dir = Path(ROOT_PATH) / ".trash"
    
    if trash_dir.exists():
        shutil.rmtree(trash_dir)
        trash_dir.mkdir(parents=True, exist_ok=True)
    
    return {"emptied": True}

# =============================================================================
# Gerenciamento de Usuários (Admin)
# =============================================================================

@app.get("/api/admin/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    """Lista todos os usuários (admin apenas)."""
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Apenas administradores")
    
    users = load_users()
    result = []
    for username, data in users.items():
        result.append({
            "username": username,
            "name": data.get("name", username),
            "role": data.get("role", "user"),
            "scope": data.get("scope", "/"),
            "created_at": data.get("created_at", "")
        })
    
    return {"users": result}

@app.post("/api/admin/users")
async def create_user(
    username: str = Form(...),
    password: str = Form(...),
    name: Optional[str] = Form(None),
    role: str = Form("user"),
    current_user: dict = Depends(get_current_user)
):
    """Cria novo usuário (admin apenas)."""
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Apenas administradores")
    
    users = load_users()
    
    if username in users:
        raise HTTPException(409, "Usuário já existe")
    
    users[username] = {
        "password": hash_password(password),
        "name": name or username,
        "role": role,
        "scope": "/",
        "created_at": datetime.datetime.now().isoformat()
    }
    save_users(users)
    
    return {"created": True, "username": username}

@app.delete("/api/admin/users/{username}")
async def delete_user(
    username: str,
    current_user: dict = Depends(get_current_user)
):
    """Remove usuário (admin apenas)."""
    if current_user.get("role") != "admin":
        raise HTTPException(403, "Apenas administradores")
    
    if username == current_user["username"]:
        raise HTTPException(400, "Não pode remover a si mesmo")
    
    users = load_users()
    if username not in users:
        raise HTTPException(404, "Usuário não encontrado")
    
    del users[username]
    save_users(users)
    
    return {"deleted": True, "username": username}

# =============================================================================
# Storage Info
# =============================================================================

@app.get("/api/storage")
async def storage_info(current_user: dict = Depends(get_current_user)):
    """Informações de armazenamento."""
    root = Path(ROOT_PATH)
    
    if not root.exists():
        return {"total": 0, "used": 0, "free": 0, "total_formatted": "0 B", "used_formatted": "0 B", "free_formatted": "0 B"}
    
    stat = None
    try:
        stat = root.stat()
        disk = shutil.disk_usage(root)
        total = disk.total
        used = disk.used
        free = disk.free
        
        return {
            "total": total,
            "used": used,
            "free": free,
            "total_formatted": format_size(total),
            "used_formatted": format_size(used),
            "free_formatted": format_size(free),
            "percent_used": round((used / total) * 100, 1) if total > 0 else 0
        }
    except:
        return {"total": 0, "used": 0, "free": 0, "error": "Não foi possível obter informações do disco"}

# =============================================================================
# Frontend Static Files (deve ser montado APÓS todas as rotas da API)
# =============================================================================

FRONTEND_DIR = os.environ.get("FRONTEND_DIR", os.path.join(os.path.dirname(__file__), "..", "frontend"))
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")

# =============================================================================
# Inicialização
# =============================================================================

@app.on_event("startup")
async def startup():
    """Inicializa diretórios e arquivos necessários."""
    # Cria diretório raiz se não existir
    os.makedirs(ROOT_PATH, exist_ok=True)
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    
    # Cria diretório de lixeira
    trash_dir = Path(ROOT_PATH) / ".trash"
    trash_dir.mkdir(parents=True, exist_ok=True)
    
    # Carrega/cria usuários
    load_users()
    
    print(f"🚀 NovaDrive iniciado!")
    print(f"📂 Diretório raiz: {ROOT_PATH}")
    print(f"🔑 Admin padrão: admin / admin")
    print(f"🌐 http://0.0.0.0:{PORT}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
