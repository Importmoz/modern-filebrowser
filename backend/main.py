# Modern File Browser
# Backend - FastAPI
#
# Dependências:
#   pip install fastapi uvicorn python-multipart pyjwt aiofiles
#
# Para rodar:
#   uvicorn main:app --host 0.0.0.0 --port 8090

import os
import sys
import json
import shutil

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
if hasattr(sys.stderr, 'reconfigure'):
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
import zipfile
import hashlib
import uuid
import mimetypes
import io
import datetime
import time
from pathlib import Path
from typing import Optional, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query, Request, Header
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
SHARES_FILE = os.environ.get("SHARES_FILE", "/app/data/shares.json")
PORT = int(os.environ.get("PORT", 8090))
MAX_FILE_SIZE = int(os.environ.get("MAX_FILE_SIZE", 500 * 1024 * 1024))  # 500MB
SECURE_CODE = os.environ.get("SECURE_CODE", "123456")

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



SECURE_CODE = os.environ.get("SECURE_CODE", "123456")

def is_system_path(path_str: str) -> bool:
    try:
        # Avoid get_full_path circular issue by resolving simply here
        safe = sanitize_path(path_str)
        full = str((Path(ROOT_PATH) / safe).resolve())
        protected = ('/etc', '/var', '/usr', '/bin', '/sbin', '/lib', '/boot', '/sys', '/proc', '/dev')
        return full.startswith(protected) or full == '/' or full == '/root'
    except:
        return False

def check_security(path_str: str, code: str):
    if is_system_path(path_str) and code != SECURE_CODE:
        raise HTTPException(403, "Código de segurança inválido ou ausente para área de sistema")


def load_shares():
    if not os.path.exists(SHARES_FILE):
        return {}
    try:
        with open(SHARES_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_shares(shares):
    os.makedirs(os.path.dirname(SHARES_FILE), exist_ok=True)
    with open(SHARES_FILE, "w") as f:
        json.dump(shares, f, indent=2)

def clean_expired_shares():
    shares = load_shares()
    now = datetime.datetime.now().timestamp()
    to_delete = [k for k, v in shares.items() if v.get('expires_at') and v['expires_at'] < now]
    if to_delete:
        for k in to_delete:
            del shares[k]
        save_shares(shares)

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
    token = None
    if auth.startswith("Bearer "):
        token = auth[7:]
    elif request.query_params.get("token"):
        token = request.query_params.get("token")
        
    if not token:
        raise HTTPException(401, "Não autenticado")
        
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

def to_relative_path(p: Path) -> str:
    """Retorna caminho relativo normalizado ao ROOT_PATH com barra inicial."""
    try:
        root_resolved = Path(ROOT_PATH).resolve()
        rel = str(p.resolve().relative_to(root_resolved)).replace("\\", "/")
        return "/" + rel if rel != "." else "/"
    except Exception:
        name = p.name if hasattr(p, 'name') else str(p)
        return "/" + name.lstrip("/")

# Cache em memória para tamanhos de pastas: path_str -> (timestamp, size_bytes, file_count, dir_count)
FOLDER_SIZE_CACHE = {}
CACHE_TTL = 30  # 30 segundos

def calculate_dir_size(dir_path: Path, max_depth: int = 15, current_depth: int = 0) -> tuple[int, int, int]:
    """Calcula tamanho total em bytes, contagem de arquivos e subpastas recursivamente."""
    path_str = str(dir_path.resolve()) if hasattr(dir_path, 'resolve') else str(dir_path)
    now = time.time()
    if path_str in FOLDER_SIZE_CACHE:
        cached_time, c_size, c_files, c_dirs = FOLDER_SIZE_CACHE[path_str]
        if now - cached_time < CACHE_TTL:
            return c_size, c_files, c_dirs

    total_size = 0
    file_count = 0
    dir_count = 0

    try:
        with os.scandir(dir_path) as it:
            for entry in it:
                try:
                    name = entry.name
                    if name in ('.trash', '.git', '.venv', '__pycache__', '.run-data'):
                        continue
                    if entry.is_file(follow_symlinks=False):
                        total_size += entry.stat(follow_symlinks=False).st_size
                        file_count += 1
                    elif entry.is_dir(follow_symlinks=False):
                        dir_count += 1
                        if current_depth < max_depth:
                            sub_size, sub_files, sub_dirs = calculate_dir_size(
                                Path(entry.path), max_depth=max_depth, current_depth=current_depth + 1
                            )
                            total_size += sub_size
                            file_count += sub_files
                            dir_count += sub_dirs
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    except (PermissionError, FileNotFoundError, OSError):
        pass

    FOLDER_SIZE_CACHE[path_str] = (now, total_size, file_count, dir_count)
    return total_size, file_count, dir_count

def search_files_deep(base_path: Path, query: str, recursive: bool = True, file_type: Optional[str] = None, limit: int = 300) -> list:
    """Busca arquivos e pastas com suporte a pesquisa recursiva e filtros de tipo."""
    query_lower = query.lower().strip()
    results = []

    type_extensions = {
        "image": {".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico", ".bmp", ".tiff"},
        "video": {".mp4", ".avi", ".mkv", ".mov", ".webm", ".flv", ".wmv", ".m4v"},
        "audio": {".mp3", ".wav", ".flac", ".ogg", ".aac", ".m4a", ".wma"},
        "document": {".pdf", ".doc", ".docx", ".odt", ".rtf", ".txt", ".md", ".xls", ".xlsx", ".csv", ".ppt", ".pptx"},
        "code": {".py", ".js", ".ts", ".jsx", ".tsx", ".html", ".css", ".json", ".xml", ".yaml", ".yml", ".sh", ".bat", ".sql", ".c", ".cpp", ".h", ".rs", ".go", ".php", ".env"},
        "archive": {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}
    }

    def matches_type(name: str, is_dir: bool) -> bool:
        if not file_type or file_type == "all":
            return True
        if file_type == "folder":
            return is_dir
        if file_type == "file":
            return not is_dir
        if is_dir:
            return False
        ext = Path(name).suffix.lower()
        allowed = type_extensions.get(file_type, set())
        return ext in allowed

    if not recursive:
        try:
            with os.scandir(base_path) as it:
                for entry in it:
                    if entry.name.startswith(".") and entry.name not in (".", ".."):
                        continue
                    if query_lower in entry.name.lower():
                        is_dir = entry.is_dir(follow_symlinks=False)
                        if not matches_type(entry.name, is_dir):
                            continue
                        stat = entry.stat(follow_symlinks=False)
                        rel = to_relative_path(Path(entry.path))
                        parent_rel = str(Path(rel).parent).replace("\\", "/")
                        if parent_rel == ".":
                            parent_rel = "/"

                        size = stat.st_size if not is_dir else 0
                        results.append({
                            "name": entry.name,
                            "path": rel,
                            "directory": parent_rel,
                            "is_dir": is_dir,
                            "size": size,
                            "size_formatted": format_size(size) if not is_dir else "",
                            "modified": datetime.datetime.fromtimestamp(stat.st_mtime).isoformat() if stat.st_mtime else "",
                            "icon": get_file_icon(entry.name, is_dir),
                            "extension": Path(entry.name).suffix.lower() if not is_dir else ""
                        })
                        if len(results) >= limit:
                            break
        except Exception:
            pass
        return results

    # Busca recursiva
    try:
        for root, dirs, files in os.walk(str(base_path), topdown=True):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ('.trash', '.git', '.venv', '__pycache__', '.run-data')]
            current_root_p = Path(root)

            for d in dirs:
                if query_lower in d.lower():
                    if matches_type(d, True):
                        dp = current_root_p / d
                        try:
                            st = dp.stat(follow_symlinks=False)
                            rel = to_relative_path(dp)
                            parent_rel = str(Path(rel).parent).replace("\\", "/")
                            results.append({
                                "name": d,
                                "path": rel,
                                "directory": parent_rel,
                                "is_dir": True,
                                "size": 0,
                                "size_formatted": "",
                                "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat() if st.st_mtime else "",
                                "icon": "folder",
                                "extension": ""
                            })
                            if len(results) >= limit:
                                return results
                        except Exception:
                            continue

            for f in files:
                if f.startswith("."):
                    continue
                if query_lower in f.lower():
                    if matches_type(f, False):
                        fp = current_root_p / f
                        try:
                            st = fp.stat(follow_symlinks=False)
                            rel = to_relative_path(fp)
                            parent_rel = str(Path(rel).parent).replace("\\", "/")
                            results.append({
                                "name": f,
                                "path": rel,
                                "directory": parent_rel,
                                "is_dir": False,
                                "size": st.st_size,
                                "size_formatted": format_size(st.st_size),
                                "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat() if st.st_mtime else "",
                                "icon": get_file_icon(f, False),
                                "extension": Path(f).suffix.lower()
                            })
                            if len(results) >= limit:
                                return results
                        except Exception:
                            continue
    except Exception:
        pass

    return results

def analyze_path_space(full_path: Path, base_rel_path: str):
    """
    Analisa os tamanhos das subpastas diretas e ranqueia a pasta que mais ocupa espaço,
    além de encontrar o top 10 maiores pastas e top 10 maiores arquivos em profundidade.
    """
    direct_folders = []
    direct_files_size = 0
    direct_files_count = 0

    all_scanned_folders = []
    all_scanned_files = []

    # 1. Analisa as pastas e arquivos diretos de full_path
    try:
        with os.scandir(full_path) as it:
            for entry in it:
                if entry.name.startswith(".") or entry.name in ('.trash', '.git', '.venv', '__pycache__', '.run-data'):
                    continue
                try:
                    if entry.is_file(follow_symlinks=False):
                        size = entry.stat(follow_symlinks=False).st_size
                        mtime = entry.stat(follow_symlinks=False).st_mtime
                        direct_files_size += size
                        direct_files_count += 1
                        rel = to_relative_path(Path(entry.path))
                        all_scanned_files.append({
                            "name": entry.name,
                            "path": rel,
                            "size": size,
                            "size_formatted": format_size(size),
                            "modified": datetime.datetime.fromtimestamp(mtime).isoformat() if mtime else "",
                            "icon": get_file_icon(entry.name, False),
                            "extension": Path(entry.name).suffix.lower()
                        })
                    elif entry.is_dir(follow_symlinks=False):
                        folder_size, f_count, d_count = calculate_dir_size(Path(entry.path))
                        rel = to_relative_path(Path(entry.path))
                        
                        f_info = {
                            "name": entry.name,
                            "path": rel,
                            "size": folder_size,
                            "size_formatted": format_size(folder_size),
                            "files_count": f_count,
                            "dirs_count": d_count,
                            "icon": "folder"
                        }
                        direct_folders.append(f_info)
                        all_scanned_folders.append(f_info)
                except (PermissionError, FileNotFoundError, OSError):
                    continue
    except (PermissionError, FileNotFoundError, OSError):
        pass

    # 2. Caminhar pelas subpastas para coletar maiores pastas e arquivos (profundidade)
    scan_count = 0
    max_scan = 5000
    try:
        for root, dirs, files in os.walk(str(full_path), topdown=True):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ('.trash', '.git', '.venv', '__pycache__', '.run-data', 'node_modules')]
            current_root_p = Path(root)
            
            if current_root_p.resolve() != full_path.resolve():
                f_size, f_count, d_count = calculate_dir_size(current_root_p)
                rel = to_relative_path(current_root_p)
                
                if not any(f["path"] == rel for f in all_scanned_folders):
                    all_scanned_folders.append({
                        "name": current_root_p.name,
                        "path": rel,
                        "size": f_size,
                        "size_formatted": format_size(f_size),
                        "files_count": f_count,
                        "dirs_count": d_count,
                        "icon": "folder"
                    })

            for f in files:
                if f.startswith("."):
                    continue
                scan_count += 1
                if scan_count > max_scan:
                    break
                fp = current_root_p / f
                try:
                    st = fp.stat(follow_symlinks=False)
                    rel = to_relative_path(fp)
                    if not any(item["path"] == rel for item in all_scanned_files):
                        all_scanned_files.append({
                            "name": f,
                            "path": rel,
                            "size": st.st_size,
                            "size_formatted": format_size(st.st_size),
                            "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat() if st.st_mtime else "",
                            "icon": get_file_icon(f, False),
                            "extension": Path(f).suffix.lower()
                        })
                except Exception:
                    continue
            if scan_count > max_scan:
                break
    except Exception:
        pass

    total_direct_folder_size = sum(f["size"] for f in direct_folders)
    total_content_size = total_direct_folder_size + direct_files_size

    for f in direct_folders:
        f["percent"] = round((f["size"] / total_content_size * 100), 1) if total_content_size > 0 else 0
        f["is_heaviest"] = False

    direct_folders.sort(key=lambda x: x["size"], reverse=True)
    if direct_folders and direct_folders[0]["size"] > 0:
        direct_folders[0]["is_heaviest"] = True

    all_scanned_folders.sort(key=lambda x: x["size"], reverse=True)
    top_folders = all_scanned_folders[:10]

    all_scanned_files.sort(key=lambda x: x["size"], reverse=True)
    top_files = all_scanned_files[:10]

    disk_total, disk_used, disk_free = 0, 0, 0
    try:
        disk = shutil.disk_usage(full_path)
        disk_total, disk_used, disk_free = disk.total, disk.used, disk.free
    except Exception:
        pass

    heaviest = direct_folders[0] if (direct_folders and direct_folders[0]["size"] > 0) else (top_folders[0] if (top_folders and top_folders[0]["size"] > 0) else None)

    return {
        "analyzed_path": base_rel_path,
        "total_content_size": total_content_size,
        "total_content_size_formatted": format_size(total_content_size),
        "direct_files_size": direct_files_size,
        "direct_files_size_formatted": format_size(direct_files_size),
        "direct_files_count": direct_files_count,
        "direct_folders_count": len(direct_folders),
        "disk_total": disk_total,
        "disk_total_formatted": format_size(disk_total),
        "disk_used": disk_used,
        "disk_used_formatted": format_size(disk_used),
        "disk_free": disk_free,
        "disk_free_formatted": format_size(disk_free),
        "heaviest_folder": heaviest,
        "folders": direct_folders,
        "top_folders": top_folders,
        "top_files": top_files
    }

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
    calc_folder_sizes: bool = Query(False, description="Calcular tamanho de cada pasta"),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Lista arquivos e pastas em um diretório."""
    check_security(path, x_secure_code)
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
            search_str = search if isinstance(search, str) and search.strip() else None
            if search_str and search_str.lower() not in entry.name.lower():
                continue
            
            rel_path = to_relative_path(entry)
            
            dir_size = 0
            dir_size_formatted = ""
            if is_dir:
                path_str = str(entry.resolve()) if hasattr(entry, 'resolve') else str(entry)
                now = time.time()
                if calc_folder_sizes:
                    dir_size, _, _ = calculate_dir_size(entry)
                    dir_size_formatted = format_size(dir_size)
                elif path_str in FOLDER_SIZE_CACHE and (now - FOLDER_SIZE_CACHE[path_str][0] < CACHE_TTL):
                    dir_size = FOLDER_SIZE_CACHE[path_str][1]
                    dir_size_formatted = format_size(dir_size)
            
            items.append({
                "name": entry.name,
                "path": rel_path,
                "is_dir": is_dir,
                "size": stat_size if not is_dir else dir_size,
                "size_formatted": format_size(stat_size) if not is_dir else dir_size_formatted,
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
    
    current_build_path = ""
    for i, part in enumerate(parts):
        if part:
            current_build_path += "/" + part
            breadcrumbs.append({
                "name": part,
                "path": current_build_path
            })
    
    return {
        "items": items,
        "breadcrumbs": breadcrumbs,
        "current_path": path,
        "total": len(items),
        "directory": full_path.name if full_path.name else "/"
    }

@app.get("/api/files/search")
async def search_files(
    query: str = Query(..., min_length=1, description="Termo de busca"),
    path: str = Query("/", description="Caminho do diretório base"),
    recursive: bool = Query(True, description="Pesquisar recursivamente em subpastas"),
    file_type: Optional[str] = Query(None, description="Filtro de tipo (folder, file, image, video, audio, document, code, archive)"),
    limit: int = Query(300, ge=1, le=1000, description="Limite máximo de resultados"),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Pesquisa arquivos e pastas com suporte a busca recursiva e filtros de tipo."""
    check_security(path, x_secure_code)
    base_full = get_full_path(path)
    
    if not base_full.exists():
        raise HTTPException(404, "Diretório não encontrado")
    if not base_full.is_dir():
        raise HTTPException(400, "Caminho base não é um diretório")
    
    limit_val = 300
    try:
        limit_val = int(limit)
    except Exception:
        limit_val = 300

    recursive_val = True
    if isinstance(recursive, bool):
        recursive_val = recursive
    elif isinstance(recursive, str):
        recursive_val = recursive.lower() in ("true", "1", "yes")

    file_type_val = file_type if isinstance(file_type, str) else None

    results = search_files_deep(base_full, str(query), recursive=recursive_val, file_type=file_type_val, limit=limit_val)
    return {
        "query": str(query),
        "base_path": path,
        "recursive": recursive_val,
        "file_type": file_type_val or "all",
        "total": len(results),
        "truncated": len(results) >= limit_val,
        "items": results
    }

@app.get("/api/files/info")
async def file_info(
    path: str = Query(..., description="Caminho do arquivo"),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Retorna informações detalhadas de um arquivo/pasta."""
    check_security(path, x_secure_code)
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
    paths: Optional[List[str]] = Form(None),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Upload de arquivos preservando a árvore de diretórios."""
    check_security(path, x_secure_code)
    upload_dir = get_full_path(path)
    
    if not upload_dir.exists() or not upload_dir.is_dir():
        raise HTTPException(404, "Diretório inválido ou não encontrado")
    
    uploaded = []
    errors = []
    
    # Se paths não for enviado, faz o fallback para o nome original do arquivo (flat)
    actual_paths = paths if paths and len(paths) == len(files) else [f.filename for f in files]
    
    for file, rel_path in zip(files, actual_paths):
        try:
            content = await file.read()
            if len(content) > MAX_FILE_SIZE:
                errors.append({"name": file.filename, "error": "Excede o tamanho máximo"})
                continue
            
            # Sanitiza o path para evitar path traversal hack e constrói a árvore
            safe_rel_path = sanitize_path(rel_path)
            file_path = upload_dir / safe_rel_path
            
            # Cria a(s) subpasta(s) necessárias automaticamente
            file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Evita sobrescrever
            if file_path.exists():
                base = file_path.stem
                ext = file_path.suffix
                counter = 1
                while file_path.exists():
                    file_path = file_path.parent / f"{base} ({counter}){ext}"
                    counter += 1
            
            with open(file_path, "wb") as f:
                f.write(content)
            uploaded.append(safe_rel_path)
        except Exception as e:
            errors.append({"name": file.filename, "error": str(e)})
            
    return {"uploaded": len(uploaded), "errors": errors}

@app.post("/api/files/folder")
async def create_folder(
    path: str = Form("/"),
    name: str = Form(...),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Cria uma nova pasta."""
    check_security(path, x_secure_code)
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
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Renomeia arquivo ou pasta."""
    check_security(path, x_secure_code)
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
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Exclui arquivo ou pasta (move para lixeira ou exclui permanentemente)."""
    check_security(path, x_secure_code)
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
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Query(None)
):
    """Download de arquivo ou pasta (ZIP se for pasta)."""
    check_security(path, x_secure_code)
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
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Copia arquivo ou pasta para outro local."""
    check_security(path, x_secure_code)
    check_security(destination, x_secure_code)
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
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Move arquivo ou pasta para outro local."""
    check_security(path, x_secure_code)
    check_security(destination, x_secure_code)
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


@app.post("/api/files/share")
async def create_share(
    path: str = Form(...),
    expires_in_hours: int = Form(168), # Padrão: 7 dias
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Gera um link público para baixar o arquivo/pasta."""
    check_security(path, x_secure_code)
    full_path = get_full_path(path)
    
    if not full_path.exists():
        raise HTTPException(404, "Arquivo não encontrado")
        
    shares = load_shares()
    
    # Verifica se já existe um share ativo para este path
    for share_id, data in shares.items():
        if data['path'] == path and (not data.get('expires_at') or data['expires_at'] > datetime.datetime.now().timestamp()):
            return {"share_id": share_id, "url": f"/api/public/share/{share_id}"}
            
    share_id = str(uuid.uuid4().hex)
    shares[share_id] = {
        "path": path,
        "is_dir": full_path.is_dir(),
        "created_by": current_user["username"],
        "created_at": datetime.datetime.now().timestamp(),
        "expires_at": (datetime.datetime.now() + datetime.timedelta(hours=expires_in_hours)).timestamp() if expires_in_hours > 0 else None
    }
    
    save_shares(shares)
    return {"share_id": share_id, "url": f"/api/public/share/{share_id}"}

@app.get("/api/public/share/{share_id}")
async def download_shared_file(share_id: str):
    """Download público sem autenticação."""
    clean_expired_shares()
    shares = load_shares()
    
    if share_id not in shares:
        raise HTTPException(404, "Link inválido ou expirado")
        
    share_data = shares[share_id]
    
    # Segurança para downloads públicos: resolve baseado no ROOT_PATH mas s/ check de sistema p/ leitura
    safe = sanitize_path(share_data["path"])
    full_path = Path(ROOT_PATH) / safe
    full_path = full_path.resolve()
    
    if not str(full_path).startswith(str(Path(ROOT_PATH).resolve())) or not full_path.exists():
        raise HTTPException(404, "Arquivo indisponível")
        
    if full_path.is_file():
        mime_type, _ = mimetypes.guess_type(str(full_path))
        return FileResponse(
            path=str(full_path),
            filename=full_path.name,
            media_type=mime_type or "application/octet-stream"
        )
    else:
        # É uma pasta zipada na mosca
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

@app.post("/api/files/extract")
async def extract_zip(
    path: str = Form(...),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Extrai arquivo ZIP no mesmo diretório."""
    check_security(path, x_secure_code)
    full_path = get_full_path(path)
    
    if not full_path.exists() or not full_path.is_file():
        raise HTTPException(404, "Arquivo não encontrado")
        
    if full_path.suffix.lower() != '.zip':
        raise HTTPException(400, "Apenas arquivos .zip são suportados no momento")
        
    extract_dir = full_path.parent / full_path.stem
    
    # Se pasta com mesmo nome já existe, anexa timestamp
    if extract_dir.exists():
        extract_dir = full_path.parent / f"{full_path.stem}_{int(datetime.datetime.now().timestamp())}"
        
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        with zipfile.ZipFile(full_path, 'r') as zf:
            zf.extractall(extract_dir)
        return {"extracted": True, "destination": str(extract_dir.relative_to(ROOT_PATH))}
    except zipfile.BadZipFile:
        raise HTTPException(400, "Arquivo ZIP corrompido")
    except Exception as e:
        raise HTTPException(500, f"Erro na extração: {str(e)}")

@app.get("/api/files/preview")
async def preview_file(
    path: str = Query(...),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Query(None)
):
    """Retorna conteúdo de arquivo de texto para preview."""
    check_security(path, x_secure_code)
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
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Salva conteúdo em arquivo de texto."""
    check_security(path, x_secure_code)
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

@app.get("/api/storage/breakdown")
async def storage_breakdown(
    path: str = Query("/", description="Caminho do diretório a analisar"),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Retorna análise detalhada do espaço em disco: ranking de pastas que mais ocupam espaço, maiores pastas e arquivos."""
    check_security(path, x_secure_code)
    full_path = get_full_path(path)
    if not full_path.exists():
        raise HTTPException(404, "Diretório não encontrado")
    if not full_path.is_dir():
        raise HTTPException(400, "Caminho não é um diretório")

    return analyze_path_space(full_path, path)

@app.get("/api/storage/folder-size")
async def get_folder_size(
    path: str = Query(..., description="Caminho da pasta"),
    current_user: dict = Depends(get_current_user),
    x_secure_code: Optional[str] = Header(None)
):
    """Calcula e retorna o tamanho total ocupado por uma pasta."""
    check_security(path, x_secure_code)
    full_path = get_full_path(path)
    if not full_path.exists() or not full_path.is_dir():
        raise HTTPException(404, "Pasta não encontrada")

    size, files, dirs = calculate_dir_size(full_path)
    return {
        "path": path,
        "size": size,
        "size_formatted": format_size(size),
        "files_count": files,
        "dirs_count": dirs
    }

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
    
    # Auto-cria workspace para evitar erro 404 inicial
    workspace_dir = Path(ROOT_PATH) / "workspace"
    try:
        os.makedirs(str(workspace_dir), exist_ok=True)
    except:
        pass

    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    
    # Cria diretório de lixeira
    trash_dir = Path(ROOT_PATH) / ".trash"
    trash_dir.mkdir(parents=True, exist_ok=True)
    
    # Carrega/cria usuários
    load_users()
    
    try:
        print(f"🚀 NovaDrive iniciado!")
        print(f"📂 Diretório raiz: {ROOT_PATH}")
        print(f"🔑 Admin padrão: admin / admin")
        print(f"🌐 http://0.0.0.0:{PORT}")
    except Exception:
        print(f"[NovaDrive] Iniciado! Diretorio: {ROOT_PATH}, Porta: {PORT}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)
