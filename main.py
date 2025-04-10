from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
import tempfile
import zipfile
import subprocess
import os
import random
# Secret key to encode/decode JWT
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Dummy user store
fake_users_db = {
    "admin": {
        "username": "admin",
        "password": "admin123"  # NEVER store plaintext passwords in production
    },
    "alice": {
        "username": "alice",
        "password": "alice123"
    },
    "bob": {
        "username": "bob",
        "password": "bob123"
    },
    "charlie": {
        "username": "charlie",
        "password": "charlie123"
    },
    "dave": {
        "username": "dave",
        "password": "dave123"
    }
}


# Function to create JWT
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Verify user credentials
def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        return False
    return user

# Dependency to verify JWT token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in fake_users_db:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception
def docker_container_exists(name: str) -> bool:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name={name}", "--format", "{{.Names}}"],
        stdout=subprocess.PIPE, text=True
    )
    return name in result.stdout.strip().splitlines()

def count_existing_user_containers() -> int:
    result = subprocess.run(
        ["docker", "ps", "-a", "--filter", "name=user_container_", "--format", "{{.Names}}"],
        stdout=subprocess.PIPE, text=True
    )
    containers = [name for name in result.stdout.strip().splitlines() if name.startswith("user_container_")]
    return len(containers)

def create_user_container(name: str):
    ps = subprocess.run(
        ["docker", "ps"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    print("\n[INFO] Checking running Docker containers:")
    print("[STDOUT]:", ps.stdout)
    port = random.randint(8001, 9000)
    result = subprocess.run(
        ["docker", "run", "-it","-v", "/var/run/docker.sock:/var/run/docker.sock", "-p", f"{port}:8000", "--name", name, "fastapi-main-app"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        print(f"[ERROR] Docker run failed:\n{result.stderr}")  # THIS IS THE IMPORTANT PART
        raise RuntimeError(f"Docker run failed with error: {result.stderr}")
    else:
        print(f"[INFO] Container started successfully: {result.stdout}")


def start_container(name: str):
    subprocess.run(["docker", "start", name], check=True)
    
    
@app.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    username = user["username"]
    container_name = f"user_container_{username}"

    if not docker_container_exists(container_name):
        
        create_user_container(container_name)
    else:
        start_container(container_name)

    access_token = create_access_token(
        data={"sub": username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}




# Main secured endpoint
# @app.post("/run-code")
# async def run_code(
#     file: UploadFile = File(...),
#     language: str = Form(...),
#     current_user: str = Depends(get_current_user)
# ):
#     if language.lower() != "python":
#         raise HTTPException(status_code=400, detail="Only 'python' language is supported.")

#     container_name = f"user_container_{current_user}"

#     try:
#         with tempfile.TemporaryDirectory() as tmpdir:
#             file_path = os.path.join(tmpdir, file.filename)
#             with open(file_path, "wb") as f:
#                 f.write(await file.read())

#             # Copy file to container
#             subprocess.run(["docker", "cp", file_path, f"{container_name}:/tmp/{file.filename}"])

#             # Run the Python file inside the container
#             result = subprocess.run([
#                 "docker", "exec", container_name,
#                 "python", f"/tmp/{file.filename}"
#             ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)

#             return JSONResponse(content={
#                 "stdout": result.stdout,
#                 "stderr": result.stderr,
#                 "return_code": result.returncode
#             })

#     except subprocess.TimeoutExpired:
#         raise HTTPException(status_code=500, detail="Execution timed out.")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))