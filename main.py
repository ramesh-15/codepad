import docker
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from datetime import datetime, timedelta
from jose import JWTError, jwt
import shutil,os
from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException
app = FastAPI()
client = docker.from_env()

# Dummy DB and settings
fake_users_db = {
    "admin": {"username": "admin", "password": "admin123"},
    "alice": {"username": "alice", "password": "alice123"},
    "bob": {"username": "bob", "password": "bob123"},
    "charlie": {"username": "charlie", "password": "charlie123"},
    "dave": {"username": "dave", "password": "dave123"},
}

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def authenticate_user(username: str, password: str):
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        return False
    return user


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
    containers = client.containers.list(all=True, filters={"name": name})
    return any(container.name == name for container in containers)


def count_existing_user_containers() -> int:
    containers = client.containers.list(all=True, filters={"name": "user_container_"})
    return sum(1 for c in containers if c.name.startswith("user_container_"))


def create_user_container(name: str):
    try:
        container = client.containers.run(
            "fastapi-main-app",
            name=name,
            detach=True,
            volumes={f"/home/dockerdata/{name}": {"bind": "/code", "mode": "rw"}
            },
            ports={"8000/tcp": 8000},
        )
        print(f"[INFO] Container started successfully: {container.id}")
    except docker.errors.APIError as e:
        print(f"[ERROR] Docker run failed: {e.explanation}")
        raise RuntimeError(f"Docker run failed: {e.explanation}")


def start_container(name: str):
    try:
        container = client.containers.get(name)
        container.start()
    except docker.errors.NotFound:
        raise RuntimeError(f"Container {name} not found.")
    except docker.errors.APIError as e:
        raise RuntimeError(f"Failed to start container: {e.explanation}")


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
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/run-code")
async def run_code(
    file: UploadFile = File(...),
    language: str = Form(...),
    current_user: str = Depends(get_current_user)
):
    if language.lower() != "python":
        raise HTTPException(status_code=400, detail="Only 'python' language is supported.")

    # 1. Save the file temporarily
    file_location = f"/tmp/{file.filename}"
    with open(file_location, "wb") as f:
        shutil.copyfileobj(file.file, f)
    print("current_user:",current_user)
    # 2. Find the user’s container (by name or label)
    container_name = f"user_container_{current_user}"
    try:
        container = client.containers.get(container_name)
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="User container not found.")

    # 3. Copy the file into the container
    exec_file_path = f"/code/{file.filename}"  # Path inside the container

    # Tar it and send to container
    import tarfile
    import io

    tarstream = io.BytesIO()
    with tarfile.open(fileobj=tarstream, mode='w') as tar:
        tarinfo = tarfile.TarInfo(name=file.filename)
        tarinfo.size = os.path.getsize(file_location)
        with open(file_location, 'rb') as f:
            tar.addfile(tarinfo, f)
    tarstream.seek(0)

    container.put_archive("/code", tarstream)  # You can change "/code" as needed

    # 4. Run the file inside the container
    exec_command = f"python3 {exec_file_path}"
    exit_code, output = container.exec_run(cmd=exec_command)

    # 5. Return the output
    return {
        "exit_code": exit_code,
        "output": output.decode("utf-8") if isinstance(output, bytes) else output
    }

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