from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware  # Importa el middleware de CORS
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel
from passlib.context import CryptContext

# Configuración de la base de datos
SQLALCHEMY_DATABASE_URL = "mysql://root:XrInlDSAyknMvgQFuAkKakRfPRlvIjIT@monorail.proxy.rlwy.net:18257/railway"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Modelo de usuario
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)  # Especifica la longitud máxima
    hashed_password = Column(String)
    full_name = Column(String)

# Clase para manipular datos de usuario
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: str

# Clase para leer datos de usuario
class UserOut(BaseModel):
    email: str
    full_name: str

# Clase para manipular datos de autenticación
class AuthDetails(BaseModel):
    username: str
    password: str

Base.metadata.create_all(bind=engine)

app = FastAPI()

# Agrega el middleware de CORS a tu aplicación FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite solicitudes desde cualquier origen
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],  # Puedes ajustar los métodos permitidos según tus necesidades
    allow_headers=["*"],  # Puedes ajustar los encabezados permitidos según tus necesidades
)

# Función para obtener una instancia de la sesión de la base de datos
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Función para crear un nuevo usuario
def create_user(db: Session, user: UserCreate):
    hashed_password = pwd_context.hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, full_name=user.full_name)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

# Función para obtener un usuario por su correo electrónico
def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

# Clase para manejar el hashing de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Ruta para crear un nuevo usuario
@app.post("/users/", response_model=UserOut)
def create_user_api(user: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")
    return create_user(db=db, user=user)

# Ruta para autenticar un usuario
@app.post("/login/")
def login(auth_details: AuthDetails, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=auth_details.username)
    if not db_user or not pwd_context.verify(auth_details.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    return {"message": "Successfully authenticated"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, port=8000)
