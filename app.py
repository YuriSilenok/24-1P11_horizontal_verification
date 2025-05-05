"""FastAPI для горизонтальной проверки"""
from datetime import datetime, timedelta, timezone
from typing import Optional
import enum
import logging
import jwt
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    status
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from peewee import DoesNotExist
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel  # pylint: disable=E0611
import models as m


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


class UserRole(str, enum.Enum):
    """Роли пользователей в системе."""
    STUDENT = "student"
    TEACHER = "teacher"


class Token(BaseModel):
    """Модель токена доступа."""
    access_token: str
    token_type: str
    role: UserRole


class TokenData(BaseModel):
    """Данные, хранящиеся в токене."""
    username: str
    role: UserRole


class User(BaseModel):
    """Модель пользователя для отображения."""
    username: str
    email: str
    full_name: str
    disabled: bool
    role: UserRole


class UserInDB(User):
    """Модель пользователя с хешем пароля для внутреннего использования."""
    hashed_password: str


class UserCreate(BaseModel):
    """Модель для создания нового пользователя."""
    username: str
    email: str
    full_name: str
    password: str
    role: UserRole = UserRole.STUDENT


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
app = FastAPI()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет соответствие пароля его хешу."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Генерирует хеш пароля."""
    return pwd_context.hash(password)


def get_db_user(username: str) -> Optional[m.User]:
    """Получает пользователя из базы данных."""
    try:
        return m.User.get(m.User.username == username)
    except DoesNotExist:
        return None


def get_user(username: str) -> Optional[UserInDB]:
    """Получает пользователя по имени."""
    db_user = get_db_user(username)
    if db_user:
        return UserInDB(
            username=db_user.username,
            email=db_user.email,
            full_name=db_user.full_name,
            disabled=db_user.disabled,
            role=UserRole(db_user.role),
            hashed_password=db_user.hashed_password
        )
    return None


def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Аутентифицирует пользователя."""
    user = get_user(username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    if user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


def create_access_token(
    data: dict, expires_delta: timedelta = None
) -> str:
    """Создает JWT-токен доступа."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme)
) -> UserInDB:
    """Получает текущего пользователя из токена."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if not username or not role:
            raise credentials_exception
        token_data = TokenData(username=username, role=UserRole(role))
    except (InvalidTokenError, ValueError) as e:
        logger.error("JWT Error: %s", e)
        raise credentials_exception from e

    user = get_user(username=token_data.username)
    if not user or user.role != token_data.role:
        raise credentials_exception
    return user


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    """Endpoint для получения токена доступа."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.warning("Failed login attempt for username: %s",
                       form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role.value},
        expires_delta=access_token_expires
    )
    return Token(
        access_token=access_token,
        token_type="bearer",
        role=user.role
    )


@app.post("/register", response_model=User)
async def register_user(user_data: UserCreate):
    """Endpoint для регистрации нового пользователя."""
    if get_db_user(user_data.username):
        raise HTTPException(
            status_code=400,
            detail="Username already registered"
        )

    hashed_password = get_password_hash(user_data.password)
    try:
        user = m.User.create(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password,
            disabled=False,
            role=user_data.role.value
        )
        logger.info("User %s registered successfully", user_data.username)
        return User(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            disabled=user.disabled,
            role=UserRole(user.role)
        )
    except Exception as e:
        logger.error("Error registering user %s: %s", user_data.username, e)
        raise HTTPException(
            status_code=500,
            detail="Error creating user"
        ) from e


@app.get("/users/me", response_model=User)
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    """Endpoint для получения информации о текущем пользователе."""
    return current_user
