"""База данных для горизонтальной проверки"""

from enum import Enum
from peewee import SqliteDatabase, Model, CharField, BooleanField
# pylint: disable=R0903

db = SqliteDatabase("test.db")


class UserRole(str, Enum):
    """Роли пользователей в системе"""
    STUDENT = "student"
    TEACHER = "teacher"


class BaseModel(Model):
    """Базовая модель Peewee для всех моделей приложения."""

    class Meta:
        """Мета-класс для указания используемой базы данных."""
        database = db


class User(BaseModel):
    """Модель пользователя системы"""
    username = CharField(unique=True)
    email = CharField()
    full_name = CharField()
    hashed_password = CharField()
    disabled = BooleanField(default=False)
    role = CharField(default=UserRole.STUDENT.value)


def initialize_database():
    """Инициализирует базу данных и создает необходимые таблицы"""
    with db:
        db.create_tables([User])


if __name__ == "__main__":
    initialize_database()
