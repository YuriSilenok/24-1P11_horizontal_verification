from peewee import SqliteDatabase, Model, CharField, BooleanField
from enum import Enum
from datetime import datetime, timezone

db = SqliteDatabase("test.db")

class UserRole(str, Enum):
    STUDENT = "student"
    TEACHER = "teacher"

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)
    email = CharField()
    full_name = CharField()
    hashed_password = CharField()
    disabled = BooleanField(default=False)
    role = CharField(default=UserRole.STUDENT.value)

def initialize_database():
    with db:
        db.create_tables([User])

if __name__ == "__main__":
    initialize_database()