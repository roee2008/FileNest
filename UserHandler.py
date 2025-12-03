import hashlib
from BaseDBHandler import BaseDBHandler

class UserHandler(BaseDBHandler):
    def __init__(self, db_name="UserDB.sqlite"):
        super().__init__(db_name)
        self.create_tables()

    def create_tables(self):
        self._execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT NOT NULL UNIQUE,
            hashed_password TEXT NOT NULL
        )
        """)

    def new_user(self, username, password):
        self._execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", (username, password))

    def get_user(self, username):
        return self._execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def delete_user(self, username):
        self._execute("DELETE FROM users WHERE username = ?", (username,))
        
    def update_password(self, username, new_password):
        self._execute("UPDATE users SET hashed_password = ? WHERE username = ?", (new_password, username))

if __name__ == "__main__":
    user_handler = UserHandler()