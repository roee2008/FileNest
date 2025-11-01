from BaseDBHandler import BaseDBHandler

class DBHandler(BaseDBHandler):
    def __init__(self, db_name="ReposDB.sqlite"):
        super().__init__(db_name)
        self.create_tables()

    def create_tables(self):
        self._execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fileName TEXT NOT NULL UNIQUE,
            ownerHash TEXT NOT NULL
        )
        """)
        self._execute("""
        CREATE TABLE IF NOT EXISTS file_access (
            fileId INTEGER,
            accessUser TEXT,
            FOREIGN KEY (fileId) REFERENCES files(id)
        )
        """)

    def create_repository(self, repo_name, owner_username):
        """Creates a new repository and assigns ownership."""
        cursor = self._execute("INSERT INTO files (fileName, ownerHash) VALUES (?, ?)", (repo_name, owner_username))
        repo_id = cursor.lastrowid
        if repo_id:
            self.share_file_with_user(repo_id, owner_username)
        return repo_id

    def insert_file(self, file_name, owner_hash, access_users):
        # This method is for inserting files within an existing repo, not creating a new repo.
        # The 'files' table now represents repositories.
        # This method might need to be re-evaluated or removed if 'files' table is solely for repos.
        # For now, assuming it's still used for some internal file tracking within a repo context.
        # If file_name is actually a repo_name, then owner_hash should be the owner.
        # If access_users are provided, they are also added.
        cursor = self._execute("INSERT INTO files (fileName, ownerHash) VALUES (?, ?)", (file_name, owner_hash))
        file_id = cursor.lastrowid
        if access_users:
            for user in access_users:
                self.share_file_with_user(file_id, user)

    def get_all_files(self):
        return self._execute("""
        SELECT f.id, f.fileName, f.ownerHash, GROUP_CONCAT(a.accessUser)
        FROM files f
        LEFT JOIN file_access a ON f.id = a.fileId
        GROUP BY f.id
        """).fetchall()

    def get_user_files(self, username, include_shared=True):
        if include_shared:
            query = """
            SELECT DISTINCT f.id, f.fileName, f.ownerHash
            FROM files AS f
            LEFT JOIN file_access AS a ON a.fileId = f.id
            WHERE f.ownerHash = ? OR a.accessUser = ?
            """
            params = (username, username)
        else:
            query = """
            SELECT id, fileName, ownerHash
            FROM files
            WHERE ownerHash = ?
            """
            params = (username,)
        return self._execute(query, params).fetchall()

    def share_file_with_user(self, file_id, username):
        """Adds a user to the access list for a given file."""
        self._execute("INSERT INTO file_access (fileId, accessUser) VALUES (?, ?)", (file_id, username))

    def has_access(self, username, file_name):
        """Checks if a user has access to a file."""
        # Check if the user owns the file OR if their username is in the access list for that file.
        # This is more robust than the previous LEFT JOIN approach.
        query = """
            SELECT 1 FROM files WHERE fileName = ? AND (ownerHash = ? OR id IN (
                SELECT fileId FROM file_access WHERE accessUser = ?
            ))
        """
        return self._execute(query, (file_name, username, username)).fetchone() is not None

if __name__ == '__main__':
    db_handler = DBHandler()

    db_handler.close()
