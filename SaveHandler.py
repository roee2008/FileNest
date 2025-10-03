import hashlib
import re
import os
import difflib
from BaseDBHandler import BaseDBHandler


class DiffCheck:
    def check_diff(self, old_file, new_file):
        with open(old_file, 'r', encoding='utf-8') as f:
            old_file_content = f.readlines()
        with open(new_file, 'r', encoding='utf-8') as f:
            new_file_content = f.readlines()

        diff = difflib.unified_diff(
            old_file_content,
            new_file_content,
            fromfile='old_file',
            tofile='new_file',
            lineterm='',
        )

        for line in diff:
            print(line)

    def apply_patch(self, patch_content, old_content):
        """
        Applies a unified diff patch to a string content.
        Returns the new string content.
        Raises ValueError if the patch does not apply cleanly.
        """
        patch_lines = patch_content.splitlines()
        old_lines = old_content.splitlines()
        new_lines = []
        old_line_idx = 0
        
        patch_iter = iter(patch_lines)
        # Skip header lines until '@@'
        for line in patch_iter:
            if line.startswith('@@'):
                break
        
        # Process hunk lines
        for line in patch_iter:
            if not line: continue
            
            if line.startswith(' '):
                # Context line
                context_line = line[1:]
                if old_line_idx < len(old_lines) and old_lines[old_line_idx] == context_line:
                    new_lines.append(old_lines[old_line_idx])
                    old_line_idx += 1
                else:
                    raise ValueError("Patch does not apply: context mismatch")
            elif line.startswith('-'):
                # Deletion line
                deleted_line = line[1:]
                if old_line_idx < len(old_lines) and old_lines[old_line_idx] == deleted_line:
                    old_line_idx += 1
                else:
                    raise ValueError("Patch does not apply: deletion mismatch")
            elif line.startswith('+'):
                # Addition line
                added_line = line[1:]
                new_lines.append(added_line)
                
        # Append any remaining lines from the old file
        if old_line_idx < len(old_lines):
            new_lines.extend(old_lines[old_line_idx:])
                
        return '\n'.join(new_lines)
    
    
class SaveHandler(BaseDBHandler):
    def __init__(self, db_name="SaveDB.sqlite"):
        super().__init__(db_name)
        self.create_tables()

    def create_tables(self):
        self._execute("""
        CREATE TABLE IF NOT EXISTS Saves (
            id TEXT PRIMARY KEY,      -- This is the hash of the fileLoc
            fileLoc TEXT NOT NULL UNIQUE,
            version INTEGER NOT NULL  -- This will now store the LATEST version
        )
        """)

    def save_file(self, file_loc,file_change):
        # The ID should be a stable hash of the file's location.
        id_hash = hashlib.sha256(file_loc.encode()).hexdigest()

        # Find the current max version for this file from the DB.
        row = self._execute("SELECT version FROM Saves WHERE id = ?", (id_hash,)).fetchone()
        # If row is None (file is new), start at version 0. Otherwise, use the found version.
        current_version = row[0] if row else 0
        next_version = current_version + 1

        # Use an "UPSERT" operation.
        # This will INSERT a new row if the `id` doesn't exist.
        # If it does exist (ON CONFLICT), it will UPDATE the version number.
        self._execute("""
            INSERT INTO Saves (id, fileLoc, version) VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET version = excluded.version
        """, (id_hash, file_loc, next_version))

        os.makedirs("Abyss", exist_ok=True)
        file_path = os.path.join("Abyss", id_hash)
        with open(file_path, "a", encoding="utf-8") as f:
            f.write(f"{file_change}\nV{next_version}\n")
        self.conn.commit()
        return id_hash, next_version

    def get_file_at_version(self, file_loc, wanted_version):
        """
        Reconstructs a file to a specific version by reading its history file
        from the 'Abyss' directory and applying changes sequentially.
        """
        file_id = hashlib.sha256(file_loc.encode()).hexdigest()
        history_file_path = os.path.join("Abyss", file_id)

        if not os.path.exists(history_file_path):
            return None  # No history found for this file

        diff_checker = DiffCheck()

        with open(history_file_path, 'rb') as f:
            full_history = f.read() # Read as bytes

        # Split the history file into chunks based on the version marker (e.g., "V1\n").
        # The regex looks for "V" followed by digits, then a newline.
        version_chunks = re.split(rb'\nV\d+\n', full_history)
        # The last split item is usually an empty string if the file ends with the delimiter, so we remove it.
        patches = [chunk for chunk in version_chunks if chunk]

        if not patches or wanted_version > len(patches):
            return None  # Requested version does not exist or is out of bounds

        # The first chunk is the initial full content of the file (version 1).
        current_content = patches[0]

        # Apply subsequent patches up to the wanted version.
        # The loop starts at 1 because we've already loaded the base content (patches[0]).
        try:
            for i in range(1, wanted_version):
                current_content = diff_checker.apply_patch(patches[i].decode('utf-8'), current_content.decode('utf-8')).encode('utf-8')
        except UnicodeDecodeError:
            # If we hit a binary file that can't be decoded for patching, we can't reconstruct past this point.
            # For simplicity, we'll just return the last valid state.
            pass
        return current_content

    def list_virtual_directory(self, directory_path):
        """
        Simulates a directory listing based on fileLoc paths in the database.
        
        Args:
            directory_path (str): The virtual path to list, e.g., "repo1/folder".

        Returns:
            list: A list of unique file and directory names inside the given path.
        """
        # Normalize the path to ensure it's treated as a directory prefix
        if directory_path and not directory_path.endswith('/'):
            directory_path += '/'

        # Fetch all file locations from the database
        all_files = self._execute("SELECT fileLoc FROM Saves").fetchall()
        
        children = set()
        for (file_loc,) in all_files:
            # Check if the file is inside the requested directory
            if file_loc.startswith(directory_path):
                # Get the part of the path relative to the directory_path
                relative_path = file_loc[len(directory_path):]
                # The first component of the relative path is the child
                child_name = relative_path.split('/', 1)[0]
                children.add(child_name)
        
        return list(children)
    def search_files_by_name(self, file_name_part):
        """Searches for files in the database where the name contains a substring."""
        query = "SELECT fileLoc FROM Saves WHERE fileLoc LIKE ?"
        params = (f'%{file_name_part}%',)
        results = self._execute(query, params).fetchall()
        return [row[0] for row in results]

    def get_latest_version(self, file_loc):
        """Gets the latest version number for a given file location."""
        id_hash = hashlib.sha256(file_loc.encode()).hexdigest()
        row = self._execute("SELECT version FROM Saves WHERE id = ?", (id_hash,)).fetchone()
        return row[0] if row else 0

if __name__ == '__main__':
    db_handler = SaveHandler()
    
    # Example usage:
    # Clear tables for a clean run
    # db_handler._execute("DELETE FROM Saves")
    # db_handler.commit()

    # Insert some files
    print(db_handler.save_file("C:/foo.txt","ddddds"))

    db_handler.close()