import hashlib
import re
import os
import difflib
from BaseDBHandler import BaseDBHandler


class DiffCheck:
    def check_diff(self, old_content, new_content):
        if old_content == new_content:
            return None
            
        old_lines = old_content.splitlines()
        new_lines = new_content.splitlines()

        diff = difflib.unified_diff(
            old_lines,
            new_lines,
            fromfile='old_version',
            tofile='new_version',
            lineterm='\n',
        )
        
        diff_str = '\n'.join(diff)
        return diff_str if diff_str else None

    def apply_patch(self, patch_content, old_content):
        """
        Applies a unified diff patch to a string content.
        Returns the new string content.
        Raises ValueError if the patch does not apply cleanly.
        """
        if not patch_content.strip():
            return old_content

        patch_lines = patch_content.splitlines()
        old_lines = old_content.splitlines()
        new_lines = []
        old_line_idx = 0
        
        patch_iter = iter(patch_lines)
        
        # Find the first hunk
        for line in patch_iter:
            if line.startswith('@@'):
                break
        else:
            return old_content # No hunks found

        # Loop through all hunks in the patch
        while True: 
            hunk_header = line.strip()
            match = re.match(r'@@ -(\d+),?\d* \+(\d+),?\d* @@', hunk_header)
            if not match:
                raise ValueError(f"Invalid hunk header: {hunk_header}")
                
            old_start_line = int(match.group(1)) - 1

            # Add the lines from the original file that come before this hunk
            if old_line_idx > old_start_line:
                 raise ValueError("Patch hunks are not in order.")
            new_lines.extend(old_lines[old_line_idx:old_start_line])
            old_line_idx = old_start_line

            # Process lines within the current hunk
            for line in patch_iter:
                if line.startswith('@@'): # Found the start of the next hunk
                    break

                if line.startswith(' '):
                    context_line = line[1:]
                    if old_line_idx < len(old_lines) and old_lines[old_line_idx] == context_line:
                        new_lines.append(old_lines[old_line_idx])
                        old_line_idx += 1
                    else:
                        expected = old_lines[old_line_idx] if old_line_idx < len(old_lines) else "EOF"
                        raise ValueError(f"Patch does not apply: context mismatch. Expected '{expected}', got '{context_line}'")
                elif line.startswith('-'):
                    deleted_line = line[1:]
                    if old_line_idx < len(old_lines) and old_lines[old_line_idx] == deleted_line:
                        old_line_idx += 1
                    else:
                        expected = old_lines[old_line_idx] if old_line_idx < len(old_lines) else "EOF"
                        raise ValueError(f"Patch does not apply: deletion mismatch. Expected '{expected}', got '{deleted_line}'")
                elif line.startswith('+'):
                    added_line = line[1:]
                    new_lines.append(added_line)
            else:
                # No more lines in iterator, so no more hunks
                break
        
        # Append the rest of the original file that comes after the last hunk
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
        with open(file_path, "ab") as f:
            f.write(file_change)
            f.write(f"\n--- FNSepV{next_version} ---\n".encode('utf-8'))
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

        with open(history_file_path, 'rb') as f:
            full_history = f.read() # Read as bytes

        version_chunks = re.split(rb'\n--- FNSepV\d+ ---\n', full_history)
        patches = [chunk for chunk in version_chunks if chunk]

        if not patches or wanted_version > len(patches):
            return None  # Requested version does not exist or is out of bounds

        current_content = patches[0] # This is always the full V1 content (bytes)

        # Apply subsequent patches up to the wanted version
        diff_checker = DiffCheck()
        for i in range(1, wanted_version):
            patch_bytes = patches[i]
            is_text_patch = False
            if patch_bytes.startswith(b'--- old_version'):
                try:
                    patch_str = patch_bytes.decode('utf-8')
                    base_str = current_content.decode('utf-8')
                    # If both decode, we can attempt a patch
                    current_content = diff_checker.apply_patch(patch_str, base_str).encode('utf-8')
                    is_text_patch = True
                except (UnicodeDecodeError, ValueError):
                    # Decoding or patching failed, so it's not a valid text patch
                    is_text_patch = False
            
            if not is_text_patch:
                # If it wasn't a valid text patch (for any reason), treat as binary
                current_content = patch_bytes
            
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

    def get_all_versions(self, file_loc):
        """Gets all version numbers for a given file location."""
        file_id = hashlib.sha256(file_loc.encode()).hexdigest()
        history_file_path = os.path.join("Abyss", file_id)

        if not os.path.exists(history_file_path):
            return []

        with open(history_file_path, 'rb') as f:
            full_history = f.read()

        version_chunks = re.split(rb'\n--- FNSepV\d+ ---\n', full_history)
        # The number of versions is the number of chunks, excluding the empty one at the end
        num_versions = len([chunk for chunk in version_chunks if chunk])
        print(f"Found {num_versions} versions for {file_loc}")
        return list(range(1, num_versions + 1))

if __name__ == '__main__':
    db_handler = SaveHandler()
    
    # Example usage:
    # Clear tables for a clean run
    # db_handler._execute("DELETE FROM Saves")
    # db_handler.commit()

    # Insert some files
    print(db_handler.save_file("C:/foo.txt","ddddds"))

    db_handler.close()