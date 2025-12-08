import hashlib
import re
import os
import difflib
from BaseDBHandler import BaseDBHandler
import win32file
import pywintypes
import win32con


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
        
        try:
            # Open the file for writing (and implicitly appending by setting file pointer)
            handle = win32file.CreateFile(
                file_path,
                win32con.GENERIC_WRITE, # Use GENERIC_WRITE for writing
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32con.OPEN_ALWAYS, # Create if not exists, open if exists
                0,
                None
            )
            
            # Move the file pointer to the end of the file to append
            win32file.SetFilePointer(handle, 0, win32con.FILE_END)
            
            # Append the file change and the separator
            win32file.WriteFile(handle, file_change)
            win32file.WriteFile(handle, f"\n--- FNSepV{next_version} ---\n".encode('utf-8'))
            
            # Close the handle
            win32file.CloseHandle(handle)
            
        except pywintypes.error as e:
            print(f"Error saving file with win32file: {e}")
            # Fallback or error handling can be added here
            return None, None

        self.conn.commit()
        return id_hash, next_version

    def get_file_at_version(self, file_loc, wanted_version):
        """
        Reconstructs a file to a specific version by reading its history file
        from the 'Abyss' directory and applying changes sequentially in a memory-efficient way.
        """
        file_id = hashlib.sha256(file_loc.encode()).hexdigest()
        history_file_path = os.path.join("Abyss", file_id)

        if not os.path.exists(history_file_path):
            return None

        current_version = 0
        current_content = b''
        separator_pattern = re.compile(rb'\r?\n--- FNSepV(\d+) ---\r?\n')

        with open(history_file_path, 'rb') as f:
            buffer = b''
            while current_version < wanted_version:
                chunk = f.read(8192)
                if not chunk:
                    break
                buffer += chunk
                
                while True:
                    match = separator_pattern.search(buffer)
                    if not match:
                        break
                    
                    version_data = buffer[:match.start()]
                    version_num = int(match.group(1))

                    if version_num == 1:
                        current_content = version_data
                    else:
                        # Apply patch or replace content
                        diff_checker = DiffCheck()
                        try:
                            patch_str = version_data.decode('utf-8')
                            base_str = current_content.decode('utf-8')
                            current_content = diff_checker.apply_patch(patch_str, base_str).encode('utf-8')
                        except (UnicodeDecodeError, ValueError):
                            current_content = version_data # Treat as binary

                    current_version = version_num
                    if current_version == wanted_version:
                        return current_content
                    
                    buffer = buffer[match.end():]
        
        # If the loop finishes, it means we've processed the whole file
        # but might not have hit the last separator. The remaining buffer is the last version's content.
        if buffer and current_version < wanted_version:
             # This part handles the last chunk of the file that doesn't end with a separator
            version_num = current_version + 1
            if version_num == 1:
                current_content = buffer
            else:
                diff_checker = DiffCheck()
                try:
                    patch_str = buffer.decode('utf-8')
                    base_str = current_content.decode('utf-8')
                    current_content = diff_checker.apply_patch(patch_str, base_str).encode('utf-8')
                except (UnicodeDecodeError, ValueError):
                    current_content = buffer
            current_version = version_num

        return current_content if current_version == wanted_version else None

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
        """Gets all version numbers for a given file location in a memory-efficient way."""
        file_id = hashlib.sha256(file_loc.encode()).hexdigest()
        history_file_path = os.path.join("Abyss", file_id)

        if not os.path.exists(history_file_path):
            return []

        count = 0
        separator_pattern = re.compile(rb'--- FNSepV\d+ ---')
        try:
            with open(history_file_path, 'rb') as f:
                # Read the file in chunks to avoid loading it all into memory
                buffer = f.read(8192)
                while buffer:
                    count += len(separator_pattern.findall(buffer))
                    buffer = f.read(8192)
            # The number of versions is the number of separators + 1, assuming the file is not empty.
            # A more robust way is to count separators. If there's content, there's at least one version.
            if os.path.getsize(history_file_path) > 0:
                 # The number of versions is the number of separators found.
                 # Let's adjust logic: each separator marks the END of a version.
                 # So, the number of versions is the number of separators.
                 pass # `count` is already the number of separators.
            else:
                return []
        except IOError:
            return []
        
        # The number of versions is the number of separators.
        # But if the file doesn't end with a separator, the last version is not counted.
        # Let's refine the logic.
        num_versions = self.get_latest_version(file_loc)
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
