import socket
import os
import threading
import re
from DBHandler import DBHandler
from UserHandler import UserHandler
from SaveHandler import SaveHandler, DiffCheck
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

HOST = '127.0.0.1'
PORT = 2122
BASE_DIR = "ftp_root"
DEBUG = True

os.makedirs(BASE_DIR, exist_ok=True)

def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")

def encrypt_message(message):
    
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # or b"your_password" if key is encrypted
            backend=default_backend()
        )
    
    # Encrypt the message
    message_bytes = message if isinstance(message, bytes) else message.encode()
    encrypted = private_key.public_key().encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted
    
    # For now, just return the message as-is (no encryption)

def decrypt_message(encrypted_data):
    """
    Decrypt a message that was encrypted with the public key.
    Uses the private key to decrypt.
    """
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,  # or b"your_password" if key is encrypted
            backend=default_backend()
        )
    
    # Decrypt the message using the private key
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return decrypted

def decrypt_aes_key_with_rsa(encrypted_aes_data):
    """Decrypt AES key and IV that were encrypted with RSA"""
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    
    # Decrypt the combined AES key and IV
    decrypted_data = private_key.decrypt(
        encrypted_aes_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Split back into AES key (32 bytes) and IV (16 bytes)
    aes_key = decrypted_data[:32]
    aes_iv = decrypted_data[32:48]
    
    return aes_key, aes_iv

def encrypt_with_aes(data: bytes, aes_key: bytes, aes_iv: bytes) -> bytes:
    """Encrypt data using AES"""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Pad data to multiple of 16 bytes
    padding_length = 16 - (len(data) % 16)
    padded_data = data + bytes([padding_length] * padding_length)
    
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_with_aes(encrypted_data: bytes, aes_key: bytes, aes_iv: bytes) -> bytes:
    """Decrypt data using AES"""
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(aes_iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Remove padding
    padding_length = padded_data[-1]
    return padded_data[:-padding_length]

def send_response(conn, message, aes_key=None, aes_iv=None):
    debug_print(f"Sent: {message.strip()[:50]}{'...' if len(message.strip()) > 50 else ''}")
    if aes_key and aes_iv:
        # Use AES encryption
        if isinstance(message, bytes):
            message_bytes = message
        else:
            message_bytes = message.encode()
        encrypted_data = encrypt_with_aes(message_bytes, aes_key, aes_iv)
        conn.sendall(encrypted_data)
    else:
        # Fallback to RSA encryption (for initial banner)
        conn.sendall(encrypt_message(message))

def have_access(username, path, fileDB):
    """
    Checks if a user has access to the repository containing the given virtual path.
    The repository is the first component of the path.
    """
    # Normalize the path and extract the repository name (the first part).
    repo_name = path.replace("\\", "/").strip("/").split('/')[0]
    if not repo_name:
        return False # Cannot determine repository from path
    return fileDB.has_access(username, repo_name)

def list_files(path):
    if not os.path.exists(path):
        return "Directory not found."
    if not os.path.isdir(path):
        return "Not a directory."
    files = os.listdir(path)
    return "\n".join(files) if files else "404 No files found."

def search_by_name(target_file_name):
    found_files = []
    abs_ftp_root = os.path.abspath(BASE_DIR)
    for dirpath, dirnames, filenames in os.walk(BASE_DIR):
        for filename in filenames:
            if target_file_name in filename:
                full_path = os.path.join(dirpath, filename)
                relative_path = os.path.relpath(full_path, abs_ftp_root)
                found_files.append(relative_path.replace(os.sep, "/"))
    return found_files

def is_valid_username(username):
    return re.match("^[a-zA-Z0-9_]{3,20}$", username)

def handle_login(conn, state, context, **kwargs):
    """Handles user login."""
    username = kwargs.get('username')
    password = kwargs.get('password')
    if not is_valid_username(username):
        send_response(conn, b"401 LOGIN FAILED: Invalid username format.\n", state.get("aes_key"), state.get("aes_iv"))
        return
    userDB = context['userDB']
    user_data = userDB.get_user(username)

    if user_data and password == user_data[1]:
        send_response(conn, b"200 LOGIN SUCCESS\n", state.get("aes_key"), state.get("aes_iv"))
        state['name'] = username
    else:
        send_response(conn, b"401 LOGIN FAILED: Invalid username or password.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_register(conn, state, context, **kwargs):
    """Handles user registration."""
    username = kwargs.get('username')
    password = kwargs.get('password')
    if not is_valid_username(username):
        send_response(conn, b"402 REGISTER FAILED: Invalid username format.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    userDB = context['userDB']

    if userDB.get_user(username) is not None:
        send_response(conn, b"402 REGISTER FAILED: User already exists.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        userDB.new_user(username, password)
        send_response(conn, b"201 REGISTER SUCCESS\n", state.get("aes_key"), state.get("aes_iv"))

def handle_list(conn, state, context, **kwargs):
    """Handles listing files and repositories."""
    save_handler = context['saveHandler']
    fileDB = context['fileDB']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    # The argument is the virtual path to list. If empty, it lists the root.
    directory_path = arg if arg else ""
    print(f"Listing virtual directory: '{directory_path}' for user '{username}'")
    # If listing a specific directory, check for access.
    # An empty path means listing all accessible repos, which is handled by filtering later.
    if directory_path and not have_access(username, directory_path, fileDB):
        send_response(conn, b"403 Access denied.\n", state.get("aes_key"), state.get("aes_iv"))
        return
    if directory_path == "":
        # List all repositories the user has access to
        user_files = fileDB.get_user_files(username, include_shared=True)
        repo_names = set()
        for file in user_files:
            repo_name = file[1]  # fileName is at index 1
            repo_names.add(repo_name)
        contents = list(repo_names)
    else:
        # Use the SaveHandler to get the virtual directory listing
        contents = save_handler.list_virtual_directory(directory_path)

    if contents:
        send_response(conn, b"200 OK\n" + "\n".join(contents).encode() + b"\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        send_response(conn, b"404 No files or directories found.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_search(conn, state, context, **kwargs):
    """Handles searching for a file."""
    fileDB = context['fileDB']
    username = state.get('name')
    target_file_name = kwargs.get('target_file_name')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    if target_file_name:
        found_files = context['saveHandler'].search_files_by_name(target_file_name)
        filtered_files = [file for file in found_files if have_access(username, file, fileDB)]
        if filtered_files:
            response = b"200 OK\n" + "\n".join(filtered_files).encode()
        else:
            response = b"404 No files found."
        send_response(conn, response, state.get("aes_key"), state.get("aes_iv"))
    else:
        send_response(conn, b"400 Bad Request: Missing filename. Usage: SEARCH <filename>\n", state.get("aes_key"), state.get("aes_iv"))

def handle_get(conn, state, context, **kwargs):
    """Handles retrieving a file."""
    fileDB = context['fileDB']
    username = state.get('name')
    arg = kwargs.get('arg')
    # arg is a single string, potentially containing path and version
    parts = arg.split(' ', 1)
    file_path = parts[0]
    version_str = parts[1] if len(parts) > 1 else None

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    if not have_access(username, file_path, fileDB):
        send_response(conn, b"403 Access denied.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        save_handler = context['saveHandler']
        
        if version_str:
            try:
                version = int(version_str)
            except ValueError:
                send_response(conn, b"400 Invalid version number.\n", state.get("aes_key"), state.get("aes_iv"))
                return
        else:
            version = save_handler.get_latest_version(file_path)

        if version == 0:
            send_response(conn, b"404 File not found in version control.\n", state.get("aes_key"), state.get("aes_iv"))
            return

        # Reconstruct the file at the specified or latest version
        content = save_handler.get_file_at_version(file_path, version) # Returns bytes

        if content is not None:
            send_response(conn, b"200 OK\n" + content, state.get("aes_key"), state.get("aes_iv"))
        else:
            send_response(conn, b"500 Could not reconstruct file.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_getdir(conn, state, context, **kwargs):
    """Handles retrieving a directory."""
    fileDB = context['fileDB']
    save_handler = context['saveHandler']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        send_response(conn, b"200 OK\n", state.get("aes_key"), state.get("aes_iv"))
        # Find all files that are inside the requested virtual directory
        all_repo_files = save_handler.search_files_by_name(arg)
        files_in_dir = [f for f in all_repo_files if f.startswith(arg)]

        for file_path in files_in_dir:
            latest_version = save_handler.get_latest_version(file_path)
            if latest_version > 0:
                content = save_handler.get_file_at_version(file_path, latest_version)
                if content:
                    size = len(content)
                    send_response(conn, f"FILE {file_path} {size}\n".encode(), state.get("aes_key"), state.get("aes_iv"))
                    send_response(conn, content, state.get("aes_key"), state.get("aes_iv"))
        send_response(conn, b"DONE\n", state.get("aes_key"), state.get("aes_iv"))

def handle_getversions(conn, state, context, **kwargs):
    """Handles retrieving all versions of a file."""
    fileDB = context['fileDB']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        save_handler = context['saveHandler']
        versions = save_handler.get_all_versions(arg)
        if versions:
            send_response(conn, b"200 OK\n" + ",".join(map(str, versions)).encode() + b"\n", state.get("aes_key"), state.get("aes_iv"))
        else:
            send_response(conn, b"404 No versions found for this file.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_put(conn, state, context, **kwargs):
    """Handles uploading a file."""
    fileDB = context['fileDB']
    save_handler = context['saveHandler']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    # Check access based on the virtual path argument
    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        send_response(conn, b"200 OK: Send file data, end with EOF marker '<EOF>'\n", state.get("aes_key"), state.get("aes_iv"))
        file_data = b""
        while True:
            chunk = conn.recv(1024)
            if b"<EOF>" in chunk:
                file_data += chunk.replace(b"<EOF>", b"")
                break
            if not chunk:
                break
            file_data += chunk
        
        latest_version = save_handler.get_latest_version(arg)
        file_change = None

        # Check for null byte to guess if it's a binary file
        is_binary = b'\x00' in file_data

        if latest_version == 0:
            # New file: the "change" is the full content.
            file_change = file_data
        elif is_binary:
            # Existing binary file: store the whole new file as the change.
            file_change = file_data
        else: # Existing text file: calculate a diff.
            diff_checker = DiffCheck()
            try:
                old_content_bytes = save_handler.get_file_at_version(arg, latest_version)
                old_content = old_content_bytes.decode('utf-8')
                new_content = file_data.decode('utf-8')
                file_change = diff_checker.check_diff(old_content, new_content)
                if file_change:
                    file_change = file_change.encode('utf-8')
            except (UnicodeDecodeError, ValueError):
                # If diffing fails for any reason, fall back to storing the full file.
                file_change = file_data

        if file_change is not None:
            save_handler.save_file(arg, file_change)
            send_response(conn, b"200 File uploaded successfully.\n", state.get("aes_key"), state.get("aes_iv"))
        else:
            send_response(conn, b"200 File is already up to date.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_mkdir(conn, state, context, **kwargs):
    """Handles creating a directory."""
    fileDB = context['fileDB']
    username = state.get('name')
    save_handler = context['saveHandler']
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        save_handler.save_file(arg, "".encode('utf-8'))
        send_response(conn, b"201 Directory will be created upon file upload.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_getrepos(conn, state, context, **kwargs):
    """Handles getting user's repositories."""
    fileDB = context['fileDB']
    username = state.get('name')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return
    repos = fileDB.get_user_files(username, include_shared=False)
    repo_names = [repo[1] for repo in repos]
    send_response(conn, b"200 OK\n" + "\n".join(repo_names).encode() + b"\n", state.get("aes_key"), state.get("aes_iv"))

def handle_adduser(conn, state, context, **kwargs):
    """Handles adding a user to a repo."""
    fileDB = context['fileDB']
    username = state.get('name')
    repo_name = kwargs.get('repo_name')
    user_to_add = kwargs.get('user_to_add')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    files = fileDB.get_all_files()
    file_id = -1
    for file in files:
        if file[1] == repo_name:
            file_id = file[0]
            break
    if file_id != -1:
        fileDB.share_file_with_user(file_id, user_to_add)
        send_response(conn, b"200 User added successfully.\n", state.get("aes_key"), state.get("aes_iv"))
    else:
        send_response(conn, b"404 Repository not found.\n", state.get("aes_key"), state.get("aes_iv"))

def handle_createrepo(conn, state, context, **kwargs):
    """Handles creating a new repository."""
    fileDB = context['fileDB']
    username = state.get('name')
    repo_name = kwargs.get('repo_name')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n", state.get("aes_key"), state.get("aes_iv"))
        return

    if not repo_name:
        send_response(conn, b"400 Bad Request: Missing repository name. Usage: CREATEREPO <repo_name>\n", state.get("aes_key"), state.get("aes_iv"))
        return

    try:
        repo_id = fileDB.create_repository(repo_name, username)
        if repo_id:
            send_response(conn, b"201 Repository created successfully.\n", state.get("aes_key"), state.get("aes_iv"))
        else:
            send_response(conn, b"500 Failed to create repository.\n", state.get("aes_key"), state.get("aes_iv"))
    except Exception as e:
        send_response(conn, f"500 Server error: {e}\n".encode(), state.get("aes_key"), state.get("aes_iv"))

def handle_quit(conn, state, context, **kwargs):
    """Handles disconnection."""
    send_response(conn, b"221 Goodbye!\n", state.get("aes_key"), state.get("aes_iv"))
    return "QUIT"

command_handlers = {
    "LOGIN": {
        "handler": handle_login,
        "args": ["username", "password"],
        "separator": "_",
        "description": "Logs in. Usage: LOGIN <username>_<password>"
    },
    "REGISTER": {
        "handler": handle_register,
        "args": ["username", "password"],
        "separator": "_",
        "description": "Registers a new user. Usage: REGISTER <username>_<password>"
    },
    "LIST": {
        "handler": handle_list,
        "args": ["arg"],
        "separator": None,
        "description": "Lists files in the current repository or all repositories. Usage: LIST [path]"
    },
    "SEARCH": {
        "handler": handle_search,
        "args": ["target_file_name"],
        "separator": " ",
        "description": "Searches for a file. Usage: SEARCH <filename>"
    },
    "GET": {
        "handler": handle_get,
        "args": ["arg"],
        "separator": None,
        "description": "Downloads a file. Usage: GET <file_path> [version]"
    },
    "GETDIR": {
        "handler": handle_getdir,
        "args": ["arg"],
        "separator": None,
        "description": "Downloads a directory. Usage: GETDIR <dir_path>"
    },
    "GETVERSIONS": {
        "handler": handle_getversions,
        "args": ["arg"],
        "separator": None,
        "description": "Gets all versions of a file. Usage: GETVERSIONS <file_path>"
    },
    "PUT": {
        "handler": handle_put,
        "args": ["arg"],
        "separator": None,
        "description": "Uploads a file. Usage: PUT <file_path>"
    },
    "MKDIR": {
        "handler": handle_mkdir,
        "args": ["arg"],
        "separator": None,
        "description": "Creates a directory. Usage: MKDIR <dir_path>"
    },
    "GETREPOS": {
        "handler": handle_getrepos,
        "args": [],
        "separator": None,
        "description": "Lists your repositories."
    },
    "ADDUSER": {
        "handler": handle_adduser,
        "args": ["repo_name", "user_to_add"],
        "separator": "_",
        "description": "Shares a repo. Usage: ADDUSER <repo_name>_<user_to_add>"
    },
    "CREATEREPO": {
        "handler": handle_createrepo,
        "args": ["repo_name"],
        "separator": None,
        "description": "Creates a new repository. Usage: CREATEREPO <repo_name>"
    },
    "QUIT": {
        "handler": handle_quit,
        "args": [],
        "separator": None,
        "description": "Disconnects from the server."
    }
}

def run_command(conn, state, context, command_string):
    """Parses and executes a command using the metadata table."""
    debug_print(f"Received: {command_string}")
    cmd, _, arg_string = command_string.strip().partition(" ")
    cmd = cmd.upper()

    if cmd not in command_handlers:
        send_response(conn, b"500 Unknown command.\n", state.get("aes_key"), state.get("aes_iv"))
        return
    config = command_handlers[cmd]

    parsed_args = {}
    expected_args = config["args"]
    if expected_args:
        if not arg_string and len(expected_args) > 0 and expected_args != ['arg']:
            send_response(conn, f"400 Command '{cmd}' requires arguments. {config['description']}".encode(), state.get("aes_key"), state.get("aes_iv"))
            return
        separator = config["separator"]
        if separator:
            values = arg_string.split(separator, len(expected_args) - 1)
        else:
            values = [arg_string]
        if len(values) != len(expected_args) and expected_args != ['arg']:
            send_response(conn, f"400 Invalid arguments for '{cmd}'. {config['description']}".encode(), state.get("aes_key"), state.get("aes_iv"))
            return
        parsed_args = dict(zip(expected_args, values))

    debug_print(f"Calling handler for {cmd} with args: {parsed_args}")
    return config['handler'](conn, state, context, **parsed_args)

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    send_response(conn, b"220 Welcome Server Online\n")
    client_state = {"name": None, "aes_key": None, "aes_iv": None}
    server_context = {
        "fileDB": DBHandler(),
        "userDB": UserHandler(),
        "saveHandler": SaveHandler()
    }

    try:
        # First, receive the encrypted AES key
        encrypted_aes_data = conn.recv(1024)  # RSA encrypted AES key
        if encrypted_aes_data:
            try:
                aes_key, aes_iv = decrypt_aes_key_with_rsa(encrypted_aes_data)
                client_state["aes_key"] = aes_key
                client_state["aes_iv"] = aes_iv
                debug_print("Successfully decrypted AES key from client")
            except Exception as e:
                debug_print(f"Failed to decrypt AES key: {e}")
                return
        
        while True:
            # Receive encrypted data
            encrypted_data = conn.recv(4096)
            if not encrypted_data:
                break
            
            # Decrypt with AES
            try:
                decrypted_data = decrypt_with_aes(encrypted_data, client_state["aes_key"], client_state["aes_iv"])
                data = decrypted_data.decode().strip()
            except Exception as e:
                debug_print(f"AES decryption failed: {e}")
                continue

            if run_command(conn, client_state, server_context, data) == "QUIT":
                break
    finally:
        conn.close()
        server_context['fileDB'].close()
        server_context['userDB'].close()
        server_context['saveHandler'].close()
        print(f"[-] {addr} disconnected")

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] FTP-like server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVECONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    main()
