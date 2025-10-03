import socket
import os
import threading
import time
import re
from DBHandler import DBHandler
from UserHandler import UserHandler
from SaveHandler import SaveHandler, DiffCheck

HOST = '127.0.0.1'
PORT = 2122
BASE_DIR = "ftp_root"
DEBUG = True

os.makedirs(BASE_DIR, exist_ok=True)

def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")

def send_response(conn, message):
    debug_print(f"Sent: {message.strip()}")
    conn.sendall(message)

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
        send_response(conn, b"401 LOGIN FAILED: Invalid username format.\n")
        return
    userDB = context['userDB']
    user_data = userDB.get_user(username)

    if user_data and password == user_data[1]:
        send_response(conn, b"200 LOGIN SUCCESS\n")
        state['name'] = username
    else:
        send_response(conn, b"401 LOGIN FAILED: Invalid username or password.\n")

def handle_register(conn, state, context, **kwargs):
    """Handles user registration."""
    username = kwargs.get('username')
    password = kwargs.get('password')
    if not is_valid_username(username):
        send_response(conn, b"402 REGISTER FAILED: Invalid username format.\n")
        return

    userDB = context['userDB']

    if userDB.get_user(username) is not None:
        send_response(conn, b"402 REGISTER FAILED: User already exists.\n")
    else:
        userDB.new_user(username, password)
        send_response(conn, b"201 REGISTER SUCCESS\n")

def handle_list(conn, state, context, **kwargs):
    """Handles listing files and repositories."""
    save_handler = context['saveHandler']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return
    
    # The argument is the virtual path to list. If empty, it lists the root.
    directory_path = arg if arg else ""
    
    # Use the SaveHandler to get the virtual directory listing
    contents = save_handler.list_virtual_directory(directory_path)
    if contents:
        send_response(conn, b"200 OK\n" + "\n".join(contents).encode() + b"\n")
    else:
        send_response(conn, b"404 No files or directories found.\n")

def handle_search(conn, state, context, **kwargs):
    """Handles searching for a file."""
    fileDB = context['fileDB']
    username = state.get('name')
    target_file_name = kwargs.get('target_file_name')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    if target_file_name:
        found_files = context['saveHandler'].search_files_by_name(target_file_name)
        filtered_files = [file for file in found_files if have_access(username, file, fileDB)]
        if filtered_files:
            response = b"200 OK\n" + "\n".join(filtered_files).encode()
        else:
            response = b"404 No files found."
        send_response(conn, response)
    else:
        send_response(conn, b"400 Bad Request: Missing filename. Usage: SEARCH <filename>\n")

def handle_get(conn, state, context, **kwargs):
    """Handles retrieving a file."""
    fileDB = context['fileDB']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n")
    else:
        save_handler = context['saveHandler']
        latest_version = save_handler.get_latest_version(arg)

        if latest_version == 0:
            send_response(conn, b"404 File not found in version control.\n")
            return

        # Reconstruct the file at its latest version
        content = save_handler.get_file_at_version(arg, latest_version) # Returns bytes

        if content is not None:
            send_response(conn, b"200 OK\n" + content)
        else:
            send_response(conn, b"500 Could not reconstruct file.\n")

def handle_getdir(conn, state, context, **kwargs):
    """Handles retrieving a directory."""
    fileDB = context['fileDB']
    save_handler = context['saveHandler']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n")
    else:
        send_response(conn, b"200 OK\n")
        # Find all files that are inside the requested virtual directory
        all_repo_files = save_handler.search_files_by_name(arg)
        files_in_dir = [f for f in all_repo_files if f.startswith(arg)]

        for file_path in files_in_dir:
            latest_version = save_handler.get_latest_version(file_path)
            if latest_version > 0:
                content = save_handler.get_file_at_version(file_path, latest_version)
                if content:
                    size = len(content)
                    send_response(conn, f"FILE {file_path} {size}\n".encode())
                    send_response(conn, content)
        send_response(conn, b"DONE\n")

def handle_put(conn, state, context, **kwargs):
    """Handles uploading a file."""
    fileDB = context['fileDB']
    save_handler = context['saveHandler']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    # Check access based on the virtual path argument
    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n")
    else:
        send_response(conn, b"200 OK: Send file data, end with EOF marker '<EOF>'\n")
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
            send_response(conn, b"200 File uploaded successfully.\n")
        else:
            send_response(conn, b"200 File is already up to date.\n")

def handle_mkdir(conn, state, context, **kwargs):
    """Handles creating a directory."""
    fileDB = context['fileDB']
    username = state.get('name')
    arg = kwargs.get('arg')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    if not have_access(username, arg, fileDB):
        send_response(conn, b"403 Access denied.\n")
    else:
        # In a virtual system, a directory "exists" as soon as a file is in it.
        # This command can simply return success.
        send_response(conn, b"201 Directory will be created upon file upload.\n")

def handle_getrepos(conn, state, context, **kwargs):
    """Handles getting user's repositories."""
    fileDB = context['fileDB']
    username = state.get('name')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    repos = fileDB.get_user_files(username, include_shared=False)
    repo_names = [repo[1] for repo in repos]
    send_response(conn, b"200 OK\n" + ",".join(repo_names).encode() + b"\n")

def handle_adduser(conn, state, context, **kwargs):
    """Handles adding a user to a repo."""
    fileDB = context['fileDB']
    username = state.get('name')
    repo_name = kwargs.get('repo_name')
    user_to_add = kwargs.get('user_to_add')

    if not username:
        send_response(conn, b"403 You must be logged in to perform this action.\n")
        return

    files = fileDB.get_all_files()
    file_id = -1
    for file in files:
        if file[1] == repo_name:
            file_id = file[0]
            break
    if file_id != -1:
        fileDB.share_file_with_user(file_id, user_to_add)
        send_response(conn, b"200 User added successfully.\n")
    else:
        send_response(conn, b"404 Repository not found.\n")

def handle_quit(conn, state, context, **kwargs):
    """Handles disconnection."""
    send_response(conn, b"221 Goodbye!\n")
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
        "description": "Downloads a file. Usage: GET <file_path>"
    },
    "GETDIR": {
        "handler": handle_getdir,
        "args": ["arg"],
        "separator": None,
        "description": "Downloads a directory. Usage: GETDIR <dir_path>"
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
        send_response(conn, b"500 Unknown command.\n")
        return
    config = command_handlers[cmd]

    parsed_args = {}
    expected_args = config["args"]
    if expected_args:
        if not arg_string and len(expected_args) > 0 and expected_args != ['arg']:
            send_response(conn, f"400 Command '{cmd}' requires arguments. {config['description']}".encode())
            return
        separator = config["separator"]
        if separator:
            values = arg_string.split(separator, len(expected_args) - 1)
        else:
            values = [arg_string]
        if len(values) != len(expected_args) and expected_args != ['arg']:
            send_response(conn, f"400 Invalid arguments for '{cmd}'. {config['description']}".encode())
            return
        parsed_args = dict(zip(expected_args, values))

    debug_print(f"Calling handler for {cmd} with args: {parsed_args}")
    return config['handler'](conn, state, context, **parsed_args)

def handle_client(conn, addr):
    print(f"[+] Connected by {addr}")
    send_response(conn, b"220 Welcome Server Online\n")
    client_state = {"name": None}
    server_context = {
        "fileDB": DBHandler(),
        "userDB": UserHandler(),
        "saveHandler": SaveHandler()
    }

    try:
        while True:
            data = conn.recv(1024).decode().strip()
            if not data:
                break

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
