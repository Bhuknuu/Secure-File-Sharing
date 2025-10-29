import tkinter as tk
from tkinter import filedialog

def select_file_to_open(title="Select a file", multiple=False):
    """
    Opens a file dialog for the user to select a file or files to read/open.
    Returns the full path to the selected file, a tuple of paths, or None if cancelled.
    """
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    file_paths = filedialog.askopenfilenames(
        title=title,
        filetypes=[("All Files", "."), ("Text Files", ".txt"), ("Encrypted Files", ".enc")],
        multiple=multiple
    )
    
    root.destroy()
    
    # If multiple is True, it always returns a tuple (can be empty).
    # If not, it returns a single string or an empty string.
    if multiple:
        return list(file_paths) if file_paths else None
    else:
        return file_paths[0] if file_paths else None

def select_file_to_save(default_filename="output", title="Save file as..."):
    """
    Opens a file dialog for the user to choose a location and name to save a file.
    Returns the full path for the new file, or None if cancelled.
    """
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    file_path = filedialog.asksaveasfilename(
        title=title,
        initialfile=default_filename,
        defaultextension=".bin",
        filetypes=[("All Files", "."), ("Binary Files", ".bin"), ("Encrypted Files", ".enc"), ("Archive Files", "*.tar.gz")]
    )
    
    root.destroy()
    
    return file_path if file_path else None

def select_directory(title="Select a directory"):
    """
    Opens a dialog for the user to select a directory.
    Returns the path to the directory, or None if cancelled.
    """
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    dir_path = filedialog.askdirectory(title=title)
    
    root.destroy()
    
    return dir_path if dir_path else None
