import tkinter as tk
from tkinter import filedialog

def select_file_to_open(title="Select a file", multiple=False):
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    file_paths = filedialog.askopenfilenames(
        title=title,
        filetypes=[
            ("All Files", "*.*"), 
            ("Gzip Files", "*.gz"), 
            ("Tar Archives", "*.tar.gz"), 
            ("Encrypted Files", "*.enc"),
            ("Signature Files", "*.sig"), 
            ("Text Files", "*.txt")
        ],
        multiple=multiple
    )
    
    root.destroy()
    
    if multiple:
        return list(file_paths) if file_paths else None
    else:
        return file_paths[0] if file_paths else None

def select_file_to_save(default_filename="output", title="Save file as..."):
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    file_path = filedialog.asksaveasfilename(
        title=title,
        initialfile=default_filename,
        defaultextension=".bin",
        filetypes=[
            ("All Files", "*.*"), 
            ("Binary Files", "*.bin"), 
            ("Encrypted Files", "*.enc"), 
            ("Archive Files", "*.tar.gz"),
            ("Gzip Files", "*.gz")
        ]
    )
    
    root.destroy()
    
    return file_path if file_path else None

def select_directory(title="Select a directory"): # to open select directory dialog.
    root = tk.Tk()
    root.withdraw()
    root.attributes('-topmost', True)
    
    dir_path = filedialog.askdirectory(title=title)
    
    root.destroy()
    
    return dir_path if dir_path else None