import tkinter as tk
from tkinter import filedialog
 
def select_file_to_open(title="Select a file"):
    """
    Opens a file dialog for the user to select a file to read/open.
    Returns the full path to the selected file, or None if cancelled.
    """
    # Create a root window, but hide it immediately
    root = tk.Tk()
    root.withdraw()
    # Set the window to be on top of all other windows
    root.attributes('-topmost', True)
    
    file_path = filedialog.askopenfilename(
        title=title,
        filetypes=[("All Files", "*.*"), ("Text Files", "*.txt"), ("Encrypted Files", "*.enc")]
    )
    
    root.destroy()
    
    # Return the path if a file was selected, otherwise return None
    return file_path if file_path else None

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
        defaultextension=".bin", # Default extension if user doesn't type one
        filetypes=[("All Files", "*.*"), ("Binary Files", "*.bin"), ("Encrypted Files", "*.enc")]
    )
    
    root.destroy()
    
    return file_path if file_path else None