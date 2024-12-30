import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import os
import zipfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinterdnd2 import DND_FILES, TkinterDnD
import json
from typing import Optional

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NightShade")
        self.root.geometry("800x600")
        
        # Set the color theme and prevent transparency issues
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.root.configure(background='#2b2b2b')
        
        # Remove the border by setting outer padding to 0
        self.main_frame = ctk.CTkFrame(
            root,
            fg_color='#2b2b2b',
            corner_radius=0
        )
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Header
        self.header = ctk.CTkLabel(
            self.main_frame,
            text="Secure File Encryption",
            font=("Helvetica", 24, "bold")
        )
        self.header.pack(pady=20)
        
        # Drop zone with darker background
        self.drop_frame = ctk.CTkFrame(
            self.main_frame,
            width=600,
            height=200,
            fg_color=("#1a1a1a", "#1a1a1a"),
            corner_radius=8
        )
        self.drop_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=(0, 20))
        self.drop_frame.pack_propagate(False)
        
        # Drop zone content
        self.drop_icon = ctk.CTkLabel(
            self.drop_frame,
            text="📁",
            font=("Helvetica", 48)
        )
        self.drop_icon.pack(pady=(30, 10))
        
        self.drop_label = ctk.CTkLabel(
            self.drop_frame,
            text="Drag and drop files or folders here",
            font=("Helvetica", 16)
        )
        self.drop_label.pack()
        
        self.sub_label = ctk.CTkLabel(
            self.drop_frame,
            text="or",
            font=("Helvetica", 12),
            text_color="gray60"
        )
        self.sub_label.pack(pady=5)
        
        self.browse_button = ctk.CTkButton(
            self.drop_frame,
            text="Browse Files",
            command=self.browse_files
        )
        self.browse_button.pack(pady=5)
        
        # Status frame with matching background
        self.status_frame = ctk.CTkFrame(
            self.main_frame,
            fg_color='#2b2b2b',
            corner_radius=0
        )
        self.status_frame.pack(fill=tk.X, padx=40, pady=(0, 20))
        
        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="Ready",
            font=("Helvetica", 12)
        )
        self.status_label.pack(pady=10)
        
        # Register drop zone
        self.drop_frame.drop_target_register(DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.drop)
        
        # Progress bar
        self.progress_bar = ctk.CTkProgressBar(self.main_frame)
        self.progress_bar.pack(fill=tk.X, padx=40, pady=(0, 20))
        self.progress_bar.set(0)

        # Prevent transparency issues after operations
        self.root.bind('<Configure>', self.prevent_transparency)
        
    def prevent_transparency(self, event=None):
        self.root.attributes('-alpha', 1.0)
        
    def browse_files(self):
        file_path = filedialog.askopenfilename(title="Select File")
        if file_path:
            self.process_file(file_path)
    
    def drop(self, event):
        file_path = event.data.strip('{}')
        self.process_file(file_path)
    
    def process_file(self, file_path: str):
        self.update_status(f"Processing {os.path.basename(file_path)}...")
        self.progress_bar.set(0.2)
        self.prevent_transparency()
        
        if self.is_encrypted(file_path):
            self.decrypt_file(file_path)
        elif os.path.isdir(file_path):
            self.encrypt_directory(file_path)
        else:
            self.encrypt_file(file_path)
    
    def update_status(self, message: str):
        self.status_label.configure(text=message)
        self.root.update()
        self.prevent_transparency()
    
    def is_encrypted(self, file_path: str) -> bool:
        try:
            with open(file_path, 'rb') as f:
                version = f.read(1)  # Read version byte
                return version == b'\x01'  # Check if it's our format
        except:
            return False
    
    def get_password(self, action: str) -> Optional[str]:
        dialog = ctk.CTkInputDialog(
            text=f"Enter password for {action}:",
            title="Password Required"
        )
        password = dialog.get_input()
        self.prevent_transparency()
        return password
    
    def encrypt_directory(self, dir_path: str):
        self.update_status("Selecting output location...")
        output_folder = filedialog.askdirectory(title="Select Output Folder")
        if not output_folder:
            self.update_status("Operation cancelled")
            self.progress_bar.set(0)
            return
        
        self.progress_bar.set(0.4)
        self.update_status("Creating archive...")
        zip_path = os.path.join(output_folder, f"{os.path.basename(dir_path)}.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            for root, dirs, files in os.walk(dir_path):
                for file in files:
                    zipf.write(os.path.join(root, file))
        
        self.progress_bar.set(0.6)
        self.encrypt_file(zip_path)
    
    def encrypt_file(self, file_path: str):
        password = self.get_password("encryption")
        if not password:
            self.update_status("Operation cancelled")
            self.progress_bar.set(0)
            return
        
        self.progress_bar.set(0.7)
        self.update_status("Encrypting file...")
        
        try:
            key = (password.encode() + b'\0' * 32)[:32]
            iv = os.urandom(16)
            
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Read the file content
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Create metadata
            metadata = {
                "original_name": os.path.basename(file_path),
                "version": 1
            }
            metadata_json = json.dumps(metadata).encode()
            
            # Encrypt both metadata and content together
            encrypted_data = encryptor.update(metadata_json + b'\x00' * 4 + file_content) + encryptor.finalize()
            
            self.progress_bar.set(0.8)
            self.update_status("Selecting output location...")
            
            output_folder = filedialog.askdirectory(title="Select Output Folder")
            if not output_folder:
                self.update_status("Operation cancelled")
                self.progress_bar.set(0)
                return
            
            # Generate encrypted filename
            scrambled_name = ''.join([chr((ord(char) + 5) % 256) for char in os.path.basename(file_path)])
            scrambled_name = ''.join(filter(str.isalnum, scrambled_name))
            encrypted_file_path = os.path.join(output_folder, scrambled_name)
            
            # Write version byte, IV, and encrypted data
            with open(encrypted_file_path, 'wb') as f:
                f.write(b'\x01')  # Version byte
                f.write(iv)
                f.write(encrypted_data)
            
            self.progress_bar.set(1.0)
            self.update_status("Encryption completed successfully!")
            
            if messagebox.askyesno("Remove Original", "Do you want to remove the original file?"):
                os.remove(file_path)
                
        except Exception as e:
            self.update_status(f"Encryption failed: {str(e)}")
            self.progress_bar.set(0)
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        
        self.prevent_transparency()
    
    def decrypt_file(self, file_path: str):
        password = self.get_password("decryption")
        if not password:
            self.update_status("Operation cancelled")
            self.progress_bar.set(0)
            return
        
        self.progress_bar.set(0.7)
        self.update_status("Decrypting file...")
        
        try:
            key = (password.encode() + b'\0' * 32)[:32]
            
            with open(file_path, 'rb') as f:
                version = f.read(1)  # Read version byte
                if version != b'\x01':
                    raise ValueError("Unsupported file format version")
                
                iv = f.read(16)
                encrypted_data = f.read()
            
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt the data
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Find the metadata separator
            separator_index = decrypted_data.find(b'\x00' * 4)
            if separator_index == -1:
                raise ValueError("Invalid file format")
            
            # Split metadata and content
            metadata_json = decrypted_data[:separator_index]
            file_content = decrypted_data[separator_index + 4:]
            
            # Parse metadata
            metadata = json.loads(metadata_json.decode())
            original_name = metadata.get("original_name", "decrypted_file")
            
            self.progress_bar.set(0.8)
            self.update_status("Selecting output location...")
            
            output_folder = filedialog.askdirectory(title="Select Output Folder")
            if not output_folder:
                self.update_status("Operation cancelled")
                self.progress_bar.set(0)
                return
            
            save_path = os.path.join(output_folder, original_name)
            with open(save_path, 'wb') as f:
                f.write(file_content)
            
            self.progress_bar.set(1.0)
            self.update_status("Decryption completed successfully!")
            
        except Exception as e:
            self.update_status(f"Decryption failed: {str(e)}")
            self.progress_bar.set(0)
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        
        self.prevent_transparency()

if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = EncryptionApp(root)
    root.mainloop()