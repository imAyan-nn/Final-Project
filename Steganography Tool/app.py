import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from PIL import Image, ImageTk
import os
import sys
from tkinterdnd2 import DND_FILES, TkinterDnD
import base64
import hashlib

class SteganographyTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool - Hide/Extract Data in Images")
        self.root.geometry("800x700")
        self.root.configure(bg='#2b2b2b')
        
        # Variables
        self.current_image = None
        self.image_path = ""
        self.password = tk.StringVar()
        self.modified_image = None
        self.file_path = None
        self.extract_image_path = None
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure style for dark theme
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Dark.TFrame', background='#2b2b2b')
        style.configure('Dark.TLabel', background='#2b2b2b', foreground='white')
        style.configure('Dark.TButton', background='#404040', foreground='white')
        
        # Title
        title_label = ttk.Label(main_frame, text="🔒 Steganography Tool", 
                               font=('Arial', 20, 'bold'), style='Dark.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Hide data tab
        hide_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(hide_frame, text="Hide Data")
        self.setup_hide_tab(hide_frame)
        
        # Extract data tab
        extract_frame = ttk.Frame(notebook, style='Dark.TFrame')
        notebook.add(extract_frame, text="Extract Data")
        self.setup_extract_tab(extract_frame)
        
    def setup_hide_tab(self, parent):
        # Create a main canvas with scrollbar
        main_canvas = tk.Canvas(parent, bg='#2b2b2b')
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=main_canvas.yview)
        scrollable_frame = ttk.Frame(main_canvas, style='Dark.TFrame')
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to canvas
        def _on_mousewheel(event):
            main_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        main_canvas.bind_all("<MouseWheel>", _on_mousewheel)
        
        # Image selection area
        image_frame = ttk.LabelFrame(scrollable_frame, text="Select Cover Image", padding="10")
        image_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        # Compact drag and drop area
        drop_frame = tk.Frame(image_frame, bg='#404040', height=100, relief=tk.RAISED, bd=2)
        drop_frame.pack(fill=tk.X, pady=5)
        drop_frame.pack_propagate(False)
        
        drop_label = tk.Label(drop_frame, text="Drag & Drop Image Here", 
                             bg='#404040', fg='white', font=('Arial', 10))
        drop_label.pack(expand=True)
        
        # Enable drag and drop
        drop_frame.drop_target_register(DND_FILES)
        drop_frame.dnd_bind('<<Drop>>', self.on_image_drop)
        
        # Browse button
        browse_btn = ttk.Button(image_frame, text="Browse Image", 
                               command=self.browse_image)
        browse_btn.pack(pady=5)
        
        # Image status (compact)
        self.image_status_label = tk.Label(image_frame, text="No image selected", 
                                          bg='#2b2b2b', fg='white', font=('Arial', 9))
        self.image_status_label.pack(pady=2)
        
        # Image preview (smaller)
        self.image_label = tk.Label(image_frame, text="", bg='#2b2b2b')
        self.image_label.pack(pady=5)
        
        # Data input area
        data_frame = ttk.LabelFrame(scrollable_frame, text="Data to Hide", padding="10")
        data_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        # Text input
        ttk.Label(data_frame, text="Enter text to hide:", style='Dark.TLabel').pack(anchor=tk.W)
        self.text_input = scrolledtext.ScrolledText(data_frame, height=6, 
                                                   bg='#404040', fg='white', 
                                                   insertbackground='white')
        self.text_input.pack(fill=tk.X, pady=5)
        
        # File input option
        file_frame = ttk.Frame(data_frame)
        file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(file_frame, text="Or select file:", style='Dark.TLabel').pack(side=tk.LEFT)
        self.file_label = ttk.Label(file_frame, text="No file selected", style='Dark.TLabel')
        self.file_label.pack(side=tk.LEFT, padx=(10, 0))
        
        browse_file_btn = ttk.Button(file_frame, text="Browse File", 
                                    command=self.browse_file)
        browse_file_btn.pack(side=tk.RIGHT)
        
        # Clear file button
        clear_file_btn = ttk.Button(file_frame, text="Clear File", 
                                   command=self.clear_file)
        clear_file_btn.pack(side=tk.RIGHT, padx=(0, 5))
        
        # Password section
        password_frame = ttk.Frame(data_frame)
        password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_frame, text="Password (optional):", style='Dark.TLabel').pack(side=tk.LEFT)
        password_entry = ttk.Entry(password_frame, textvariable=self.password, show="*")
        password_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Buttons frame
        buttons_frame = ttk.Frame(data_frame)
        buttons_frame.pack(fill=tk.X, pady=10)
        
        # Hide button
        hide_btn = ttk.Button(buttons_frame, text="Hide Data in Image", 
                             command=self.hide_data, style='Dark.TButton')
        hide_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Save button for modified image
        self.save_btn = ttk.Button(buttons_frame, text="Save Modified Image", 
                                  command=self.save_modified_image, 
                                  style='Dark.TButton', state='disabled')
        self.save_btn.pack(side=tk.LEFT)
        
    def setup_extract_tab(self, parent):
        # Create a main canvas with scrollbar for extract tab
        extract_canvas = tk.Canvas(parent, bg='#2b2b2b')
        extract_scrollbar = ttk.Scrollbar(parent, orient="vertical", command=extract_canvas.yview)
        extract_scrollable_frame = ttk.Frame(extract_canvas, style='Dark.TFrame')
        
        extract_scrollable_frame.bind(
            "<Configure>",
            lambda e: extract_canvas.configure(scrollregion=extract_canvas.bbox("all"))
        )
        
        extract_canvas.create_window((0, 0), window=extract_scrollable_frame, anchor="nw")
        extract_canvas.configure(yscrollcommand=extract_scrollbar.set)
        
        extract_canvas.pack(side="left", fill="both", expand=True)
        extract_scrollbar.pack(side="right", fill="y")
        
        # Bind mousewheel to extract canvas
        def _on_extract_mousewheel(event):
            extract_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        extract_canvas.bind_all("<MouseWheel>", _on_extract_mousewheel)
        
        # Image selection for extraction
        extract_image_frame = ttk.LabelFrame(extract_scrollable_frame, text="Select Image with Hidden Data", padding="10")
        extract_image_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        # Compact drag and drop area for extraction
        extract_drop_frame = tk.Frame(extract_image_frame, bg='#404040', height=80, relief=tk.RAISED, bd=2)
        extract_drop_frame.pack(fill=tk.X, pady=5)
        extract_drop_frame.pack_propagate(False)
        
        extract_drop_label = tk.Label(extract_drop_frame, text="Drag & Drop Image Here", 
                                     bg='#404040', fg='white', font=('Arial', 10))
        extract_drop_label.pack(expand=True)
        
        # Enable drag and drop for extraction
        extract_drop_frame.drop_target_register(DND_FILES)
        extract_drop_frame.dnd_bind('<<Drop>>', self.on_extract_image_drop)
        
        # Browse button for extraction
        extract_browse_btn = ttk.Button(extract_image_frame, text="Browse Image", 
                                       command=self.browse_extract_image)
        extract_browse_btn.pack(pady=5)
        
        # Image status for extraction
        self.extract_image_status_label = tk.Label(extract_image_frame, text="No image selected", 
                                                  bg='#2b2b2b', fg='white', font=('Arial', 9))
        self.extract_image_status_label.pack(pady=2)
        
        # Password for extraction
        extract_password_frame = ttk.Frame(extract_image_frame)
        extract_password_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(extract_password_frame, text="Password:", style='Dark.TLabel').pack(side=tk.LEFT)
        self.extract_password = tk.StringVar()
        extract_password_entry = ttk.Entry(extract_password_frame, textvariable=self.extract_password, show="*")
        extract_password_entry.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Extract button
        extract_btn = ttk.Button(extract_image_frame, text="Extract Hidden Data", 
                                command=self.extract_data, style='Dark.TButton')
        extract_btn.pack(pady=10)
        
        # Results area
        results_frame = ttk.LabelFrame(extract_scrollable_frame, text="Extracted Data", padding="10")
        results_frame.pack(fill=tk.X, pady=(0, 10), padx=10)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=12, 
                                                     bg='#404040', fg='white', 
                                                     insertbackground='white')
        self.results_text.pack(fill=tk.X, pady=5)
        
        # Save extracted data button
        save_btn = ttk.Button(results_frame, text="Save Extracted Data", 
                             command=self.save_extracted_data, style='Dark.TButton')
        save_btn.pack(pady=5)
        
    def on_image_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            self.load_image(files[0])
            
    def on_extract_image_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            self.extract_image_path = files[0]
            messagebox.showinfo("Success", f"Image loaded: {os.path.basename(files[0])}")
            
    def browse_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Cover Image",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff")]
        )
        if file_path:
            self.load_image(file_path)
            
    def browse_extract_image(self):
        file_path = filedialog.askopenfilename(
            title="Select Image with Hidden Data",
            filetypes=[("Image files", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff")]
        )
        if file_path:
            self.extract_image_path = file_path
            messagebox.showinfo("Success", f"Image loaded: {os.path.basename(file_path)}")
            
    def load_image(self, file_path):
        try:
            self.image_path = file_path
            image = Image.open(file_path)
            
            # Resize for preview (smaller)
            image.thumbnail((200, 150))
            photo = ImageTk.PhotoImage(image)
            
            self.image_label.configure(image=photo, text="")
            self.image_label.image = photo  # Keep a reference
            
            # Update status
            filename = os.path.basename(file_path)
            self.image_status_label.configure(text=f"✓ Loaded: {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load image: {str(e)}")
            
    def clear_file(self):
        """Clear selected file"""
        self.file_path = None
        self.file_label.configure(text="No file selected")
            
    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Hide")
        if file_path:
            self.file_path = file_path
            self.file_label.configure(text=f"Selected: {os.path.basename(file_path)}")
            
    def text_to_binary(self, text):
        """Convert text to binary string"""
        return ''.join(format(ord(char), '08b') for char in text)
        
    def binary_to_text(self, binary_str):
        """Convert binary string to text"""
        text = ""
        for i in range(0, len(binary_str), 8):
            byte = binary_str[i:i+8]
            if len(byte) == 8:
                text += chr(int(byte, 2))
        return text
        
    def encrypt_data(self, data, password):
        """Simple encryption using password"""
        if not password:
            return data
        
        # Create a hash of the password to use as key
        key = hashlib.sha256(password.encode()).digest()
        
        # Simple XOR encryption
        encrypted = bytearray()
        for i, byte in enumerate(data.encode('utf-8')):
            encrypted.append(byte ^ key[i % len(key)])
            
        return base64.b64encode(encrypted).decode('ascii')
        
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using password"""
        if not password:
            return encrypted_data
            
        try:
            # Create a hash of the password to use as key
            key = hashlib.sha256(password.encode()).digest()
            
            # Decode from base64
            encrypted = base64.b64decode(encrypted_data.encode('ascii'))
            
            # Simple XOR decryption
            decrypted = bytearray()
            for i, byte in enumerate(encrypted):
                decrypted.append(byte ^ key[i % len(key)])
                
            return decrypted.decode('utf-8')
        except:
            return None
            
    def hide_data(self):
        if not self.image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        # Get data to hide
        data_to_hide = ""
        if self.file_path:
            try:
                with open(self.file_path, 'rb') as f:
                    file_data = f.read()
                    # Encode binary file data to base64 for text storage
                    import base64
                    data_to_hide = base64.b64encode(file_data).decode('ascii')
                    data_to_hide = f"FILE:{os.path.basename(self.file_path)}|{data_to_hide}"
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read file: {str(e)}")
                return
        else:
            data_to_hide = self.text_input.get(1.0, tk.END).strip()
            
        if not data_to_hide:
            messagebox.showerror("Error", "Please enter text or select a file to hide!")
            return
            
        try:
            # Encrypt data if password provided
            password = self.password.get().strip()
            if password:
                data_to_hide = self.encrypt_data(data_to_hide, password)
            
            # Add delimiter to mark end of data
            data_to_hide += "<<<END_OF_HIDDEN_DATA>>>"
            
            # Convert to binary
            binary_data = self.text_to_binary(data_to_hide)
            
            # Load image
            image = Image.open(self.image_path)
            image = image.convert('RGB')
            pixels = list(image.getdata())
            
            # Check if image is large enough
            max_data_size = len(pixels) * 3
            if len(binary_data) > max_data_size:
                messagebox.showerror("Error", 
                    f"Image too small! Can hide {max_data_size//8} characters max, "
                    f"but you're trying to hide {len(binary_data)//8} characters.")
                return
                
            # Hide data in LSB of pixels
            data_index = 0
            new_pixels = []
            
            for i, pixel in enumerate(pixels):
                r, g, b = pixel
                
                if data_index < len(binary_data):
                    # Modify red channel LSB
                    r = (r & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                    
                if data_index < len(binary_data):
                    # Modify green channel LSB
                    g = (g & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                    
                if data_index < len(binary_data):
                    # Modify blue channel LSB
                    b = (b & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                    
                new_pixels.append((r, g, b))
                
            # Create new image and store it
            self.modified_image = Image.new('RGB', image.size)
            self.modified_image.putdata(new_pixels)
            
            # Enable save button
            self.save_btn.configure(state='normal')
            
            messagebox.showinfo("Success", 
                f"Data hidden successfully!\n"
                f"Hidden {len(binary_data)} bits of data.\n"
                f"Click 'Save Modified Image' to save the result.")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide data: {str(e)}")
            import traceback
            print(traceback.format_exc())
    
    def save_modified_image(self):
        if not self.modified_image:
            messagebox.showerror("Error", "No modified image to save!")
            return
            
        save_path = filedialog.asksaveasfilename(
            title="Save Image with Hidden Data",
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("JPEG files", "*.jpg"),
                ("BMP files", "*.bmp"),
                ("All files", "*.*")
            ]
        )
        
        if save_path:
            try:
                # Always save as PNG to preserve data integrity
                if not save_path.lower().endswith('.png'):
                    save_path += '.png'
                    
                self.modified_image.save(save_path, "PNG")
                messagebox.showinfo("Success", f"Image saved to:\n{save_path}")
                
                # Reset the modified image and disable save button
                self.modified_image = None
                self.save_btn.configure(state='disabled')
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save image: {str(e)}")
            
    def extract_data(self):
        if not hasattr(self, 'extract_image_path') or not self.extract_image_path:
            messagebox.showerror("Error", "Please select an image first!")
            return
            
        try:
            # Load image
            image = Image.open(self.extract_image_path)
            image = image.convert('RGB')
            pixels = list(image.getdata())
            
            # Extract binary data from LSB
            binary_data = ""
            
            for pixel in pixels:
                r, g, b = pixel
                
                # Extract LSB from each channel
                binary_data += str(r & 1)
                binary_data += str(g & 1)
                binary_data += str(b & 1)
                
            # Convert binary to text
            extracted_text = ""
            try:
                extracted_text = self.binary_to_text(binary_data)
            except:
                messagebox.showerror("Error", "Failed to decode hidden data!")
                return
            
            # Find the delimiter
            delimiter = "<<<END_OF_HIDDEN_DATA>>>"
            end_index = extracted_text.find(delimiter)
            
            if end_index == -1:
                messagebox.showwarning("Warning", "No hidden data found or data is corrupted!")
                return
                
            hidden_data = extracted_text[:end_index]
            
            # Try to decrypt if password provided
            password = self.extract_password.get().strip()
            if password:
                decrypted_data = self.decrypt_data(hidden_data, password)
                if decrypted_data is None:
                    messagebox.showerror("Error", "Wrong password or corrupted data!")
                    return
                hidden_data = decrypted_data
            
            # Check if it's a file
            if hidden_data.startswith("FILE:"):
                try:
                    # Extract filename and data
                    parts = hidden_data[5:].split("|", 1)
                    if len(parts) == 2:
                        filename, file_data = parts
                        # Decode base64 file data
                        import base64
                        original_data = base64.b64decode(file_data)
                        
                        # Ask user where to save the file
                        save_path = filedialog.asksaveasfilename(
                            title="Save Extracted File",
                            initialvalue=filename,
                            defaultextension=os.path.splitext(filename)[1]
                        )
                        
                        if save_path:
                            with open(save_path, 'wb') as f:
                                f.write(original_data)
                            messagebox.showinfo("Success", f"File extracted and saved to:\n{save_path}")
                            self.results_text.delete(1.0, tk.END)
                            self.results_text.insert(1.0, f"Extracted file: {filename}\nSaved to: {save_path}")
                        return
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to extract file: {str(e)}")
                    return
                
            # Display text results
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(1.0, hidden_data)
            
            messagebox.showinfo("Success", "Text data extracted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to extract data: {str(e)}")
            import traceback
            print(traceback.format_exc())
            
    def save_extracted_data(self):
        data = self.results_text.get(1.0, tk.END).strip()
        if not data:
            messagebox.showwarning("Warning", "No data to save!")
            return
            
        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if save_path:
            try:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(data)
                messagebox.showinfo("Success", f"Data saved to: {save_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {str(e)}")

def main():
    # Check if required modules are installed
    try:
        from tkinterdnd2 import TkinterDnD
        from PIL import Image, ImageTk
    except ImportError as e:
        print(f"Required module not found: {e}")
        print("\nPlease install required modules:")
        print("pip install tkinterdnd2 Pillow")
        input("Press Enter to exit...")
        return
        
    root = TkinterDnD.Tk()
    app = SteganographyTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()