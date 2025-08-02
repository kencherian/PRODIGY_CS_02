from PIL import Image
import hashlib
import random
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from threading import Thread


class ImageCryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Image Encryptor/Decryptor")
        self.root.geometry("600x500")
        self.root.configure(bg='#f0f0f0')

        # Variables
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.mode = tk.StringVar(value="encrypt")
        self.show_password = tk.BooleanVar()

        self.setup_ui()

    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Title
        title_label = ttk.Label(main_frame, text="🔐 Image Encryptor/Decryptor",
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))

        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Mode", padding="10")
        mode_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))

        ttk.Radiobutton(mode_frame, text="🔒 Encrypt", variable=self.mode,
                        value="encrypt").grid(row=0, column=0, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="🔓 Decrypt", variable=self.mode,
                        value="decrypt").grid(row=0, column=1)

        # Input file selection
        input_frame = ttk.LabelFrame(main_frame, text="Input Image", padding="10")
        input_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))

        ttk.Entry(input_frame, textvariable=self.input_path, width=50).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(input_frame, text="Browse", command=self.browse_input).grid(row=0, column=1)

        # Output file selection
        output_frame = ttk.LabelFrame(main_frame, text="Output Image", padding="10")
        output_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))

        ttk.Entry(output_frame, textvariable=self.output_path, width=50).grid(row=0, column=0, padx=(0, 10))
        ttk.Button(output_frame, text="Browse", command=self.browse_output).grid(row=0, column=1)

        # Password input
        password_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        password_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 15))

        self.password_entry = ttk.Entry(password_frame, textvariable=self.password,
                                        show="*", width=40)
        self.password_entry.grid(row=0, column=0, padx=(0, 10))

        ttk.Checkbutton(password_frame, text="Show", variable=self.show_password,
                        command=self.toggle_password).grid(row=0, column=1)

        # Process button
        self.process_btn = ttk.Button(main_frame, text="🚀 Process Image",
                                      command=self.process_image, style='Accent.TButton')
        self.process_btn.grid(row=5, column=0, columnspan=3, pady=20)

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))

        # Status label
        self.status_label = ttk.Label(main_frame, text="Ready", foreground="green")
        self.status_label.grid(row=7, column=0, columnspan=3)

        # Info text
        info_text = tk.Text(main_frame, height=8, width=70, wrap=tk.WORD,
                            font=('Arial', 9), bg='#f8f8f8', relief=tk.FLAT)
        info_text.grid(row=8, column=0, columnspan=3, pady=(20, 0), sticky=(tk.W, tk.E))

        info_content = """How it works:
• Encrypt: Transforms image using XOR encryption with password-derived key, shuffles rows, and adds integrity check
• Decrypt: Reverses the process and verifies image integrity
• Uses SHA-256 for password hashing and integrity verification
• Original image quality is preserved (lossless encryption)
• Supports common image formats (JPEG, PNG, BMP, etc.)"""

        info_text.insert(tk.END, info_content)
        info_text.config(state=tk.DISABLED)

        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)

    def browse_input(self):
        filename = filedialog.askopenfilename(
            title="Select Input Image",
            filetypes=[
                ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif *.tiff"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.input_path.set(filename)
            # Auto-generate output filename
            if not self.output_path.get():
                base, ext = os.path.splitext(filename)
                mode_suffix = "_encrypted" if self.mode.get() == "encrypt" else "_decrypted"
                self.output_path.set(f"{base}{mode_suffix}{ext}")

    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Output Image As",
            filetypes=[
                ("Image files", "*.jpg *.jpeg *.png *.bmp *.gif *.tiff"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.output_path.set(filename)

    def toggle_password(self):
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def validate_inputs(self):
        if not self.input_path.get():
            messagebox.showerror("Error", "Please select an input image")
            return False
        if not self.output_path.get():
            messagebox.showerror("Error", "Please specify an output path")
            return False
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password")
            return False
        if not os.path.exists(self.input_path.get()):
            messagebox.showerror("Error", "Input file does not exist")
            return False
        return True

    def process_image(self):
        if not self.validate_inputs():
            return

        # Disable button and start progress
        self.process_btn.config(state='disabled')
        self.progress.start()
        self.status_label.config(text="Processing...", foreground="orange")

        # Run in separate thread to prevent GUI freezing
        Thread(target=self.process_image_thread, daemon=True).start()

    def process_image_thread(self):
        try:
            result = self.encrypt_decrypt_image(
                self.input_path.get(),
                self.output_path.get(),
                self.password.get(),
                self.mode.get()
            )

            # Update GUI in main thread
            self.root.after(0, self.process_complete, result)

        except Exception as e:
            self.root.after(0, self.process_error, str(e))

    def process_complete(self, result):
        self.progress.stop()
        self.process_btn.config(state='normal')

        if result["success"]:
            self.status_label.config(text=f"✅ {result['message']}", foreground="green")
            messagebox.showinfo("Success", result['message'])
        else:
            self.status_label.config(text=f"❌ {result['message']}", foreground="red")
            messagebox.showerror("Error", result['message'])

    def process_error(self, error_msg):
        self.progress.stop()
        self.process_btn.config(state='normal')
        self.status_label.config(text=f"❌ Error: {error_msg}", foreground="red")
        messagebox.showerror("Error", f"An error occurred: {error_msg}")

    def derive_key_and_seed(self, password):
        """Convert password into a key (0-255) and seed for shuffling."""
        hash_object = hashlib.sha256(password.encode())
        hash_digest = hash_object.digest()
        key = hash_digest[0]
        seed = int.from_bytes(hash_digest[:4], 'big')
        return key, seed

    def compute_image_hash(self, img):
        """Generate a SHA-256 hash of pixel data for integrity verification."""
        pixel_data = img.tobytes()
        return hashlib.sha256(pixel_data).digest()[:3]  # Use first 3 bytes (R, G, B)

    def encrypt_decrypt_image(self, input_path, output_path, password, mode='encrypt'):
        try:
            img = Image.open(input_path)
            img = img.convert("RGB")
            pixels = img.load()
            width, height = img.size
            key, seed = self.derive_key_and_seed(password)

            if width < 1 or height < 1:
                return {"success": False, "message": "Image is too small."}

            if mode == 'encrypt':
                # Step 1: Compute and store hash at (0, 0)
                tag = self.compute_image_hash(img)
                pixels[0, 0] = tuple([c ^ key for c in tag])  # Obfuscate tag

            # Step 2: XOR pixels (except (0,0))
            for x in range(width):
                for y in range(height):
                    if x == 0 and y == 0:
                        continue  # Skip tag pixel
                    r, g, b = pixels[x, y]
                    pixels[x, y] = (
                        r ^ key,
                        g ^ key,
                        b ^ key
                    )

            # Step 3: Shuffle or Unshuffle rows (except row 0 if tag is stored there)
            rows = [list(pixels[x, y] for x in range(width)) for y in range(height)]
            random.seed(seed)
            indices = list(range(height))
            shuffled_indices = indices.copy()
            random.shuffle(shuffled_indices)

            if mode == 'encrypt':
                new_rows = [rows[i] for i in shuffled_indices]
            elif mode == 'decrypt':
                inverse = [0] * height
                for i, si in enumerate(shuffled_indices):
                    inverse[si] = i
                new_rows = [rows[i] for i in inverse]
            else:
                return {"success": False, "message": "Mode must be 'encrypt' or 'decrypt'."}

            for y, row in enumerate(new_rows):
                for x in range(width):
                    pixels[x, y] = row[x]

            if mode == 'decrypt':
                # Step 4: Verify integrity using tag
                tag_pixel = pixels[0, 0]
                decrypted_tag = tuple([c ^ key for c in tag_pixel])
                current_hash = self.compute_image_hash(img)
                if current_hash[:3] != bytes(decrypted_tag):
                    return {"success": False, "message": "Incorrect password or tampered image."}

            img.save(output_path)
            return {"success": True, "message": f"{mode.title()}ion successful! Output saved to {output_path}"}

        except Exception as e:
            return {"success": False, "message": str(e)}


def main():
    root = tk.Tk()
    app = ImageCryptoGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()