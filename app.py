# app.py
import tkinter as tk
from tkinter import filedialog, messagebox
import os
from encrypt_decrypt import (
    generate_key, load_key, encrypt_message, decrypt_message,
    encrypt_csv, decrypt_csv
)

KEY_PATH = "key.key"  # default key file in project folder

# --- GUI callbacks ---
def do_generate_key():
    path = filedialog.asksaveasfilename(defaultextension=".key",
                                        filetypes=[("Key files", "*.key"), ("All files","*.*")],
                                        initialfile="key.key",
                                        title="Save key as...")
    if not path:
        return
    generate_key(path)
    messagebox.showinfo("Key saved", f"Key generated and saved to:\n{path}")
    key_label.config(text=f"Key: {os.path.basename(path)}")
    app_state["key_path"] = path

def do_load_key():
    path = filedialog.askopenfilename(defaultextension=".key",
                                      filetypes=[("Key files", "*.key"), ("All files","*.*")],
                                      title="Select key file")
    if not path:
        return
    try:
        load_key(path)
    except Exception as e:
        messagebox.showerror("Error", f"Cannot load key:\n{e}")
        return
    messagebox.showinfo("Key loaded", f"Loaded key:\n{path}")
    key_label.config(text=f"Key: {os.path.basename(path)}")
    app_state["key_path"] = path

def do_encrypt_text():
    kp = app_state.get("key_path")
    if not kp or not os.path.exists(kp):
        messagebox.showwarning("No key", "Please generate or load a key first.")
        return
    text = text_input.get("1.0", tk.END).strip()
    if not text:
        messagebox.showwarning("Empty", "Please type a message to encrypt.")
        return
    try:
        token = encrypt_message(text, kp)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, token)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_decrypt_text():
    kp = app_state.get("key_path")
    if not kp or not os.path.exists(kp):
        messagebox.showwarning("No key", "Please generate or load a key first.")
        return
    token = text_input.get("1.0", tk.END).strip()
    if not token:
        messagebox.showwarning("Empty", "Please paste the encrypted token to decrypt.")
        return
    try:
        plain = decrypt_message(token, kp)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, plain)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

def do_encrypt_csv():
    kp = app_state.get("key_path")
    if not kp or not os.path.exists(kp):
        messagebox.showwarning("No key", "Please generate or load a key first.")
        return
    inpath = filedialog.askopenfilename(title="Select CSV to encrypt",
                                        filetypes=[("CSV files", "*.csv"), ("All files","*.*")])
    if not inpath:
        return
    outpath = filedialog.asksaveasfilename(defaultextension=".csv",
                                           filetypes=[("CSV files","*.csv")],
                                           initialfile="encrypted_messages.csv",
                                           title="Save encrypted CSV as")
    if not outpath:
        return
    try:
        encrypt_csv(inpath, outpath, column="message", key=kp)
        messagebox.showinfo("Done", f"Encrypted CSV saved to:\n{outpath}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_decrypt_csv():
    kp = app_state.get("key_path")
    if not kp or not os.path.exists(kp):
        messagebox.showwarning("No key", "Please generate or load a key first.")
        return
    inpath = filedialog.askopenfilename(title="Select encrypted CSV to decrypt",
                                        filetypes=[("CSV files", "*.csv"), ("All files","*.*")])
    if not inpath:
        return
    outpath = filedialog.asksaveasfilename(defaultextension=".csv",
                                           filetypes=[("CSV files","*.csv")],
                                           initialfile="decrypted_messages.csv",
                                           title="Save decrypted CSV as")
    if not outpath:
        return
    try:
        decrypt_csv(inpath, outpath, column="message", key=kp)
        messagebox.showinfo("Done", f"Decrypted CSV saved to:\n{outpath}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- Build GUI ---
import tkinter.scrolledtext as st

root = tk.Tk()
root.title("Secret Message Encryptor / Decryptor")
root.geometry("780x640")
root.resizable(False, False)

app_state = {"key_path": None}

top_frame = tk.Frame(root)
top_frame.pack(pady=10)

gen_btn = tk.Button(top_frame, text="Generate Key", width=18, command=do_generate_key)
gen_btn.grid(row=0, column=0, padx=6)

load_btn = tk.Button(top_frame, text="Load Key", width=18, command=do_load_key)
load_btn.grid(row=0, column=1, padx=6)

enc_csv_btn = tk.Button(top_frame, text="Encrypt CSV", width=18, command=do_encrypt_csv)
enc_csv_btn.grid(row=0, column=2, padx=6)

dec_csv_btn = tk.Button(top_frame, text="Decrypt CSV", width=18, command=do_decrypt_csv)
dec_csv_btn.grid(row=0, column=3, padx=6)

key_label = tk.Label(root, text="Key: (none)", fg="blue")
key_label.pack(pady=6)

# Text input and output panes
label_in = tk.Label(root, text="Input (type message to encrypt OR paste encrypted token to decrypt):")
label_in.pack(anchor="w", padx=12)
text_input = st.ScrolledText(root, height=8, width=92)
text_input.pack(padx=12, pady=6)

button_frame = tk.Frame(root)
button_frame.pack(pady=6)
enc_text_btn = tk.Button(button_frame, text="Encrypt Text →", width=20, command=do_encrypt_text)
enc_text_btn.grid(row=0, column=0, padx=8)
dec_text_btn = tk.Button(button_frame, text="Decrypt Text →", width=20, command=do_decrypt_text)
dec_text_btn.grid(row=0, column=1, padx=8)

label_out = tk.Label(root, text="Output:")
label_out.pack(anchor="w", padx=12)
output_text = st.ScrolledText(root, height=8, width=92)
output_text.pack(padx=12, pady=6)

# Footer / hint
hint = tk.Label(root, text="Tip: Save your key file in a safe place. Without it you cannot decrypt.", fg="red")
hint.pack(pady=10)

root.mainloop()
