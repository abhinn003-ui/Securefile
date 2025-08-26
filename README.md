# 🔐 Secure File Vault

**Secure File Vault** is a desktop application built with **Python** and **Tkinter** that provides a safe and user-friendly way to store, manage, and share files. It uses **AES-256 encryption** to protect files, ensures secure user authentication, and supports fine-grained access control.

---

## 🚀 Key Features
- 🔑 **User Authentication** – Sign up & login with securely hashed credentials  
- 🔒 **AES-256 Encryption** – All files are encrypted before storage or sharing  
- 📂 **Upload & Download** – Easily add and retrieve encrypted files  
- 🧾 **Access Control Lists (ACLs)** – Grant Read or Read/Write access per file  
- 🗑️ **Delete Files** – Owners can remove their files securely  
- 📊 **Encryption Benchmarking** – Compare AES encryption/decryption performance  
- 🖥️ **Intuitive GUI** – Tkinter-based, clean, and simple to use  

---

## 🛠️ Technologies Used
- **Frontend:** Tkinter (Python GUI)  
- **Backend:** Python + SQLite  
- **Encryption:** AES-256 (PyCryptodome)  
- **Other Modules:** `os`, `hashlib`, `datetime`, `tkinter.filedialog`  

---

## ⚙️ Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/secure-file-vault.git
cd secure-file-vault

# Install required libraries
pip install pycryptodome

# Run the application
python pbl.py
