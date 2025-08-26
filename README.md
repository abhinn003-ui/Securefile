# 🔐 Secure File Vault

The **Secure File Vault** is a desktop application built with **Python** and **Tkinter** that provides a secure, easy-to-use environment for storing, encrypting, and managing sensitive files.  
It leverages **AES-256 encryption** to protect files, **SQLite** for user and file management, and offers **fine-grained access control** for secure file sharing.  

This project demonstrates how strong encryption, access policies, and a user-friendly GUI can be combined to ensure data security while keeping the app intuitive and accessible.

---

## 📌 Problem Statement
As the volume of digital data grows, individuals and organizations need secure ways to **store, share, and manage sensitive files**. Traditional file systems lack built-in encryption and fine-grained access control. The **Secure File Vault** addresses these challenges by providing:  
- Strong file encryption using **AES-256**  
- **User authentication** with hashed credentials  
- **Access Control Lists (ACLs)** to control file sharing permissions  
- A simple **Tkinter-based GUI** that makes it easy for anyone to use  

---

## 🚀 Features
- 🔑 **User Authentication** – Secure login/signup with hashed passwords  
- 🔒 **AES-256 Encryption** – All files encrypted before upload & decrypted on download  
- 📂 **Upload & Download** – Manage encrypted files seamlessly  
- 🧾 **Access Control (ACLs)** – Assign Read / Read-Write permissions per user  
- 🗑️ **File Deletion** – Owners can securely delete their files  
- 📊 **Encryption Benchmarking** – Compare encryption/decryption performance  
- 🖥️ **Intuitive GUI** – Tkinter interface with simple navigation and dialogs  
- 📜 **File Access History** – Track file usage and access logs  

---

## 🛠️ Technologies Used
- **Frontend:** Tkinter (Python GUI library)  
- **Backend:** Python + SQLite (for user & file database)  
- **Encryption:** AES (from PyCryptodome’s `Crypto.Cipher`)  
- **Other Modules:** `os`, `tkinter.filedialog`, `hashlib`, `datetime`  

---

## 🧠 Workflow
1. **User Authentication**  
   - New users register with hashed credentials  
   - Existing users log in securely  

2. **File Management**  
   - Uploads are **encrypted with AES-256** before storage  
   - Downloads are decrypted and restored to original form  

3. **Access Control**  
   - Owners can assign permissions: **Read** or **Read-Write**  
   - Ensures only authorized users can modify or delete files  

4. **Encryption Benchmarking**  
   - Benchmarks run on AES to measure performance  
   - (Optionally compare with 3DES or RSA in extensions)  

---

## ⚙️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/secure-file-vault.git
cd secure-file-vault
