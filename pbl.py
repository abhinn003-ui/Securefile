import os
import sqlite3
import uuid
import time
import rsa
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

DB_FILE = "securefile.db"
VAULT_DIR = "vault"
os.makedirs(VAULT_DIR, exist_ok=True)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def aes_encrypt(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()
    ct = enc.update(data) + enc.finalize()
    return iv + enc.tag + ct

def aes_decrypt(blob: bytes, key: bytes) -> bytes:
    iv, tag, ct = blob[:12], blob[12:28], blob[28:]
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    return dec.update(ct) + dec.finalize()

def des3_encrypt(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key[:24]), modes.CBC(iv), backend=default_backend())
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded = padder.update(data) + padder.finalize()
    ct = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    return iv + ct

def des3_decrypt(blob: bytes, key: bytes) -> bytes:
    iv, ct = blob[:8], blob[8:]
    cipher = Cipher(algorithms.TripleDES(key[:24]), modes.CBC(iv), backend=default_backend())
    padded = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def setup_db():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password BLOB, salt BLOB)")
        conn.execute("CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, owner TEXT, name TEXT)")
        conn.execute("CREATE TABLE IF NOT EXISTS acls (file_id TEXT, username TEXT, access TEXT)")

def register_user(username: str, password: str):
    salt = os.urandom(16)
    pwd_hash = derive_key(password, salt)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO users VALUES (?, ?, ?)", (username, pwd_hash, salt))

def authenticate(username: str, password: str) -> bytes | None:
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("SELECT password, salt FROM users WHERE username=?", (username,)).fetchone()
    if not row: return None
    pwd_hash, salt = row
    try:
        dk = derive_key(password, salt)
        if dk == pwd_hash: return dk
    except: pass
    return None

def save_file(owner: str, name: str, encrypted: bytes, acl: dict[str,str]):
    fid = str(uuid.uuid4())
    with open(os.path.join(VAULT_DIR, fid),'wb') as f: f.write(encrypted)
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("INSERT INTO files VALUES (?, ?, ?)", (fid, owner, name))
        for u, a in acl.items(): conn.execute("INSERT INTO acls VALUES (?, ?, ?)", (fid,u,a))

def list_user_files(username: str) -> list[tuple[str,str,str]]:
    rows = []
    with sqlite3.connect(DB_FILE) as conn:
        for fid, name in conn.execute(
            "SELECT f.id, f.name FROM files f JOIN acls a ON f.id=a.file_id WHERE a.username=?",(username,)
        ).fetchall():
            access = conn.execute("SELECT access FROM acls WHERE file_id=? AND username=?",(fid,username)).fetchone()[0]
            rows.append((fid, name, access))
    return rows

def check_access(fid:str,username:str) -> str|None:
    with sqlite3.connect(DB_FILE) as conn:
        row = conn.execute("SELECT access FROM acls WHERE file_id=? AND username=?",(fid,username)).fetchone()
    return row[0] if row else None

def read_encrypted(fid:str)->bytes:
    with open(os.path.join(VAULT_DIR,fid),'rb') as f: return f.read()

def delete_file(fid:str):
    try: os.remove(os.path.join(VAULT_DIR,fid))
    except: pass
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("DELETE FROM files WHERE id=?",(fid,))
        conn.execute("DELETE FROM acls WHERE file_id=?",(fid,))

class SecureVaultApp:
    def __init__(self, root:Tk):
        self.root=root
        self.root.title("\U0001F537 Secure File Vault")
        self.accent = '#800080'
        self.bg = '#E6E6FA'
        self.btn_bg = '#FF7F50'
        self.btn_fg = 'white'
        self.label_fg = '#006400'
        self.entry_bg = 'white'
        self.entry_fg = 'black'
        self.frame_bg = '#ADD8E6'
        self.user=None; self.key=None
        setup_db()
        self.build_styles(); self.build_gui()

    def build_styles(self):
        style=ttk.Style(); style.theme_use('clam')
        style.configure('Treeview.Heading', background='#00008B', foreground='#FFFF00', font=('Segoe UI',10,'bold'))
        style.configure('Treeview', rowheight=26, font=('Segoe UI',9))
        style.configure('Treeview', background='#FFDDEE', fieldbackground='#FFDDEE')
        style.map('Treeview',
            background=[('selected', '#e6f7ff')],
            foreground=[('selected', '#00008B')]
        )
        style.configure('TButton', background=self.btn_bg, foreground=self.btn_fg, font=('Segoe UI',9,'bold'))

    def build_gui(self):
        self.root.configure(bg=self.bg)
        header=Frame(self.root,bg=self.accent,pady=12)
        header.pack(fill=X)
        Label(header,text='Secure File Vault',bg=self.accent,fg='white',font=('Segoe UI',16,'bold')).pack()

        frm=Frame(self.root,bg=self.frame_bg,pady=10)
        frm.pack(fill=X)
        Label(frm,text='Username:',bg=self.frame_bg,fg=self.label_fg,font=('Segoe UI',10)).grid(row=0,column=0,padx=10,pady=6)
        self.uent=Entry(frm,font=('Segoe UI',10), bg=self.entry_bg, fg=self.entry_fg); self.uent.grid(row=0,column=1,padx=10)
        Label(frm,text='Password:',bg=self.frame_bg,fg=self.label_fg,font=('Segoe UI',10)).grid(row=1,column=0,padx=10,pady=6)
        self.pent=Entry(frm,show='*',font=('Segoe UI',10), bg=self.entry_bg, fg=self.entry_fg); self.pent.grid(row=1,column=1,padx=10)

        btnf=Frame(frm,bg=self.frame_bg); btnf.grid(row=2,column=0,columnspan=3,pady=12)
        for txt,cmd in [('Login',self.login),('Register',self.register),('Logout',self.logout)]:
            b=Button(btnf,text=txt,command=cmd,width=12,bg=self.btn_bg,fg=self.btn_fg,font=('Segoe UI',9,'bold'), activebackground='#FF4500')
            b.pack(side=LEFT,padx=8)

        self.tree=ttk.Treeview(self.root,columns=('ID','Name','Perm'),show='headings',height=6)
        for col,txt,w in [('ID','File ID',200),('Name','Filename',300),('Perm','Permission',120)]:
            self.tree.heading(col,text=txt); self.tree.column(col,width=w)
        self.tree.pack(padx=14,pady=12,fill=X)

        self.tree.bind("<Motion>", self.on_hover)
        self.hover_row = None

        act=Frame(self.root,bg=self.frame_bg,pady=12)
        act.pack()
        for txt,cmd in [('Upload',self.upload),('Download',self.download),
                        ('Delete',self.delete),('Manage ACL',self.manage_acl),('Benchmark',self.benchmark)]:
            b=Button(act,text=txt,command=cmd,width=14,bg=self.btn_bg,fg=self.btn_fg,font=('Segoe UI',9,'bold'), activebackground='#FF4500')
            b.pack(side=LEFT,padx=10)

    def on_hover(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            row = self.tree.identify_row(event.y)
            if row != self.hover_row:
                if self.hover_row:
                    self.tree.tag_configure(self.hover_row, background='#FFDDEE')
                self.tree.tag_configure(row, background='#FFFACD')
                self.hover_row = row

    def register(self):
        try: register_user(self.uent.get(),self.pent.get()); messagebox.showinfo('Success','Registered')
        except sqlite3.IntegrityError: messagebox.showerror('Error','User exists')

    def login(self):
        k=authenticate(self.uent.get(),self.pent.get())
        if k: self.user,self.key=self.uent.get(),k; self.refresh(); messagebox.showinfo('Success','Logged in')
        else: messagebox.showerror('Error','Login failed')

    def logout(self):
        self.user,self.key=None,None; self.tree.delete(*self.tree.get_children());
        self.uent.delete(0,END); self.pent.delete(0,END)
        messagebox.showinfo('Success','Logged out')

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for fid,name,perm in list_user_files(self.user):
            self.tree.insert('','end',values=(fid,name,perm))

    def upload(self):
        if not self.key: return
        p=filedialog.askopenfilename();
        if not p: return
        data=open(p,'rb').read(); enc=aes_encrypt(data,self.key)
        acl={self.user:'read-write'}
        if messagebox.askyesno('Share','Set custom permission?'):
            u2=simpledialog.askstring('Share','User to share:');
            if u2:
                lvl=simpledialog.askstring('Permission','Access (read/read-write):')
                acl[u2]=lvl if lvl in ['read','read-write'] else 'read'
        save_file(self.user,os.path.basename(p),enc,acl)
        self.refresh(); messagebox.showinfo('Success','Uploaded')

    def download(self):
        sel=self.tree.focus();
        if not sel: return
        fid,_,_ = self.tree.item(sel)['values']
        if check_access(fid,self.user) not in ['read','read-write']:
            return messagebox.showerror('Error','No access')
        data=aes_decrypt(read_encrypted(fid),self.key)
        sp=filedialog.asksaveasfilename();
        if sp: open(sp,'wb').write(data); messagebox.showinfo('Success','Downloaded')

    def delete(self):
        sel=self.tree.focus();
        if not sel: return
        fid,_,_ = self.tree.item(sel)['values']
        if check_access(fid,self.user)!='read-write': return messagebox.showerror('Error','No access')
        delete_file(fid); self.refresh(); messagebox.showinfo('Success','Deleted')

    def manage_acl(self):
        sel=self.tree.focus();
        if not sel: return
        fid,_,_ = self.tree.item(sel)['values']
        if check_access(fid,self.user)!='read-write': return messagebox.showerror('Error','Owner only')
        top=Toplevel(self.root); top.title('Manage ACL'); top.configure(bg=self.bg)
        Label(top,text='Username:',bg=self.bg,font=('Segoe UI',10)).pack(pady=6)
        ue=Entry(top,font=('Segoe UI',10)); ue.pack(pady=6)
        Label(top,text='Access:',bg=self.bg,font=('Segoe UI',10)).pack(pady=6)
        cb=ttk.Combobox(top,values=['read','read-write','none'],font=('Segoe UI',10)); cb.pack(pady=6)
        Button(top,text='Apply',bg=self.accent,fg=self.btn_fg,command=lambda: self.apply_acl(fid,ue.get(),cb.get(),top), width=12).pack(pady=12)

    def apply_acl(self,fid,u,lv,win):
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM acls WHERE file_id=? AND username=?",(fid,u))
            if lv!='none': conn.execute("INSERT INTO acls VALUES(?,?,?)",(fid,u,lv))
        win.destroy(); self.refresh(); messagebox.showinfo('Success','Permissions updated')

    def benchmark(self):
        sel=self.tree.focus();
        if not sel: return
        fid,name,_ = self.tree.item(sel)['values']
        if check_access(fid,self.user) not in ['read','read-write']: return messagebox.showerror('Error','No access')
        data=aes_decrypt(read_encrypted(fid),self.key)
        size=len(data)/1024
        s=time.perf_counter(); b=aes_encrypt(data,self.key); t1=time.perf_counter()-s
        s=time.perf_counter(); aes_decrypt(b,self.key); t2=time.perf_counter()-s
        s=time.perf_counter(); d3=des3_encrypt(data,self.key); t3=time.perf_counter()-s
        s=time.perf_counter(); des3_decrypt(d3,self.key); t4=time.perf_counter()-s
        pub,priv=rsa.newkeys(2048)
        s=time.perf_counter(); w=rsa.encrypt(self.key,pub); t5=time.perf_counter()-s
        s=time.perf_counter(); rsa.decrypt(w,priv); t6=time.perf_counter()-s
        res=[('AES-GCM',t1,t2),('3DES',t3,t4),('Hybrid',t1+t5,t2+t6)]
        best=min(res,key=lambda x:x[1])[0]
        win=Toplevel(self.root); win.title('Benchmark'); win.configure(bg=self.bg)
        Label(win,text=f"{name} ({size:.2f} KB)",bg=self.bg,font=('Segoe UI',11)).pack(pady=8)
        tv=ttk.Treeview(win,columns=('enc','dec'),show='headings'); tv.heading('enc',text='Enc(s)'); tv.heading('dec',text='Dec(s)'); tv.pack(fill=BOTH,expand=True,padx=12,pady=12)
        for lbl,e,d in res: tv.insert('', 'end', values=(lbl,f"{e:.6f}",f"{d:.6f}"), tags=('best',) if lbl==best else ())
        tv.tag_configure('best',background='#d0f0c0')
if __name__=='__main__':
    root=Tk(); SecureVaultApp(root); root.mainloop()
