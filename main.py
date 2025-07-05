import configparser
import ctypes
import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from PIL import Image, ImageTk
import bcrypt
import json
from datetime import datetime

def resource_path(relative_path):

    try:
        base_path = sys._MEIPASS

    except Exception:
        base_path = os.path.abspath(".")
    full_path = os.path.join(base_path, relative_path)

    if not os.path.exists(full_path):
        raise FileNotFoundError(f"Resource not found: {full_path}")
    return full_path

class PlaceholderEntry(ttk.Entry):

    def __init__(self, master=None, placeholder="", textvariable=None, font_normal=("Arial", 14), show=None, **kwargs):
        self.placeholder = placeholder
        self.placeholder_font = ("Arial", 12, "italic")
        self.normal_font = font_normal
        self.default_show = show or ''
        self.real_show = show or ''
        self.is_placeholder = False
        self.textvariable = textvariable or tk.StringVar()
        super().__init__(master, textvariable=self.textvariable, font=self.normal_font, **kwargs)
        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._set_placeholder)
        self._set_placeholder()

    def _clear_placeholder(self, event=None):

        if self.is_placeholder:
            self.configure(font=self.normal_font, show=self.real_show)
            self.textvariable.set("")
            self.is_placeholder = False

    def _set_placeholder(self, event=None):

        if not self.textvariable.get():
            self.configure(font=self.placeholder_font, show='')
            self.textvariable.set(self.placeholder)
            self.is_placeholder = True

    def get(self):
        return "" if self.is_placeholder else self.textvariable.get()

    def set(self, value):
        self.is_placeholder = False
        self.configure(font=self.normal_font, show=self.real_show)
        self.textvariable.set(value)

class PlaceholderEntryForMasterPasswordChange(ttk.Entry):

    def __init__(self, master=None, placeholder="", textvariable=None, font_normal=("Arial", 14), show=None, **kwargs):
        self.master = master
        self.placeholder = placeholder
        self.placeholder_font = ("Arial", 12, "italic")
        self.normal_font = font_normal
        self.default_show = show or ''
        self.real_show = show or ''
        self.is_placeholder = False
        self.textvariable = textvariable or tk.StringVar()
        style = ttk.Style()
        style.configure("RedPlaceholder.TEntry", foreground="#8C8C93")
        style.configure("Normal.TEntry", foreground="black")
        super().__init__(master, textvariable=self.textvariable, font=self.normal_font, style="Normal.TEntry", **kwargs)
        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._set_placeholder)
        self.after(100, self._bind_click_outside)
        self._set_placeholder()

    def _bind_click_outside(self):
        root = self.master.winfo_toplevel()
        root.bind("<Button-1>", self._handle_click_outside, add="+")

    def _handle_click_outside(self, event):
        widget = event.widget

        if widget != self and not str(widget).startswith(str(self)):
            self.master.focus_set()

    def _clear_placeholder(self, event=None):

        if self.is_placeholder:
            self.configure(font=self.normal_font, show=self.real_show, style="Normal.TEntry")
            self.textvariable.set("")
            self.is_placeholder = False

    def _set_placeholder(self, event=None):

        if not self.textvariable.get():
            self.configure(font=self.placeholder_font, show='', style="RedPlaceholder.TEntry")
            self.textvariable.set(self.placeholder)
            self.is_placeholder = True

    def get(self):
        return "" if self.is_placeholder else self.textvariable.get()

    def set(self, value):
        self.is_placeholder = False
        self.configure(font=self.normal_font, show=self.real_show, style="Normal.TEntry")
        self.textvariable.set(value)

class FolderLockApp:

    def __init__(self, root):
        self.root = root
        self.root.title("SecureLock Pro")
        self.root.geometry("700x600")
        self.root.resizable(False, False)
        self.root.configure(bg="#2c3e50")

        if sys.platform == "win32":
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("com.example.FolderLockApp")

        try:
            self.root.iconbitmap(resource_path(r"icons/icon.ico"))

        except:
            pass
        self.data_dir = os.path.join(os.path.expanduser("~"), ".FolderLock&Hide")
        os.makedirs(self.data_dir, exist_ok=True)

        if sys.platform == "win32":

            try:
                ctypes.windll.kernel32.SetFileAttributesW(self.data_dir, 2)

            except:
                pass
        self.config_file = os.path.join(self.data_dir, "config.ini")
        self.history_file = os.path.join(self.data_dir, "history.json")
        self.password_file = os.path.join(self.data_dir, "password.txt")
        self.locked_folders = []
        self.load_window_geometry()
        self.load_history()
        self.setup_ui()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.check_first_run()

    def load_window_geometry(self):

        if os.path.exists(self.config_file):
            config = configparser.ConfigParser()
            config.read(self.config_file)

            if "Geometry" in config:
                geometry = config["Geometry"].get("size", "")
                state = config["Geometry"].get("state", "normal")

                if geometry:
                    self.root.geometry(geometry)
                    self.root.update_idletasks()
                    self.root.update()

                if state == "zoomed":
                    self.root.state("zoomed")
                elif state == "iconic":
                    self.root.iconify()

    def save_window_geometry(self):
        config = configparser.ConfigParser()
        config["Geometry"] = {
            "size": self.root.geometry(),
            "state": self.root.state()
        }

        with open(self.config_file, "w") as f:
            config.write(f)

    def on_close(self):
        self.save_window_geometry()
        root.destroy()

    def load_history(self):

        try:

            if os.path.exists(self.history_file):

                with open(self.history_file, "r") as f:
                    self.locked_folders = json.load(f)

        except:
            self.locked_folders = []

    def save_history(self):

        try:

            with open(self.history_file, "w") as f:
                json.dump(self.locked_folders, f, indent=4)

        except:
            pass

    def add_to_history(self, folder_path):
        for item in self.locked_folders:

            if item['original'] == folder_path:
                return
        self.locked_folders.append({
            'path': folder_path,
            'date': datetime.now().strftime("%d-%m-%Y | %I:%M:%S %p"),
            'original': folder_path
        })
        self.save_history()
        self.update_treeview()

    def update_treeview(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for i, folder in enumerate(self.locked_folders):
            tag = 'evenrow' if i % 2 == 0 else 'oddrow'
            self.tree.insert("", "end", values=(folder['date'], folder['original']), tags=(tag,))

    def setup_ui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.lock_tab = ttk.Frame(self.notebook)
        self.unlock_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.lock_tab, text="Hide Folder")
        self.notebook.add(self.unlock_tab, text="Unhide Folder")
        self.notebook.add(self.settings_tab, text="Settings")
        style = ttk.Style()
        style.configure("TNotebook", background="#2c3e50")
        style.configure("TNotebook.Tab", background="#3498db", foreground="white",font = ('arial',12,'bold'), padding=[10, 5])
        style.map("TNotebook.Tab", background=[("selected", "#0968a8")])
        show_password_img= Image.open(resource_path(r"icons\show_password.png")).resize((20, 17))
        self.show_password_icon= ImageTk.PhotoImage(show_password_img)
        hide_password_img= Image.open(resource_path(r"icons\hide_password.png")).resize((20, 17))
        self.hide_password_icon= ImageTk.PhotoImage(hide_password_img)
        self.setup_lock_tab()
        self.setup_unlock_tab()
        self.setup_settings_tab()

    def setup_lock_tab(self):
        frame = ttk.Frame(self.lock_tab)
        frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        header = ttk.Label(
            frame,
            text="🔒 HIDE FOLDER",
            font=("Segoe UI", 24, "bold"),
            foreground="#3498db"
        )
        header.pack(pady=10)
        ttk.Label(frame, text="Select Folder to Hide:", font=("Segoe UI", 15, "bold")).pack(anchor=tk.W, pady=(10, 5))
        self.folder_path = tk.StringVar()
        path_frame = ttk.Frame(frame)
        path_frame.pack(fill=tk.X)
        self.folder_path_entry = PlaceholderEntry(
            path_frame,
            textvariable=self.folder_path,
            placeholder="   Enter folder path...",
            font_normal=('Arial', 14)
        )
        self.folder_path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        ttk.Button(
            path_frame, text="Browse...",
            command=self.browse_folder,
            style="Accent.TButton"
        ).pack(side=tk.RIGHT)
        ttk.Label(frame, text="Enter Password:",font=("Segoe UI", 15, "bold")).pack(anchor=tk.W, pady=(15, 5))
        hide_folder_frame = tk.Frame(frame)
        hide_folder_frame.pack(fill=tk.X)
        self.lock_password = tk.StringVar()
        hide_folder_pwd_entry = PlaceholderEntry(
            hide_folder_frame,
            textvariable=self.lock_password,
            placeholder="   Password...",
            font_normal=('Arial', 14),
            show="•"
        )
        hide_folder_pwd_entry.pack(fill=tk.X,side='left',expand=True,padx=0)
        hide_folder_pwd_entry.bind("<Return>", self.hide_folder)
        show_pwd = tk.BooleanVar(value=False)

        def toggle_password():

            if show_pwd.get():
                hide_folder_pwd_entry.config(show="•")
                show_pwd.set(False)
                eye_btn.config(image=self.show_password_icon)
            else:
                hide_folder_pwd_entry.config(show="")
                show_pwd.set(True)
                eye_btn.config(image=self.hide_password_icon)
        eye_btn = ttk.Button(hide_folder_frame, image=self.show_password_icon, width=3, command=toggle_password)
        eye_btn.pack(side=tk.RIGHT, padx=(5, 0))
        self.lock_btn = ttk.Button(
            frame, text="HIDE FOLDER",
            command=self.hide_folder,
            style="Accent.TButton"
        )
        self.lock_btn.pack(pady=20)
        tips_frame = tk.LabelFrame(frame, text="Security Tips",font=("Segoe UI", 18, "bold"))
        tips_frame.pack(fill=tk.X, pady=20)
        ttk.Label(
            tips_frame,
            text="• Use a strong \"Master password\" with mix of characters\n"
                 "• Don't share your password\n"
                 "• Remember your password - it cannot be recovered",
            justify=tk.LEFT,
            font=('Arial', 12)
        ).pack(padx=10, pady=5)

    def setup_unlock_tab(self):
        frame = ttk.Frame(self.unlock_tab)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        header = ttk.Label(
            frame,
            text="🔓 UNHIDE FOLDER",
            font=("Segoe UI", 24, "bold"),
            foreground="#2ecc71"
        )
        header.pack(pady=5)
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True, pady=(5, 10))
        columns = ("Date Locked", "Folder Path")
        self.tree = ttk.Treeview(
            tree_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
            height=8
        )
        self.tree.heading("Date Locked", text="Date Locked")
        self.tree.heading("Folder Path", text="Hidden Folder Path")
        self.tree.column("Date Locked", width=200, minwidth=200, anchor=tk.CENTER, )
        self.tree.column("Folder Path", width=400, anchor=tk.CENTER, )
        vsb = ttk.Scrollbar(tree_frame,
                            orient="vertical",
                            command=self.tree.yview,
                            style="Vertical.TScrollbar"
                            )
        hsb = ttk.Scrollbar(tree_frame,
                            orient="horizontal",
                            command=self.tree.xview,
                            style="Horizontal.TScrollbar"
                            )
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        style = ttk.Style()
        style.configure("Treeview",
                    font=("Arial", 12),
                    rowheight=32,
                    background="#ea3737",  # Default background
                    fieldbackground="#ffffff")
        style.configure("Treeview.Heading",
                        background="#098ee7",
                        foreground="white",
                    font=("Arial", 12, "bold"),
                    padding=5)
        style.map("Treeview.Heading",
                background=[('active', "#0441DB")],
                foreground=[('active', 'white')],
                )
        self.tree.tag_configure('evenrow', background="#d6dedf")
        self.tree.tag_configure('oddrow', background='#ffffff')
        style.map('Treeview',
                background=[('selected', "#10EB17")],  # Green selection
                foreground=[('selected', 'black')])
        self.tree.bind("<<TreeviewSelect>>", self.on_folder_select)
        style.configure("Vertical.TScrollbar",
                        gripcount=0,
                        background="#11B0EA",
                        darkcolor="#14A9E8",
                        lightcolor="#0C94E3",
                        troughcolor="#E2E9E4",
                        bordercolor="#EBEAF2",
                        arrowcolor="#0a0aef",
                        relief="flat")
        style.map("Vertical.TScrollbar",
                background=[('active', "#0441DB")],
                )
        style.configure("Horizontal.TScrollbar",
                        gripcount=0,
                        background="#11B0EA",
                        darkcolor="#14A9E8",
                        lightcolor="#0C94E3",
                        troughcolor="#E2E9E4",
                        bordercolor="#EBEAF2",
                        arrowcolor="#0a0aef",
                        relief="flat")
        style.map("Horizontal.TScrollbar",
                background=[('active', "#0441DB")],
                )
        self.update_treeview()
        ttk.Label(frame, text="Selected Folder:", font=("Arial", 15,'bold')).pack(anchor=tk.W, pady=(5, 0))
        self.locked_path = tk.StringVar()
        lock_folder_entry =ttk.Entry(frame, textvariable=self.locked_path,
                                     state='readonly',
                                       font=("Arial", 11))
        lock_folder_entry.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(frame, text="Enter Password:", font=("Arial", 15,'bold')).pack(anchor=tk.W, pady=(5, 0))
        self.unlock_password = tk.StringVar()
        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(fill=tk.X)
        self.unhide_pwd_entry = PlaceholderEntry(
            pwd_frame,
            textvariable=self.unlock_password,
            placeholder="   Password...",
            font_normal=('Arial', 14),
            show="•"
        )
        self.unhide_pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.unhide_pwd_entry.bind('<Return>', self.unhide_folder)
        show_pwd = tk.BooleanVar(value=False)

        def toggle_password():

            if show_pwd.get():
                self.unhide_pwd_entry.config(show="•")
                show_pwd.set(False)
                eye_btn.config(image=self.show_password_icon)
            else:
                self.unhide_pwd_entry.config(show="")
                show_pwd.set(True)
                eye_btn.config(image=self.hide_password_icon)
        eye_btn = ttk.Button(pwd_frame, image=self.show_password_icon, width=3, command=toggle_password)
        eye_btn.pack(side=tk.RIGHT)
        unlock_btn = ttk.Button(
            frame, text="UNHIDE FOLDER",
            command=self.unhide_folder,
            style="Accent.TButton"
        )
        unlock_btn.pack(pady=(10,0))

    def on_folder_select(self, event):
        selected = self.tree.selection()

        if selected:
            values = self.tree.item(selected[0], "values")

            if values and len(values) >= 2:
                self.locked_path.set(values[1])

    def setup_settings_tab(self):
        frame = ttk.Frame(self.settings_tab)
        frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        header = ttk.Label(
            frame,
            text="⚙️ Application Settings",
            font=("Segoe UI", 24, "bold")
        )
        header.pack(pady=10)
        pw_frame = tk.LabelFrame(frame, text="Master Password",font=('arial',18,'bold'))
        pw_frame.pack(fill=tk.X, pady=10)
        ttk.Label(pw_frame, text="Change Master Password:",font=('arial',12,'bold')).pack(anchor=tk.W, pady=(10, 5))
        entry_eye_frame = ttk.Frame(pw_frame)
        entry_eye_frame.pack(fill='x', padx=10, pady=(0, 5))
        self.new_password = tk.StringVar()
        new_pwd_entry=PlaceholderEntryForMasterPasswordChange(entry_eye_frame, textvariable=self.new_password, placeholder="   Enter New Password...")
        new_pwd_entry.pack(fill='x',expand=True, side='left',padx=10, pady=(0, 5))
        new_pwd_entry.bind('<Return>', self.change_password)
        show_pwd = tk.BooleanVar(value=False)

        def toggle_password():

            if show_pwd.get():
                new_pwd_entry.config(show="•")
                show_pwd.set(False)
                eye_btn.config(image=self.show_password_icon)
            else:
                new_pwd_entry.config(show="")
                show_pwd.set(True)
                eye_btn.config(image=self.hide_password_icon)
        eye_btn = ttk.Button(entry_eye_frame, image = self.show_password_icon, width=3, command=toggle_password)
        eye_btn.pack(side='left', padx=(5, 0))
        ttk.Button(
            pw_frame, text="Change Password",
            command=self.change_password,
            style="Accent.TButton"
        ).pack(pady=5)
        info_frame = tk.LabelFrame(frame, text="Application Information",font=('arial',18,'bold'))
        info_frame.pack(fill=tk.X, pady=10)
        ttk.Label(
            info_frame,
            text="• SecureLock Pro v1.0\n\n"
                 "• Gmail:   souravbhattacharya8159@gmail.com.\n\n"
                 "• If you forgot your master password, then contact with me.\n\n"
                 "• MOB:   8159058135.\n\n",
            justify=tk.LEFT,
            font=('Arial', 12)
        ).pack(padx=10, pady=5)
        img_frame = ttk.Frame(frame)
        img_frame.pack(pady=10)

        try:
            img = Image.open("lock_icon.png")
            img = img.resize((64, 64), Image.LANCZOS)
            self.lock_img = ImageTk.PhotoImage(img)
            ttk.Label(img_frame, image=self.lock_img).pack()

        except:
            pass

    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Folder to Lock")

        if folder:
            self.folder_path_entry.set(folder)

    def check_first_run(self):

        if not os.path.exists(self.password_file):
            self.setup_master_password()

    def setup_master_password(self):
        password = self.enter_master_password("Create Master Password", "==Enter Master Password==\nThis will be used to secure all operations:")

        if password:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            with open(self.password_file, "wb") as f:
                f.write(hashed)
            messagebox.showinfo("Success", "Master password set up successfully!")

    def verify_password(self, password):

        if not os.path.exists(self.password_file):
            return False

        with open(self.password_file, "rb") as f:
            hashed = f.read()
        return bcrypt.checkpw(password.encode(), hashed)

    def change_password(self,event=None):
        new_pwd = self.new_password.get()

        if not new_pwd or new_pwd == "   Enter New Password...":
            messagebox.showwarning("Input Error", "Please enter a new password")
            return

        if len(new_pwd)<4:
            messagebox.showwarning("Input Error", "Password must be at least 4 characters long")
            return
        current = self.get_conformation_password("Verify Current Password", "Enter your current master password:")

        if current is None:
            return

        if not self.verify_password(current):
            messagebox.showerror("Error", "Incorrect current password")
            return
        hashed = bcrypt.hashpw(new_pwd.encode(), bcrypt.gensalt())

        with open(self.password_file, "wb") as f:
            f.write(hashed)
        self.new_password.set("")
        messagebox.showinfo("Success", "Password changed successfully")

    def get_conformation_password(self, title, prompt):
        dialog = tk.Toplevel(self.root)
        dialog.geometry("")
        dialog.overrideredirect(True)
        dialog.attributes("-topmost", True)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.focus_force()
        dialog.update_idletasks()
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        dialog_width = dialog.winfo_reqwidth()
        dialog_height = dialog.winfo_reqheight()
        x = main_x + (main_width - dialog_width) // 2
        y = main_y + (main_height - dialog_height) // 2
        dialog.geometry(f"+{x}+{y}")
        dialog.deiconify()

        def force_focus():

            try:
                dialog.deiconify()
                dialog.lift()
                dialog.attributes("-topmost", True)
                dialog.focus_force()

            except:
                pass
        dialog.after(10, force_focus)
        dialog.after(100, force_focus)
        bg = tk.Frame(dialog, bg="#ecf0f1", bd=2, relief=tk.RIDGE)
        bg.pack(fill=tk.BOTH, expand=True)
        title_bar = tk.Frame(bg, bg="#3498db", height=30)
        title_bar.pack(fill=tk.X)
        tk.Label(title_bar, text=title, bg="#3498db", fg="white",
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=10)
        close_btn = tk.Label(title_bar, text="✕", bg="#3498db",activebackground='red', fg="white",
                            font=("Arial", 12, "bold"), cursor="hand2")
        close_btn.pack(side=tk.RIGHT, padx=10)

        def start_move(event):
            dialog.x = event.x
            dialog.y = event.y

        def do_move(event):
            x = dialog.winfo_pointerx() - dialog.x
            y = dialog.winfo_pointery() - dialog.y
            dialog.geometry(f"+{x}+{y}")
        title_bar.bind("<Button-1>", start_move)
        title_bar.bind("<B1-Motion>", do_move)
        tk.Label(bg, text=prompt, font=("Segoe UI", 12), bg="#ecf0f1").pack(pady=(20, 5), padx=20)
        password = tk.StringVar()
        entry_frame = tk.Frame(bg, bg="#ecf0f1")
        entry_frame.pack(fill=tk.X, padx=20, pady=5)
        show_pwd = tk.BooleanVar(value=False)
        pwd_entry = ttk.Entry(entry_frame, textvariable=password, font=("Segoe UI", 12), foreground='grey')
        pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        placeholder_text = "  Password..."
        pwd_entry.insert(0, placeholder_text)
        pwd_entry.config(show="")

        def on_focus_in(event):

            if pwd_entry.get() == placeholder_text:
                pwd_entry.delete(0, tk.END)
                pwd_entry.config(foreground="black", show="•" if not show_pwd.get() else "")

        def on_focus_out(event):

            if not pwd_entry.get():
                pwd_entry.insert(0, placeholder_text)
                pwd_entry.config(foreground="grey", show="")
        pwd_entry.bind("<FocusIn>", on_focus_in)
        pwd_entry.bind("<FocusOut>", on_focus_out)

        def toggle_password():

            if pwd_entry.get() == placeholder_text:
                return

            if show_pwd.get():
                pwd_entry.config(show="•")
                show_pwd.set(False)
                eye_btn.config(image=self.show_password_icon)
            else:
                pwd_entry.config(show="")
                show_pwd.set(True)
                eye_btn.config(image=self.hide_password_icon)
        eye_btn = ttk.Button(entry_frame, image=self.show_password_icon, width=3, command=toggle_password)
        eye_btn.pack(side=tk.RIGHT, padx=(5, 0))
        pwd_entry.focus_set()
        result = [None]

        def on_ok():
            pwd = pwd_entry.get()

            if pwd == placeholder_text or not pwd:
                dialog.attributes("-topmost", False)
                self.root.update()
                messagebox.showwarning("Input Required", "Please enter the current master password.", parent=self.root)
                dialog.attributes("-topmost", True)
                return
            result[0] = pwd
            dialog.destroy()

        def on_cancel():
            dialog.destroy()
        pwd_entry.bind('<Return>', lambda event: on_ok())
        close_btn.bind("<Button-1>", lambda e: on_cancel())
        btn_frame = tk.Frame(bg, bg="#ecf0f1")
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel, style="Accent.TButton").pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="OK", command=on_ok, style="Accent.TButton").pack(side=tk.LEFT, padx=10)
        dialog.wait_window()
        return result[0]

    def enter_master_password(self, title, prompt):
        dialog = tk.Toplevel(self.root)
        dialog.geometry("")
        dialog.overrideredirect(True)
        dialog.attributes("-topmost", True)
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.focus_force()
        dialog.update_idletasks()
        main_x = self.root.winfo_x()
        main_y = self.root.winfo_y()
        main_width = self.root.winfo_width()
        main_height = self.root.winfo_height()
        dialog_width = dialog.winfo_reqwidth()
        dialog_height = dialog.winfo_reqheight()
        x = main_x + (main_width - dialog_width) // 2
        y = main_y + (main_height - dialog_height) // 2
        dialog.geometry(f"+{x}+{y}")
        dialog.deiconify()

        def force_focus():

            try:
                dialog.deiconify()
                dialog.lift()
                dialog.attributes("-topmost", True)
                dialog.focus_force()

            except:
                pass
        dialog.after(10, force_focus)
        dialog.after(100, force_focus)
        bg = tk.Frame(dialog, bg="#ecf0f1", bd=2, relief=tk.RIDGE)
        bg.pack(fill=tk.BOTH, expand=True)
        title_bar = tk.Frame(bg, bg="#3498db", height=30)
        title_bar.pack(fill=tk.X)
        tk.Label(title_bar, text=title, bg="#3498db", fg="white",
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=10)
        close_btn = tk.Label(title_bar, text="✕", bg="#3498db",activebackground='red', fg="white",
                            font=("Arial", 12, "bold"), cursor="hand2")
        close_btn.pack(side=tk.RIGHT, padx=10)

        def start_move(event):
            dialog.x = event.x
            dialog.y = event.y

        def do_move(event):
            x = dialog.winfo_pointerx() - dialog.x
            y = dialog.winfo_pointery() - dialog.y
            dialog.geometry(f"+{x}+{y}")
        title_bar.bind("<Button-1>", start_move)
        title_bar.bind("<B1-Motion>", do_move)
        tk.Label(bg, text=prompt, font=("Segoe UI", 12), bg="#ecf0f1").pack(pady=(20, 5), padx=20)
        password = tk.StringVar()
        entry_frame = tk.Frame(bg, bg="#ecf0f1")
        entry_frame.pack(fill=tk.X, padx=20, pady=5)
        show_pwd = tk.BooleanVar(value=False)
        pwd_entry = ttk.Entry(entry_frame, textvariable=password, font=("Segoe UI", 12), foreground='grey')
        pwd_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        placeholder_text = "  Password..."
        pwd_entry.insert(0, placeholder_text)
        pwd_entry.config(show="")

        def on_focus_in(event):

            if pwd_entry.get() == placeholder_text:
                pwd_entry.delete(0, tk.END)
                pwd_entry.config(foreground="black", show="•" if not show_pwd.get() else "")

        def on_focus_out(event):

            if not pwd_entry.get():
                pwd_entry.insert(0, placeholder_text)
                pwd_entry.config(foreground="grey", show="")
        pwd_entry.bind("<FocusIn>", on_focus_in)
        pwd_entry.bind("<FocusOut>", on_focus_out)

        def toggle_password():

            if pwd_entry.get() == placeholder_text:
                return

            if show_pwd.get():
                pwd_entry.config(show="•")
                show_pwd.set(False)
                eye_btn.config(image=self.show_password_icon)
            else:
                pwd_entry.config(show="")
                show_pwd.set(True)
                eye_btn.config(image=self.hide_password_icon)
        eye_btn = ttk.Button(entry_frame, image=self.show_password_icon, width=3, command=toggle_password)
        eye_btn.pack(side=tk.RIGHT, padx=(5, 0))
        pwd_entry.focus_set()
        result = [None]

        def on_ok():
            pwd = pwd_entry.get()

            if pwd == placeholder_text or not pwd:
                dialog.attributes("-topmost", False)
                self.root.update()
                messagebox.showwarning("Input Required", "Please enter a password.", parent=self.root)
                dialog.attributes("-topmost", True)
                return

            if len(pwd) < 4:
                dialog.attributes("-topmost", False)
                self.root.update()
                messagebox.showwarning("Input Required", "Please enter at least a 4-digit password.", parent=self.root)
                dialog.attributes("-topmost", True)
                return
            result[0] = pwd
            dialog.destroy()

        def on_cancel():
            dialog.destroy()
            self.root.destroy()
        pwd_entry.bind('<Return>', lambda event: on_ok())
        close_btn.bind("<Button-1>", lambda e: on_cancel())
        btn_frame = tk.Frame(bg, bg="#ecf0f1")
        btn_frame.pack(pady=20)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel, style="Accent.TButton").pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="OK", command=on_ok, style="Accent.TButton").pack(side=tk.LEFT, padx=10)
        dialog.wait_window()
        return result[0]

    def hide_folder(self, e=None):
        folder = self.folder_path.get()
        password = self.lock_password.get()

        if not folder or not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder")
            return

        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return

        if len(password) < 4:
            messagebox.showerror("Error", "Please enter at least 4 digit password")
            return

        if not self.verify_password(password):
            messagebox.showerror("Incorrect password!", "Please enter the correct master password.")
            return

        try:

            if sys.platform == "win32":
                folder = os.path.abspath(folder)
                ctypes.windll.kernel32.SetFileAttributesW(folder, 2)
            else:
                parent = os.path.dirname(folder)
                base = os.path.basename(folder)
                new_path = os.path.join(parent, f".{base}")
                os.rename(folder, new_path)
            self.add_to_history(folder)
            messagebox.showinfo("Success", "Folder hidden successfully!")
            self.lock_password.set("")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to hide folder: {str(e)}")

    def unhide_folder(self, event=None):
        folder_path = self.locked_path.get()

        if not folder_path or not os.path.isdir(folder_path):
            messagebox.showerror("Error", "Folder Not Found.\nI think, You replace the parent folder to somewhere")
            return

        if not folder_path:
            messagebox.showerror("Error", "Please select a folder from history")
            return
        password = self.unlock_password.get()

        if not password or password == "   Password...":
            messagebox.showerror("Error", "Please enter the password")
            return

        if not self.verify_password(password):
            messagebox.showerror("Error", "Incorrect password")
            return

        try:

            if sys.platform == "win32":
                folder_path = os.path.abspath(folder_path)
                ctypes.windll.kernel32.SetFileAttributesW(folder_path, 128)
            else:
                parent = os.path.dirname(folder_path)
                base = os.path.basename(folder_path)

                if base.startswith("."):
                    new_path = os.path.join(parent, base[1:])
                    os.rename(folder_path, new_path)
            self.remove_from_history(folder_path)
            messagebox.showinfo("Success", "Folder unhide successfully!")
            self.unlock_password.set("")
            self.locked_path.set("")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to unhide folder: {str(e)}")

    def remove_from_history(self, folder_path):
        self.locked_folders = [item for item in self.locked_folders if item['path'] != folder_path]
        self.save_history()
        self.update_treeview()

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    style.theme_use("clam")
    style.configure(".", background="#ecf0f1", foreground="#2c502d")
    style.configure("Accent.TButton", background="#3498db",font=("Arial", 12, "bold"), foreground="white")
    style.map("Accent.TButton",
              background=[("active", "#1376b9"), ("disabled", "#bdc3c7")])
    app = FolderLockApp(root)
    root.mainloop()
