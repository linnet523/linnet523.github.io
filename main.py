#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
import json
import os
import urllib.request
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ITERATIONS = 600000


def derive_key(pwd: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
    return kdf.derive(pwd.encode("utf-8"))


def encrypt(text: str, pwd: str) -> str:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(pwd, salt)
    ct = AESGCM(key).encrypt(iv, text.encode("utf-8"), None)
    return base64.b64encode(salt + iv + ct).decode("ascii")


def decrypt(b64: str, pwd: str) -> str:
    raw = base64.b64decode(b64.strip())
    salt, iv, ct = raw[:16], raw[16:28], raw[28:]
    key = derive_key(pwd, salt)
    return AESGCM(key).decrypt(iv, ct, None).decode("utf-8")


# ---------- 运行期配置 ----------
# 不再使用任何磁盘配置文件：token 与 gist_id 都只存在于内存中，
# 程序关闭即消失。gist 靠固定描述 GIST_DESC 自动定位，无需持久化 id。


# ---------- GitHub Gist API（纯标准库 urllib）----------
GIST_FILENAME = "note.lr"
GIST_DESC = "linnets"  # 本程序创建的 gist 固定描述，用于自动定位


def _gist_call(method: str, path: str, token: str, body=None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "LinnetS",
        "Content-Type": "application/json",
    }
    # 公共 gist 的读取无需鉴权；只有写操作和列出账号 gist 才带 token。
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        "https://api.github.com" + path, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else None


def gist_push(token: str, gist_id: str, cipher_b64: str) -> str:
    """有 gist_id 就更新，否则新建；返回 gist id。"""
    files = {GIST_FILENAME: {"content": cipher_b64}}
    if gist_id:
        _gist_call("PATCH", f"/gists/{gist_id}", token, {"files": files})
        return gist_id
    r = _gist_call("POST", "/gists", token,
                   {"description": GIST_DESC, "public": True, "files": files})
    return r["id"]


def gist_pull(token: str, gist_id: str) -> str:
    r = _gist_call("GET", f"/gists/{gist_id}", token)
    return r["files"][GIST_FILENAME]["content"]


def gist_delete(token: str, gist_id: str):
    """删除整个 gist（含全部历史版本）。用于改密码后清除旧密码加密的密文。"""
    _gist_call("DELETE", f"/gists/{gist_id}", token)


def gist_find(token: str) -> str:
    """用 token 在账号下查找本程序创建的 gist，返回其 id（找不到返回 None）。

    匹配条件：description 为 GIST_DESC 且包含 note.lr 文件。
    用于在新环境中只凭 token 自动定位之前上传的 gist。
    """
    page = 1
    while True:
        items = _gist_call("GET", f"/gists?per_page=100&page={page}", token)
        if not items:
            return None
        for g in items:
            if g.get("description") == GIST_DESC and GIST_FILENAME in g.get("files", {}):
                return g["id"]
        if len(items) < 100:
            return None
        page += 1


def gist_find_by_user(username: str) -> str:
    """凭 GitHub 用户名查找其公开 gist 中本程序创建的那个（无需 token）。

    走无鉴权接口 GET /users/{username}/gists，匹配 description 为 GIST_DESC
    且包含 note.lr 文件。找不到返回 None。
    """
    page = 1
    while True:
        items = _gist_call(
            "GET", f"/users/{username}/gists?per_page=100&page={page}", None)
        if not items:
            return None
        for g in items:
            if g.get("description") == GIST_DESC and GIST_FILENAME in g.get("files", {}):
                return g["id"]
        if len(items) < 100:
            return None
        page += 1


class PwdDialog:
    """密码输入弹窗，带显示/隐藏切换。"""

    def __init__(self, parent, prompt):
        self.result = None
        top = self.top = tk.Toplevel(parent)
        top.title("密码")
        top.resizable(False, False)
        top.transient(parent)
        frm = ttk.Frame(top, padding=20)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=prompt).pack(anchor="w", pady=(0, 10))
        self.var = tk.StringVar()
        self.entry = ttk.Entry(frm, textvariable=self.var, show="●", width=28)
        self.entry.pack(fill="x")

        row = ttk.Frame(frm)
        row.pack(fill="x", pady=(16, 0))
        self.show = False
        self.toggle = ttk.Button(row, text="显示", width=6, command=self._toggle)
        self.toggle.pack(side="left")
        ttk.Button(row, text="取消", width=6, command=self._cancel).pack(side="right")
        ttk.Button(row, text="确定", width=6,
                   command=self._ok).pack(side="right", padx=(0, 8))

        self.entry.focus_set()
        top.bind("<Return>", lambda e: self._ok())
        top.bind("<Escape>", lambda e: self._cancel())
        self._center(parent)
        top.grab_set()
        parent.wait_window(top)

    def _center(self, parent):
        self.top.update_idletasks()
        w, h = self.top.winfo_width(), self.top.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.top.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _toggle(self):
        self.show = not self.show
        self.entry.config(show="" if self.show else "●")
        self.toggle.config(text="隐藏" if self.show else "显示")

    def _ok(self):
        self.result = self.var.get()
        self.top.destroy()

    def _cancel(self):
        self.result = None
        self.top.destroy()


class SettingsDialog:
    """设置：仅 GitHub token（gist 由程序自动定位，无需手填 ID）。"""

    def __init__(self, parent, cfg, on_save=None):
        self.cfg = cfg
        self.on_save = on_save
        top = self.top = tk.Toplevel(parent)
        top.title("设置")
        top.resizable(False, False)
        top.transient(parent)
        frm = ttk.Frame(top, padding=20)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text="GitHub Token（需 Gist 读写权限，仅本次运行有效）").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))
        self.token_var = tk.StringVar(value=cfg.get("token", ""))
        self.token_entry = ttk.Entry(frm, textvariable=self.token_var, show="●", width=48)
        self.token_entry.grid(row=1, column=0, sticky="we")
        self.show = False
        ttk.Button(frm, text="显示", width=5, command=self._toggle).grid(
            row=1, column=1, padx=(6, 0))

        row = ttk.Frame(frm)
        row.grid(row=2, column=0, columnspan=2, sticky="we", pady=(18, 0))
        ttk.Button(row, text="清除 Token", command=self._clear).pack(side="left")
        ttk.Button(row, text="取消", command=top.destroy).pack(side="right")
        ttk.Button(row, text="保存", command=self._save).pack(side="right", padx=(0, 8))

        ttk.Label(frm, text="⚠ Token 不会写入磁盘，关闭程序后需重新输入。\n"
                            "有 token 时上传/拉取一键完成；无 token 时拉取改用 GitHub 用户名查找。",
                  foreground="#888", wraplength=380, justify="left").grid(
            row=3, column=0, columnspan=2, sticky="w", pady=(12, 0))

        self.token_entry.focus_set()
        top.bind("<Escape>", lambda e: top.destroy())
        self._center(parent)
        top.grab_set()
        parent.wait_window(top)

    def _center(self, parent):
        self.top.update_idletasks()
        w, h = self.top.winfo_width(), self.top.winfo_height()
        x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.top.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _toggle(self):
        self.show = not self.show
        self.token_entry.config(show="" if self.show else "●")

    def _clear(self):
        self.token_var.set("")

    def _save(self):
        token = self.token_var.get().strip()
        if token:
            self.cfg["token"] = token
        else:
            self.cfg.pop("token", None)
        if self.on_save:
            self.on_save()
        self.top.destroy()


class App:
    def __init__(self, root):
        self.root = root
        self.path = None       # 当前密文文件路径
        self.password = None   # 当前会话密码
        self.pwd_changed = False  # 改过密码：下次上传需删旧 gist 重建以清除历史
        self.cfg = {}  # 运行期内存配置（token / gist_id），不落盘
        root.title("LinnetS")
        root.geometry("1040x600")

        bar = ttk.Frame(root, padding=(10, 8))
        bar.pack(fill="x")
        for txt, cmd in [("打开密文", self.open_file), ("新建", self.new_file),
                         ("保存", self.save), ("重命名", self.rename_file),
                         ("改密码", self.change_pwd), ("上传", self.upload),
                         ("拉取", self.download), ("设置", self.open_settings)]:
            ttk.Button(bar, text=txt, command=cmd).pack(side="left", padx=(0, 6))
        self.status = ttk.Label(bar, text="", foreground="#888")
        self.status.pack(side="right")

        wrap = ttk.Frame(root, padding=(10, 0, 10, 10))
        wrap.pack(fill="both", expand=True)
        self.text = tk.Text(wrap, wrap="word", undo=True, padx=8, pady=8,
                            state="disabled")
        self.text.pack(fill="both", expand=True)
        self._refresh_sync_status()

    def set_status(self, msg, color="#888"):
        self.status.config(text=msg, foreground=color)

    def ask_pwd(self, prompt="请输入密码"):
        return PwdDialog(self.root, prompt).result

    def open_file(self):
        path = filedialog.askopenfilename(
            title="选择密文文件",
            filetypes=[("LinnetS 密文", "*.lr"), ("文本文件", "*.txt"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                b64 = f.read()
        except Exception as e:
            messagebox.showerror("错误", f"读取文件失败：{e}")
            return
        pwd = self.ask_pwd()
        if pwd is None:
            return
        try:
            plain = decrypt(b64, pwd)
        except Exception:
            messagebox.showerror("解密失败", "密码错误或密文损坏")
            return
        self.path = path
        self.password = pwd
        self._load_text(plain)
        self.set_status(f"已解密：{os.path.basename(path)}", "#27ae60")

    def new_file(self):
        pwd = self.ask_pwd("为新文件设置密码")
        if not pwd:
            return
        self.path = None
        self.password = pwd
        self._load_text("")
        self.set_status("新文件（尚未保存）", "#888")

    def _load_text(self, content):
        self.text.config(state="normal")
        self.text.delete("1.0", "end")
        self.text.insert("1.0", content)
        self.text.edit_reset()

    def _ensure_open(self):
        if self.password is None:
            messagebox.showinfo("提示", "请先打开密文文件或新建")
            return False
        return True

    def save(self):
        if not self._ensure_open():
            return
        if not self.path:
            return self._save_to_new_path()
        self._write(self.path)

    def _save_to_new_path(self):
        """新建文件首次保存时选择路径（无独立「另存为」按钮）。"""
        path = filedialog.asksaveasfilename(
            title="保存密文", defaultextension=".lr",
            filetypes=[("LinnetS 密文", "*.lr"), ("文本文件", "*.txt")])
        if not path:
            return
        self.path = path
        self._write(path)

    def _write(self, path):
        plain = self.text.get("1.0", "end-1c")
        try:
            b64 = encrypt(plain, self.password)
            with open(path, "w", encoding="utf-8") as f:
                f.write(b64)
        except Exception as e:
            messagebox.showerror("错误", f"保存失败：{e}")
            return
        self.set_status(f"已加密保存：{os.path.basename(path)}", "#27ae60")

    def change_pwd(self):
        if not self._ensure_open():
            return
        new = self.ask_pwd("输入新密码（保存时生效）")
        if not new:
            return
        self.password = new
        self.pwd_changed = True
        self.set_status("密码已更改，请保存以生效", "#27ae60")

    def rename_file(self):
        """重命名磁盘上当前打开的密文文件。"""
        if not self.path:
            messagebox.showinfo("提示", "当前没有已保存的文件，请先「保存」")
            return
        old_dir = os.path.dirname(self.path)
        old_name = os.path.basename(self.path)
        new_name = simpledialog.askstring("重命名", "新文件名：",
                                          initialvalue=old_name, parent=self.root)
        if not new_name or new_name == old_name:
            return
        new_path = os.path.join(old_dir, new_name)
        if os.path.exists(new_path):
            messagebox.showerror("错误", "目标文件名已存在")
            return
        try:
            os.rename(self.path, new_path)
        except OSError as e:
            messagebox.showerror("错误", f"重命名失败：{e}")
            return
        self.path = new_path
        self.set_status(f"已重命名为：{new_name}", "#27ae60")

    def _refresh_sync_status(self):
        """根据是否配置 token 显示同步状态。"""
        if not self.cfg.get("token"):
            self.set_status("⚠ 无网络同步（未设置 token）", "#c0392b")
        else:
            self.set_status("✓ 已启用网络同步", "#27ae60")

    def open_settings(self):
        SettingsDialog(self.root, self.cfg, on_save=self._refresh_sync_status)

    def _has_token(self):
        if not self.cfg.get("token"):
            messagebox.showinfo("未设置同步", "请先在「设置」里填写 GitHub token")
            return False
        return True

    def upload(self):
        """把当前内容加密后上传到 Gist（首次新建，之后更新同一 gist）。"""
        if not self._ensure_open():
            return
        if not self._has_token():
            return
        token = self.cfg["token"]
        self.set_status("上传中...", "#888")
        self.root.update_idletasks()
        try:
            gid = self.cfg.get("gist_id")
            if not gid:
                # 无缓存 id：先查账号下是否已有本程序的 gist，避免重复创建
                gid = gist_find(token)
            if self.pwd_changed and gid:
                # 改过密码：删掉旧 gist（连同用旧密码加密的全部历史版本）再重建
                gist_delete(token, gid)
                gid = None
            cipher = encrypt(self.text.get("1.0", "end-1c"), self.password)
            gid = gist_push(token, gid, cipher)
        except Exception as e:
            messagebox.showerror("上传失败", str(e))
            self.set_status("上传失败", "#c0392b")
            return
        self.pwd_changed = False
        self.cfg["gist_id"] = gid  # 仅内存缓存本次会话，关闭即丢弃
        self.set_status(f"已上传到云端 (gist {gid[:8]})", "#27ae60")

    def download(self):
        """从 Gist 拉取密文，输入密码解密后载入。

        有 token：用本地缓存的 gist_id 或自动在账号下查找，一键拉取。
        无 token：提示输入 GitHub 用户名，在其公开 gist 中查找（无需鉴权）。
        """
        token = self.cfg.get("token")
        gid = self.cfg.get("gist_id")
        if token:
            if not gid:
                self.set_status("查找云端 gist...", "#888")
                self.root.update_idletasks()
                try:
                    gid = gist_find(token)
                except Exception as e:
                    messagebox.showerror("查找失败", str(e))
                    self.set_status("查找失败", "#c0392b")
                    return
                if not gid:
                    messagebox.showinfo("未找到", "账号下还没有本程序创建的云端笔记，请先「上传」")
                    self.set_status("云端无笔记", "#888")
                    return
        else:
            username = simpledialog.askstring(
                "拉取", "输入 GitHub 用户名以查找云端笔记：", parent=self.root)
            if not username or not username.strip():
                self.set_status("已取消", "#888")
                return
            self.set_status("按用户名查找...", "#888")
            self.root.update_idletasks()
            try:
                gid = gist_find_by_user(username.strip())
            except Exception as e:
                messagebox.showerror("查找失败", str(e))
                self.set_status("查找失败", "#c0392b")
                return
            if not gid:
                messagebox.showinfo(
                    "未找到", f"在用户 {username.strip()} 的公开 gist 中"
                    f"未找到本程序的笔记（描述 {GIST_DESC} / 文件 {GIST_FILENAME}）")
                self.set_status("未找到", "#888")
                return
        self.set_status("拉取中...", "#888")
        self.root.update_idletasks()
        try:
            cipher = gist_pull(token, gid)
        except Exception as e:
            messagebox.showerror("拉取失败", str(e))
            self.set_status("拉取失败", "#c0392b")
            return
        pwd = self.ask_pwd("输入密码以解密云端内容")
        if pwd is None:
            return
        try:
            plain = decrypt(cipher, pwd)
        except Exception:
            messagebox.showerror("解密失败", "密码错误或密文损坏")
            return
        self.path = None  # 云端内容默认未关联本地文件
        self.password = pwd
        self.cfg["gist_id"] = gid  # 仅内存缓存本次会话，关闭即丢弃
        self._load_text(plain)
        self.set_status("已从云端拉取并解密", "#27ae60")


if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
