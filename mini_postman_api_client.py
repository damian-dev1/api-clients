import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import requests
import json
import time
import threading
import queue
import base64
from urllib.parse import urlencode
import re
import os
import uuid
from datetime import datetime
from tkinter import font as tkfont
try:
    import ttkbootstrap as tb
except Exception:
    tb = None
MAX_HIGHLIGHT_CHARS = 200_000
HIGHLIGHT_REQUEST_BODY = False
HISTORY_FILE = os.path.join(os.path.expanduser("~"), ".mini_postman_history.json")
SETTINGS_FILE = os.path.join(os.path.expanduser("~"), ".mini_postman_settings.json")
MAX_HISTORY_ITEMS = 500
class ThinScrolledText(ttk.Frame):
    """A ttk.Frame containing a tk.Text and a thin, styled ttk.Scrollbar.
       Access the underlying Text as .text
    """
    def __init__(self, master, *, wrap=tk.WORD, font=("Consolas", 10), scrollbar_style="Thin.Vertical.TScrollbar"):
        super().__init__(master)
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        self.text = tk.Text(
            self,
            wrap=wrap,
            font=font,
            undo=False,
            highlightthickness=0,
            borderwidth=0,
        )
        self.vsb = ttk.Scrollbar(self, orient="vertical", command=self.text.yview, style=scrollbar_style)
        self.text.configure(yscrollcommand=self.vsb.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        self.vsb.grid(row=0, column=1, sticky="ns")
class _KVEditor(ttk.Frame):
    def __init__(self, master, title="Items"):
        super().__init__(master)
        toolbar = ttk.Frame(self)
        ttk.Label(toolbar, text=title).pack(side="left")
        ttk.Button(toolbar, text="+", width=3, command=self.add_row, style="Mini.TButton").pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="−", width=3, command=self.remove_selected, style="Mini.TButton").pack(side="left", padx=(3, 6))
        ttk.Button(toolbar, text="Clear", command=self.clear, style="Warn.Mini.TButton").pack(side="right")
        toolbar.pack(fill="x", pady=(0, 6))
        self.tree = ttk.Treeview(self, columns=("key", "value"), show="headings", height=6)
        self.tree.heading("key", text="Key")
        self.tree.heading("value", text="Value")
        self.tree.column("key", width=160, anchor="w")
        self.tree.column("value", width=280, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._edit_cell)
    def add_row(self, key="", value=""):
        return self.tree.insert("", "end", values=(key, value))
    def remove_selected(self):
        for iid in self.tree.selection():
            self.tree.delete(iid)
    def clear(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
    def items(self):
        out = []
        for iid in self.tree.get_children():
            key, value = self.tree.item(iid, "values")
            if str(key).strip() != "":
                out.append((str(key), str(value)))
        return out
    def to_dict(self):
        return {k: v for k, v in self.items()}
    def set_dict(self, d):
        self.clear()
        if not d:
            return
        for k, v in d.items():
            self.add_row(k, v)
    def _edit_cell(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        rowid = self.tree.identify_row(event.y)
        colid = self.tree.identify_column(event.x)
        if not rowid or not colid:
            return
        bbox = self.tree.bbox(rowid, colid)
        if not bbox:
            return
        x, y, w, h = bbox
        col_index = int(colid[1:]) - 1
        old_vals = list(self.tree.item(rowid, "values"))
        initial = old_vals[col_index] if col_index < len(old_vals) else ""
        entry = ttk.Entry(self.tree)
        entry.insert(0, initial)
        entry.select_range(0, "end")
        entry.focus_set()
        entry.place(x=x, y=y, width=w, height=h)
        def on_commit(*_):
            new = entry.get()
            entry.destroy()
            old_vals[col_index] = new
            self.tree.item(rowid, values=tuple(old_vals))
        entry.bind("<Return>", on_commit)
        entry.bind("<Escape>", lambda *_: entry.destroy())
        entry.bind("<FocusOut>", on_commit)
class MiniPostman(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mini Postman")
        self.geometry("465x770")
        self.minsize(300, 550)
        self.request_queue = queue.Queue()
        self.history = []
        self.history_index = {}
        self._init_styles()
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self._build_ui()
        self._load_history()
        self._load_settings()
        self.after(100, self._process_queue)
    def _init_styles(self):
        style = ttk.Style()
        if tb is not None:
            try:
                tb.Style("cyborg")
            except Exception:
                pass
        style.configure("Mini.TButton", padding=(6, 2), font=("Segoe UI", 9))
        style.configure("Go.Mini.TButton", padding=(8, 2), font=("Segoe UI", 9, "bold"), foreground="#ffffff", background="#0ea5e9")
        style.map("Go.Mini.TButton", background=[("active", "#38bdf8")])
        style.configure("Warn.Mini.TButton", padding=(6, 2), font=("Segoe UI", 9), foreground="#111", background="#fbbf24")
        style.map("Warn.Mini.TButton", background=[("active", "#f59e0b")])
        style.configure("Danger.Mini.TButton", padding=(6, 2), font=("Segoe UI", 9), foreground="#fff", background="#ef4444")
        style.map("Danger.Mini.TButton", background=[("active", "#dc2626")])
        style.configure("Info.Mini.TButton", padding=(6, 2), font=("Segoe UI", 9), foreground="#fff", background="#3b82f6")
        style.map("Info.Mini.TButton", background=[("active", "#2563eb")])
        style.configure("Success.Mini.TButton", padding=(6, 2), font=("Segoe UI", 9), foreground="#fff", background="#10b981")
        style.map("Success.Mini.TButton", background=[("active", "#059669")])
        style.configure("Status.TLabel", font=('Segoe UI', 9), padding=2, foreground="#e6e6e6", background="#1e1e1e")
        style.configure("Success.Status.TLabel", foreground="#eaffea", background="#14532d")
        style.configure("Redirect.Status.TLabel", foreground="#eaf2ff", background="#0c4a6e")
        style.configure("ClientError.Status.TLabel", foreground="#fff5e6", background="#7c2d12")
        style.configure("ServerError.Status.TLabel", foreground="#ffecec", background="#5c1a1a")
        style.configure("Treeview",
                        background="#121212",
                        fieldbackground="#121212",
                        foreground="#e6e6e6",
                        bordercolor="#2a2a2a")
        style.configure("Treeview.Heading", background="#1b1b1b", foreground="#e6e6e6")
        style.map("Treeview", background=[("selected", "#0ea5e9")], foreground=[("selected", "#ffffff")])
        self._create_thin_scrollbar_style(style, "Thin.Vertical.TScrollbar")
        self._create_thin_scrollbar_style(style, "Hist.Vertical.TScrollbar", thumb="#3f3f46", trough="#18181b")
    def _create_thin_scrollbar_style(self, style: ttk.Style, stylename: str, *, thumb="#52525b", trough="#0b0f14"):
        style.layout(stylename, [
            ("Vertical.Scrollbar.trough", {
                "children": [("Vertical.Scrollbar.thumb", {"unit": 1, "sticky": "nswe"})],
                "sticky": "ns"
            })
        ])
        style.configure(stylename, arrowsize=8, background=thumb, troughcolor=trough, bordercolor=trough, lightcolor=thumb, darkcolor=thumb)
        style.map(stylename,
                  background=[("active", "#737373"), ("!active", thumb)],
                  troughcolor=[("active", trough), ("!active", trough)])
    def _highlight_json_into(self, text_widget: tk.Text, json_str: str):
        if len(json_str) > MAX_HIGHLIGHT_CHARS:
            text_widget.configure(state="normal")
            text_widget.delete("1.0", "end")
            text_widget.insert("1.0", json_str)
            text_widget.configure(state="disabled")
            return
        text_widget.configure(state="normal")
        for tag in text_widget.tag_names():
            if tag != "sel":
                text_widget.tag_delete(tag)
        text_widget.tag_configure("key", foreground="#7dd3fc")
        text_widget.tag_configure("string", foreground="#f472b6")
        text_widget.tag_configure("number", foreground="#facc15")
        text_widget.tag_configure("boolean", foreground="#34d399")
        text_widget.tag_configure("null", foreground="#a3a3a3")
        text_widget.tag_configure("punct", foreground="#b4b4b4")
        text_widget.delete("1.0", "end")
        text_widget.insert("1.0", json_str)
        key_pattern = r'(".*?")\s*:'
        string_pattern = r':\s*(".*?")'
        number_pattern = r'(:\s*)(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)'
        boolean_pattern = r'(:\s*)(true|false)'
        null_pattern = r'(:\s*)null'
        punct_pattern = r'[{}\[\]:,]'
        for m in re.finditer(key_pattern, json_str):
            s, e = m.span(1); text_widget.tag_add("key", f"1.0+{s}c", f"1.0+{e}c")
        for m in re.finditer(string_pattern, json_str):
            s, e = m.span(1); text_widget.tag_add("string", f"1.0+{s}c", f"1.0+{e}c")
        for m in re.finditer(number_pattern, json_str):
            s, e = m.span(2); text_widget.tag_add("number", f"1.0+{s}c", f"1.0+{e}c")
        for m in re.finditer(boolean_pattern, json_str, flags=re.IGNORECASE):
            s, e = m.span(2); text_widget.tag_add("boolean", f"1.0+{s}c", f"1.0+{e}c")
        for m in re.finditer(null_pattern, json_str, flags=re.IGNORECASE):
            s, e = m.span(0); text_widget.tag_add("null", f"1.0+{s}c", f"1.0+{e}c")
        start = "1.0"
        while True:
            idx = text_widget.search(punct_pattern, start, "end", regexp=True)
            if not idx:
                break
            end = f"{idx}+1c"
            text_widget.tag_add("punct", idx, end)
            start = end
        text_widget.configure(state="disabled")
    def _maybe_json_and_highlight(self, widget: tk.Text, content: str):
        try:
            obj = json.loads(content)
            pretty = json.dumps(obj, indent=2, ensure_ascii=False)
            self._highlight_json_into(widget, pretty)
        except Exception:
            widget.configure(state="normal")
            widget.delete("1.0", "end")
            widget.insert("1.0", content)
            widget.configure(state="disabled")
    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.grid(row=0, column=0, sticky="ew")
        top.columnconfigure(1, weight=1)
        self.method_var = tk.StringVar(value="GET")
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
        ttk.Combobox(top, textvariable=self.method_var, values=methods, state="readonly", width=8).grid(row=0, column=0, padx=(0, 6))
        self.url_entry = ttk.Entry(top, font=('Segoe UI', 10))
        self.url_entry.grid(row=0, column=1, sticky="ew")
        self.url_entry.bind("<Return>", lambda e: self.send_request())
        ttk.Button(top, text="Send", command=self.send_request, style="Go.Mini.TButton").grid(row=0, column=2, padx=(6, 0))
        panes = ttk.Panedwindow(self, orient=tk.VERTICAL)
        panes.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.grid_rowconfigure(1, weight=1)
        self.req_nb = ttk.Notebook(panes)
        body_tab = ttk.Frame(self.req_nb)
        ttk.Label(body_tab, text="Body (JSON):").pack(anchor="w")
        self.body_text = scrolledtext.ScrolledText(body_tab, wrap=tk.WORD, height=10, font=("Consolas", 10))
        self.body_text.pack(fill="both", expand=True, pady=(2, 0))
        self.body_text.bind("<KeyRelease>", lambda e: self._on_body_change())
        self.req_nb.add(body_tab, text="Body")
        self.params_kv = _KVEditor(self.req_nb, "Params")
        self.req_nb.add(self.params_kv, text="Params")
        self.headers_kv = _KVEditor(self.req_nb, "Headers")
        self.req_nb.add(self.headers_kv, text="Headers")
        auth_tab = ttk.Frame(self.req_nb, padding=10)
        auth_tab.columnconfigure(0, weight=1)
        auth_tab.columnconfigure(1, weight=1)
        auth_frame = ttk.LabelFrame(auth_tab, text=" Auth Type ", padding=8)
        auth_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))
        auth_frame.columnconfigure(0, weight=1)
        self.auth_var = tk.StringVar(value="None")
        auth_types = [("None", "None"), ("Bearer Token", "Bearer"), ("Basic Auth", "Basic")]
        for i, (label, value) in enumerate(auth_types):
            ttk.Radiobutton(auth_frame, text=label, variable=self.auth_var, value=value,
                            command=self._update_auth_fields).grid(row=0, column=i, sticky="w", padx=(0, 15))
        fields_frame = ttk.LabelFrame(auth_tab, text=" Credentials ", padding=8)
        fields_frame.grid(row=1, column=0, sticky="ew", padx=(0, 6))
        ttk.Label(fields_frame, text="Token:").grid(row=0, column=0, sticky="w", pady=(0, 4))
        self.token_entry = ttk.Entry(fields_frame, width=25)
        self.token_entry.grid(row=0, column=1, sticky="ew", pady=(0, 4), padx=(6, 0))
        ttk.Label(fields_frame, text="Username:").grid(row=1, column=0, sticky="w", pady=(6, 4))
        self.username_entry = ttk.Entry(fields_frame, width=25)
        self.username_entry.grid(row=1, column=1, sticky="ew", pady=(6, 4), padx=(6, 0))
        ttk.Label(fields_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=(0, 4))
        self.password_entry = ttk.Entry(fields_frame, show="*", width=25)
        self.password_entry.grid(row=2, column=1, sticky="ew", pady=(0, 4), padx=(6, 0))
        apply_frame = ttk.Frame(auth_tab)
        apply_frame.grid(row=1, column=1, sticky="ns", padx=(6, 0))
        ttk.Button(apply_frame, text="Apply", command=self._apply_auth, style="Info.Mini.TButton").pack(side="top", pady=8)
        self._update_auth_fields()
        self.req_nb.add(auth_tab, text="Auth")
        settings_tab = ttk.Frame(self.req_nb, padding=10)
        settings_tab.columnconfigure(0, weight=1)
        settings_tab.columnconfigure(1, weight=1)
        cell1 = ttk.LabelFrame(settings_tab, text=" SSL & Redirects ", padding=8)
        cell1.grid(row=0, column=0, sticky="ew", padx=(0, 6), pady=(0, 8))
        self.ssl_verify_var = tk.BooleanVar(value=True)
        self.follow_redirects_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(cell1, text="Verify SSL", variable=self.ssl_verify_var).pack(anchor="w", pady=(0, 2))
        ttk.Checkbutton(cell1, text="Follow Redirects", variable=self.follow_redirects_var).pack(anchor="w")
        cell2 = ttk.LabelFrame(settings_tab, text=" Rate & Batch ", padding=8)
        cell2.grid(row=0, column=1, sticky="ew", padx=(6, 0), pady=(0, 8))
        ttk.Label(cell2, text="Rate Limit:").grid(row=0, column=0, sticky="w")
        self.rate_limit_spin = tk.Spinbox(cell2, from_=1, to=1000, width=8)
        self.rate_limit_spin.grid(row=0, column=1, sticky="w", padx=(4, 0))
        ttk.Label(cell2, text="Batch Size:").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.batch_size_spin = tk.Spinbox(cell2, from_=1, to=1000, width=8)
        self.batch_size_spin.grid(row=1, column=1, sticky="w", padx=(4, 0), pady=(4, 0))
        cell3 = ttk.LabelFrame(settings_tab, text=" Retries & Delay ", padding=8)
        cell3.grid(row=1, column=0, sticky="ew", padx=(0, 6), pady=(0, 8))
        ttk.Label(cell3, text="Max Retries:").grid(row=0, column=0, sticky="w")
        self.max_retries_spin = tk.Spinbox(cell3, from_=0, to=10, width=6)
        self.max_retries_spin.grid(row=0, column=1, sticky="w", padx=(4, 0))
        ttk.Label(cell3, text="Delay (s):").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.retry_delay_spin = tk.Spinbox(cell3, from_=0.0, to=120.0, increment=0.5, width=6)
        self.retry_delay_spin.grid(row=1, column=1, sticky="w", padx=(4, 0), pady=(4, 0))
        cell4 = ttk.LabelFrame(settings_tab, text=" Delay Mode ", padding=8)
        cell4.grid(row=1, column=1, sticky="ew", padx=(6, 0), pady=(0, 8))
        self.delay_mode_var = tk.StringVar(value="fixed")
        ttk.Radiobutton(cell4, text="Fixed", variable=self.delay_mode_var, value="fixed").pack(anchor="w", pady=(0, 2))
        ttk.Radiobutton(cell4, text="Exponential", variable=self.delay_mode_var, value="exp").pack(anchor="w")
        ttk.Button(settings_tab, text="Save Settings", command=self._save_settings, style="Success.Mini.TButton").grid(row=2, column=1, sticky="e", pady=(0, 5))
        self.req_nb.add(settings_tab, text="Settings")
        self.history_tab = ttk.Frame(self.req_nb, padding=6)
        self.history_tab.grid_rowconfigure(0, weight=1)
        self.history_tab.grid_columnconfigure(0, weight=1)
        hist_container = ttk.Frame(self.history_tab)
        hist_container.grid(row=0, column=0, sticky="nsew")
        hist_container.grid_rowconfigure(0, weight=1)
        hist_container.grid_columnconfigure(0, weight=1)
        self.history_tree = ttk.Treeview(
            hist_container,
            columns=("when", "method", "url", "status", "time", "size"),
            show="headings",
            height=8
        )
        vsb = ttk.Scrollbar(hist_container, orient="vertical", command=self.history_tree.yview, style="Hist.Vertical.TScrollbar")
        self.history_tree.configure(yscrollcommand=vsb.set)
        self.history_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        for col, w in (("when", 150), ("method", 70), ("url", 360), ("status", 80), ("time", 80), ("size", 90)):
            self.history_tree.heading(col, text=col.capitalize())
            self.history_tree.column(col, width=w, anchor="w")
        hist_btns = ttk.Frame(self.history_tab)
        hist_btns.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        hist_btns.grid_columnconfigure(2, weight=1)
        ttk.Button(hist_btns, text="Delete", command=self._history_delete, style="Danger.Mini.TButton").grid(row=0, column=0, padx=(0, 6), sticky="w")
        ttk.Button(hist_btns, text="Clear All", command=self._history_clear_all, style="Danger.Mini.TButton").grid(row=0, column=1, sticky="e")
        self.history_tree.bind("<Double-1>", self._history_load_selected)
        self.req_nb.add(self.history_tab, text="History")
        panes.add(self.req_nb, weight=1)
        res_frame = ttk.Frame(panes)
        res_frame.columnconfigure(0, weight=1)
        res_frame.rowconfigure(1, weight=1)
        self.status_label = ttk.Label(res_frame, text="Status: Idle", style="Status.TLabel")
        self.status_label.grid(row=0, column=0, sticky="ew", pady=(6, 6))
        res_nb = ttk.Notebook(res_frame)
        res_nb.grid(row=1, column=0, sticky="nsew")
        self.response_body   = ThinScrolledText(res_nb, wrap=tk.WORD, font=("Consolas", 10), scrollbar_style="Thin.Vertical.TScrollbar")
        self.response_headers= ThinScrolledText(res_nb, wrap=tk.WORD, font=("Consolas", 10), scrollbar_style="Thin.Vertical.TScrollbar")
        self.response_info   = ThinScrolledText(res_nb, wrap=tk.WORD, font=("Consolas", 10), scrollbar_style="Thin.Vertical.TScrollbar")
        res_nb.add(self.response_body, text="Body")
        res_nb.add(self.response_headers, text="Headers")
        res_nb.add(self.response_info, text="Info")
        panes.add(res_frame, weight=2)
        bottom_actions = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom_actions.grid(row=2, column=0)
        bottom_actions.columnconfigure(10, weight=1)
        ttk.Button(bottom_actions, text="Copy cURL", command=self._copy_curl, style="Info.Mini.TButton").grid(row=0, column=0, padx=(0, 6), sticky="w")
        ttk.Button(bottom_actions, text="Save Response", command=self._save_response, style="Warn.Mini.TButton").grid(row=0, column=1, padx=(0, 6), sticky="w")
        ttk.Button(bottom_actions, text="Reset", command=self._reset_form, style="Danger.Mini.TButton").grid(row=0, column=2, sticky="e")
        self._apply_dark_overrides()
    def _on_body_change(self):
        self._validate_json_bg(self.body_text)
        if HIGHLIGHT_REQUEST_BODY:
            content = self.body_text.get("1.0", "end-1c")
            try:
                obj = json.loads(content)
                pretty = json.dumps(obj, indent=2, ensure_ascii=False)
                if pretty != content:
                    pos = self.body_text.index(tk.INSERT)
                    self.body_text.delete("1.0", "end")
                    self.body_text.insert("1.0", pretty)
                    self.body_text.mark_set(tk.INSERT, pos)
                self._highlight_json_into(self.body_text, pretty)
            except Exception:
                pass
    def _update_auth_fields(self):
        auth_type = self.auth_var.get()
        if auth_type == "Bearer":
            self.token_entry.config(state="normal")
            self.username_entry.config(state="disabled")
            self.password_entry.config(state="disabled")
        elif auth_type == "Basic":
            self.token_entry.config(state="disabled")
            self.username_entry.config(state="normal")
            self.password_entry.config(state="normal")
        else:
            self.token_entry.config(state="disabled")
            self.username_entry.config(state="disabled")
            self.password_entry.config(state="disabled")
    def _validate_json_bg(self, widget):
        content = widget.get("1.0", "end-1c").strip()
        ok_bg = widget.cget("bg")
        bad_bg = "#3b1a1a"
        try:
            if not content:
                widget.configure(bg=ok_bg); return True
            json.loads(content)
            widget.configure(bg=ok_bg); return True
        except json.JSONDecodeError:
            widget.configure(bg=bad_bg); return False
    def _parse_body_headers_params(self):
        params = dict(self.params_kv.items())
        headers = dict(self.headers_kv.items())
        body_raw = self.body_text.get("1.0", "end-1c").strip()
        body = None
        if body_raw:
            try:
                body = json.loads(body_raw)
            except json.JSONDecodeError:
                messagebox.showerror("JSON Error", "Body contains invalid JSON.")
                return None, None, None
        return params, headers, body
    def _apply_auth(self):
        mode = self.auth_var.get()
        if mode == "None":
            return
        if mode == "Bearer":
            token = self.token_entry.get().strip()
            if not token:
                messagebox.showwarning("Bearer Token", "Please enter a token.")
                return
            self._upsert_header("Authorization", f"Bearer {token}")
        elif mode == "Basic":
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()
            if not username or not password:
                messagebox.showwarning("Basic Auth", "Please enter both username and password.")
                return
            credentials = f"{username}:{password}"
            enc = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
            self._upsert_header("Authorization", f"Basic {enc}")
    def _upsert_header(self, key, value):
        found = False
        for iid in self.headers_kv.tree.get_children():
            k, _ = self.headers_kv.tree.item(iid, "values")
            if k.lower() == key.lower():
                self.headers_kv.tree.item(iid, values=(key, value))
                found = True
                break
        if not found:
            self.headers_kv.add_row(key, value)
    def _current_settings(self):
        return {
            "ssl_verify": bool(self.ssl_verify_var.get()),
            "follow_redirects": bool(self.follow_redirects_var.get()),
            "rate_limit": int(self.rate_limit_spin.get() or 1),
            "batch_size": int(self.batch_size_spin.get() or 1),
            "max_retries": int(self.max_retries_spin.get() or 0),
            "retry_delay": float(self.retry_delay_spin.get() or 0.0),
            "delay_mode": self.delay_mode_var.get(),
        }
    def _apply_settings_to_ui(self, s):
        try:
            self.ssl_verify_var.set(bool(s.get("ssl_verify", True)))
            self.follow_redirects_var.set(bool(s.get("follow_redirects", True)))
            self.rate_limit_spin.delete(0, "end"); self.rate_limit_spin.insert(0, int(s.get("rate_limit", 1)))
            self.batch_size_spin.delete(0, "end"); self.batch_size_spin.insert(0, int(s.get("batch_size", 1)))
            self.max_retries_spin.delete(0, "end"); self.max_retries_spin.insert(0, int(s.get("max_retries", 0)))
            self.retry_delay_spin.delete(0, "end"); self.retry_delay_spin.insert(0, float(s.get("retry_delay", 0.0)))
            self.delay_mode_var.set(s.get("delay_mode", "fixed") if s.get("delay_mode") in ("fixed", "exp") else "fixed")
        except Exception:
            pass
    def _load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                    s = json.load(f)
                if isinstance(s, dict):
                    self._apply_settings_to_ui(s)
            except Exception:
                pass
    def _save_settings(self):
        s = self._current_settings()
        try:
            with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
                json.dump(s, f, ensure_ascii=False, indent=2)
            messagebox.showinfo("Settings", "Settings saved.")
        except Exception as e:
            messagebox.showerror("Settings", f"Failed to save settings: {e}")
    def _ensure_id(self, item: dict):
        if not isinstance(item, dict):
            return
        if "id" not in item or not item["id"]:
            item["id"] = str(uuid.uuid4())
    def _normalize_history(self):
        normalized = []
        now = datetime.now()
        for it in self.history if isinstance(self.history, list) else []:
            if not isinstance(it, dict):
                continue
            self._ensure_id(it)
            when_iso = it.get("when") or now.isoformat()
            it["when"] = when_iso
            when_str = it.get("when_str")
            if not when_str:
                try:
                    dt = datetime.fromisoformat(str(when_iso).replace("Z", "+00:00"))
                except Exception:
                    dt = now
                it["when_str"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            req = it.get("request") or {}
            resp = it.get("response") or {}
            it["request"] = {
                "method": req.get("method", ""),
                "url": req.get("url", ""),
                "params": req.get("params", {}) or {},
                "headers": req.get("headers", {}) or {},
                "body": req.get("body", None),
                "auth": req.get("auth", {}) or {},
            }
            it["response"] = {
                "status": resp.get("status", ""),
                "status_line": resp.get("status_line", ""),
                "elapsed_ms": resp.get("elapsed_ms", ""),
                "size_kb": resp.get("size_kb", ""),
                "body_text": resp.get("body_text", ""),
                "headers_json": resp.get("headers_json", "{}"),
                "info_json": resp.get("info_json", "{}"),
            }
            normalized.append(it)
        self.history = normalized
    def _load_history(self):
        try:
            if os.path.exists(HISTORY_FILE):
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    self.history = json.load(f)
            else:
                self.history = []
        except Exception:
            self.history = []
        self._normalize_history()
        self._rebuild_history_index()
        self._refresh_history_view()
        self._save_history()
    def _save_history(self):
        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.history, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print("History save error:", e)
    def _rebuild_history_index(self):
        self.history_index = {item["id"]: item for item in self.history if isinstance(item, dict) and "id" in item}
    def _refresh_history_view(self):
        self.history_tree.delete(*self.history_tree.get_children())
        def _fmt_size(v):
            try:
                return f"{float(v):.2f} KB"
            except Exception:
                return str(v) if v is not None else ""
        def _fmt_time_ms(v):
            try:
                return f"{int(v)} ms"
            except Exception:
                return str(v) if v is not None else ""
        for item in reversed(self.history):
            if not isinstance(item, dict):
                continue
            iid = item.get("id") or str(uuid.uuid4())
            when = item.get("when_str", "")
            req = item.get("request", {}) or {}
            resp = item.get("response", {}) or {}
            method = req.get("method", "")
            url = req.get("url", "")
            status = resp.get("status", "")
            time_ms = _fmt_time_ms(resp.get("elapsed_ms", ""))
            size_disp = _fmt_size(resp.get("size_kb", ""))
            self.history_tree.insert("", "end", iid=iid, values=(when, method, url, status, time_ms, size_disp))
        self._autosize_history_columns()
    def _autosize_history_columns(self):
        fnt = tkfont.nametofont("TkDefaultFont")
        pad = 24
        for col in ("when", "method", "url", "status", "time", "size"):
            header_text = col.capitalize()
            max_w = fnt.measure(header_text) + pad
            for iid in self.history_tree.get_children(""):
                val = self.history_tree.set(iid, col)
                w = fnt.measure(str(val)) + pad
                if w > max_w:
                    max_w = w
            if col == "url":
                max_w = min(max_w, 600)
            self.history_tree.column(col, width=max_w, stretch=(col == "url"))
    def _history_add(self, request_dict, response_dict):
        now = datetime.now()
        item = {
            "id": f"{int(now.timestamp()*1000)}",
            "when": now.isoformat(),
            "when_str": now.strftime("%Y-%m-%d %H:%M:%S"),
            "request": request_dict,
            "response": response_dict,
        }
        self.history.append(item)
        if len(self.history) > MAX_HISTORY_ITEMS:
            self.history = self.history[-MAX_HISTORY_ITEMS:]
        self._rebuild_history_index()
        self._refresh_history_view()
        self._save_history()
    def _history_delete(self):
        sel = self.history_tree.selection()
        if not sel:
            return
        ids = set(sel)
        self.history = [it for it in self.history if it.get("id") not in ids]
        self._rebuild_history_index()
        self._refresh_history_view()
        self._save_history()
    def _history_clear_all(self):
        if messagebox.askyesno("Clear All History", "Delete all saved requests?"):
            self.history = []
            self._rebuild_history_index()
            self._refresh_history_view()
            self._save_history()
    def _history_load_selected(self, _evt=None):
        sel = self.history_tree.selection()
        if not sel:
            return
        hid = sel[0]
        item = self.history_index.get(hid)
        if not item:
            return
        req = item.get("request", {})
        resp = item.get("response", {})
        self.method_var.set(req.get("method", "GET"))
        self.url_entry.delete(0, "end"); self.url_entry.insert(0, req.get("url", ""))
        self.params_kv.set_dict(req.get("params", {}))
        self.headers_kv.set_dict(req.get("headers", {}))
        self.body_text.delete("1.0", "end")
        body_obj = req.get("body")
        if body_obj is not None:
            try:
                self.body_text.insert("1.0", json.dumps(body_obj, indent=2, ensure_ascii=False))
            except Exception:
                self.body_text.insert("1.0", str(body_obj))
        auth = req.get("auth", {})
        self.auth_var.set(auth.get("mode", "None"))
        self._update_auth_fields()
        self.status_label.config(text=resp.get("status_line", "Status: (loaded)"), style="Status.TLabel")
        self._maybe_json_and_highlight(self.response_body.text, resp.get("body_text", ""))
        self._highlight_json_into(self.response_headers.text, resp.get("headers_json", "{}"))
        self._highlight_json_into(self.response_info.text, resp.get("info_json", "{}"))
        self.req_nb.select(self.history_tab)
    def _reset_form(self):
        self.method_var.set("GET")
        self.url_entry.delete(0, "end")
        self.params_kv.clear()
        self.headers_kv.clear()
        self.body_text.delete("1.0", "end")
        for w in (self.response_body.text, self.response_headers.text, self.response_info.text):
            w.configure(state="normal"); w.delete("1.0", "end"); w.configure(state="disabled")
        self.status_label.config(text="Status: Idle", style="Status.TLabel")
        self.auth_var.set("None")
        for w in (self.response_body.text, self.response_headers.text, self.response_info.text, self.body_text):
            for tag in w.tag_names():
                if tag != "sel":
                    w.tag_delete(tag)
    def _copy_curl(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        params, headers, body = self._parse_body_headers_params()
        if params is None:
            return
        method = self.method_var.get().upper()
        curl = ["curl", "-X", method]
        for k, v in headers.items():
            curl += ["-H", f"{k}: {v}"]
        final_url = url
        if params:
            qs = urlencode(params, doseq=True)
            sep = "&" if "?" in final_url else "?"
            final_url = f"{final_url}{sep}{qs}"
        if body is not None and method not in ("GET", "HEAD"):
            curl += ["-d", json.dumps(body, separators=(",", ":"))]
        curl += [final_url]
        cmd = " ".join([self._shell_quote(x) for x in curl])
        self.clipboard_clear()
        self.clipboard_append(cmd)
        messagebox.showinfo("cURL", "Copied cURL command to clipboard.")
    @staticmethod
    def _shell_quote(s):
        if not s:
            return "''"
        if any(ch in s for ch in " \t\n\"'\\$`"):
            return "'" + s.replace("'", "'\"'\"'") + "'"
        return s
    def _save_response(self):
        text = self.response_body.text.get("1.0", "end-1c")
        if not text:
            messagebox.showinfo("Save Response", "Nothing to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
                                            filetypes=[("All Files", "*.*"),
                                                       ("JSON", "*.json"),
                                                       ("Text", "*.txt")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            messagebox.showinfo("Save Response", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Save Response", f"Failed: {e}")
    def send_request(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "URL cannot be empty.")
            return
        params, headers, body = self._parse_body_headers_params()
        if params is None:
            return
        for w in (self.response_body.text, self.response_headers.text, self.response_info.text):
            w.configure(state="normal"); w.delete("1.0", "end"); w.configure(state="disabled")
        self.status_label.config(text="Status: Sending...", style="Status.TLabel")
        thread = threading.Thread(target=self._send_request_thread, args=(url, params, headers, body), daemon=True)
        thread.start()
    def _send_request_thread(self, url, params, headers, body):
        settings = self._current_settings()
        max_retries = max(0, int(settings.get("max_retries", 0)))
        delay = max(0.0, float(settings.get("retry_delay", 0.0)))
        mode = settings.get("delay_mode", "fixed")
        attempt = 0
        last_exc = None
        while attempt <= max_retries:
            try:
                method = self.method_var.get()
                start = time.time()
                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers or None,
                    params=params or None,
                    json=body if method not in ["GET", "HEAD"] else None,
                    timeout=30,
                    verify=self.ssl_verify_var.get(),
                    allow_redirects=self.follow_redirects_var.get(),
                )
                dur = time.time() - start
                self.request_queue.put(("success", (url, params, headers, body, response, dur)))
                return
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt >= max_retries:
                    break
                sleep_for = delay if mode == "fixed" else (delay * (2 ** attempt) if delay > 0 else 0.0)
                time.sleep(sleep_for)
                attempt += 1
        self.request_queue.put(("error", last_exc))
    def _process_queue(self):
        try:
            msg_type, data = self.request_queue.get_nowait()
            if msg_type == "success":
                url, params, headers, body, response, duration = data
                self._render_response(response, duration)
                req_dict = {
                    "method": self.method_var.get(),
                    "url": url,
                    "params": params,
                    "headers": headers,
                    "body": body,
                    "auth": {"mode": self.auth_var.get()},
                }
                headers_json = json.dumps(dict(response.headers), indent=2, ensure_ascii=False)
                info = {
                    "url": response.url,
                    "ok": response.ok,
                    "status_code": response.status_code,
                    "reason": response.reason,
                    "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
                    "encoding": response.encoding,
                    "cookies": requests.utils.dict_from_cookiejar(response.cookies),
                    "request_headers": dict(response.request.headers or {}),
                    "method": response.request.method if response.request else None,
                }
                info_json = json.dumps(info, indent=2, ensure_ascii=False)
                resp_dict = {
                    "status": response.status_code,
                    "status_line": f"Status: {response.status_code} {response.reason} | Time: {duration:.2f}s | Size: {len(response.content)/1024:.2f} KB",
                    "elapsed_ms": int(duration * 1000),
                    "size_kb": len(response.content) / 1024,
                    "body_text": response.text,
                    "headers_json": headers_json,
                    "info_json": info_json,
                }
                self._history_add(req_dict, resp_dict)
                self._flash_feedback(success=(200 <= response.status_code < 300))
            elif msg_type == "error":
                self.status_label.config(text="Status: Error", style="ServerError.Status.TLabel")
                self.response_body.text.configure(state="normal")
                self.response_body.text.insert("1.0", str(data))
                self.response_body.text.configure(state="disabled")
                for w in (self.response_headers.text, self.response_info.text):
                    w.configure(state="normal"); w.delete("1.0", "end"); w.configure(state="disabled")
                self._flash_feedback(success=False)
        except queue.Empty:
            pass
        finally:
            self.after(100, self._process_queue)
    def _apply_dark_overrides(self):
        dark_bg = "#1e1e1e"
        dark_fg = "#e6e6e6"
        caret = "#e6e6e6"
        for w in (self.body_text, self.response_body.text, self.response_headers.text, self.response_info.text):
            try:
                w.configure(bg=dark_bg, fg=dark_fg, insertbackground=caret)
            except Exception:
                pass
    def _flash_feedback(self, success: bool):
        """Overlay a translucent flash (green/red) over the whole window for strong feedback."""
        color = "#16a34a" if success else "#dc2626"  # green / red
        overlay = tk.Toplevel(self)
        overlay.overrideredirect(True)
        overlay.attributes("-topmost", True)
        try:
            overlay.attributes("-alpha", 0.18)
        except Exception:
            pass
        self.update_idletasks()
        x = self.winfo_rootx()
        y = self.winfo_rooty()
        w = self.winfo_width()
        h = self.winfo_height()
        overlay.geometry(f"{w}x{h}+{x}+{y}")
        canvas = tk.Canvas(overlay, highlightthickness=0, bd=0, bg=color)
        canvas.pack(fill="both", expand=True)
        overlay.after(180, overlay.destroy)
    def _render_response(self, response, duration):
        code = response.status_code
        style = "ServerError.Status.TLabel"
        if 100 <= code < 300:
            style = "Success.Status.TLabel"
        elif 300 <= code < 400:
            style = "Redirect.Status.TLabel"
        elif 400 <= code < 500:
            style = "ClientError.Status.TLabel"
        size_kb = len(response.content) / 1024
        self.status_label.config(
            text=f"Status: {code} {response.reason} | Time: {duration:.2f}s | Size: {size_kb:.2f} KB",
            style=style,
        )
        self._maybe_json_and_highlight(self.response_body.text, response.text)
        try:
            headers_json = json.dumps(dict(response.headers), indent=2, ensure_ascii=False)
            self._highlight_json_into(self.response_headers.text, headers_json)
        except Exception:
            self.response_headers.text.configure(state="normal")
            self.response_headers.text.delete("1.0", "end")
            self.response_headers.text.insert("1.0", str(response.headers))
            self.response_headers.text.configure(state="disabled")
        info = {
            "url": response.url,
            "ok": response.ok,
            "status_code": response.status_code,
            "reason": response.reason,
            "elapsed_ms": int(response.elapsed.total_seconds() * 1000),
            "encoding": response.encoding,
            "cookies": requests.utils.dict_from_cookiejar(response.cookies),
            "request_headers": dict(response.request.headers or {}),
            "method": response.request.method if response.request else None,
        }
        info_s = json.dumps(info, indent=2, ensure_ascii=False)
        self._highlight_json_into(self.response_info.text, info_s)
if __name__ == "__main__":
    app = MiniPostman()
    if tb is not None:
        try:
            tb.Style("cyborg")
        except Exception:
            pass
    app._apply_dark_overrides()
    app.mainloop()
