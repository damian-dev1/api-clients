import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import requests, json, time, threading, queue, base64
from urllib.parse import urlencode
from pathlib import Path
CONFIG_FILENAME = ".mini_postman_config.json"
HISTORY_MAX_ENTRIES = 500
def _now_ts() -> float: return time.time()
class _KVEditor(ttk.Frame):
    def __init__(self, master, title="Items"):
        super().__init__(master)
        toolbar = ttk.Frame(self)
        ttk.Label(toolbar, text=title).pack(side="left")
        ttk.Button(toolbar, text="+", width=3, command=self.add_row).pack(side="left", padx=(3,0))
        ttk.Button(toolbar, text="−", width=3, command=self.remove_selected).pack(side="left", padx=(3,0))
        ttk.Button(toolbar, text="Clear", width=5, command=self.clear).pack(side="left")
        toolbar.pack(fill="x", pady=(0,3))
        self.tree = ttk.Treeview(self, columns=("key","value"), show="headings", height=5)
        self.tree.heading("key", text="Key")
        self.tree.heading("value", text="Value")
        self.tree.column("key", width=120, anchor="w")
        self.tree.column("value", width=220, anchor="w")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Double-1>", self._edit_cell)
    def add_row(self, key="", value=""): return self.tree.insert("", "end", values=(key, value))
    def remove_selected(self): [self.tree.delete(iid) for iid in self.tree.selection()]
    def clear(self): [self.tree.delete(iid) for iid in self.tree.get_children()]
    def items(self):
        out=[]; 
        for iid in self.tree.get_children():
            k,v = self.tree.item(iid,"values")
            if str(k).strip()!="": out.append((str(k),str(v)))
        return out
    def to_dict(self): return {k:v for k,v in self.items()}
    def set_data(self, data):
        self.clear()
        if isinstance(data, dict):
            for k,v in data.items(): self.add_row(k,v)
        elif isinstance(data,(list,tuple)):
            for pair in data:
                if isinstance(pair,(list,tuple)) and pair: self.add_row(pair[0], pair[1] if len(pair)>1 else "")
    def get_data(self): return self.to_dict()
    def _edit_cell(self, e):
        if self.tree.identify("region", e.x, e.y)!="cell": return
        rowid=self.tree.identify_row(e.y); colid=self.tree.identify_column(e.x)
        if not rowid or not colid: return
        x,y,w,h=self.tree.bbox(rowid,colid); idx=int(colid[1:])-1
        vals=list(self.tree.item(rowid,"values")); initial=vals[idx] if idx<len(vals) else ""
        entry=ttk.Entry(self.tree); entry.insert(0,initial); entry.select_range(0,"end"); entry.focus_set()
        entry.place(x=x,y=y,width=w,height=h)
        def commit(*_):
            new=entry.get(); entry.destroy(); vals[idx]=new; self.tree.item(rowid, values=tuple(vals))
        entry.bind("<Return>",commit); entry.bind("<Escape>",lambda *_:entry.destroy()); entry.bind("<FocusOut>",commit)
class MiniPostman(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mini Postman")
        self.geometry("400x600")
        self.minsize(350, 400)
        style=ttk.Style()
        style.configure(".", padding=0)
        style.configure("TButton", padding=(4,2))
        style.configure("TNotebook.Tab", padding=(6,2))
        style.configure("Status.TLabel", font=('Segoe UI', 9), padding=1)
        style.configure("Success.Status.TLabel", foreground="#2e7d32")
        style.configure("Redirect.Status.TLabel", foreground="#1565c0")
        style.configure("ClientError.Status.TLabel", foreground="#ef6c00")
        style.configure("ServerError.Status.TLabel", foreground="#c62828")
        self.request_queue = queue.Queue()
        self.request_history = []     # dicts with name, method, url, headers, params, body, ts
        self.profiles = {}
        self.active_profile = "Default"
        self._editing_history_index = None
        self._build_ui()
        self._load_config_safe()
        self.after(120, self._set_initial_sash)  # make bottom half taller
        self.after(100, self._process_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
    def _build_ui(self):
        top = ttk.Frame(self, padding=(6,6,6,4)); top.pack(fill="x")
        top.columnconfigure(1, weight=1)
        self.method_var = tk.StringVar(value="GET")
        ttk.Combobox(top, textvariable=self.method_var,
                     values=["GET","POST","PUT","DELETE","PATCH","HEAD"],
                     state="readonly", width=6).grid(row=0, column=0, padx=(0,4))
        self.url_entry = ttk.Entry(top); self.url_entry.grid(row=0, column=1, sticky="ew")
        self.url_entry.bind("<Return>", lambda _e: self.send_request())
        ttk.Button(top, text="Send", width=7, command=self.send_request).grid(row=0, column=2, padx=(4,0))
        self.panes = ttk.Panedwindow(self, orient=tk.VERTICAL)
        self.panes.pack(fill="both", expand=True, padx=6, pady=(0,6))
        req_nb = ttk.Notebook(self.panes)
        body_tab = ttk.Frame(req_nb, padding=6)
        ttk.Label(body_tab, text="Body (JSON)").pack(anchor="w")
        self.body_text = scrolledtext.ScrolledText(body_tab, wrap=tk.WORD, height=6, font=("Consolas", 10))
        self.body_text.pack(fill="both", expand=True, pady=(2,0))
        self.body_text.bind("<KeyRelease>", lambda _e: self._validate_json_bg(self.body_text))
        req_nb.add(body_tab, text="Body")
        prof = ttk.Frame(req_nb, padding=6); [prof.columnconfigure(c, weight=1) for c in range(3)]
        ttk.Label(prof, text="Profile").grid(row=0, column=0, sticky="w")
        self.profile_var = tk.StringVar(value="Default")
        self.profile_combo = ttk.Combobox(prof, textvariable=self.profile_var, state="readonly", width=16, values=["Default"])
        self.profile_combo.grid(row=1, column=0, sticky="ew", pady=(2,4))
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_change)
        ttk.Button(prof, text="New", width=7, command=self._new_profile).grid(row=1, column=1, sticky="ew", padx=2)
        ttk.Button(prof, text="Save", width=7, command=self._save_profile).grid(row=1, column=2, sticky="ew", padx=2)
        ttk.Button(prof, text="Apply → Form", width=14, command=self._apply_active_profile_to_form).grid(row=2, column=0, sticky="w", pady=(0,2))
        ttk.Button(prof, text="Form → Save", width=14, command=self._save_form_into_active_profile).grid(row=2, column=1, sticky="w", padx=2, pady=(0,2))
        ttk.Button(prof, text="Delete", width=7, command=self._delete_profile).grid(row=2, column=2, sticky="e", padx=2, pady=(0,2))
        req_nb.add(prof, text="Profile")
        self.params_kv = _KVEditor(req_nb, "Params");   req_nb.add(self.params_kv, text="Params")
        self.headers_kv = _KVEditor(req_nb, "Headers"); req_nb.add(self.headers_kv, text="Headers")
        auth_tab = ttk.Frame(req_nb, padding=6); auth_tab.columnconfigure(1, weight=1)
        ttk.Label(auth_tab, text="Env").grid(row=0, column=0, sticky="w")
        self.env_profile_var = tk.StringVar(value="Development")
        ttk.Combobox(auth_tab, textvariable=self.env_profile_var, state="readonly",
                     values=["Development","Staging","Production"], width=14)\
                     .grid(row=0, column=1, sticky="ew", padx=(4,0))
        ttk.Label(auth_tab, text="Auth").grid(row=1, column=0, sticky="w", pady=(3,0))
        self.auth_var = tk.StringVar(value="None")
        ttk.Combobox(auth_tab, textvariable=self.auth_var, state="readonly",
                     values=["None","Bearer Token","Basic"], width=14)\
                     .grid(row=1, column=1, sticky="ew", padx=(4,0), pady=(3,0))
        ttk.Label(auth_tab, text="Token/Creds").grid(row=2, column=0, sticky="w", pady=(3,0))
        self.auth_field = ttk.Entry(auth_tab); self.auth_field.grid(row=2, column=1, sticky="ew", padx=(4,0), pady=(3,0))
        ttk.Button(auth_tab, text="Apply", width=7, command=self._apply_auth).grid(row=0, column=2, rowspan=3, padx=(6,0))
        ttk.Label(auth_tab, text="Timeout (s)").grid(row=3, column=0, sticky="w", pady=(3,0))
        self.timeout_spin = tk.Spinbox(auth_tab, from_=1, to=300, width=6); self.timeout_spin.delete(0,"end"); self.timeout_spin.insert(0,"30")
        self.timeout_spin.grid(row=3, column=1, sticky="w", padx=(4,0), pady=(3,0))
        self.ssl_verify_var = tk.BooleanVar(value=True)
        self.follow_redirects_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(auth_tab, text="Verify SSL", variable=self.ssl_verify_var).grid(row=4, column=0, sticky="w")
        ttk.Checkbutton(auth_tab, text="Redirects", variable=self.follow_redirects_var).grid(row=4, column=1, sticky="w")
        req_nb.add(auth_tab, text="Auth")
        hist = ttk.Frame(req_nb, padding=6)
        hist.columnconfigure(0, weight=1)
        ttk.Label(hist, text="Request History").grid(row=0, column=0, sticky="w")
        name_row = ttk.Frame(hist)
        name_row.grid(row=1, column=0, sticky="ew", pady=(2, 2))
        name_row.columnconfigure(1, weight=1)
        ttk.Label(name_row, text="Name:").grid(row=0, column=0, sticky="w")
        self.history_name_var = tk.StringVar()
        self.history_name_entry = ttk.Entry(name_row, textvariable=self.history_name_var)
        self.history_name_entry.grid(row=0, column=1, sticky="ew", padx=(4, 0))
        self.history_name_entry.insert(0, "Enter new name…")
        self.history_name_entry.bind("<FocusIn>", lambda e: self.history_name_entry.delete(0, tk.END))
        ttk.Button(name_row, text="Rename", width=8, command=self._rename_selected_history).grid(row=0, column=2, padx=(4, 0))
        self.history_listbox = tk.Listbox(hist, height=7)
        self.history_listbox.grid(row=2, column=0, sticky="nsew", pady=(2, 4))
        self.history_listbox.bind("<<ListboxSelect>>", self._on_history_select)
        self.history_listbox.bind("<Double-Button-1>", self._on_history_double_click)
        row_btns = ttk.Frame(hist)
        row_btns.grid(row=3, column=0, sticky="ew")
        for i in range(6):
            row_btns.columnconfigure(i, weight=1)
        ttk.Button(row_btns, text="Edit", width=7, command=self._edit_selected_history).grid(row=0, column=0, padx=1, pady=1, sticky="ew")
        ttk.Button(row_btns, text="Save", width=7, command=self._save_edited_history).grid(row=0, column=1, padx=1, pady=1, sticky="ew")
        ttk.Button(row_btns, text="Delete", width=7, command=self._delete_selected_history).grid(row=0, column=2, padx=1, pady=1, sticky="ew")
        ttk.Button(row_btns, text="Clear All", width=8, command=self._clear_all_history).grid(row=0, column=3, padx=1, pady=1, sticky="ew")
        ttk.Button(row_btns, text="Export", width=7, command=self._export_history).grid(row=0, column=4, padx=1, pady=1, sticky="ew")
        ttk.Button(row_btns, text="Copy cURL", width=9, command=self._copy_curl).grid(row=0, column=5, padx=1, pady=1, sticky="ew")
        hist.rowconfigure(2, weight=1)
        req_nb.add(hist, text="History")
        self.panes.add(req_nb, weight=1)  # top (shorter)
        res = ttk.Frame(self.panes, padding=(0,4,0,0)); res.columnconfigure(0, weight=1); res.rowconfigure(1, weight=1)
        self.status_label = ttk.Label(res, text="Status: Idle", style="Status.TLabel")
        self.status_label.grid(row=0, column=0, sticky="w", pady=(0,4))
        res_nb = ttk.Notebook(res)
        res_nb.grid(row=1, column=0, sticky="nsew")
        self.response_body = scrolledtext.ScrolledText(res_nb, wrap=tk.WORD, font=("Consolas", 10), height=10)
        self.response_headers = scrolledtext.ScrolledText(res_nb, wrap=tk.WORD, font=("Consolas", 10), height=10)
        self.response_info = scrolledtext.ScrolledText(res_nb, wrap=tk.WORD, font=("Consolas", 10), height=10)
        res_nb.add(self.response_body, text="Body"); res_nb.add(self.response_headers, text="Headers"); res_nb.add(self.response_info, text="Info")
        self.panes.add(res, weight=3)      # bottom (taller)
        bottom = ttk.Frame(self, padding=(6,0,6,6)); bottom.pack(fill="x")
        ttk.Button(bottom, text="Save", width=7, command=self._save_response).pack(side="left")
        ttk.Button(bottom, text="Reset", width=7, command=self._reset_form).pack(side="left", padx=4)
    def _set_initial_sash(self):
        try:
            total = self.panes.winfo_height()
            pos = max(140, int(total * 0.40))
            self.panes.sashpos(0, pos)
        except Exception:
            pass
    def _config_path(self) -> Path: return Path.home() / CONFIG_FILENAME
    def _default_profile(self):
        return {"base_url":"","headers":{},"params":{},"auth_type":"None","auth_value":"",
                "verify_ssl":True,"follow_redirects":True,"timeout":30,"env":"Development","notes":""}
    def _default_config(self):
        return {"profiles":{"Default":self._default_profile()},"active_profile":"Default","history":[],"version":1,"saved_at":_now_ts()}
    def _load_config_safe(self):
        p=self._config_path(); cfg=None
        if p.exists():
            try: cfg=json.loads(p.read_text(encoding="utf-8"))
            except Exception as e: messagebox.showwarning("Config", f"Failed to load config; using defaults:\n{e}")
        if not isinstance(cfg,dict): cfg=self._default_config()
        self.profiles=dict(cfg.get("profiles") or {})
        self.profiles.setdefault("Default", self._default_profile())
        self.active_profile=str(cfg.get("active_profile") or "Default")
        self.request_history=list(cfg.get("history") or [])[-HISTORY_MAX_ENTRIES:]
        self._refresh_profile_combo()
        if self.active_profile not in self.profiles: self.active_profile="Default"
        self.profile_var.set(self.active_profile); self._apply_profile_to_form(self.profiles[self.active_profile])
        self._refresh_history_listbox()
    def _save_config_safe(self):
        try:
            cfg={"profiles":self.profiles,"active_profile":self.active_profile,
                 "history":self.request_history[-HISTORY_MAX_ENTRIES:],"version":1,"saved_at":_now_ts()}
            self._config_path().write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        except Exception as e:
            messagebox.showwarning("Config", f"Failed to save config:\n{e}")
    def _refresh_profile_combo(self):
        self.profile_combo.configure(values=sorted(self.profiles.keys()))
    def _collect_form_as_profile(self):
        try: timeout=int(self.timeout_spin.get())
        except Exception: timeout=30
        return {"base_url":self.url_entry.get().strip(),"headers":self.headers_kv.get_data(),
                "params":self.params_kv.get_data(),"auth_type":self.auth_var.get(),
                "auth_value":self.auth_field.get().strip(),"verify_ssl":bool(self.ssl_verify_var.get()),
                "follow_redirects":bool(self.follow_redirects_var.get()),"timeout":timeout,
                "env":self.env_profile_var.get(),"notes":""}
    def _apply_profile_to_form(self, prof:dict):
        self.url_entry.delete(0,"end"); self.url_entry.insert(0, prof.get("base_url",""))
        self.headers_kv.set_data(prof.get("headers",{})); self.params_kv.set_data(prof.get("params",{}))
        self.auth_var.set(prof.get("auth_type","None")); self.auth_field.delete(0,"end"); self.auth_field.insert(0, prof.get("auth_value",""))
        self.ssl_verify_var.set(bool(prof.get("verify_ssl",True))); self.follow_redirects_var.set(bool(prof.get("follow_redirects",True)))
        t=int(prof.get("timeout",30) or 30); self.timeout_spin.delete(0,"end"); self.timeout_spin.insert(0,str(t))
        self.env_profile_var.set(prof.get("env","Development"))
    def _on_profile_change(self,_=None):
        name=self.profile_var.get()
        if name in self.profiles:
            self.active_profile=name; self._apply_profile_to_form(self.profiles[name]); self._save_config_safe()
    def _new_profile(self):
        name=simpledialog.askstring("New Profile","Profile name:"); 
        if not name: return
        name=name.strip()
        if name in self.profiles: messagebox.showerror("New Profile","Profile already exists."); return
        self.profiles[name]=self._collect_form_as_profile(); self.active_profile=name
        self._refresh_profile_combo(); self.profile_var.set(name); self._save_config_safe()
    def _save_profile(self):
        name=self.profile_var.get().strip() or "Default"
        self.profiles[name]=self._collect_form_as_profile(); self.active_profile=name; self._save_config_safe()
    def _delete_profile(self):
        name=self.profile_var.get()
        if name=="Default": messagebox.showinfo("Profile","Cannot delete Default."); return
        if name in self.profiles and messagebox.askyesno("Delete Profile", f"Delete '{name}'?"):
            del self.profiles[name]; self.active_profile="Default"; self._refresh_profile_combo(); self.profile_var.set("Default")
            self._apply_profile_to_form(self.profiles["Default"]); self._save_config_safe()
    def _apply_active_profile_to_form(self): self._apply_profile_to_form(self.profiles.get(self.active_profile, self._default_profile()))
    def _save_form_into_active_profile(self):
        name=self.profile_var.get().strip() or "Default"
        self.profiles[name]=self._collect_form_as_profile(); self.active_profile=name; self._save_config_safe()
    def _refresh_history_listbox(self):
        self.history_listbox.delete(0, tk.END)
        for it in self.request_history:
            title = it.get("name") or f"{it.get('method','')} {it.get('url','')}"
            self.history_listbox.insert(tk.END, title)
    def _on_history_select(self, _evt=None):
        sel=self.history_listbox.curselection()
        if not sel: self.history_name_var.set(""); return
        idx=sel[0]; item=self.request_history[idx]
        self.history_name_var.set(item.get("name") or f"{item.get('method','')} {item.get('url','')}")
    def _on_history_double_click(self, _evt=None):
        sel=self.history_listbox.curselection()
        if not sel: return
        self._load_history_item_into_form(sel[0])  # double-click loads into form
        self._editing_history_index = sel[0]
    def _rename_selected_history(self):
        sel=self.history_listbox.curselection()
        if not sel: return
        idx=sel[0]; name=self.history_name_var.get().strip()
        self.request_history[idx]["name"]=name or None
        self._refresh_history_listbox(); self.history_listbox.selection_set(idx); self._save_config_safe()
    def _load_history_item_into_form(self, idx:int):
        item=self.request_history[idx]
        self.method_var.set(item.get("method","GET"))
        self.url_entry.delete(0,tk.END); self.url_entry.insert(0, item.get("url",""))
        self.headers_kv.set_data(item.get("headers",{})); self.params_kv.set_data(item.get("params",{}))
        self.body_text.delete("1.0",tk.END); self.body_text.insert(tk.END, item.get("body","") or "")
        self.history_name_var.set(item.get("name") or f"{item.get('method','')} {item.get('url','')}")
    def _edit_selected_history(self):
        sel=self.history_listbox.curselection()
        if not sel: messagebox.showinfo("Edit","Select an item first."); return
        self._editing_history_index=sel[0]; self._load_history_item_into_form(self._editing_history_index)
    def _save_edited_history(self):
        if self._editing_history_index is None:
            messagebox.showinfo("Save Edited","No item is being edited."); return
        url=self.url_entry.get().strip()
        if not url: messagebox.showerror("Save Edited","URL cannot be empty."); return
        params, headers, body_raw, _ = self._parse_body_headers_params()
        if params is None: return
        i=self._editing_history_index
        self.request_history[i].update({
            "name": self.history_name_var.get().strip() or None,
            "method": self.method_var.get().upper(),
            "url": url,
            "headers": headers.copy(),
            "params": params.copy(),
            "body": body_raw or "",
            "ts": _now_ts(),
        })
        self._editing_history_index=None; self._refresh_history_listbox(); self._save_config_safe()
    def _delete_selected_history(self):
        sel=self.history_listbox.curselection()
        if not sel: return
        idx=sel[0]; del self.request_history[idx]
        if self._editing_history_index==idx: self._editing_history_index=None
        self._refresh_history_listbox(); self._save_config_safe()
    def _clear_all_history(self):
        if messagebox.askyesno("Clear History","Delete all history?"):
            self.request_history.clear(); self._editing_history_index=None
            self._refresh_history_listbox(); self._save_config_safe()
    def _export_history(self):
        path=filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json"),("All Files","*.*")], title="Export History")
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f: json.dump(self.request_history,f,indent=2)
            messagebox.showinfo("Export", f"Exported to {path}")
        except Exception as e: messagebox.showerror("Export", f"Failed: {e}")
    def _validate_json_bg(self, w):
        content=w.get("1.0","end-1c").strip(); ok=w.cget("bg"); bad="#ffecec"
        try:
            if not content: w.configure(bg=ok); return True
            json.loads(content); w.configure(bg=ok); return True
        except json.JSONDecodeError:
            w.configure(bg=bad); return False
    def _parse_body_headers_params(self):
        params=dict(self.params_kv.items()); headers=dict(self.headers_kv.items())
        raw=self.body_text.get("1.0","end-1c").strip(); obj=None
        if raw:
            try: obj=json.loads(raw)
            except json.JSONDecodeError:
                messagebox.showerror("JSON Error","Body contains invalid JSON."); return None,None,None,None
        return params, headers, raw, obj
    def _apply_auth(self):
        mode=self.auth_var.get(); token=self.auth_field.get().strip()
        if mode=="None" or not token: return
        if mode=="Bearer Token": self._upsert_header("Authorization", f"Bearer {token}")
        elif mode=="Basic":
            if ":" not in token: messagebox.showwarning("Basic Auth","Use username:password"); return
            u,p=token.split(":",1); enc=base64.b64encode(f"{u}:{p}".encode("utf-8")).decode("ascii")
            self._upsert_header("Authorization", f"Basic {enc}")
    def _upsert_header(self,k,v):
        for iid in self.headers_kv.tree.get_children():
            key,_ = self.headers_kv.tree.item(iid,"values")
            if key.lower()==k.lower():
                self.headers_kv.tree.item(iid, values=(k,v)); break
        else: self.headers_kv.add_row(k,v)
    def _copy_curl(self):
        url=self.url_entry.get().strip()
        if not url: return
        params, headers, _, obj = self._parse_body_headers_params()
        if params is None: return
        m=self.method_var.get().upper(); parts=["curl","-X",m]
        for k,v in headers.items(): parts+=["-H",f"{k}: {v}"]
        final=url
        if params:
            qs=urlencode(params, doseq=True); sep="&" if "?" in final else "?"
            final=f"{final}{sep}{qs}"
        if obj is not None and m not in ("GET","HEAD"): parts+=["-d", json.dumps(obj, separators=(",",":"))]
        parts+=[final]
        cmd=" ".join([self._shell_quote(x) for x in parts])
        self.clipboard_clear(); self.clipboard_append(cmd); messagebox.showinfo("cURL","Copied.")
    @staticmethod
    def _shell_quote(s):
        if not s: return "''"
        if any(ch in s for ch in " \t\n\"'\\$`"): return "'" + s.replace("'","'\"'\"'") + "'"
        return s
    def _save_response(self):
        txt=self.response_body.get("1.0","end-1c")
        if not txt: messagebox.showinfo("Save Response","Nothing to save."); return
        path=filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("JSON","*.json"),("Text","*.txt"),("All Files","*.*")])
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f: f.write(txt)
            messagebox.showinfo("Save Response", f"Saved to {path}")
        except Exception as e: messagebox.showerror("Save Response", f"Failed: {e}")
    def send_request(self):
        url=self.url_entry.get().strip()
        if not url: messagebox.showerror("Error","URL cannot be empty."); return
        params, headers, raw, obj = self._parse_body_headers_params()
        if params is None: return
        m=self.method_var.get().upper()
        default_name=f"{m} {url}"
        self.request_history.append({
            "name": default_name, "method": m, "url": url,
            "headers": headers.copy(), "params": params.copy(),
            "body": raw or "", "ts": _now_ts(),
        })
        if len(self.request_history)>HISTORY_MAX_ENTRIES:
            self.request_history=self.request_history[-HISTORY_MAX_ENTRIES:]
        self._refresh_history_listbox(); self._save_config_safe()
        self.response_body.delete("1.0","end"); self.response_headers.delete("1.0","end"); self.response_info.delete("1.0","end")
        self.status_label.config(text="Status: Sending...", style="Status.TLabel")
        verify=bool(self.ssl_verify_var.get()); redirects=bool(self.follow_redirects_var.get())
        try: timeout=int(self.timeout_spin.get())
        except Exception: timeout=30
        threading.Thread(target=self._send_request_thread,
                         args=(m,url,params,headers,obj,verify,redirects,timeout), daemon=True).start()
    def _send_request_thread(self, m, url, params, headers, obj, verify, redirects, timeout):
        try:
            start=time.time()
            resp=requests.request(method=m, url=url, headers=headers or None, params=params or None,
                                  json=obj if m not in ("GET","HEAD") else None, timeout=timeout,
                                  verify=verify, allow_redirects=redirects)
            dur=time.time()-start
            self.request_queue.put(("success",(resp,dur)))
        except requests.exceptions.RequestException as e:
            self.request_queue.put(("error",e))
    def _process_queue(self):
        try:
            msg,data=self.request_queue.get_nowait()
            if msg=="success": self._render_response(*data)
            else:
                self.status_label.config(text="Status: Error", style="ServerError.Status.TLabel")
                self.response_body.insert("1.0", str(data))
                self.response_headers.delete("1.0","end"); self.response_info.delete("1.0","end")
        except queue.Empty: pass
        finally: self.after(100, self._process_queue)
    def _render_response(self, response, duration):
        code=response.status_code
        style="ServerError.Status.TLabel"
        if 100<=code<300: style="Success.Status.TLabel"
        elif 300<=code<400: style="Redirect.Status.TLabel"
        elif 400<=code<500: style="ClientError.Status.TLabel"
        size_kb=len(response.content)/1024 if response.content is not None else 0
        self.status_label.config(text=f"Status: {code} {response.reason} | {duration:.2f}s | {size_kb:.2f} KB", style=style)
        self.response_body.delete("1.0","end")
        try: self.response_body.insert("1.0", json.dumps(response.json(), indent=2, ensure_ascii=False))
        except Exception: self.response_body.insert("1.0", response.text)
        self.response_headers.delete("1.0","end")
        try: self.response_headers.insert("1.0", json.dumps(dict(response.headers), indent=2))
        except Exception: self.response_headers.insert("1.0", str(response.headers))
        info={"url":response.url,"ok":response.ok,"status_code":response.status_code,"reason":response.reason,
              "elapsed_ms": int(response.elapsed.total_seconds()*1000) if response.elapsed else None,
              "encoding":response.encoding,"cookies":requests.utils.dict_from_cookiejar(response.cookies),
              "request_headers": dict(response.request.headers or {}),"method": response.request.method if response.request else None}
        self.response_info.delete("1.0","end"); self.response_info.insert("1.0", json.dumps(info, indent=2))
    def _reset_form(self):
        self.method_var.set("GET")
        self.body_text.delete("1.0","end")
        for w in (self.response_body, self.response_headers, self.response_info): w.delete("1.0","end")
        self.status_label.config(text="Status: Idle", style="Status.TLabel")
    def _on_close(self):
        self._save_config_safe(); self.destroy()
if __name__ == "__main__":
    MiniPostman().mainloop()
