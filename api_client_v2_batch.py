import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from ttkbootstrap import Style
from ttkbootstrap.constants import *
import json, os, time, threading, shlex, queue, csv, math
from datetime import datetime
import requests

APP_TITLE    = "DamianAPI Client Pro"
GEOMETRY     = "660x630"
HISTORY_FILE = "request_history.json"
CONFIG_FILE  = "postman_client_config.json"

request_history = []
stop_event  = threading.Event()
pause_event = threading.Event()

def load_json(path, default):
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

root = tk.Tk()
style = Style("flatly")
root.title(APP_TITLE)
root.geometry(GEOMETRY)

status_var = tk.StringVar(value="Ready")
status_bar = ttk.Label(root, textvariable=status_var, anchor="w")
status_bar.pack(side="bottom", fill="x")

def update_status(msg):
    status_var.set(msg)
    status_bar.update_idletasks()

toolbar = ttk.Frame(root, padding=(6,6,6,0))
toolbar.pack(fill="x")

method_var = tk.StringVar(value="GET")
method_dd = ttk.Combobox(toolbar, textvariable=method_var,
                         values=["GET","POST","PUT","PATCH","DELETE","HEAD"], width=8, state="readonly")
method_dd.pack(side="left")
method_dd.configure(style="primary.TCombobox")

url_entry = ttk.Entry(toolbar)
url_entry.pack(side="left", padx=6, fill="x", expand=True)

send_btn   = ttk.Button(toolbar, text="Send", bootstyle=SUCCESS)
send_btn.pack(side="left", padx=6)
cancel_btn = ttk.Button(toolbar, text="Cancel", bootstyle=DANGER, state="disabled")
cancel_btn.pack(side="left")

nb = ttk.Notebook(root)
nb.pack(fill="both", expand=True, padx=6, pady=6)

tab_request  = ttk.Frame(nb, padding=10); nb.add(tab_request,  text="Request")
tab_params   = ttk.Frame(nb, padding=10); nb.add(tab_params,   text="Params")
tab_headers  = ttk.Frame(nb, padding=10); nb.add(tab_headers,  text="Headers")
tab_body     = ttk.Frame(nb, padding=10); nb.add(tab_body,     text="Body")
tab_files    = ttk.Frame(nb, padding=10); nb.add(tab_files,    text="Files")
tab_batch    = ttk.Frame(nb, padding=10); nb.add(tab_batch,    text="Batch")
tab_response = ttk.Frame(nb, padding=10); nb.add(tab_response, text="Response")
tab_tests    = ttk.Frame(nb, padding=10); nb.add(tab_tests,    text="Tests")
tab_history  = ttk.Frame(nb, padding=10); nb.add(tab_history,  text="History")
tab_settings = ttk.Frame(nb, padding=10); nb.add(tab_settings, text="Settings")

def add_kv_row(parent, rows_list, key_w=20, val_w=30, is_file=False):
    row = ttk.Frame(parent)
    k = ttk.Entry(row, width=key_w)
    v = ttk.Entry(row, width=val_w)
    k.pack(side="left", padx=2); v.pack(side="left", padx=2)

    if is_file:
        def pick_file():
            path = filedialog.askopenfilename()
            if path:
                v.delete(0, tk.END); v.insert(0, path)
        ttk.Button(row, text="Browse", command=pick_file).pack(side="left", padx=2)

    del_btn = ttk.Button(row, text="X", width=2, bootstyle=DANGER,
                         command=lambda: (rows_list.remove((k, v)), row.destroy()))
    del_btn.pack(side="left", padx=2)
    row.pack(fill="x", pady=2)
    rows_list.append((k, v))

def collect_kv(rows_list):
    out = {}
    for k, v in rows_list:
        kk = k.get().strip(); vv = v.get().strip()
        if kk: out[kk] = vv
    return out

def set_text(widget: tk.Text, value: str):
    widget.config(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", value)
    widget.config(state="disabled")

def pretty_or_raw(text: str):
    if not pretty_var.get(): return text
    try:
        obj = json.loads(text)
        return json.dumps(obj, indent=2)
    except Exception:
        return text

req_actions = ttk.Frame(tab_request)
req_actions.pack(fill="x")
save_named_btn = ttk.Button(req_actions, text="Save as Named Request")
save_named_btn.pack(side="left")
ttk.Label(tab_request, text="Use the tabs to configure Params, Headers, Body, Files, Batch and Settings.").pack(anchor="w", pady=8)

params_rows = []
params_box = ttk.LabelFrame(tab_params, text="Query Params (key=value)", padding=8)
params_box.pack(fill="both", expand=True)
def add_param(): add_kv_row(params_box, params_rows)
ttk.Button(tab_params, text="Add Param", bootstyle=INFO, command=add_param).pack(anchor="w", pady=8)
add_param()

header_rows = []
headers_box = ttk.LabelFrame(tab_headers, text="Headers (key:value)", padding=8)
headers_box.pack(fill="both", expand=True)
def add_header(): add_kv_row(headers_box, header_rows)
ttk.Button(tab_headers, text="Add Header", bootstyle=INFO, command=add_header).pack(anchor="w", pady=8)
add_header()

ttk.Label(tab_body, text="Request Body (JSON or raw)").pack(anchor="w")
body_text = tk.Text(tab_body, height=18, undo=True, wrap="none")
body_text.pack(fill="both", expand=True, pady=(4,8))
def method_changed(_=None):
    body_text.config(state=("disabled" if method_var.get().upper()=="HEAD" else "normal"))
method_dd.bind("<<ComboboxSelected>>", method_changed)

file_rows = []
files_box = ttk.LabelFrame(tab_files, text="Files (multipart/form-data)", padding=8)
files_box.pack(fill="both", expand=True)
def add_file(): add_kv_row(files_box, file_rows, is_file=True)
ttk.Button(tab_files, text="Add File", bootstyle=INFO, command=add_file).pack(anchor="w", pady=8)

resp_split = ttk.Panedwindow(tab_response, orient="vertical")
resp_split.pack(fill="both", expand=True)
resp_tabs = ttk.Notebook(resp_split)
resp_body = tk.Text(resp_tabs, wrap="word", state="disabled")
resp_hdrs = tk.Text(resp_tabs, wrap="word", state="disabled")
resp_tabs.add(resp_body, text="Body"); resp_tabs.add(resp_hdrs, text="Headers")
resp_split.add(resp_tabs, weight=3)

metrics_bar = ttk.Frame(tab_response); metrics_bar.pack(fill="x", pady=(8,0))
response_code_label = ttk.Label(metrics_bar, text="Status: —")
response_time_label = ttk.Label(metrics_bar, text="Time: —")
response_size_label = ttk.Label(metrics_bar, text="Size: —")
response_code_label.pack(side="left", padx=10)
response_time_label.pack(side="left", padx=10)
response_size_label.pack(side="left", padx=10)

resp_actions = ttk.Frame(tab_response); resp_actions.pack(fill="x", pady=8)
pretty_var = tk.BooleanVar(value=True)
ttk.Checkbutton(resp_actions, text="Pretty JSON", variable=pretty_var).pack(side="left")
def copy_response():
    resp_body.config(state="normal"); txt = resp_body.get("1.0","end-1c"); resp_body.config(state="disabled")
    root.clipboard_clear(); root.clipboard_append(txt); update_status("Response copied.")
def save_response():
    resp_body.config(state="normal"); txt = resp_body.get("1.0","end-1c"); resp_body.config(state="disabled")
    fp = filedialog.asksaveasfilename(defaultextension=".txt",
                                      filetypes=[("All files","*.*"),("JSON","*.json"),("Text","*.txt")])
    if fp: open(fp,"w",encoding="utf-8").write(txt); update_status(f"Saved response to {fp}")
ttk.Button(resp_actions, text="Copy", command=copy_response).pack(side="left", padx=6)
ttk.Button(resp_actions, text="Save", command=save_response).pack(side="left", padx=6)

expected_status = tk.StringVar(value=""); contains_text  = tk.StringVar(value="")
ttk.Label(tab_tests, text="Expect Status Code").pack(anchor="w")
ttk.Entry(tab_tests, textvariable=expected_status, width=10).pack(anchor="w", pady=(0,6))
ttk.Label(tab_tests, text="Body must contain").pack(anchor="w")
ttk.Entry(tab_tests, textvariable=contains_text, width=40).pack(anchor="w")
tests_result = ttk.Label(tab_tests, text=""); tests_result.pack(anchor="w", pady=8)
def run_simple_tests(status_code, body_text_val):
    ok = True; msgs=[]
    if expected_status.get().strip():
        try:
            want = int(expected_status.get().strip())
            if status_code != want: ok=False; msgs.append(f"Status {status_code} ≠ {want}")
        except ValueError:
            ok=False; msgs.append("Invalid expected status")
    needle = contains_text.get().strip()
    if needle and needle not in body_text_val: ok=False; msgs.append(f"Missing '{needle}'")
    tests_result.config(text=("PASS" if ok else f"FAIL: {', '.join(msgs)}"),
                        bootstyle=(SUCCESS if ok else DANGER))

tab_history.columnconfigure(1, weight=1); tab_history.rowconfigure(0, weight=1)
history_list = tk.Listbox(tab_history); history_list.grid(row=0, column=0, sticky="nsw", padx=(0,8))
history_preview = tk.Text(tab_history, state="disabled", wrap="word"); history_preview.grid(row=0, column=1, sticky="nsew")
def populate_history():
    history_list.delete(0, tk.END)
    for req in request_history:
        history_list.insert(tk.END, req.get("name", f"{req.get('method','')} {req.get('url','')}"))
def load_history_file():
    global request_history
    request_history = load_json(HISTORY_FILE, [])
    populate_history()
load_history_file()
def on_history_select(_=None):
    sel = history_list.curselection()
    if not sel: return
    req = request_history[sel[0]]
    txt = json.dumps(req, indent=2)
    history_preview.config(state="normal"); history_preview.delete("1.0", "end"); history_preview.insert("1.0", txt)
    history_preview.config(state="disabled")
history_list.bind("<<ListboxSelect>>", on_history_select)
def load_selected_to_editor():
    sel = history_list.curselection()
    if not sel: return
    req = request_history[sel[0]]
    method_var.set(req.get("method","GET"))
    url_entry.delete(0, tk.END); url_entry.insert(0, req.get("url",""))
    for (k, v) in params_rows[:]: k.master.destroy()
    params_rows.clear()
    for pk, pv in req.get("params", {}).items():
        add_param(); params_rows[-1][0].insert(0, pk); params_rows[-1][1].insert(0, pv)
    for (k, v) in header_rows[:]: k.master.destroy()
    header_rows.clear()
    for hk, hv in req.get("headers", {}).items():
        add_header(); header_rows[-1][0].insert(0, hk); header_rows[-1][1].insert(0, hv)
    body_text.config(state="normal"); body_text.delete("1.0", "end")
    if req.get("body") is not None:
        try: body_text.insert("1.0", json.dumps(req["body"], indent=2))
        except Exception: body_text.insert("1.0", str(req["body"]))
    method_changed(); update_status("Loaded request into editor.")
def delete_selected_request():
    sel = history_list.curselection()
    if not sel: return
    del request_history[sel[0]]
    save_json(HISTORY_FILE, request_history); populate_history()
    history_preview.config(state="normal"); history_preview.delete("1.0","end"); history_preview.config(state="disabled")
    update_status("Deleted request.")
def export_collection():
    fp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")])
    if fp: save_json(fp, request_history); update_status(f"Exported to {fp}")
hist_btns = ttk.Frame(tab_history); hist_btns.grid(row=1, column=0, columnspan=2, sticky="ew", pady=8)
ttk.Button(hist_btns, text="Load to Editor", command=load_selected_to_editor).pack(side="left", padx=4)
ttk.Button(hist_btns, text="Export Collection", command=export_collection).pack(side="left", padx=4)
ttk.Button(hist_btns, text="Delete Selected", command=delete_selected_request).pack(side="left", padx=4)

auth_frame = ttk.LabelFrame(tab_settings, text="Auth", padding=8); auth_frame.pack(fill="x", pady=(0,8))
auth_mode = tk.StringVar(value="None")
ttk.Label(auth_frame, text="Mode").grid(row=0, column=0, sticky="w", padx=4, pady=2)
auth_combo = ttk.Combobox(auth_frame, textvariable=auth_mode,
                          values=["None", "Basic", "Bearer Token", "API Key in Header", "API Key in Query"],
                          state="readonly", width=24)
auth_combo.grid(row=0, column=1, sticky="w", padx=4, pady=2)
ttk.Label(auth_frame, text="Username").grid(row=1, column=0, sticky="w", padx=4, pady=2)
username_entry = ttk.Entry(auth_frame, width=36); username_entry.grid(row=1, column=1, sticky="w", padx=4, pady=2)
ttk.Label(auth_frame, text="Password/Secret").grid(row=2, column=0, sticky="w", padx=4, pady=2)
password_entry = ttk.Entry(auth_frame, show="*", width=36); password_entry.grid(row=2, column=1, sticky="w", padx=4, pady=2)
ttk.Label(auth_frame, text="Token / API Key").grid(row=3, column=0, sticky="w", padx=4, pady=2)
token_entry = ttk.Entry(auth_frame, width=50); token_entry.grid(row=3, column=1, sticky="w", padx=4, pady=2)
ttk.Label(auth_frame, text="API Key Header Name").grid(row=4, column=0, sticky="w", padx=4, pady=2)
api_key_header_name = ttk.Entry(auth_frame, width=36); api_key_header_name.insert(0, "Authorization")
api_key_header_name.grid(row=4, column=1, sticky="w", padx=4, pady=2)

opts_frame = ttk.LabelFrame(tab_settings, text="Options", padding=8); opts_frame.pack(fill="x", pady=(0,8))
ssl_var = tk.BooleanVar(value=False); redirect_var = tk.BooleanVar(value=True); timeout_var = tk.StringVar(value="30")
ttk.Checkbutton(opts_frame, text="Verify SSL", variable=ssl_var).grid(row=0, column=0, sticky="w", padx=4, pady=2)
ttk.Checkbutton(opts_frame, text="Follow Redirects", variable=redirect_var).grid(row=0, column=1, sticky="w", padx=4, pady=2)
ttk.Label(opts_frame, text="Timeout (s)").grid(row=0, column=2, sticky="w", padx=4, pady=2)
ttk.Entry(opts_frame, textvariable=timeout_var, width=6).grid(row=0, column=3, sticky="w", padx=4, pady=2)

ui_frame = ttk.LabelFrame(tab_settings, text="UI / Utilities", padding=8); ui_frame.pack(fill="x")
theme_var = tk.StringVar(value=style.theme.name)
ttk.Label(ui_frame, text="Theme").grid(row=0, column=0, sticky="w", padx=4, pady=2)
ttk.Combobox(ui_frame, textvariable=theme_var, values=style.theme_names(), state="readonly", width=18)\
   .grid(row=0, column=1, sticky="w", padx=4, pady=2)
def apply_theme(): style.theme_use(theme_var.get())
ttk.Button(ui_frame, text="Apply Theme", command=apply_theme).grid(row=0, column=2, padx=6)

def import_curl():
    text = simpledialog.askstring("Import cURL", "Paste curl command:"); 
    if not text: return
    try:
        parts = shlex.split(text)
        if parts[0].lower() != "curl": raise ValueError("Not a curl command")
        m = "GET"; headers_local=[]; data_raw=None; url_local=None; i = 1
        while i < len(parts):
            p = parts[i]
            if p.upper() in ("-X","--request"): i += 1; m = parts[i].upper()
            elif p in ("-H","--header"): i += 1; headers_local.append(parts[i])
            elif p in ("-d","--data","--data-raw","--data-binary"): i += 1; data_raw = parts[i]
            elif p.startswith("http"): url_local = p
            i += 1
        if url_local: url_entry.delete(0, tk.END); url_entry.insert(0, url_local)
        method_var.set(m)
        for (k, v) in header_rows[:]: k.master.destroy()
        header_rows.clear(); add_header()
        for h in headers_local:
            if ":" in h:
                k, v = h.split(":", 1)
                add_header(); header_rows[-1][0].insert(0, k.strip()); header_rows[-1][1].insert(0, v.strip())
        if data_raw:
            body_text.config(state="normal"); body_text.delete("1.0","end"); body_text.insert("1.0", data_raw)
        update_status("cURL imported.")
    except Exception as e:
        messagebox.showerror("Import failed", f"Could not parse cURL:\n{e}")
ttk.Button(ui_frame, text="Import cURL", command=import_curl).grid(row=0, column=3, padx=6)

def save_config():
    cfg = {
        "auth_mode": auth_mode.get(), "username": username_entry.get(),
        "verify_ssl": ssl_var.get(), "follow_redirects": redirect_var.get(),
        "timeout": timeout_var.get(), "theme": theme_var.get(),
        "api_key_header_name": api_key_header_name.get(),
    }
    save_json(CONFIG_FILE, cfg); update_status("Config saved.")
def load_config():
    cfg = load_json(CONFIG_FILE, {})
    if not cfg: return
    auth_mode.set(cfg.get("auth_mode","None"))
    username_entry.delete(0, tk.END); username_entry.insert(0, cfg.get("username",""))
    ssl_var.set(cfg.get("verify_ssl", False)); redirect_var.set(cfg.get("follow_redirects", True))
    timeout_var.set(cfg.get("timeout", "30"))
    api_key_header_name.delete(0, tk.END); api_key_header_name.insert(0, cfg.get("api_key_header_name","Authorization"))
    t = cfg.get("theme", style.theme.name); theme_var.set(t); style.theme_use(t)
ttk.Button(ui_frame, text="Save Config", command=save_config).grid(row=0, column=4, padx=6)
ttk.Button(ui_frame, text="Reload Config", command=load_config).grid(row=0, column=5, padx=6)

def build_auth(headers, params):
    mode = auth_mode.get(); user = username_entry.get(); pwd = password_entry.get()
    token = token_entry.get(); key_header = api_key_header_name.get().strip() or "Authorization"
    if mode == "None": return None
    if mode == "Basic": return requests.auth.HTTPBasicAuth(user, pwd)
    if mode == "Bearer Token": headers["Authorization"] = f"Bearer {token}"; return None
    if mode == "API Key in Header": headers[key_header] = token; return None
    if mode == "API Key in Query": params["api_key"] = token; return None
    return None

def attach_default_headers(headers, has_body, has_files):
    if has_files: return
    if has_body and not any(h.lower()=="content-type" for h in headers.keys()):
        headers["Content-Type"] = "application/json"

def ui_error(msg):
    messagebox.showerror("Request Error", msg)
    update_status("Error")

def cancel_request():
    stop_event.set()
    update_status("Cancel requested; will stop on next timeout.")

def make_request():
    send_btn.config(state="disabled"); cancel_btn.config(state="normal")
    update_status("Sending request..."); stop_event.clear()
    def worker():
        try:
            url = url_entry.get().strip(); method = method_var.get().upper()
            try: timeout = float(timeout_var.get())
            except ValueError: timeout = 30.0
            headers = collect_kv(header_rows); params  = collect_kv(params_rows)
            files_kv = collect_kv(file_rows)
            files = None; has_files = False
            if files_kv:
                files = {}
                for k, path in files_kv.items():
                    try: files[k] = open(path, "rb")
                    except Exception as e: return ui_error(f"File error for {k}: {e}")
                has_files = True
            body_raw = body_text.get("1.0","end-1c").strip(); body_json = None
            if body_raw and not has_files:
                try: body_json = json.loads(body_raw)
                except Exception: body_json = None
            auth = build_auth(headers, params); attach_default_headers(headers, bool(body_raw), has_files)
            start = time.time()
            try:
                resp = requests.request(method, url, headers=headers, params=params,
                                        json=body_json if (body_json is not None and not has_files) else None,
                                        data=None if (body_json is not None or has_files or not body_raw) else body_raw.encode("utf-8"),
                                        files=files, verify=ssl_var.get(), allow_redirects=redirect_var.get(),
                                        timeout=timeout)
            finally:
                if files:
                    for f in files.values():
                        try: f.close()
                        except: pass
            dur  = round(time.time() - start, 2); size = len(resp.content or b"")
            response_code_label.config(text=f"Status: {resp.status_code}")
            response_time_label.config(text=f"Time: {dur}s"); response_size_label.config(text=f"Size: {size} bytes")
            if   200 <= resp.status_code < 300: response_code_label.configure(bootstyle=SUCCESS)
            elif 400 <= resp.status_code < 500: response_code_label.configure(bootstyle=WARNING)
            elif resp.status_code >= 500:       response_code_label.configure(bootstyle=DANGER)
            else:                                response_code_label.configure(bootstyle=SECONDARY)
            hdr_dump = "\n".join([f"{k}: {v}" for k, v in resp.headers.items()]); set_text(resp_hdrs, hdr_dump)
            set_text(resp_body, pretty_or_raw(resp.text or "")); run_simple_tests(resp.status_code, resp.text or "")
            entry = {"name": f"{method} {url}", "url": url, "method": method, "headers": headers,
                     "params": params, "body": json.loads(body_raw) if body_json is not None else (body_raw if body_raw else None),
                     "ts": time.time()}
            request_history.append(entry); save_json(HISTORY_FILE, request_history); populate_history()
            update_status(f"Done: {method} {url}")
        except requests.exceptions.RequestException as e:
            ui_error(str(e))
        except Exception as e:
            ui_error(str(e))
        finally:
            send_btn.config(state="normal"); cancel_btn.config(state="disabled")
    threading.Thread(target=worker, daemon=True).start()

send_btn.config(command=make_request); cancel_btn.config(command=cancel_request)

def save_current_request_as():
    name = simpledialog.askstring("Save Request", "Name:")
    if not name: return
    to_save = {"name": name, "url": url_entry.get().strip(), "method": method_var.get().upper(),
               "headers": collect_kv(header_rows), "params": collect_kv(params_rows), "body": None}
    raw = body_text.get("1.0","end-1c").strip()
    if raw:
        try: to_save["body"] = json.loads(raw)
        except Exception: to_save["body"] = raw
    request_history.append(to_save); save_json(HISTORY_FILE, request_history); populate_history()
    update_status(f"Saved request '{name}'")
save_named_btn.config(command=save_current_request_as)

def send_shortcut(_=None): make_request()
def save_shortcut(_=None): save_current_request_as()
def focus_url(_=None): url_entry.focus_set()
root.bind("<Control-Return>", send_shortcut)
root.bind("<Control-s>", save_shortcut)
root.bind("<F6>", focus_url)

tab_batch.columnconfigure(0, weight=1); tab_batch.rowconfigure(3, weight=1)

batch_cfg = ttk.LabelFrame(tab_batch, text="Batch Config", padding=8); batch_cfg.grid(row=0, column=0, sticky="ew", pady=(0,8))
ttk.Label(batch_cfg, text="Param name to replace").grid(row=0, column=0, sticky="w")
sku_param_var = tk.StringVar(value="part_number")
ttk.Entry(batch_cfg, textvariable=sku_param_var, width=20).grid(row=0, column=1, sticky="w", padx=6)

ttk.Label(batch_cfg, text="Requests/min").grid(row=0, column=2, sticky="w", padx=(12,0))
rpm_var = tk.StringVar(value="150"); ttk.Entry(batch_cfg, textvariable=rpm_var, width=6).grid(row=0, column=3, sticky="w", padx=6)
ttk.Label(batch_cfg, text="Workers").grid(row=0, column=4, sticky="w", padx=(12,0))
workers_var = tk.StringVar(value="4"); ttk.Entry(batch_cfg, textvariable=workers_var, width=4).grid(row=0, column=5, sticky="w", padx=6)

append_var = tk.BooleanVar(value=True)
skip_done_var = tk.BooleanVar(value=True)
ttk.Checkbutton(batch_cfg, text="Append output", variable=append_var).grid(row=1, column=0, sticky="w", pady=4)
ttk.Checkbutton(batch_cfg, text="Skip already processed (resume)", variable=skip_done_var).grid(row=1, column=1, sticky="w", pady=4)

src = ttk.LabelFrame(tab_batch, text="Input SKUs", padding=8); src.grid(row=1, column=0, sticky="ew", pady=(0,8))
source_mode = tk.StringVar(value="csv")
ttk.Radiobutton(src, text="CSV (column)", value="csv",    variable=source_mode).grid(row=0, column=0, sticky="w")
ttk.Radiobutton(src, text="TXT (one per line)", value="txt",     variable=source_mode).grid(row=0, column=1, sticky="w")
ttk.Radiobutton(src, text="Paste", value="paste", variable=source_mode).grid(row=0, column=2, sticky="w")

ttk.Label(src, text="File").grid(row=1, column=0, sticky="w")
batch_file_var = tk.StringVar(value="")
def pick_batch_file():
    p = filedialog.askopenfilename(filetypes=[("All", "*.*"),("CSV","*.csv"),("Text","*.txt")])
    if p: batch_file_var.set(p)
ttk.Entry(src, textvariable=batch_file_var).grid(row=1, column=1, sticky="ew", padx=6)
src.columnconfigure(1, weight=1)
ttk.Button(src, text="Browse", command=pick_batch_file).grid(row=1, column=2, sticky="w", padx=4)

ttk.Label(src, text="CSV Column").grid(row=2, column=0, sticky="w")
csv_col_var = tk.StringVar(value="part_number")
ttk.Entry(src, textvariable=csv_col_var, width=20).grid(row=2, column=1, sticky="w", padx=6)

ttk.Label(src, text="Paste SKUs (one per line)").grid(row=3, column=0, sticky="w", pady=(8,0))
paste_box = tk.Text(src, height=6); paste_box.grid(row=4, column=0, columnspan=3, sticky="ew")

out = ttk.LabelFrame(tab_batch, text="Output", padding=8); out.grid(row=2, column=0, sticky="ew", pady=(0,8))
ttk.Label(out, text="Output folder").grid(row=0, column=0, sticky="w")
out_dir_var = tk.StringVar(value=os.getcwd())
def pick_out_dir():
    p = filedialog.askdirectory()
    if p: out_dir_var.set(p)
ttk.Entry(out, textvariable=out_dir_var).grid(row=0, column=1, sticky="ew", padx=6)
out.columnconfigure(1, weight=1)
ttk.Button(out, text="Browse", command=pick_out_dir).grid(row=0, column=2, sticky="w")

ttk.Label(out, text="Base filename").grid(row=1, column=0, sticky="w")
base_file_var = tk.StringVar(value="batch_results")
ttk.Entry(out, textvariable=base_file_var, width=30).grid(row=1, column=1, sticky="w", padx=6)

ctrl = ttk.Frame(tab_batch); ctrl.grid(row=3, column=0, sticky="nsew"); tab_batch.rowconfigure(3, weight=1)
ctrl.columnconfigure(0, weight=1)

progress = ttk.Progressbar(ctrl, mode="determinate"); progress.grid(row=0, column=0, sticky="ew", pady=(0,6))
stats_var = tk.StringVar(value="Queued: 0 | Processed: 0 | Success: 0 | Errors: 0 | RPS: 0 | ETA: —")
stats_lbl = ttk.Label(ctrl, textvariable=stats_var); stats_lbl.grid(row=1, column=0, sticky="w")

btns = ttk.Frame(ctrl); btns.grid(row=2, column=0, sticky="w", pady=6)
start_btn  = ttk.Button(btns, text="Start / Resume", bootstyle=SUCCESS)
pause_btn  = ttk.Button(btns, text="Pause", bootstyle=WARNING)
cancel_btn2 = ttk.Button(btns, text="Cancel", bootstyle=DANGER)
start_btn.pack(side="left", padx=4); pause_btn.pack(side="left", padx=4); cancel_btn2.pack(side="left", padx=4)

class RateLimiter:
    def __init__(self, rpm: float):
        self.capacity = max(1.0, float(rpm))
        self.tokens   = self.capacity
        self.refill   = self.capacity / 60.0
        self.lock     = threading.Lock()
        self.last     = time.time()
    def acquire(self):
        while True:
            with self.lock:
                now = time.time()
                dt  = now - self.last
                self.tokens = min(self.capacity, self.tokens + dt * self.refill)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    self.last = now
                    return
                need = (1.0 - self.tokens) / self.refill
            if stop_event.is_set(): return
            time.sleep(max(need, 0.01))

def read_processed_set(ndjson_path):
    done = set()
    if not os.path.exists(ndjson_path): return done
    try:
        with open(ndjson_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                    if "sku" in obj: done.add(str(obj["sku"]))
                except Exception:
                    continue
    except Exception:
        pass
    return done

def load_skus_from_ui():
    mode = source_mode.get()
    fp   = batch_file_var.get().strip()
    skus = []
    if mode in ("csv","txt") and not fp:
        raise ValueError("Select an input file.")
    if mode == "csv":
        with open(fp, newline="", encoding="utf-8") as f:
            rdr = csv.DictReader(f)
            col = csv_col_var.get().strip()
            if not col: raise ValueError("Provide CSV column name.")
            for row in rdr:
                val = str(row.get(col, "")).strip()
                if val: skus.append(val)
    elif mode == "txt":
        with open(fp, "r", encoding="utf-8") as f:
            for line in f:
                val = line.strip()
                if val: skus.append(val)
    elif mode == "paste":
        txt = paste_box.get("1.0","end-1c")
        for line in txt.splitlines():
            val = line.strip()
            if val: skus.append(val)
    else:
        raise ValueError("Unsupported source.")
    seen=set(); out=[]
    for s in skus:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

batch_state = {
    "total": 0, "processed": 0, "success": 0, "errors": 0,
    "start_time": None, "q": None, "threads": [], "running": False
}
write_lock = threading.Lock()

def update_batch_stats_periodic():
    if not batch_state["running"]: return
    tot = batch_state["total"]; proc = batch_state["processed"]; ok = batch_state["success"]; err = batch_state["errors"]
    elapsed = max(1e-6, time.time() - (batch_state["start_time"] or time.time()))
    rps = proc / elapsed
    rem = max(0, tot - proc)
    eta = "—" if proc == 0 else f"{int(rem/max(rps,1e-6))}s"
    progress["maximum"] = max(1, tot); progress["value"] = proc
    stats_var.set(f"Queued: {tot} | Processed: {proc} | Success: {ok} | Errors: {err} | RPS: {rps:.1f} | ETA: {eta}")
    root.after(300, update_batch_stats_periodic)

def start_or_resume_batch():
    try:
        url = url_entry.get().strip()
        if not url: raise ValueError("URL is required.")
        method = method_var.get().upper()
        param_name = sku_param_var.get().strip() or "part_number"
        rpm = float(rpm_var.get()); workers = int(workers_var.get()); assert rpm>0 and workers>0
        base_headers = collect_kv(header_rows); base_params = collect_kv(params_rows)
        body_raw = body_text.get("1.0","end-1c").strip()
        body_json = None
        if body_raw:
            try: body_json = json.loads(body_raw)
            except Exception: body_json = None

        out_dir = out_dir_var.get().strip() or os.getcwd()
        base_fn = base_file_var.get().strip() or "batch_results"
        ndjson_path  = os.path.join(out_dir, f"{base_fn}.ndjson")
        failures_csv = os.path.join(out_dir, f"{base_fn}.failures.csv")

        os.makedirs(out_dir, exist_ok=True)
        mode = "a" if append_var.get() else "w"
        if not os.path.exists(failures_csv) or not append_var.get():
            with open(failures_csv, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f); w.writerow(["sku","status","error"])

        skus = load_skus_from_ui()
        if not skus: raise ValueError("No SKUs loaded.")
        processed_set = read_processed_set(ndjson_path) if skip_done_var.get() else set()
        if processed_set:
            skus = [s for s in skus if s not in processed_set]

        q = queue.Queue()
        for s in skus: q.put(s)

        batch_state.update({"total": len(skus), "processed": 0, "success": 0, "errors": 0,
                            "start_time": time.time(), "q": q, "threads": [], "running": True})
        progress["value"] = 0; update_batch_stats_periodic()
        pause_event.clear(); stop_event.clear()

        limiter = RateLimiter(rpm)
        session = requests.Session()

        def worker():
            while not stop_event.is_set():
                while pause_event.is_set() and not stop_event.is_set():
                    time.sleep(0.05)
                try:
                    sku = q.get_nowait()
                except queue.Empty:
                    return
                try:
                    headers = dict(base_headers)
                    params  = dict(base_params)
                    params[param_name] = sku
                    auth = build_auth(headers, params)
                    attach_default_headers(headers, has_body=bool(body_raw), has_files=False)

                    try: timeout = float(timeout_var.get())
                    except ValueError: timeout = 30.0

                    limiter.acquire()
                    start_t = time.time()
                    resp = session.request(
                        method, url, headers=headers, params=params,
                        json=body_json if body_json is not None else None,
                        data=None if (body_json is not None or not body_raw) else body_raw.encode("utf-8"),
                        verify=ssl_var.get(), allow_redirects=redirect_var.get(), timeout=timeout
                    )
                    ok = (200 <= resp.status_code < 300)
                    obj = {
                        "ts": datetime.utcnow().isoformat()+"Z",
                        "sku": sku,
                        "status": resp.status_code,
                        "ok": ok,
                        "elapsed_s": round(time.time()-start_t, 3),
                        "response": None
                    }
                    obj["response"] = resp.text

                    with write_lock:
                        with open(ndjson_path, mode, encoding="utf-8") as f:
                            f.write(json.dumps(obj, ensure_ascii=False) + "\n")
                        if not ok:
                            with open(failures_csv, "a", newline="", encoding="utf-8") as f2:
                                w = csv.writer(f2); w.writerow([sku, resp.status_code, (resp.text[:200] if resp.text else "")])
                    if ok: batch_state["success"] += 1
                    else:  batch_state["errors"]  += 1
                except requests.exceptions.RequestException as e:
                    with write_lock:
                        with open(failures_csv, "a", newline="", encoding="utf-8") as f2:
                            w = csv.writer(f2); w.writerow([sku, "REQUEST_ERROR", str(e)[:200]])
                except Exception as e:
                    with write_lock:
                        with open(failures_csv, "a", newline="", encoding="utf-8") as f2:
                            w = csv.writer(f2); w.writerow([sku, "EXCEPTION", str(e)[:200]])
                finally:
                    batch_state["processed"] += 1
                    q.task_done()

        threads = []
        for _ in range(workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start(); threads.append(t)
        batch_state["threads"] = threads

        def monitor():
            while any(t.is_alive() for t in threads) and not stop_event.is_set():
                time.sleep(0.15)
            batch_state["running"] = False
            update_status(f"Batch finished. Output: {ndjson_path} | Failures: {failures_csv}")

        threading.Thread(target=monitor, daemon=True).start()
        update_status(f"Started batch: {len(skus)} SKUs → {base_fn}.ndjson")
    except Exception as e:
        ui_error(str(e))

def pause_batch():
    if not batch_state["running"]: return
    if not pause_event.is_set():
        pause_event.set(); update_status("Batch paused.")
        pause_btn.config(text="Resume", bootstyle=SUCCESS)
    else:
        pause_event.clear(); update_status("Batch resumed.")
        pause_btn.config(text="Pause", bootstyle=WARNING)

def cancel_batch():
    if not batch_state["running"]: return
    stop_event.set(); pause_event.clear()
    update_status("Cancel requested; workers will stop shortly.")

start_btn.config(command=start_or_resume_batch)
pause_btn.config(command=pause_batch)
cancel_btn2.config(command=cancel_batch)

def focus_batch(_=None): nb.select(tab_batch)
root.bind("<F7>", focus_batch)

load_config(); method_changed()
update_status("Ready. Ctrl+Enter=Send · Ctrl+S=Save · F6=URL · F7=Batch")
root.mainloop()
