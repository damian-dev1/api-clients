#!/usr/bin/env python3
# Tokyo Midnight API Client (ttkbootstrap)
# - Fixes: safe header/param row handling (no TclError on destroyed widgets)
# - Sidebar toggles by clicking empty space; compact on launch; consistent after theme change
# - Bottom bar shows color-coded HTTP status
# - History tab has resizable sash between Saved Requests and Preview
# - Request code preview generation
# - Import/Export history collection
# - Does not store passwords by default

import os, json, time, re, keyword
import tkinter as tk
from tkinter import filedialog, simpledialog
from ttkbootstrap import ttk, Style
import tkinter.font as tkfont
import requests
from urllib.parse import parse_qsl

HISTORY_FILE = "request_history.json"
request_history = []

# -------------------- Tooltip helper --------------------
class ToolTip:
    def __init__(self, widget, text: str, delay=500):
        self.widget = widget; self.text = text; self.delay = delay
        self.tip = None; self._after_id = None
        widget.bind("<Enter>", self._schedule); widget.bind("<Leave>", self._hide)
        widget.bind("<ButtonPress>", self._hide)
    def _schedule(self, _=None):
        self._cancel(); self._after_id = self.widget.after(self.delay, self._show)
    def _show(self):
        if self.tip or not self.text: return
        x = self.widget.winfo_rootx() + 10
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        self.tip = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True); tw.wm_attributes("-topmost", True)
        frm = ttk.Frame(tw, padding=6, style="tooltip.TFrame")
        ttk.Label(frm, text=self.text, style="tooltip.TLabel", justify="left").pack()
        frm.pack(fill="both", expand=True); tw.wm_geometry(f"+{x}+{y}")
    def _hide(self, _=None):
        self._cancel()
        if self.tip:
            try: self.tip.destroy()
            except tk.TclError: pass
            self.tip = None
    def _cancel(self):
        if self._after_id:
            try: self.widget.after_cancel(self._after_id)
            except tk.TclError: pass
            self._after_id = None

def add_tooltip(w, text, delay=450):
    try: return ToolTip(w, text, delay)
    except: return None

# -------------------- Syntax highlighting --------------------
def _clear_tags(widget, tags):
    for t in tags:
        try: widget.tag_remove(t, "1.0", "end")
        except tk.TclError: pass

def highlight_json(widget):
    if "j_str" not in widget.tag_names():
        widget.tag_configure("j_str", foreground="#C3E88D")
        widget.tag_configure("j_num", foreground="#F78C6C")
        widget.tag_configure("j_bool", foreground="#FFCB6B")
        widget.tag_configure("j_null", foreground="#FF5370")
        widget.tag_configure("j_brace", foreground="#89DDFF")
        widget.tag_configure("j_key", foreground="#82AAFF")
    _clear_tags(widget, ("j_str","j_num","j_bool","j_null","j_brace","j_key"))
    text = widget.get("1.0", "end-1c")
    for m in re.finditer(r'"([^"\\]|\\.)*"', text):
        s, e = m.span(); widget.tag_add("j_str", f"1.0+{s}c", f"1.0+{e}c")
    for m in re.finditer(r'("([^"\\]|\\.)*")\s*:', text):
        s, e = m.span(1); widget.tag_add("j_key", f"1.0+{s}c", f"1.0+{e}c")
    for m in re.finditer(r'\b-?(0|[1-9]\d*)(\.\d+)?([eE][+\-]?\d+)?\b', text):
        s, e = m.span(); widget.tag_add("j_num", f"1.0+{s}c", f"1.0+{e}c")
    for m in re.finditer(r'\b(true|false)\b', text, re.I):
        s, e = m.span(); widget.tag_add("j_bool", f"1.0+{s}c", f"1.0+{e}c")
    for m in re.finditer(r'\bnull\b', text, re.I):
        s, e = m.span(); widget.tag_add("j_null", f"1.0+{s}c", f"1.0+{e}c")
    for m in re.finditer(r'[{}\[\]]', text):
        s, e = m.span(); widget.tag_add("j_brace", f"1.0+{s}c", f"1.0+{e}c")

def highlight_python(widget):
    if "py_kw" not in widget.tag_names():
        widget.tag_configure("py_kw", foreground="#C792EA")
        widget.tag_configure("py_str", foreground="#C3E88D")
        widget.tag_configure("py_num", foreground="#F78C6C")
        widget.tag_configure("py_cmt", foreground="#5C6370")
        widget.tag_configure("py_name", foreground="#82AAFF")
    _clear_tags(widget, ("py_kw","py_str","py_num","py_cmt","py_name"))
    text = widget.get("1.0", "end-1c")
    for m in re.finditer(r'#.*', text):
        widget.tag_add("py_cmt", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
    for m in re.finditer(r"('([^'\\]|\\.)*'|\"([^\"\\]|\\.)*\")", text):
        widget.tag_add("py_str", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
    for m in re.finditer(r'\b\d+(\.\d+)?\b', text):
        widget.tag_add("py_num", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
    kw = r'\b(' + '|'.join(keyword.kwlist) + r')\b'
    for m in re.finditer(kw, text):
        widget.tag_add("py_kw", f"1.0+{m.start()}c", f"1.0+{m.end()}c")
    for m in re.finditer(r'\b(requests|response|resp|headers|params|json|data)\b', text):
        widget.tag_add("py_name", f"1.0+{m.start()}c", f"1.0+{m.end()}c")

# -------------------- App Setup --------------------
root = tk.Tk()
root.title("Tokyo Midnight API Client")
root.geometry("900x760")
root.resizable(True, True)

style = Style("darkly")
style.configure("tooltip.TFrame", background="#222638", relief="flat", borderwidth=0)
style.configure("tooltip.TLabel", background="#222638", foreground="#E6F3FF", font=("Segoe UI", 9))

mono_font = tkfont.Font(family=("Consolas", "Courier New", "Menlo", "monospace"), size=10)

def _emoji_font():
    preferred = ["Segoe UI Emoji", "Apple Color Emoji", "Noto Color Emoji",
                 "Twemoji Mozilla", "EmojiOne Color", "Segoe UI Symbol"]
    avail = set(tkfont.families())
    for f in preferred:
        if f in avail: return f
    return "Segoe UI"
ICON_FONT = tkfont.Font(family=_emoji_font(), size=15)

def apply_sidebar_styles():
    # Reapply custom styles after theme changes so padding/size stays consistent
    style.configure("SidebarIcon.TButton", font=ICON_FONT, padding=(6, 6))
    style.configure("SidebarIconActive.TButton", font=ICON_FONT, padding=(6, 6))
    style.map("SidebarIconActive.TButton",
              background=[("!disabled", style.colors.primary)],
              foreground=[("!disabled", style.colors.light)])

apply_sidebar_styles()

# -------------------- Top Bar --------------------
root.grid_columnconfigure(0, weight=1)
top_bar = ttk.Frame(root, padding=(10, 10, 10, 5))
top_bar.grid(row=0, column=0, sticky="ew")
top_bar.grid_columnconfigure(2, weight=1)

method_var = tk.StringVar(value="GET")
method_dropdown = ttk.Combobox(
    top_bar, textvariable=method_var,
    values=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], width=8, state="readonly")
method_dropdown.grid(row=0, column=0, sticky="w")
add_tooltip(method_dropdown, "HTTP method")

ttk.Label(top_bar, text="URL").grid(row=0, column=1, sticky="w", padx=(10, 5))
url_entry = ttk.Entry(top_bar); url_entry.grid(row=0, column=2, sticky="ew")
add_tooltip(url_entry, "Request URL (F6 to focus)")
send_button = ttk.Button(top_bar, text="▶ Send", bootstyle="success", width=8)
send_button.grid(row=0, column=3, sticky="e", padx=(6, 0))
add_tooltip(send_button, "Send request (Ctrl+Enter)")

ttk.Separator(root, orient="horizontal").grid(row=1, column=0, sticky="ew")

# -------------------- Main Paned (sidebar ↔ content) --------------------
main_paned = ttk.PanedWindow(root, orient="horizontal")
main_paned.grid(row=2, column=0, sticky="nsew")
root.grid_rowconfigure(2, weight=1)

left_pane  = ttk.Frame(main_paned)
right_pane = ttk.Frame(main_paned)
main_paned.add(left_pane,  weight=0)
main_paned.add(right_pane, weight=1)

# Sidebar sizing (small like screenshot)
ICON_BAR_WIDTH = 56          # collapsed width (icon-only)
EXP_DEFAULT   = 220          # expanded width
THRESHOLD     = ICON_BAR_WIDTH + 20
_sidebar_collapsed = True    # start compact
_last_sidebar_width = EXP_DEFAULT

def _sash():
    try: return main_paned.sashpos(0)
    except tk.TclError: return ICON_BAR_WIDTH

def _set_sidebar_width(px):
    try: main_paned.sashpos(0, max(px, 0))
    except tk.TclError: pass

def _apply_sidebar_mode(collapsed: bool, from_drag: bool=False):
    """Collapsed = icon-only fixed width; Expanded = icon + label."""
    global _sidebar_collapsed, _last_sidebar_width, active_tab
    _sidebar_collapsed = collapsed
    for key, meta in sidebar_buttons.items():
        b, icon, label = meta['button'], meta['icon'], meta['label']
        b.configure(text=icon if collapsed else f"{icon}  {label}",
                    width=(3 if collapsed else 18),
                    style="SidebarIconActive.TButton" if key == active_tab else "SidebarIcon.TButton")
    if not from_drag:
        if collapsed:
            _last_sidebar_width = max(_sash(), EXP_DEFAULT)
            _set_sidebar_width(ICON_BAR_WIDTH)
        else:
            _set_sidebar_width(max(_last_sidebar_width, EXP_DEFAULT))
    _set_active(active_tab)

def _toggle_sidebar(_=None): _apply_sidebar_mode(not _sidebar_collapsed, from_drag=False)

def _on_sash_drag(event):
    pos = _sash()
    if pos < THRESHOLD and not _sidebar_collapsed:
        _apply_sidebar_mode(True, from_drag=True)
    elif pos >= THRESHOLD and _sidebar_collapsed:
        _apply_sidebar_mode(False, from_drag=True)
    else:
        global _last_sidebar_width
        if not _sidebar_collapsed:
            _last_sidebar_width = pos
        _set_sidebar_width(pos)
main_paned.bind("<B1-Motion>", _on_sash_drag)

# -------------------- Left sidebar (buttons) --------------------
left_pane.grid_rowconfigure(1, weight=1)
top_btns = ttk.Frame(left_pane, padding=(6,8,6,4)); top_btns.grid(row=0, column=0, sticky="n")
click_catcher = ttk.Frame(left_pane); click_catcher.grid(row=1, column=0, sticky="nsew")
click_catcher.bind("<Button-1>", _toggle_sidebar)  # toggle sidebar by clicking empty space
bottom_area = ttk.Frame(left_pane, padding=(6,6,6,6)); bottom_area.grid(row=2, column=0, sticky="s")

active_tab = "request"
sidebar_buttons = {}

def _show_tab(name):
    for f in (req_content_frame, auth_content_frame, hist_content_frame, settings_content_frame):
        f.grid_forget()
    if name == "request":   req_content_frame.grid(row=0, column=0, sticky="nsew")
    elif name == "auth":    auth_content_frame.grid(row=0, column=0, sticky="nsew")
    elif name == "history": hist_content_frame.grid(row=0, column=0, sticky="nsew")
    else:                   settings_content_frame.grid(row=0, column=0, sticky="nsew")

def _set_active(btn_key):
    global active_tab
    active_tab = btn_key
    for k, meta in sidebar_buttons.items():
        b = meta['button']
        b.configure(style="SidebarIconActive.TButton" if k == active_tab else "SidebarIcon.TButton")
    _show_tab(btn_key)

def _mk_sidebar_btn(parent, icon: str, label: str, key: str, tooltip: str):
    b = ttk.Button(parent, text=icon, width=3, style="SidebarIcon.TButton",
                   command=lambda k=key: _set_active(k))
    b.pack(pady=4, fill="x")
    add_tooltip(b, tooltip)
    sidebar_buttons[key] = {'button': b, 'icon': icon, 'label': label}

_mk_sidebar_btn(top_btns, "📡", "Request", "request", "Request")
_mk_sidebar_btn(top_btns, "🔐", "Auth",    "auth",    "Authentication")
_mk_sidebar_btn(top_btns, "🕘", "History", "history", "History")
_mk_sidebar_btn(bottom_area, "⚙️", "Settings", "settings", "Settings")
_mk_sidebar_btn(bottom_area, "❓", "Help",    "help",    "Help (opens GitHub page)")
def _open_help():
    import webbrowser
    webbrowser.open("https://github.com/damian-dev1/Ecommerce-Manager")
sidebar_buttons["help"]['button'].configure(command=_open_help)

right_pane.grid_rowconfigure(0, weight=1)
right_pane.grid_columnconfigure(0, weight=1)
req_content_frame       = ttk.Frame(right_pane)
auth_content_frame      = ttk.Frame(right_pane, padding=10)
hist_content_frame      = ttk.Frame(right_pane, padding=10)
settings_content_frame  = ttk.Frame(right_pane, padding=10)
req_content_frame.grid(row=0, column=0, sticky="nsew")
auth_content_frame.grid(row=0, column=0, sticky="nsew")
hist_content_frame.grid(row=0, column=0, sticky="nsew")
settings_content_frame.grid(row=0, column=0, sticky="nsew")
_show_tab("request")

req_vpaned = ttk.PanedWindow(req_content_frame, orient="vertical")
req_vpaned.pack(fill="both", expand=True)

req_editor = ttk.Frame(req_vpaned)
resp_frame = ttk.Frame(req_vpaned)
req_vpaned.add(req_editor, weight=1)
req_vpaned.add(resp_frame, weight=2)

req_editor.grid_rowconfigure(0, weight=1)
req_editor.grid_columnconfigure(0, weight=1)
req_details_nb = ttk.Notebook(req_editor)
req_details_nb.grid(row=0, column=0, sticky='nsew', pady=(5,0))
params_tab  = ttk.Frame(req_details_nb, padding=5)
headers_tab = ttk.Frame(req_details_nb, padding=5)
body_tab    = ttk.Frame(req_details_nb, padding=5)
req_details_nb.add(params_tab,  text="Params")
req_details_nb.add(headers_tab, text="Headers")
req_details_nb.add(body_tab,    text="Body")

def _track_row(rows_list, row, k, v):
    def _on_destroy(_evt):
        try: rows_list.remove((k, v, row))
        except ValueError: pass
    row.bind("<Destroy>", _on_destroy)

def _collect_kv(rows_list):
    out = {}
    for k, v, row in list(rows_list):
        if not (k.winfo_exists() and v.winfo_exists()):
            try: rows_list.remove((k, v, row))
            except ValueError: pass
            continue
        key = k.get().strip()
        if key:
            out[key] = v.get().strip()
    return out

params_frame = ttk.Frame(params_tab)
params_frame.pack(fill="x", pady=(4, 0))
param_rows = []

def add_param(key: str = "", val: str = ""):
    row = ttk.Frame(params_frame)
    row.pack(fill="x", pady=2)
    row.grid_columnconfigure(0, weight=1)
    row.grid_columnconfigure(1, weight=2)

    k = ttk.Entry(row, font=mono_font)
    v = ttk.Entry(row, font=mono_font)
    k.insert(0, key or "")
    v.insert(0, val or "")

    def _remove():
        try: param_rows.remove((k, v, row))
        except ValueError: pass
        row.destroy()

    ttk.Button(row, text="✕", width=3, bootstyle="danger-outline", command=_remove)\
        .grid(row=0, column=2, sticky="e")
    k.grid(row=0, column=0, sticky="ew", padx=(0, 6))
    v.grid(row=0, column=1, sticky="ew", padx=(0, 6))

    param_rows.append((k, v, row))
    _track_row(param_rows, row, k, v)

ttk.Button(params_frame, text="➕ Add Param", bootstyle="info", command=add_param)\
    .pack(anchor="w", pady=(6, 0))
add_param("key", "value")

headers_frame = ttk.Frame(headers_tab)
headers_frame.pack(fill="x", pady=(4, 0))
header_rows = []

def add_header(key: str = "", val: str = ""):
    row = ttk.Frame(headers_frame)
    row.pack(fill="x", pady=2)
    row.grid_columnconfigure(0, weight=1)
    row.grid_columnconfigure(1, weight=2)

    k = ttk.Entry(row, font=mono_font)
    v = ttk.Entry(row, font=mono_font)
    k.insert(0, key or "")
    v.insert(0, val or "")

    def _remove():
        try: header_rows.remove((k, v, row))
        except ValueError: pass
        row.destroy()

    ttk.Button(row, text="✕", width=3, bootstyle="danger-outline", command=_remove)\
        .grid(row=0, column=2, sticky="e")
    k.grid(row=0, column=0, sticky="ew", padx=(0, 6))
    v.grid(row=0, column=1, sticky="ew", padx=(0, 6))

    header_rows.append((k, v, row))
    _track_row(header_rows, row, k, v)

ttk.Button(headers_frame, text="➕ Add Header", bootstyle="info", command=add_header)\
    .pack(anchor="w", pady=(6, 0))
add_header("Content-Type", "application/json")

body_box = ttk.LabelFrame(body_tab, text="Body"); body_box.pack(fill="both", expand=True)
body_mode = tk.StringVar(value="json")
mode_bar = ttk.Frame(body_box); mode_bar.pack(anchor="w", pady=(0,6))
for text, val in (("None","none"),("JSON","json"),("Raw Text","text"),("Form (key=val)","form")):
    ttk.Radiobutton(mode_bar, text=text, value=val, variable=body_mode).pack(side="left", padx=2)

body_text = tk.Text(
    body_box, height=10, bg="#0f0f1f", fg="#cfcfff", insertbackground="#cfcfff",
    relief="flat", wrap="word", font=mono_font)
body_text.pack(fill="both", expand=True)

def _format_json():
    try:
        obj = json.loads(body_text.get("1.0","end-1c"))
        body_text.delete("1.0", tk.END); body_text.insert("1.0", json.dumps(obj, indent=2))
        highlight_json(body_text); flash_status("JSON formatted.", "success", 2000)
    except Exception as e:
        flash_status(f"JSON not valid: {e}", "warning")
ttk.Button(body_box, text="Format JSON", bootstyle="secondary", command=_format_json)\
    .pack(anchor="w", pady=(6,0))

# ---------------- Response ----------------
resp_frame.grid_rowconfigure(2, weight=1)
resp_frame.grid_columnconfigure(0, weight=1)
resp_actions = ttk.Frame(resp_frame); resp_actions.grid(row=0, column=0, sticky='ew', pady=(0, 5))
btn_copy = ttk.Button(resp_actions, text="Copy", bootstyle="info-outline")
btn_save = ttk.Button(resp_actions, text="Save Body", bootstyle="info-outline")
btn_clear = ttk.Button(resp_actions, text="Clear", bootstyle="danger-outline")
btn_copy_req = ttk.Button(resp_actions, text="Copy as requests", bootstyle="warning-outline")
for b in (btn_copy, btn_save, btn_clear, btn_copy_req): b.pack(side="left", padx=(0,5))

metrics = ttk.Frame(resp_frame); metrics.grid(row=1, column=0, sticky='ew', pady=(0,6))
status_lbl = ttk.Label(metrics, text="Status: —"); status_lbl.pack(side="left", padx=(0,10))
time_lbl   = ttk.Label(metrics, text="Time: —");   time_lbl.pack(side="left", padx=(0,10))
size_lbl   = ttk.Label(metrics, text="Size: —");   size_lbl.pack(side="left", padx=(0,10))

resp_nb = ttk.Notebook(resp_frame); resp_nb.grid(row=2, column=0, sticky='nsew')
resp_body = tk.Text(resp_nb, bg="#0f0f1f", fg="#cfcfff", insertbackground="#cfcfff", relief="flat", wrap="word", font=mono_font)
resp_hdrs = tk.Text(resp_nb, bg="#0f0f1f", fg="#cfcfff", insertbackground="#cfcfff", relief="flat", wrap="word", font=mono_font)
code_text = tk.Text(resp_nb, bg="#0f0f1f", fg="#cfcfff", insertbackground="#cfcfff", relief="flat", wrap="word", font=mono_font)
resp_nb.add(resp_body, text="Body"); resp_nb.add(resp_hdrs, text="Headers"); resp_nb.add(code_text, text="Code")

# ---------------- AUTH ----------------
auth_content_frame.grid_columnconfigure(0, weight=1)
credentials = ttk.LabelFrame(auth_content_frame, text="Authentication", padding=10); credentials.pack(fill="x", pady=10)
ttk.Label(credentials, text="Username").grid(row=0, column=0, sticky="w", pady=2)
username_entry = ttk.Entry(credentials, width=30); username_entry.grid(row=0, column=1, sticky="ew")
ttk.Label(credentials, text="Password").grid(row=1, column=0, sticky="w", pady=2)
password_entry = ttk.Entry(credentials, show="*", width=30); password_entry.grid(row=1, column=1, sticky="ew")
ttk.Label(credentials, text="Note: password is NOT saved in history by default.").grid(row=2, column=0, columnspan=2, sticky="w", pady=(6,0))
credentials.grid_columnconfigure(1, weight=1)
auth_instructions = ttk.Label(auth_content_frame, text="Currently only Basic Auth is supported.", foreground="#cccccc")
auth_instructions.pack(anchor="w", pady=(6,0))
settings_content_frame.grid_columnconfigure(0, weight=1)
options = ttk.LabelFrame(settings_content_frame, text="Request Options", padding=10); options.pack(fill="x", pady=10)
ssl_var = tk.BooleanVar(value=False); redirect_var = tk.BooleanVar(value=True)
pretty_var = tk.BooleanVar(value=True); wrap_var = tk.BooleanVar(value=True)
ttk.Checkbutton(options, text="Verify SSL", variable=ssl_var, bootstyle="secondary").pack(anchor="w")
ttk.Checkbutton(options, text="Follow Redirects", variable=redirect_var, bootstyle="secondary").pack(anchor="w")
ttk.Checkbutton(options, text="Pretty Print JSON", variable=pretty_var, bootstyle="secondary").pack(anchor="w")
ttk.Checkbutton(options, text="Wrap Response", variable=wrap_var, bootstyle="secondary").pack(anchor="w")

theme_box = ttk.LabelFrame(settings_content_frame, text="Appearance", padding=10)
theme_box.pack(fill="x", pady=10)
ttk.Label(theme_box, text="Theme").grid(row=0, column=0, sticky="w")
theme_var = tk.StringVar(value="darkly")
theme_cb = ttk.Combobox(
    theme_box, textvariable=theme_var, values=style.theme_names(),
    width=20, state="readonly"
)
theme_cb.grid(row=0, column=1, sticky="w")

def _apply_theme(event=None):
    style.theme_use(theme_var.get())
    apply_sidebar_styles()
    _apply_sidebar_mode(_sidebar_collapsed, from_drag=False)
theme_cb.bind("<<ComboboxSelected>>", _apply_theme)
theme_box.grid_columnconfigure(1, weight=1)
ttk.Label(theme_box, text="(Restart app to apply font changes)").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6,0))

hist_content_frame.grid_rowconfigure(0, weight=1)
hist_content_frame.grid_columnconfigure(0, weight=1)

hist_paned = ttk.PanedWindow(hist_content_frame, orient="vertical")
hist_paned.grid(row=0, column=0, sticky="nsew")

listbox_frame = ttk.LabelFrame(hist_paned, text="Saved Requests", padding=5)
preview_frame = ttk.LabelFrame(hist_paned, text="Request Preview", padding=5)
hist_paned.add(listbox_frame, weight=1)
hist_paned.add(preview_frame, weight=2)

hist_list = tk.Listbox(listbox_frame, height=10, bg="#0f0f1f", fg="#cfcfff",
                       selectbackground="#00d4c4", highlightthickness=0,
                       relief="flat", font=mono_font)
hist_list.pack(side="left", fill="both", expand=True)
scroll = ttk.Scrollbar(listbox_frame, orient="vertical", command=hist_list.yview)
scroll.pack(side="right", fill="y"); hist_list.config(yscrollcommand=scroll.set)

hist_preview = tk.Text(preview_frame, bg="#0f0f1f", fg="#cfcfff",
                       insertbackground="#cfcfff", relief="flat",
                       wrap="word", font=mono_font)
hist_preview.pack(fill="both", expand=True)

history_menu = tk.Menu(hist_list, tearoff=0)

hist_btns = ttk.Frame(hist_content_frame)
hist_btns.grid(row=1, column=0, sticky="ew", pady=(10,0))
ttk.Button(hist_btns, text="💾 Save", bootstyle="success-outline",
           command=lambda: save_to_history(simpledialog.askstring("Save Request", "Name:", parent=root) or None)).pack(side="left")
ttk.Button(hist_btns, text="📥 Import", bootstyle="secondary-outline",
           command=lambda: import_collection()).pack(side="left", padx=5)
ttk.Button(hist_btns, text="📤 Export", bootstyle="info-outline",
           command=lambda: export_collection()).pack(side="left", padx=5)
ttk.Button(hist_btns, text="🗑 Delete", bootstyle="danger-outline",
           command=lambda: _hist_delete()).pack(side="left", padx=5)


# -------------------- Bottom status bar --------------------
bottom_bar = ttk.Frame(root, padding=(8, 4))
bottom_bar.grid(row=3, column=0, sticky="ew")
bottom_bar.grid_columnconfigure(0, weight=1)
status_var = tk.StringVar(value="Ready")
status_lbl_bottom = ttk.Label(bottom_bar, textvariable=status_var, anchor="w")
status_lbl_bottom.grid(row=0, column=0, sticky="w")
resp_code_var = tk.StringVar(value="")
resp_code_lbl = ttk.Label(bottom_bar, textvariable=resp_code_var, anchor="e",
                          padding=(8, 2), bootstyle="secondary")
resp_code_lbl.grid(row=0, column=1, sticky="e")

def _color_for_status(code: int) -> str:
    if   100 <= code < 200: return "info"
    elif 200 <= code < 300: return "success"
    elif 300 <= code < 400: return "warning"
    elif 400 <= code < 600: return "danger"
    return "secondary"

def _set_resp_code(code: int|None, reason: str|None):
    if code is None:
        resp_code_var.set(""); resp_code_lbl.configure(bootstyle="secondary"); return
    style_name = _color_for_status(code) + "-inverse"
    resp_code_var.set(f"{code} {reason or ''}".strip())
    resp_code_lbl.configure(bootstyle=style_name)

def flash_status(msg: str, style_name: str = "info", duration_ms: int = 3000):
    status_var.set(msg); status_lbl_bottom.configure(bootstyle=style_name)
    if style_name != "info":
        root.after(duration_ms, lambda: status_lbl_bottom.configure(bootstyle="info"))
        root.after(duration_ms, lambda: status_var.set("Ready"))

def _params_dict():  return _collect_kv(param_rows)
def _headers_dict(): return _collect_kv(header_rows)

def _set_method_style(*_):
    m = method_var.get().upper()
    style_map = {"GET":"info","POST":"success","PUT":"warning","PATCH":"primary","DELETE":"danger","HEAD":"secondary"}
    method_dropdown.configure(bootstyle=style_map.get(m, "secondary"))
    state = "normal" if m not in ("GET", "HEAD") else "disabled"
    req_details_nb.tab(body_tab, state=state)

def populate_history():
    hist_list.delete(0, tk.END)
    for req in request_history:
        hist_list.insert(tk.END, req.get("name", f"{req.get('method','')} {req.get('url','')}"))

def load_history():
    global request_history
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f: request_history = json.load(f)
            if not isinstance(request_history, list): request_history = []
        except Exception:
            request_history = []
    populate_history()

def on_hist_select(_=None):
    sel = hist_list.curselection()
    if not sel: return
    req = request_history[sel[0]]
    hist_preview.delete("1.0", tk.END); hist_preview.insert("1.0", json.dumps(req, indent=2))

    method_var.set(req.get("method","GET")); _set_method_style()
    url_entry.delete(0, tk.END); url_entry.insert(0, req.get("url",""))

    for _, __, rf in list(header_rows):
        try: header_rows.remove((_[0] if isinstance(_, tuple) else _, __, rf))
        except Exception: pass
        rf.destroy()
    header_rows.clear()
    for k, v in (req.get("headers") or {}).items(): add_header(k, v)

    for _, __, rf in list(param_rows):
        try: param_rows.remove((_[0] if isinstance(_, tuple) else _, __, rf))
        except Exception: pass
        rf.destroy()
    param_rows.clear()
    for k, v in (req.get("params") or {}).items(): add_param(k, v)
    username_entry.delete(0, tk.END); username_entry.insert(0, req.get("auth_username",""))
    password_entry.delete(0, tk.END)

    body_mode.set(req.get("body_mode", "none"))
    body_text.delete("1.0", tk.END)
    if req.get("body") is not None:
        body_text.insert("1.0", req["body"])
        if body_mode.get()=="json": highlight_json(body_text)
    body_text.config(state="normal" if body_mode.get() != "none" else "disabled")

def save_to_history(name=None):
    if not name: name = f"{method_var.get()} {url_entry.get().strip()[:30] or '(no url)'}"
    req = {
        "name": name,
        "method": method_var.get(),
        "url": url_entry.get().strip(),
        "params": _params_dict(),
        "headers": _headers_dict(),
        "body_mode": body_mode.get(),
        "body": body_text.get("1.0","end-1c").strip() if body_mode.get() != "none" else None,
        "auth_username": username_entry.get().strip() or None,
    }
    request_history.append(req)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f: json.dump(request_history, f, indent=2)
    populate_history()
    flash_status("Saved to history.", "success", 2000)

def import_collection():
    fp = filedialog.askopenfilename(filetypes=[("JSON files","*.json")])
    if not fp: return
    try:
        with open(fp, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            request_history.clear()
            request_history.extend(data)
            with open(HISTORY_FILE, "w", encoding="utf-8") as f2: json.dump(request_history, f2, indent=2)
            populate_history()
            flash_status(f"Imported {len(request_history)} requests.", "success")
        else:
            flash_status("Invalid collection file.", "danger")
    except Exception as e:
        flash_status(f"Import failed: {e}", "danger")

def export_collection():
    fp = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")])
    if fp:
        with open(fp, "w", encoding="utf-8") as f: f.write(json.dumps(request_history, indent=2))
        flash_status(f"Exported to {fp}", "success")

_set_method_style()
method_var.trace_add("write", _set_method_style)
hist_list.bind("<<ListboxSelect>>", on_hist_select)
hist_list.bind("<Button-3>", lambda e: history_menu.tk_popup(e.x_root, e.y_root))

load_history()

def _hist_delete():
    sel = hist_list.curselection()
    if not sel: return
    del request_history[sel[0]]
    with open(HISTORY_FILE, "w", encoding="utf-8") as f: json.dump(request_history, f, indent=2)
    populate_history(); hist_preview.delete("1.0", tk.END); flash_status("Deleted.", "info", 2000)
    
def _show_hist_menu(event):
    try:
        hist_list.selection_clear(0, tk.END)
        hist_list.selection_set(hist_list.nearest(event.y))
        history_menu.tk_popup(event.x_root, event.y_root)
    finally:
        history_menu.grab_release()

def _hist_rename():
    sel = hist_list.curselection()
    if not sel: return
    idx = sel[0]
    current = request_history[idx].get("name","")
    new = simpledialog.askstring("Rename Request", "New name:", initialvalue=current, parent=root)
    if not new: return
    request_history[idx]["name"] = new
    with open(HISTORY_FILE, "w", encoding="utf-8") as f: json.dump(request_history, f, indent=2)
    populate_history(); hist_list.selection_set(idx)
hist_list.bind("<<ListboxSelect>>", on_hist_select)
hist_list.bind("<Button-3>", lambda e: history_menu.tk_popup(e.x_root, e.y_root))
history_menu.add_command(label="Load into Request", command=lambda: _set_active("request"))
history_menu.add_command(label="Delete", command=_hist_delete)
history_menu.add_command(label="Rename…", command=lambda: _hist_rename())
history_menu.add_separator()
history_menu.add_command(label="Delete", command=_hist_delete)

def _fill_response(resp, elapsed_s):
    status_lbl.config(text=f"Status: {resp.status_code}")
    time_lbl.config(text=f"Time: {elapsed_s:.2f}s")
    size_lbl.config(text=f"Size: {len(resp.content or b'')} bytes")

    hdr_dump = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    resp_hdrs.config(state="normal"); resp_hdrs.delete("1.0", tk.END); resp_hdrs.insert("1.0", hdr_dump); resp_hdrs.config(state="disabled")

    body_out = resp.text or ""
    if pretty_var.get():
        try: body_out = json.dumps(resp.json(), indent=2)
        except Exception: pass
    resp_body.config(state="normal"); resp_body.delete("1.0", tk.END); resp_body.insert("1.0", body_out); resp_body.config(state="disabled")
    try:
        json.loads(body_out)
        resp_body.config(state="normal"); highlight_json(resp_body); resp_body.config(state="disabled")
    except (json.JSONDecodeError, TypeError): pass

    code_text.config(state="normal"); code_text.delete("1.0", tk.END)
    code_text.insert("1.0", build_requests_snippet()); highlight_python(code_text); code_text.config(state="disabled")

    _set_resp_code(resp.status_code, getattr(resp, "reason", ""))

def build_requests_snippet():
    method, url = method_var.get().upper(), url_entry.get().strip()
    headers, params = _headers_dict(), _params_dict()
    headers_str = json.dumps(headers, indent=4) if headers else "{}"
    params_str = json.dumps(params, indent=4) if params else "{}"
    body_lines, body_block = [], ""
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        raw = body_text.get("1.0","end-1c").strip()
        if body_mode.get() == "json":
            try:
                payload = json.loads(raw) if raw else {}
                body_lines.append(f"json_payload = {json.dumps(payload, indent=4)}")
            except Exception:
                body_lines.append(f'# Invalid JSON body\njson_payload = {repr(raw)}')
        elif body_mode.get() == "form":
            payload = dict(parse_qsl("&".join([ln.strip() for ln in raw.splitlines() if ln.strip()]), keep_blank_values=True))
            body_lines.append(f"form_data = {json.dumps(payload, indent=4)}")
        elif body_mode.get() == "text":
            body_lines.append(f'raw_data = {repr(raw)}')
    if body_lines: body_block = "\n".join(body_lines) + "\n\n"
    req_args = [f'"{method}"', "url", "headers=headers", "params=params"]
    if "json_payload" in body_block: req_args.append("json=json_payload")
    if "form_data" in body_block: req_args.append("data=form_data")
    if "raw_data" in body_block: req_args.append("data=raw_data")
    req_args.extend([f"verify={ssl_var.get()}", f"allow_redirects={redirect_var.get()}", "timeout=30"])
    req_args_str = ",\n    ".join(req_args)
    return f"""import requests, json

url = {json.dumps(url)}
headers = {headers_str}
params = {params_str}
{body_block}response = requests.request(
    {req_args_str}
)

print(f"Status Code: {{response.status_code}}")
try:
    print(json.dumps(response.json(), indent=2))
except requests.exceptions.JSONDecodeError:
    print(response.text)"""

def send_request():
    send_button.config(state="disabled"); flash_status("Sending...", "info")
    _set_resp_code(None, None)
    method, url = method_var.get().upper(), url_entry.get().strip()
    try:
        if not url:
            flash_status("URL is required.", "warning"); return
        headers, params = _headers_dict(), _params_dict()

        json_payload, data_payload = None, None
        raw = body_text.get("1.0","end-1c").strip()
        if method in ("POST", "PUT", "PATCH", "DELETE"):
            if body_mode.get() == "json":
                try: json_payload = json.loads(raw) if raw else {}
                except Exception as e: flash_status(f"Invalid JSON: {e}", "danger"); return
                headers.setdefault("Content-Type", "application/json")
            elif body_mode.get() == "form":
                data_payload = dict(parse_qsl("&".join([ln.strip() for ln in raw.splitlines() if ln.strip()]), keep_blank_values=True))
                headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            elif body_mode.get() == "text":
                data_payload = raw.encode("utf-8") if raw else b""

        auth = (username_entry.get(), password_entry.get()) if username_entry.get().strip() else None

        t0 = time.time()
        resp = requests.request(method, url, headers=headers, params=params, json=json_payload,
                                data=data_payload, auth=auth, verify=ssl_var.get(),
                                allow_redirects=redirect_var.get(), timeout=30)
        elapsed = time.time() - t0
        _fill_response(resp, elapsed); flash_status(f"{method} {url[:50]}... → {resp.status_code}", "success")
    except Exception as e:
        for w in (resp_body, resp_hdrs, code_text):
            w.config(state="normal"); w.delete("1.0", tk.END); w.config(state="disabled")
        resp_body.config(state="normal"); resp_body.insert("1.0", f"Error: {e}"); resp_body.config(state="disabled")
        code_text.config(state="normal"); code_text.insert("1.0", build_requests_snippet()); highlight_python(code_text); code_text.config(state="disabled")
        _set_resp_code(0, "ERROR"); flash_status(f"Request failed: {type(e).__name__}", "danger")
    finally:
        send_button.config(state="normal")
        try: save_to_history()
        except Exception: pass

def copy_body():
    resp_body.config(state="normal"); txt = resp_body.get("1.0","end-1c"); resp_body.config(state="disabled")
    root.clipboard_clear(); root.clipboard_append(txt); flash_status("Body copied.", "info", 2000)

def save_body():
    resp_body.config(state="normal"); txt = resp_body.get("1.0","end-1c"); resp_body.config(state="disabled")
    fp = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("All","*.*"),("JSON","*.json"),("Text","*.txt")])
    if fp: open(fp,"w",encoding="utf-8").write(txt); flash_status(f"Body saved to {fp}", "success")

def clear_response():
    for widget in (resp_body, resp_hdrs, code_text):
        widget.config(state="normal"); widget.delete("1.0", tk.END); widget.config(state="disabled")
    status_lbl.config(text="Status: —"); time_lbl.config(text="Time: —"); size_lbl.config(text="Size: —")
    _set_resp_code(None, None); flash_status("Cleared.", "info", 2000)

def copy_as_requests():
    snippet = build_requests_snippet()
    root.clipboard_clear(); root.clipboard_append(snippet); flash_status("Copied as Python requests.", "success")
    code_text.config(state="normal"); code_text.delete("1.0", tk.END); code_text.insert("1.0", snippet)
    highlight_python(code_text); code_text.config(state="disabled"); resp_nb.select(code_text)

def _apply_wrap(*_):
    wrap_mode = "word" if wrap_var.get() else "none"
    for widget in (resp_body, resp_hdrs, code_text, body_text): widget.config(wrap=wrap_mode)

btn_copy.config(command=copy_body)
btn_save.config(command=save_body)
btn_clear.config(command=clear_response)
btn_copy_req.config(command=copy_as_requests)
send_button.config(command=send_request)
root.bind("<Control-Return>", lambda _e: send_request())
root.bind("<F6>", lambda _e: url_entry.focus_set())
method_dropdown.bind("<<ComboboxSelected>>", _set_method_style)
hist_list.bind("<<ListboxSelect>>", on_hist_select)
hist_list.bind("<Double-Button-1>", on_hist_select)
hist_list.bind("<Button-3>", _show_hist_menu)
hist_list.bind("<Button-2>", _show_hist_menu)
wrap_var.trace_add("write", _apply_wrap)
body_mode.trace_add("write", lambda *_: body_text.config(state="normal" if body_mode.get() != "none" else "disabled"))
body_text.config(state="disabled")

_set_method_style()
_apply_wrap()
load_history()
req_content_frame.grid(row=0, column=0, sticky="nsew")
_set_active("request")
_set_sidebar_width(ICON_BAR_WIDTH)
_apply_sidebar_mode(collapsed=True, from_drag=False)

flash_status("Ready.", "info")
root.mainloop()

