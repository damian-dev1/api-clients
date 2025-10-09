# import os
# import csv
# import json
# import time
# import base64
# import copy
# import random
# import threading
# import logging
# from typing import Optional, List, Dict, Any

# import requests
# import tkinter as tk
# from tkinter import ttk, filedialog, messagebox

# # -------------------------------------------------------
# # Logging
# # -------------------------------------------------------
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s | %(levelname)s | %(message)s"
# )

# # -------------------------------------------------------
# # Defaults / Settings
# # -------------------------------------------------------
# SETTINGS_FILE = "settings.json"

# DEFAULT_PROFILE = {
#     "name": "default-router",
#     "method": "GET",
#     "url": "https://api.virtualstock.com/restapi/v4/orders/",
#     "params": {"limit": 200, "offset": 0, "part_number": ""},
#     "headers": {"Content-Type": "application/json", "Accept": "application/json"},
#     "body_mode": "json",   # json|raw
#     "body": {},
#     "timeout": 20,
#     "sort_enabled": False,
#     "sort": "desc",        # asc|desc
#     "status_enabled": False,
#     "status": "",
#     "rate_limit_enabled": True,
#     "requests_per_minute": 150,
#     "batch_size": 200,
#     "max_retries": 5,
#     "allow_redirects": True,
#     "verify": True,
#     "username": "your-username",
#     "password": "your-password"
# }

# DEFAULT_SETTINGS = {
#     "current_profile": "default-router",
#     "profiles": {
#         "default-router": DEFAULT_PROFILE
#     }
# }

# # -------------------------------------------------------
# # Helpers: settings
# # -------------------------------------------------------
# def deep_merge(a: dict, b: dict) -> dict:
#     out = copy.deepcopy(a)
#     for k, v in b.items():
#         if isinstance(v, dict) and isinstance(out.get(k), dict):
#             out[k] = deep_merge(out[k], v)
#         else:
#             out[k] = v
#     return out

# def load_settings() -> dict:
#     if not os.path.exists(SETTINGS_FILE):
#         return copy.deepcopy(DEFAULT_SETTINGS)
#     try:
#         with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
#             data = json.load(f)
#         merged = deep_merge(DEFAULT_SETTINGS, data)
#         cp = merged.get("current_profile") or "default-router"
#         if cp not in merged["profiles"]:
#             merged["profiles"][cp] = copy.deepcopy(DEFAULT_PROFILE)
#         return merged
#     except Exception as e:
#         logging.exception("Failed to load settings")
#         messagebox.showerror("Error", f"Failed to load settings:\n{e}")
#         return copy.deepcopy(DEFAULT_SETTINGS)

# def save_settings(settings: dict):
#     try:
#         with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
#             json.dump(settings, f, indent=2)
#     except Exception as e:
#         logging.exception("Failed to save settings")
#         messagebox.showerror("Error", f"Failed to save settings:\n{e}")

# # -------------------------------------------------------
# # Rate limiter (token bucket)
# # -------------------------------------------------------
# class RateLimiter:
#     def __init__(self, rpm: int):
#         self.capacity = max(1, rpm)
#         self.tokens = float(self.capacity)
#         self.fill_rate = self.capacity / 60.0
#         self.ts = time.monotonic()
#         self.lock = threading.Lock()

#     def acquire(self):
#         with self.lock:
#             now = time.monotonic()
#             elapsed = now - self.ts
#             self.ts = now
#             self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
#             if self.tokens < 1.0:
#                 sleep_for = (1.0 - self.tokens) / self.fill_rate
#                 time.sleep(sleep_for)
#                 self.ts = time.monotonic()
#                 self.tokens = 0.0
#             else:
#                 self.tokens -= 1.0

# # -------------------------------------------------------
# # API client
# # -------------------------------------------------------
# class APIClient:
#     def __init__(self, profile: dict, cancel_evt: threading.Event):
#         self.p = profile
#         self.cancel_evt = cancel_evt
#         self.sess = requests.Session()
#         self._configure()
#         self.limiter = RateLimiter(int(self.p["requests_per_minute"])) if self.p.get("rate_limit_enabled", True) else None

#     def _configure(self):
#         headers = copy.deepcopy(self.p.get("headers", {})) or {}
#         u, pw = self.p.get("username", ""), self.p.get("password", "")
#         auth = base64.b64encode(f"{u}:{pw}".encode()).decode()
#         headers["Authorization"] = f"Basic {auth}"
#         self.sess.headers.clear()
#         self.sess.headers.update(headers)

#     def _apply_rl(self):
#         if self.limiter:
#             self.limiter.acquire()

#     def _sleep_cancel(self, secs: float):
#         end = time.monotonic() + secs
#         while time.monotonic() < end:
#             if self.cancel_evt.is_set():
#                 return
#             time.sleep(min(0.2, end - time.monotonic()))

#     def _request(self, url: str, params: dict, body: Any, attempt: int = 0):
#         if self.cancel_evt.is_set():
#             return 0, None

#         method = self.p.get("method", "GET").upper()
#         timeout = int(self.p.get("timeout", 20))
#         allow_redirects = bool(self.p.get("allow_redirects", True))
#         verify = bool(self.p.get("verify", True))
#         body_mode = self.p.get("body_mode", "json").lower()
#         max_retries = int(self.p.get("max_retries", 5))

#         self._apply_rl()
#         try:
#             if method in ("POST", "PUT", "PATCH"):
#                 if body_mode == "json":
#                     resp = self.sess.request(method, url, params=params, json=body, timeout=timeout,
#                                              allow_redirects=allow_redirects, verify=verify)
#                 else:
#                     resp = self.sess.request(method, url, params=params, data=body, timeout=timeout,
#                                              allow_redirects=allow_redirects, verify=verify)
#             else:
#                 resp = self.sess.request(method, url, params=params, timeout=timeout,
#                                          allow_redirects=allow_redirects, verify=verify)

#             if resp.status_code == 429 and attempt < max_retries:
#                 ra = resp.headers.get("Retry-After")
#                 sleep_for = float(ra) if ra and ra.isdigit() else (2 ** attempt + random.random())
#                 logging.warning(f"429 Too Many Requests. Sleeping {sleep_for:.2f}s")
#                 self._sleep_cancel(sleep_for)
#                 return self._request(url, params, body, attempt + 1)

#             if resp.status_code == 200:
#                 try:
#                     return 200, resp.json()
#                 except Exception as e:
#                     logging.error(f"JSON decode failed: {e}")
#                     return resp.status_code, None

#             if attempt < max_retries:
#                 back = 2 ** attempt + random.random()
#                 logging.warning(f"HTTP {resp.status_code}. Retrying in {back:.2f}s...")
#                 self._sleep_cancel(back)
#                 return self._request(url, params, body, attempt + 1)

#             logging.error(f"Request failed after {max_retries} retries. Status {resp.status_code}.")
#             return resp.status_code, None

#         except Exception as e:
#             if attempt < max_retries:
#                 back = 2 ** attempt + random.random()
#                 logging.warning(f"Exception: {e}. Retrying in {back:.2f}s...")
#                 self._sleep_cancel(back)
#                 return self._request(url, params, body, attempt + 1)
#             logging.exception("Unrecoverable error during request")
#             return 0, None

#     def fetch_all(self, part_number: Optional[str], progress_cb=None) -> List[dict]:
#         url = self.p["url"]
#         body = self.p.get("body", {})
#         base_params = copy.deepcopy(self.p.get("params", {})) or {}

#         # optional filters
#         if self.p.get("sort_enabled", False):
#             base_params["sort"] = self.p.get("sort", "desc")
#         if self.p.get("status_enabled", False) and self.p.get("status", "").strip():
#             base_params["status"] = self.p.get("status", "").strip()

#         if part_number is not None:
#             base_params["part_number"] = part_number

#         limit = int(self.p.get("batch_size", base_params.get("limit", 200)))
#         base_params["limit"] = limit
#         offset = int(base_params.get("offset", 0))

#         results = []
#         total_count = None
#         next_url = None

#         while not self.cancel_evt.is_set():
#             params = copy.deepcopy(base_params)
#             params["offset"] = offset
#             params["limit"] = limit

#             if progress_cb:
#                 progress_cb(f"Fetching offset {offset} (limit {limit})...")

#             status, payload = self._request(next_url or url, params, body)
#             if status != 200 or payload is None:
#                 break

#             if total_count is None:
#                 total_count = int(payload.get("count", 0))

#             batch = payload.get("results") or []
#             results.extend(batch)

#             if progress_cb:
#                 if total_count:
#                     progress_cb(f"Fetched {len(results)}/{total_count}...")
#                 else:
#                     progress_cb(f"Fetched {len(results)}...")

#             next_url = payload.get("next")
#             if next_url:
#                 offset += limit
#                 continue

#             if len(batch) < limit:
#                 break
#             offset += limit

#         return results

# # -------------------------------------------------------
# # CSV export (atomic)
# # -------------------------------------------------------
# CSV_HEADERS = [
#     "Order Reference", "Order Date", "Status", "Item Name", "Quantity", "Total",
#     "Shipping Full Name", "Address Line 1", "City", "State", "Postal Code", "Country"
# ]

# def export_orders_atomic(orders: List[dict], path: str):
#     tmp = path + ".tmp"
#     with open(tmp, "w", newline="", encoding="utf-8") as f:
#         w = csv.writer(f)
#         w.writerow(CSV_HEADERS)
#         for order in orders:
#             items = order.get("items") or []
#             item0 = items[0] if items else {}
#             ship = order.get("shipping_address") or {}
#             w.writerow([
#                 order.get("order_reference", ""),
#                 order.get("order_date", ""),
#                 order.get("status", ""),
#                 item0.get("name", ""),
#                 item0.get("quantity", ""),
#                 order.get("total", ""),
#                 ship.get("full_name", ""),
#                 ship.get("line_1", ""),
#                 ship.get("city", ""),
#                 ship.get("state", ""),
#                 ship.get("postal_code", ""),
#                 ship.get("country", "")
#             ])
#     os.replace(tmp, path)

# # -------------------------------------------------------
# # UI Class (based on your demo style)
# # -------------------------------------------------------
# class ApiRouterApp:
#     METHODS = ["GET", "POST", "PUT", "PATCH"]
#     SORT_OPTIONS = ["desc", "asc"]
#     STATUS_OPTIONS = ["", "ORDER_ACK", "DISPATCHED", "CANCELLED", "BACKORDER"]  # extend as needed
#     PAGE_SIZES = [50, 100, 200, 500, 1000]
#     RPM_PRESETS = [60, 120, 150, 300, 600]

#     def __init__(self, root):
#         self.root = root
#         self.root.title("API Router Dashboard")
#         self.root.geometry("820x900")
#         self.root.configure(padx=16, pady=12)

#         self.settings = load_settings()
#         self.profile = self._current_profile()
#         self.cancel_evt = threading.Event()
#         self.results: List[dict] = []

#         self.style = ttk.Style()
#         self.style.configure("TCheckbutton", font=("Segoe UI", 10))
#         self.style.configure("TButton", font=("Segoe UI", 10))
#         self.style.configure("TLabel", font=("Segoe UI", 10))

#         self.bulk_parts: List[str] = []
#         self.bulk_headers: List[str] = []
#         self.bulk_selected_col = tk.StringVar(value="")
#         self.bulk_file_path = tk.StringVar(value="")

#         self.create_widgets()
#         self.update_status_panel("--- Ready ---\n")

#     # ---------- Settings/Profile helpers ----------
#     def _current_profile(self) -> dict:
#         cp = self.settings.get("current_profile", "default-router")
#         return copy.deepcopy(self.settings["profiles"].get(cp, DEFAULT_PROFILE))

#     def _sync_profile_back(self):
#         cp = self.settings.get("current_profile", "default-router")
#         self.settings["profiles"][cp] = copy.deepcopy(self.profile)

#     # ---------- UI ----------
#     def create_widgets(self):
#         # Section: Profile / Connection
#         conn = ttk.LabelFrame(self.root, text="Connection & Profile")
#         conn.pack(fill="x", pady=8)

#         ttk.Label(conn, text="Profile").grid(row=0, column=0, sticky="e", padx=6, pady=5)
#         self.cmb_profile = ttk.Combobox(conn, values=list(self.settings["profiles"].keys()), state="readonly", width=28)
#         self.cmb_profile.set(self.settings.get("current_profile", "default-router"))
#         self.cmb_profile.grid(row=0, column=1, sticky="w", padx=6, pady=5)

#         ttk.Button(conn, text="Load", command=self.on_profile_load).grid(row=0, column=2, padx=4, pady=5)
#         ttk.Button(conn, text="Save", command=self.on_profile_save).grid(row=0, column=3, padx=4, pady=5)
#         ttk.Button(conn, text="Save As…", command=self.on_profile_save_as).grid(row=0, column=4, padx=4, pady=5)

#         ttk.Label(conn, text="Base URL").grid(row=1, column=0, sticky="e", padx=6, pady=5)
#         self.ent_url = ttk.Entry(conn, width=54)
#         self.ent_url.insert(0, self.profile["url"])
#         self.ent_url.grid(row=1, column=1, columnspan=4, sticky="we", padx=6, pady=5)

#         ttk.Label(conn, text="Username").grid(row=2, column=0, sticky="e", padx=6, pady=5)
#         self.ent_user = ttk.Entry(conn, width=28)
#         self.ent_user.insert(0, self.profile["username"])
#         self.ent_user.grid(row=2, column=1, sticky="w", padx=6, pady=5)

#         ttk.Label(conn, text="Password").grid(row=2, column=2, sticky="e", padx=6, pady=5)
#         self.ent_pass = ttk.Entry(conn, width=28, show="*")
#         self.ent_pass.insert(0, self.profile["password"])
#         self.ent_pass.grid(row=2, column=3, sticky="w", padx=6, pady=5)

#         for c in range(5):
#             conn.grid_columnconfigure(c, weight=1)

#         # Section: Request Options (dropdowns, checkboxes)
#         opts = ttk.LabelFrame(self.root, text="Request Options")
#         opts.pack(fill="x", pady=8)

#         ttk.Label(opts, text="Method").grid(row=0, column=0, sticky="e", padx=6, pady=5)
#         self.cmb_method = ttk.Combobox(opts, values=self.METHODS, state="readonly", width=10)
#         self.cmb_method.set(self.profile["method"].upper())
#         self.cmb_method.grid(row=0, column=1, sticky="w", padx=6, pady=5)

#         ttk.Label(opts, text="Timeout (s)").grid(row=0, column=2, sticky="e", padx=6, pady=5)
#         self.spn_timeout = ttk.Spinbox(opts, from_=1, to=600, width=8)
#         self.spn_timeout.delete(0, "end"); self.spn_timeout.insert(0, str(self.profile["timeout"]))
#         self.spn_timeout.grid(row=0, column=3, sticky="w", padx=6, pady=5)

#         ttk.Label(opts, text="Page Size").grid(row=0, column=4, sticky="e", padx=6, pady=5)
#         self.cmb_pagesize = ttk.Combobox(opts, values=[str(x) for x in self.PAGE_SIZES], state="readonly", width=8)
#         self.cmb_pagesize.set(str(self.profile["batch_size"]))
#         self.cmb_pagesize.grid(row=0, column=5, sticky="w", padx=6, pady=5)

#         self.var_sort = tk.BooleanVar(value=self.profile["sort_enabled"])
#         ttk.Checkbutton(opts, text="Enable Sort", variable=self.var_sort).grid(row=1, column=0, sticky="w", padx=6, pady=5)
#         ttk.Label(opts, text="Sort").grid(row=1, column=1, sticky="e", padx=6, pady=5)
#         self.cmb_sort = ttk.Combobox(opts, values=self.SORT_OPTIONS, state="readonly", width=10)
#         self.cmb_sort.set(self.profile["sort"])
#         self.cmb_sort.grid(row=1, column=2, sticky="w", padx=6, pady=5)

#         self.var_status = tk.BooleanVar(value=self.profile["status_enabled"])
#         ttk.Checkbutton(opts, text="Enable Status", variable=self.var_status).grid(row=1, column=3, sticky="w", padx=6, pady=5)
#         ttk.Label(opts, text="Status").grid(row=1, column=4, sticky="e", padx=6, pady=5)
#         self.cmb_status = ttk.Combobox(opts, values=self.STATUS_OPTIONS, state="readonly", width=12)
#         self.cmb_status.set(self.profile["status"])
#         self.cmb_status.grid(row=1, column=5, sticky="w", padx=6, pady=5)

#         self.var_rl = tk.BooleanVar(value=self.profile["rate_limit_enabled"])
#         ttk.Checkbutton(opts, text="Rate Limit", variable=self.var_rl).grid(row=2, column=0, sticky="w", padx=6, pady=5)
#         ttk.Label(opts, text="RPM").grid(row=2, column=1, sticky="e", padx=6, pady=5)
#         self.cmb_rpm = ttk.Combobox(opts, values=[str(x) for x in self.RPM_PRESETS], state="readonly", width=10)
#         self.cmb_rpm.set(str(self.profile["requests_per_minute"]))
#         self.cmb_rpm.grid(row=2, column=2, sticky="w", padx=6, pady=5)

#         self.var_redirects = tk.BooleanVar(value=self.profile["allow_redirects"])
#         ttk.Checkbutton(opts, text="Allow Redirects", variable=self.var_redirects).grid(row=2, column=3, sticky="w", padx=6, pady=5)
#         self.var_verify = tk.BooleanVar(value=self.profile["verify"])
#         ttk.Checkbutton(opts, text="Verify SSL", variable=self.var_verify).grid(row=2, column=4, sticky="w", padx=6, pady=5)

#         for c in range(6):
#             opts.grid_columnconfigure(c, weight=1)

#         # Section: Single Part / Body
#         bodysec = ttk.LabelFrame(self.root, text="Single Request Params / Body")
#         bodysec.pack(fill="x", pady=8)

#         ttk.Label(bodysec, text="Part Number").grid(row=0, column=0, sticky="e", padx=6, pady=5)
#         self.ent_part = ttk.Entry(bodysec, width=30)
#         self.ent_part.insert(0, self.profile["params"].get("part_number", ""))
#         self.ent_part.grid(row=0, column=1, sticky="w", padx=6, pady=5)

#         ttk.Label(bodysec, text="Body Mode").grid(row=0, column=2, sticky="e", padx=6, pady=5)
#         self.cmb_bodymode = ttk.Combobox(bodysec, values=["json", "raw"], state="readonly", width=8)
#         self.cmb_bodymode.set(self.profile.get("body_mode", "json"))
#         self.cmb_bodymode.grid(row=0, column=3, sticky="w", padx=6, pady=5)

#         ttk.Label(bodysec, text="Body").grid(row=1, column=0, sticky="ne", padx=6, pady=5)
#         self.txt_body = tk.Text(bodysec, height=5, width=70, wrap="word")
#         init_body = self.profile.get("body", {})
#         if isinstance(init_body, (dict, list)):
#             self.txt_body.insert("1.0", json.dumps(init_body))
#         else:
#             self.txt_body.insert("1.0", str(init_body))
#         self.txt_body.grid(row=1, column=1, columnspan=3, sticky="we", padx=6, pady=5)

#         for c in range(4):
#             bodysec.grid_columnconfigure(c, weight=1)

#         # Section: Bulk CSV Import
#         bulk = ttk.LabelFrame(self.root, text="Bulk Ops (CSV Import)")
#         bulk.pack(fill="x", pady=8)

#         ttk.Button(bulk, text="Import CSV…", command=self.on_import_csv).grid(row=0, column=0, padx=6, pady=6, sticky="w")
#         ttk.Label(bulk, textvariable=self.bulk_file_path, foreground="#666").grid(row=0, column=1, columnspan=3, sticky="w", padx=6, pady=6)

#         ttk.Label(bulk, text="Part Number Column").grid(row=1, column=0, sticky="e", padx=6, pady=6)
#         self.cmb_bulk_col = ttk.Combobox(bulk, textvariable=self.bulk_selected_col, state="readonly", width=28, values=[])
#         self.cmb_bulk_col.grid(row=1, column=1, sticky="w", padx=6, pady=6)

#         ttk.Button(bulk, text="Run Bulk", command=self.on_run_bulk).grid(row=1, column=2, padx=6, pady=6)
#         ttk.Button(bulk, text="Cancel", command=self.on_cancel, state="disabled").grid(row=1, column=3, padx=6, pady=6)

#         for c in range(4):
#             bulk.grid_columnconfigure(c, weight=1)

#         # Section: Actions
#         actions = ttk.LabelFrame(self.root, text="Actions")
#         actions.pack(fill="x", pady=8)
#         ttk.Button(actions, text="Test Single Page", command=self.on_test_single).pack(side="left", padx=6, pady=6)
#         ttk.Button(actions, text="Fetch All (Single Part)", command=self.on_fetch_single).pack(side="left", padx=6, pady=6)
#         self.btn_export = ttk.Button(actions, text="Export CSV (last results)", command=self.on_export, state="disabled")
#         self.btn_export.pack(side="left", padx=6, pady=6)

#         # Section: Live Status
#         status = ttk.LabelFrame(self.root, text="Live Status")
#         status.pack(fill="both", expand=True, pady=8)
#         self.txt_status = tk.Text(status, height=14, wrap="word", font=("Consolas", 10))
#         self.txt_status.pack(fill="both", expand=True, padx=8, pady=8)

#     # ---------- Status ----------
#     def update_status_panel(self, text: str):
#         self.txt_status.insert("end", text)
#         self.txt_status.see("end")

#     def set_progress(self, msg: str):
#         self.root.after(0, lambda m=msg: self._set_progress_text(m))

#     def _set_progress_text(self, msg: str):
#         self.update_status_panel(f"{msg}\n")

#     # ---------- Profile actions ----------
#     def on_profile_load(self):
#         sel = self.cmb_profile.get().strip()
#         if not sel:
#             return
#         self.settings["current_profile"] = sel
#         save_settings(self.settings)
#         self.profile = self._current_profile()
#         # reload form fields
#         self.ent_url.delete(0, "end"); self.ent_url.insert(0, self.profile["url"])
#         self.ent_user.delete(0, "end"); self.ent_user.insert(0, self.profile["username"])
#         self.ent_pass.delete(0, "end"); self.ent_pass.insert(0, self.profile["password"])
#         self.cmb_method.set(self.profile["method"].upper())
#         self.spn_timeout.delete(0, "end"); self.spn_timeout.insert(0, str(self.profile["timeout"]))
#         self.cmb_pagesize.set(str(self.profile["batch_size"]))
#         self.var_sort.set(self.profile["sort_enabled"]); self.cmb_sort.set(self.profile["sort"])
#         self.var_status.set(self.profile["status_enabled"]); self.cmb_status.set(self.profile["status"])
#         self.var_rl.set(self.profile["rate_limit_enabled"]); self.cmb_rpm.set(str(self.profile["requests_per_minute"]))
#         self.ent_part.delete(0, "end"); self.ent_part.insert(0, self.profile["params"].get("part_number", ""))
#         self.cmb_bodymode.set(self.profile.get("body_mode", "json"))
#         self.txt_body.delete("1.0", "end")
#         body = self.profile.get("body", {})
#         self.txt_body.insert("1.0", json.dumps(body) if isinstance(body, (dict, list)) else str(body))
#         self.update_status_panel(f"[Profile] Loaded '{sel}'\n")

#     def on_profile_save(self):
#         if not self.collect_profile_from_form():
#             return
#         self._sync_profile_back()
#         save_settings(self.settings)
#         self.update_status_panel("[Profile] Saved\n")

#     def on_profile_save_as(self):
#         new_name = tk.simpledialog.askstring("Save Profile As", "Enter new profile name:")
#         if not new_name:
#             return
#         if not self.collect_profile_from_form():
#             return
#         self.profile["name"] = new_name
#         self.settings["profiles"][new_name] = copy.deepcopy(self.profile)
#         self.settings["current_profile"] = new_name
#         save_settings(self.settings)
#         self.cmb_profile["values"] = list(self.settings["profiles"].keys())
#         self.cmb_profile.set(new_name)
#         self.update_status_panel(f"[Profile] Saved as '{new_name}'\n")

#     def collect_profile_from_form(self) -> bool:
#         try:
#             self.profile["url"] = self.ent_url.get().strip()
#             self.profile["username"] = self.ent_user.get()
#             self.profile["password"] = self.ent_pass.get()
#             self.profile["method"] = self.cmb_method.get().strip().upper()
#             self.profile["timeout"] = int(self.spn_timeout.get())
#             self.profile["batch_size"] = int(self.cmb_pagesize.get())

#             self.profile["sort_enabled"] = bool(self.var_sort.get())
#             self.profile["sort"] = self.cmb_sort.get().strip()
#             self.profile["status_enabled"] = bool(self.var_status.get())
#             self.profile["status"] = self.cmb_status.get().strip()

#             self.profile["rate_limit_enabled"] = bool(self.var_rl.get())
#             self.profile["requests_per_minute"] = int(self.cmb_rpm.get())

#             self.profile["params"]["part_number"] = self.ent_part.get().strip()
#             self.profile["params"]["limit"] = self.profile["batch_size"]

#             mode = self.cmb_bodymode.get().strip().lower()
#             self.profile["body_mode"] = "json" if mode not in ("json", "raw") else mode
#             body_txt = self.txt_body.get("1.0", "end").strip()
#             if self.profile["body_mode"] == "json":
#                 self.profile["body"] = json.loads(body_txt) if body_txt else {}
#             else:
#                 self.profile["body"] = body_txt
#             return True
#         except json.JSONDecodeError as e:
#             messagebox.showerror("Error", f"Body must be valid JSON.\n{e}")
#             return False
#         except Exception as e:
#             messagebox.showerror("Error", f"Invalid setting: {e}")
#             return False

#     # ---------- Single ops ----------
#     def on_test_single(self):
#         if not self.collect_profile_from_form():
#             return
#         self.update_status_panel("[Test] Single page request…\n")
#         t = threading.Thread(target=self._test_worker, daemon=True)
#         t.start()

#     def _test_worker(self):
#         try:
#             p = copy.deepcopy(self.profile)
#             client = APIClient(p, threading.Event())
#             params = copy.deepcopy(p.get("params", {})) or {}
#             params["limit"] = int(p.get("batch_size", 200))
#             if p.get("sort_enabled", False):
#                 params["sort"] = p.get("sort", "desc")
#             if p.get("status_enabled", False) and p.get("status", "").strip():
#                 params["status"] = p.get("status", "").strip()
#             code, payload = client._request(p["url"], params, p.get("body", {}))
#             if code == 200 and isinstance(payload, dict):
#                 count = int(payload.get("count", 0))
#                 got = len(payload.get("results", []) or [])
#                 self.set_progress(f"[Test] OK. Total={count}, Page={got}")
#             else:
#                 self.set_progress(f"[Test] Failed. HTTP {code}. See logs.")
#         except Exception as e:
#             logging.exception("Test failed")
#             self.set_progress(f"[Test] Exception: {e}")

#     def on_fetch_single(self):
#         if not self.collect_profile_from_form():
#             return
#         part = self.ent_part.get().strip()
#         if not part:
#             messagebox.showerror("Error", "Enter a Part Number for single fetch.")
#             return
#         self.results = []
#         self.btn_export.config(state="disabled")
#         self.cancel_evt.clear()
#         self.update_status_panel("[Fetch] Single part — starting…\n")
#         t = threading.Thread(target=self._fetch_single_worker, args=(part,), daemon=True)
#         t.start()

#     def _fetch_single_worker(self, part: str):
#         try:
#             p = copy.deepcopy(self.profile)
#             client = APIClient(p, self.cancel_evt)
#             orders = client.fetch_all(part, progress_cb=self.set_progress)
#             self.results = orders
#             total = sum(float(o.get("total", 0) or 0) for o in orders) if orders else 0.0
#             self.set_progress(f"[Fetch] Done. Orders={len(orders)} | ${total:,.2f}")
#             self.root.after(0, lambda: self.btn_export.config(state="normal"))
#         except Exception as e:
#             logging.exception("Fetch single failed")
#             self.set_progress(f"[Fetch] Failed: {e}")

#     # ---------- Bulk ops ----------
#     def on_import_csv(self):
#         path = filedialog.askopenfilename(
#             title="Select CSV with Part Numbers",
#             filetypes=[("CSV files", "*.csv")]
#         )
#         if not path:
#             return
#         try:
#             with open(path, "r", encoding="utf-8", newline="") as f:
#                 r = csv.reader(f)
#                 rows = list(r)
#             if not rows:
#                 messagebox.showerror("Error", "CSV is empty.")
#                 return
#             headers = rows[0]
#             self.bulk_headers = headers
#             self.bulk_file_path.set(path)
#             self.cmb_bulk_col["values"] = headers
#             if headers:
#                 self.cmb_bulk_col.set(headers[0])
#             # store data for later processing (we stream later)
#             self._bulk_rows = rows  # keep raw to avoid re-read
#             self.update_status_panel(f"[Bulk] Loaded CSV: {os.path.basename(path)} | Columns: {len(headers)} | Rows: {len(rows)-1}\n")
#         except Exception as e:
#             logging.exception("CSV import failed")
#             messagebox.showerror("Error", f"Failed to load CSV:\n{e}")

#     def on_run_bulk(self):
#         if not hasattr(self, "_bulk_rows"):
#             messagebox.showerror("Error", "Import a CSV first.")
#             return
#         col = self.cmb_bulk_col.get().strip()
#         if not col:
#             messagebox.showerror("Error", "Select the Part Number column.")
#             return
#         if not self.collect_profile_from_form():
#             return

#         # extract part numbers (dedup, keep order)
#         try:
#             idx = self.bulk_headers.index(col)
#         except ValueError:
#             messagebox.showerror("Error", f"Column '{col}' not found.")
#             return

#         parts = []
#         seen = set()
#         for row in self._bulk_rows[1:]:
#             if idx < len(row):
#                 pn = (row[idx] or "").strip()
#                 if pn and pn not in seen:
#                     parts.append(pn)
#                     seen.add(pn)
#         if not parts:
#             messagebox.showerror("Error", "No part numbers found in the selected column.")
#             return

#         self.bulk_parts = parts
#         self.results = []
#         self.btn_export.config(state="disabled")
#         self.cancel_evt.clear()
#         self.update_status_panel(f"[Bulk] Starting for {len(parts)} parts…\n")

#         # enable cancel button in bulk section
#         # find the Cancel button by traversing from parent frame if needed; easiest is disable it in place:
#         for child in self.root.winfo_children():
#             if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Bulk Ops (CSV Import)":
#                 for btn in child.winfo_children():
#                     if isinstance(btn, ttk.Button) and btn.cget("text") == "Cancel":
#                         btn.configure(state="normal")

#         t = threading.Thread(target=self._bulk_worker, daemon=True)
#         t.start()

#     def _bulk_worker(self):
#         try:
#             p = copy.deepcopy(self.profile)
#             client = APIClient(p, self.cancel_evt)

#             total_parts = len(self.bulk_parts)
#             combined: List[dict] = []
#             t0 = time.time()

#             for i, pn in enumerate(self.bulk_parts, start=1):
#                 if self.cancel_evt.is_set():
#                     break
#                 self.set_progress(f"[Bulk] ({i}/{total_parts}) {pn}")
#                 orders = client.fetch_all(pn, progress_cb=None)  # per-part fetch; quiet inner progress
#                 combined.extend(orders)

#             self.results = combined
#             elapsed = time.time() - t0
#             total_val = sum(float(o.get("total", 0) or 0) for o in combined) if combined else 0.0
#             msg = "Cancelled." if self.cancel_evt.is_set() else "Completed."
#             self.set_progress(f"[Bulk] {msg} Orders={len(combined)} | ${total_val:,.2f} | {elapsed:.1f}s")
#             self.root.after(0, lambda: self.btn_export.config(state="normal"))
#         except Exception as e:
#             logging.exception("Bulk failed")
#             self.set_progress(f"[Bulk] Failed: {e}")
#         finally:
#             # disable cancel button
#             for child in self.root.winfo_children():
#                 if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Bulk Ops (CSV Import)":
#                     for btn in child.winfo_children():
#                         if isinstance(btn, ttk.Button) and btn.cget("text") == "Cancel":
#                             btn.configure(state="disabled")

#     def on_cancel(self):
#         self.cancel_evt.set()
#         self.update_status_panel("[Action] Cancelling…\n")

#     # ---------- Export ----------
#     def on_export(self):
#         if not self.results:
#             messagebox.showinfo("No data", "No results to export.")
#             return
#         path = filedialog.asksaveasfilename(
#             title="Save CSV",
#             defaultextension=".csv",
#             filetypes=[("CSV files", "*.csv")]
#         )
#         if not path:
#             return
#         try:
#             export_orders_atomic(self.results, path)
#             messagebox.showinfo("Done", f"Exported to {path}")
#             self.update_status_panel(f"[Export] {path}\n")
#         except Exception as e:
#             logging.exception("Export failed")
#             messagebox.showerror("Error", f"Export failed:\n{e}")

# # -------------------------------------------------------
# # Main
# # -------------------------------------------------------
# if __name__ == "__main__":
#     root = tk.Tk()
#     app = ApiRouterApp(root)
#     root.mainloop()

import os
import csv
import json
import time
import base64
import copy
import random
import threading
import logging
from typing import Optional, List, Dict, Any
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)
SETTINGS_FILE = "settings.json"
DEFAULT_PROFILE = {
    "name": "default-router",
    "method": "GET",
    "url": "https://api.virtualstock.com/restapi/v4/orders/",
    "params": {"limit": 200, "offset": 0, "part_number": ""},
    "headers": {"Content-Type": "application/json", "Accept": "application/json"},
    "body_mode": "json",   
    "body": {},
    "timeout": 20,
    "sort_enabled": False,
    "sort": "desc",        
    "status_enabled": False,
    "status": "",
    "rate_limit_enabled": True,
    "requests_per_minute": 150,
    "batch_size": 200,
    "max_retries": 5,
    "allow_redirects": True,
    "verify": True,
    "username": "your-username",
    "password": "your-password"
}
DEFAULT_SETTINGS = {
    "current_profile": "default-router",
    "profiles": {
        "default-router": DEFAULT_PROFILE
    }
}
def deep_merge(a: dict, b: dict) -> dict:
    out = copy.deepcopy(a)
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out
def load_settings() -> dict:
    if not os.path.exists(SETTINGS_FILE):
        return copy.deepcopy(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        merged = deep_merge(DEFAULT_SETTINGS, data)
        cp = merged.get("current_profile") or "default-router"
        if cp not in merged["profiles"]:
            merged["profiles"][cp] = copy.deepcopy(DEFAULT_PROFILE)
        return merged
    except Exception as e:
        logging.exception("Failed to load settings")
        messagebox.showerror("Error", f"Failed to load settings:\n{e}")
        return copy.deepcopy(DEFAULT_SETTINGS)
def save_settings(settings: dict):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception as e:
        logging.exception("Failed to save settings")
        messagebox.showerror("Error", f"Failed to save settings:\n{e}")
class RateLimiter:
    def __init__(self, rpm: int):
        self.capacity = max(1, rpm)
        self.tokens = float(self.capacity)
        self.fill_rate = self.capacity / 60.0
        self.ts = time.monotonic()
        self.lock = threading.Lock()
    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.ts
            self.ts = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.fill_rate)
            if self.tokens < 1.0:
                sleep_for = (1.0 - self.tokens) / self.fill_rate
                time.sleep(sleep_for)
                self.ts = time.monotonic()
                self.tokens = 0.0
            else:
                self.tokens -= 1.0
class APIClient:
    def __init__(self, profile: dict, cancel_evt: threading.Event):
        self.p = profile
        self.cancel_evt = cancel_evt
        self.sess = requests.Session()
        self._configure()
        self.limiter = RateLimiter(int(self.p["requests_per_minute"])) if self.p.get("rate_limit_enabled", True) else None
    def _configure(self):
        headers = copy.deepcopy(self.p.get("headers", {})) or {}
        u, pw = self.p.get("username", ""), self.p.get("password", "")
        auth = base64.b64encode(f"{u}:{pw}".encode()).decode()
        headers["Authorization"] = f"Basic {auth}"
        self.sess.headers.clear()
        self.sess.headers.update(headers)
    def _apply_rl(self):
        if self.limiter:
            self.limiter.acquire()
    def _sleep_cancel(self, secs: float):
        end = time.monotonic() + secs
        while time.monotonic() < end:
            if self.cancel_evt.is_set():
                return
            time.sleep(min(0.2, end - time.monotonic()))
    def _request(self, url: str, params: dict, body: Any, attempt: int = 0):
        if self.cancel_evt.is_set():
            return 0, None
        method = self.p.get("method", "GET").upper()
        timeout = int(self.p.get("timeout", 20))
        allow_redirects = bool(self.p.get("allow_redirects", True))
        verify = bool(self.p.get("verify", True))
        body_mode = self.p.get("body_mode", "json").lower()
        max_retries = int(self.p.get("max_retries", 5))
        self._apply_rl()
        try:
            if method in ("POST", "PUT", "PATCH"):
                if body_mode == "json":
                    resp = self.sess.request(method, url, params=params, json=body, timeout=timeout,
                                             allow_redirects=allow_redirects, verify=verify)
                else:
                    resp = self.sess.request(method, url, params=params, data=body, timeout=timeout,
                                             allow_redirects=allow_redirects, verify=verify)
            else:
                resp = self.sess.request(method, url, params=params, timeout=timeout,
                                         allow_redirects=allow_redirects, verify=verify)
            if resp.status_code == 429 and attempt < max_retries:
                ra = resp.headers.get("Retry-After")
                sleep_for = float(ra) if ra and ra.isdigit() else (2 ** attempt + random.random())
                logging.warning(f"429 Too Many Requests. Sleeping {sleep_for:.2f}s")
                self._sleep_cancel(sleep_for)
                return self._request(url, params, body, attempt + 1)
            if resp.status_code == 200:
                try:
                    return 200, resp.json()
                except Exception as e:
                    logging.error(f"JSON decode failed: {e}")
                    return resp.status_code, None
            if attempt < max_retries:
                back = 2 ** attempt + random.random()
                logging.warning(f"HTTP {resp.status_code}. Retrying in {back:.2f}s...")
                self._sleep_cancel(back)
                return self._request(url, params, body, attempt + 1)
            logging.error(f"Request failed after {max_retries} retries. Status {resp.status_code}.")
            return resp.status_code, None
        except Exception as e:
            if attempt < max_retries:
                back = 2 ** attempt + random.random()
                logging.warning(f"Exception: {e}. Retrying in {back:.2f}s...")
                self._sleep_cancel(back)
                return self._request(url, params, body, attempt + 1)
            logging.exception("Unrecoverable error during request")
            return 0, None
    def fetch_all(self, part_number: Optional[str], progress_cb=None) -> List[dict]:
        url = self.p["url"]
        body = self.p.get("body", {})
        base_params = copy.deepcopy(self.p.get("params", {})) or {}
        if self.p.get("sort_enabled", False):
            base_params["sort"] = self.p.get("sort", "desc")
        if self.p.get("status_enabled", False) and self.p.get("status", "").strip():
            base_params["status"] = self.p.get("status", "").strip()
        if part_number is not None:
            base_params["part_number"] = part_number
        limit = int(self.p.get("batch_size", base_params.get("limit", 200)))
        base_params["limit"] = limit
        offset = int(base_params.get("offset", 0))
        results = []
        total_count = None
        next_url = None
        while not self.cancel_evt.is_set():
            params = copy.deepcopy(base_params)
            params["offset"] = offset
            params["limit"] = limit
            if progress_cb:
                progress_cb(f"Fetching offset {offset} (limit {limit})...")
            status, payload = self._request(next_url or url, params, body)
            if status != 200 or payload is None:
                break
            if total_count is None:
                total_count = int(payload.get("count", 0))
            batch = payload.get("results") or []
            results.extend(batch)
            if progress_cb:
                if total_count:
                    progress_cb(f"Fetched {len(results)}/{total_count}...")
                else:
                    progress_cb(f"Fetched {len(results)}...")
            next_url = payload.get("next")
            if next_url:
                offset += limit
                continue
            if len(batch) < limit:
                break
            offset += limit
        return results
CSV_HEADERS = [
    "Order Reference", "Order Date", "Status", "Item Name", "Quantity", "Total",
    "Shipping Full Name", "Address Line 1", "City", "State", "Postal Code", "Country"
]
def export_orders_atomic(orders: List[dict], path: str):
    tmp = path + ".tmp"
    with open(tmp, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(CSV_HEADERS)
        for order in orders:
            items = order.get("items") or []
            item0 = items[0] if items else {}
            ship = order.get("shipping_address") or {}
            w.writerow([
                order.get("order_reference", ""),
                order.get("order_date", ""),
                order.get("status", ""),
                item0.get("name", ""),
                item0.get("quantity", ""),
                order.get("total", ""),
                ship.get("full_name", ""),
                ship.get("line_1", ""),
                ship.get("city", ""),
                ship.get("state", ""),
                ship.get("postal_code", ""),
                ship.get("country", "")
            ])
    os.replace(tmp, path)
class ApiRouterApp:
    METHODS = ["GET", "POST", "PUT", "PATCH"]
    SORT_OPTIONS = ["desc", "asc"]
    STATUS_OPTIONS = ["", "ORDER_ACK", "DISPATCHED", "CANCELLED", "BACKORDER"]  
    PAGE_SIZES = [50, 100, 200, 500, 1000]
    RPM_PRESETS = [60, 120, 150, 300, 600]
    def __init__(self, root):
        self.root = root
        self.root.title("API Router Dashboard")
        self.root.geometry("820x900")
        self.root.configure(padx=16, pady=12)
        self.settings = load_settings()
        self.profile = self._current_profile()
        self.cancel_evt = threading.Event()
        self.results: List[dict] = []
        self.style = ttk.Style()
        self.style.configure("TCheckbutton", font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.bulk_parts: List[str] = []
        self.bulk_headers: List[str] = []
        self.bulk_selected_col = tk.StringVar(value="")
        self.bulk_file_path = tk.StringVar(value="")
        self.create_widgets()
        self.update_status_panel("--- Ready ---\n")
    def _current_profile(self) -> dict:
        cp = self.settings.get("current_profile", "default-router")
        return copy.deepcopy(self.settings["profiles"].get(cp, DEFAULT_PROFILE))
    def _sync_profile_back(self):
        cp = self.settings.get("current_profile", "default-router")
        self.settings["profiles"][cp] = copy.deepcopy(self.profile)
    def create_widgets(self):
        conn = ttk.LabelFrame(self.root, text="Connection & Profile")
        conn.pack(fill="x", pady=8)
        ttk.Label(conn, text="Profile").grid(row=0, column=0, sticky="e", padx=6, pady=5)
        self.cmb_profile = ttk.Combobox(conn, values=list(self.settings["profiles"].keys()), state="readonly", width=28)
        self.cmb_profile.set(self.settings.get("current_profile", "default-router"))
        self.cmb_profile.grid(row=0, column=1, sticky="w", padx=6, pady=5)
        ttk.Button(conn, text="Load", command=self.on_profile_load).grid(row=0, column=2, padx=4, pady=5)
        ttk.Button(conn, text="Save", command=self.on_profile_save).grid(row=0, column=3, padx=4, pady=5)
        ttk.Button(conn, text="Save As…", command=self.on_profile_save_as).grid(row=0, column=4, padx=4, pady=5)
        ttk.Label(conn, text="Base URL").grid(row=1, column=0, sticky="e", padx=6, pady=5)
        self.ent_url = ttk.Entry(conn, width=54)
        self.ent_url.insert(0, self.profile["url"])
        self.ent_url.grid(row=1, column=1, columnspan=4, sticky="we", padx=6, pady=5)
        ttk.Label(conn, text="Username").grid(row=2, column=0, sticky="e", padx=6, pady=5)
        self.ent_user = ttk.Entry(conn, width=28)
        self.ent_user.insert(0, self.profile["username"])
        self.ent_user.grid(row=2, column=1, sticky="w", padx=6, pady=5)
        ttk.Label(conn, text="Password").grid(row=2, column=2, sticky="e", padx=6, pady=5)
        self.ent_pass = ttk.Entry(conn, width=28, show="*")
        self.ent_pass.insert(0, self.profile["password"])
        self.ent_pass.grid(row=2, column=3, sticky="w", padx=6, pady=5)
        for c in range(5):
            conn.grid_columnconfigure(c, weight=1)
        opts = ttk.LabelFrame(self.root, text="Request Options")
        opts.pack(fill="x", pady=8)
        ttk.Label(opts, text="Method").grid(row=0, column=0, sticky="e", padx=6, pady=5)
        self.cmb_method = ttk.Combobox(opts, values=self.METHODS, state="readonly", width=10)
        self.cmb_method.set(self.profile["method"].upper())
        self.cmb_method.grid(row=0, column=1, sticky="w", padx=6, pady=5)
        ttk.Label(opts, text="Timeout (s)").grid(row=0, column=2, sticky="e", padx=6, pady=5)
        self.spn_timeout = ttk.Spinbox(opts, from_=1, to=600, width=8)
        self.spn_timeout.delete(0, "end"); self.spn_timeout.insert(0, str(self.profile["timeout"]))
        self.spn_timeout.grid(row=0, column=3, sticky="w", padx=6, pady=5)
        ttk.Label(opts, text="Page Size").grid(row=0, column=4, sticky="e", padx=6, pady=5)
        self.cmb_pagesize = ttk.Combobox(opts, values=[str(x) for x in self.PAGE_SIZES], state="readonly", width=8)
        self.cmb_pagesize.set(str(self.profile["batch_size"]))
        self.cmb_pagesize.grid(row=0, column=5, sticky="w", padx=6, pady=5)
        self.var_sort = tk.BooleanVar(value=self.profile["sort_enabled"])
        ttk.Checkbutton(opts, text="Enable Sort", variable=self.var_sort).grid(row=1, column=0, sticky="w", padx=6, pady=5)
        ttk.Label(opts, text="Sort").grid(row=1, column=1, sticky="e", padx=6, pady=5)
        self.cmb_sort = ttk.Combobox(opts, values=self.SORT_OPTIONS, state="readonly", width=10)
        self.cmb_sort.set(self.profile["sort"])
        self.cmb_sort.grid(row=1, column=2, sticky="w", padx=6, pady=5)
        self.var_status = tk.BooleanVar(value=self.profile["status_enabled"])
        ttk.Checkbutton(opts, text="Enable Status", variable=self.var_status).grid(row=1, column=3, sticky="w", padx=6, pady=5)
        ttk.Label(opts, text="Status").grid(row=1, column=4, sticky="e", padx=6, pady=5)
        self.cmb_status = ttk.Combobox(opts, values=self.STATUS_OPTIONS, state="readonly", width=12)
        self.cmb_status.set(self.profile["status"])
        self.cmb_status.grid(row=1, column=5, sticky="w", padx=6, pady=5)
        self.var_rl = tk.BooleanVar(value=self.profile["rate_limit_enabled"])
        ttk.Checkbutton(opts, text="Rate Limit", variable=self.var_rl).grid(row=2, column=0, sticky="w", padx=6, pady=5)
        ttk.Label(opts, text="RPM").grid(row=2, column=1, sticky="e", padx=6, pady=5)
        self.cmb_rpm = ttk.Combobox(opts, values=[str(x) for x in self.RPM_PRESETS], state="readonly", width=10)
        self.cmb_rpm.set(str(self.profile["requests_per_minute"]))
        self.cmb_rpm.grid(row=2, column=2, sticky="w", padx=6, pady=5)
        self.var_redirects = tk.BooleanVar(value=self.profile["allow_redirects"])
        ttk.Checkbutton(opts, text="Allow Redirects", variable=self.var_redirects).grid(row=2, column=3, sticky="w", padx=6, pady=5)
        self.var_verify = tk.BooleanVar(value=self.profile["verify"])
        ttk.Checkbutton(opts, text="Verify SSL", variable=self.var_verify).grid(row=2, column=4, sticky="w", padx=6, pady=5)
        for c in range(6):
            opts.grid_columnconfigure(c, weight=1)
        bodysec = ttk.LabelFrame(self.root, text="Single Request Params / Body")
        bodysec.pack(fill="x", pady=8)
        ttk.Label(bodysec, text="Part Number").grid(row=0, column=0, sticky="e", padx=6, pady=5)
        self.ent_part = ttk.Entry(bodysec, width=30)
        self.ent_part.insert(0, self.profile["params"].get("part_number", ""))
        self.ent_part.grid(row=0, column=1, sticky="w", padx=6, pady=5)
        ttk.Label(bodysec, text="Body Mode").grid(row=0, column=2, sticky="e", padx=6, pady=5)
        self.cmb_bodymode = ttk.Combobox(bodysec, values=["json", "raw"], state="readonly", width=8)
        self.cmb_bodymode.set(self.profile.get("body_mode", "json"))
        self.cmb_bodymode.grid(row=0, column=3, sticky="w", padx=6, pady=5)
        ttk.Label(bodysec, text="Body").grid(row=1, column=0, sticky="ne", padx=6, pady=5)
        self.txt_body = tk.Text(bodysec, height=5, width=70, wrap="word")
        init_body = self.profile.get("body", {})
        if isinstance(init_body, (dict, list)):
            self.txt_body.insert("1.0", json.dumps(init_body))
        else:
            self.txt_body.insert("1.0", str(init_body))
        self.txt_body.grid(row=1, column=1, columnspan=3, sticky="we", padx=6, pady=5)
        for c in range(4):
            bodysec.grid_columnconfigure(c, weight=1)
        bulk = ttk.LabelFrame(self.root, text="Bulk Ops (CSV Import)")
        bulk.pack(fill="x", pady=8)
        ttk.Button(bulk, text="Import CSV…", command=self.on_import_csv).grid(row=0, column=0, padx=6, pady=6, sticky="w")
        ttk.Label(bulk, textvariable=self.bulk_file_path, foreground="")
        ttk.Label(bulk, text="Part Number Column").grid(row=1, column=0, sticky="e", padx=6, pady=6)
        self.cmb_bulk_col = ttk.Combobox(bulk, textvariable=self.bulk_selected_col, state="readonly", width=28, values=[])
        self.cmb_bulk_col.grid(row=1, column=1, sticky="w", padx=6, pady=6)
        ttk.Button(bulk, text="Run Bulk", command=self.on_run_bulk).grid(row=1, column=2, padx=6, pady=6)
        ttk.Button(bulk, text="Cancel", command=self.on_cancel, state="disabled").grid(row=1, column=3, padx=6, pady=6)
        for c in range(4):
            bulk.grid_columnconfigure(c, weight=1)
        actions = ttk.LabelFrame(self.root, text="Actions")
        actions.pack(fill="x", pady=8)
        ttk.Button(actions, text="Test Single Page", command=self.on_test_single).pack(side="left", padx=6, pady=6)
        ttk.Button(actions, text="Fetch All (Single Part)", command=self.on_fetch_single).pack(side="left", padx=6, pady=6)
        self.btn_export = ttk.Button(actions, text="Export CSV (last results)", command=self.on_export, state="disabled")
        self.btn_export.pack(side="left", padx=6, pady=6)
        status = ttk.LabelFrame(self.root, text="Live Status")
        status.pack(fill="both", expand=True, pady=8)
        self.txt_status = tk.Text(status, height=14, wrap="word", font=("Consolas", 10))
        self.txt_status.pack(fill="both", expand=True, padx=8, pady=8)
    def update_status_panel(self, text: str):
        self.txt_status.insert("end", text)
        self.txt_status.see("end")
    def set_progress(self, msg: str):
        self.root.after(0, lambda m=msg: self._set_progress_text(m))
    def _set_progress_text(self, msg: str):
        self.update_status_panel(f"{msg}\n")
    def on_profile_load(self):
        sel = self.cmb_profile.get().strip()
        if not sel:
            return
        self.settings["current_profile"] = sel
        save_settings(self.settings)
        self.profile = self._current_profile()
        self.ent_url.delete(0, "end"); self.ent_url.insert(0, self.profile["url"])
        self.ent_user.delete(0, "end"); self.ent_user.insert(0, self.profile["username"])
        self.ent_pass.delete(0, "end"); self.ent_pass.insert(0, self.profile["password"])
        self.cmb_method.set(self.profile["method"].upper())
        self.spn_timeout.delete(0, "end"); self.spn_timeout.insert(0, str(self.profile["timeout"]))
        self.cmb_pagesize.set(str(self.profile["batch_size"]))
        self.var_sort.set(self.profile["sort_enabled"]); self.cmb_sort.set(self.profile["sort"])
        self.var_status.set(self.profile["status_enabled"]); self.cmb_status.set(self.profile["status"])
        self.var_rl.set(self.profile["rate_limit_enabled"]); self.cmb_rpm.set(str(self.profile["requests_per_minute"]))
        self.ent_part.delete(0, "end"); self.ent_part.insert(0, self.profile["params"].get("part_number", ""))
        self.cmb_bodymode.set(self.profile.get("body_mode", "json"))
        self.txt_body.delete("1.0", "end")
        body = self.profile.get("body", {})
        self.txt_body.insert("1.0", json.dumps(body) if isinstance(body, (dict, list)) else str(body))
        self.update_status_panel(f"[Profile] Loaded '{sel}'\n")
    def on_profile_save(self):
        if not self.collect_profile_from_form():
            return
        self._sync_profile_back()
        save_settings(self.settings)
        self.update_status_panel("[Profile] Saved\n")
    def on_profile_save_as(self):
        new_name = tk.simpledialog.askstring("Save Profile As", "Enter new profile name:")
        if not new_name:
            return
        if not self.collect_profile_from_form():
            return
        self.profile["name"] = new_name
        self.settings["profiles"][new_name] = copy.deepcopy(self.profile)
        self.settings["current_profile"] = new_name
        save_settings(self.settings)
        self.cmb_profile["values"] = list(self.settings["profiles"].keys())
        self.cmb_profile.set(new_name)
        self.update_status_panel(f"[Profile] Saved as '{new_name}'\n")
    def collect_profile_from_form(self) -> bool:
        try:
            self.profile["url"] = self.ent_url.get().strip()
            self.profile["username"] = self.ent_user.get()
            self.profile["password"] = self.ent_pass.get()
            self.profile["method"] = self.cmb_method.get().strip().upper()
            self.profile["timeout"] = int(self.spn_timeout.get())
            self.profile["batch_size"] = int(self.cmb_pagesize.get())
            self.profile["sort_enabled"] = bool(self.var_sort.get())
            self.profile["sort"] = self.cmb_sort.get().strip()
            self.profile["status_enabled"] = bool(self.var_status.get())
            self.profile["status"] = self.cmb_status.get().strip()
            self.profile["rate_limit_enabled"] = bool(self.var_rl.get())
            self.profile["requests_per_minute"] = int(self.cmb_rpm.get())
            self.profile["params"]["part_number"] = self.ent_part.get().strip()
            self.profile["params"]["limit"] = self.profile["batch_size"]
            mode = self.cmb_bodymode.get().strip().lower()
            self.profile["body_mode"] = "json" if mode not in ("json", "raw") else mode
            body_txt = self.txt_body.get("1.0", "end").strip()
            if self.profile["body_mode"] == "json":
                self.profile["body"] = json.loads(body_txt) if body_txt else {}
            else:
                self.profile["body"] = body_txt
            return True
        except json.JSONDecodeError as e:
            messagebox.showerror("Error", f"Body must be valid JSON.\n{e}")
            return False
        except Exception as e:
            messagebox.showerror("Error", f"Invalid setting: {e}")
            return False
    def on_test_single(self):
        if not self.collect_profile_from_form():
            return
        self.update_status_panel("[Test] Single page request…\n")
        t = threading.Thread(target=self._test_worker, daemon=True)
        t.start()
    def _test_worker(self):
        try:
            p = copy.deepcopy(self.profile)
            client = APIClient(p, threading.Event())
            params = copy.deepcopy(p.get("params", {})) or {}
            params["limit"] = int(p.get("batch_size", 200))
            if p.get("sort_enabled", False):
                params["sort"] = p.get("sort", "desc")
            if p.get("status_enabled", False) and p.get("status", "").strip():
                params["status"] = p.get("status", "").strip()
            code, payload = client._request(p["url"], params, p.get("body", {}))
            if code == 200 and isinstance(payload, dict):
                count = int(payload.get("count", 0))
                got = len(payload.get("results", []) or [])
                self.set_progress(f"[Test] OK. Total={count}, Page={got}")
            else:
                self.set_progress(f"[Test] Failed. HTTP {code}. See logs.")
        except Exception as e:
            logging.exception("Test failed")
            self.set_progress(f"[Test] Exception: {e}")
    def on_fetch_single(self):
        if not self.collect_profile_from_form():
            return
        part = self.ent_part.get().strip()
        if not part:
            messagebox.showerror("Error", "Enter a Part Number for single fetch.")
            return
        self.results = []
        self.btn_export.config(state="disabled")
        self.cancel_evt.clear()
        self.update_status_panel("[Fetch] Single part — starting…\n")
        t = threading.Thread(target=self._fetch_single_worker, args=(part,), daemon=True)
        t.start()
    def _fetch_single_worker(self, part: str):
        try:
            p = copy.deepcopy(self.profile)
            client = APIClient(p, self.cancel_evt)
            orders = client.fetch_all(part, progress_cb=self.set_progress)
            self.results = orders
            total = sum(float(o.get("total", 0) or 0) for o in orders) if orders else 0.0
            self.set_progress(f"[Fetch] Done. Orders={len(orders)} | ${total:,.2f}")
            self.root.after(0, lambda: self.btn_export.config(state="normal"))
        except Exception as e:
            logging.exception("Fetch single failed")
            self.set_progress(f"[Fetch] Failed: {e}")
    def on_import_csv(self):
        path = filedialog.askopenfilename(
            title="Select CSV with Part Numbers",
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", newline="") as f:
                r = csv.reader(f)
                rows = list(r)
            if not rows:
                messagebox.showerror("Error", "CSV is empty.")
                return
            headers = rows[0]
            self.bulk_headers = headers
            self.bulk_file_path.set(path)
            self.cmb_bulk_col["values"] = headers
            if headers:
                self.cmb_bulk_col.set(headers[0])
            self._bulk_rows = rows  
            self.update_status_panel(f"[Bulk] Loaded CSV: {os.path.basename(path)} | Columns: {len(headers)} | Rows: {len(rows)-1}\n")
        except Exception as e:
            logging.exception("CSV import failed")
            messagebox.showerror("Error", f"Failed to load CSV:\n{e}")
    def on_run_bulk(self):
        if not hasattr(self, "_bulk_rows"):
            messagebox.showerror("Error", "Import a CSV first.")
            return
        col = self.cmb_bulk_col.get().strip()
        if not col:
            messagebox.showerror("Error", "Select the Part Number column.")
            return
        if not self.collect_profile_from_form():
            return
        try:
            idx = self.bulk_headers.index(col)
        except ValueError:
            messagebox.showerror("Error", f"Column '{col}' not found.")
            return
        parts = []
        seen = set()
        for row in self._bulk_rows[1:]:
            if idx < len(row):
                pn = (row[idx] or "").strip()
                if pn and pn not in seen:
                    parts.append(pn)
                    seen.add(pn)
        if not parts:
            messagebox.showerror("Error", "No part numbers found in the selected column.")
            return
        self.bulk_parts = parts
        self.results = []
        self.btn_export.config(state="disabled")
        self.cancel_evt.clear()
        self.update_status_panel(f"[Bulk] Starting for {len(parts)} parts…\n")
        for child in self.root.winfo_children():
            if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Bulk Ops (CSV Import)":
                for btn in child.winfo_children():
                    if isinstance(btn, ttk.Button) and btn.cget("text") == "Cancel":
                        btn.configure(state="normal")
        t = threading.Thread(target=self._bulk_worker, daemon=True)
        t.start()
    def _bulk_worker(self):
        try:
            p = copy.deepcopy(self.profile)
            client = APIClient(p, self.cancel_evt)
            total_parts = len(self.bulk_parts)
            combined: List[dict] = []
            t0 = time.time()
            for i, pn in enumerate(self.bulk_parts, start=1):
                if self.cancel_evt.is_set():
                    break
                self.set_progress(f"[Bulk] ({i}/{total_parts}) {pn}")
                orders = client.fetch_all(pn, progress_cb=None)  
                combined.extend(orders)
            self.results = combined
            elapsed = time.time() - t0
            total_val = sum(float(o.get("total", 0) or 0) for o in combined) if combined else 0.0
            msg = "Cancelled." if self.cancel_evt.is_set() else "Completed."
            self.set_progress(f"[Bulk] {msg} Orders={len(combined)} | ${total_val:,.2f} | {elapsed:.1f}s")
            self.root.after(0, lambda: self.btn_export.config(state="normal"))
        except Exception as e:
            logging.exception("Bulk failed")
            self.set_progress(f"[Bulk] Failed: {e}")
        finally:
            for child in self.root.winfo_children():
                if isinstance(child, ttk.LabelFrame) and child.cget("text") == "Bulk Ops (CSV Import)":
                    for btn in child.winfo_children():
                        if isinstance(btn, ttk.Button) and btn.cget("text") == "Cancel":
                            btn.configure(state="disabled")
    def on_cancel(self):
        self.cancel_evt.set()
        self.update_status_panel("[Action] Cancelling…\n")
    def on_export(self):
        if not self.results:
            messagebox.showinfo("No data", "No results to export.")
            return
        path = filedialog.asksaveasfilename(
            title="Save CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return
        try:
            export_orders_atomic(self.results, path)
            messagebox.showinfo("Done", f"Exported to {path}")
            self.update_status_panel(f"[Export] {path}\n")
        except Exception as e:
            logging.exception("Export failed")
            messagebox.showerror("Error", f"Export failed:\n{e}")
if __name__ == "__main__":
    root = tk.Tk()
    app = ApiRouterApp(root)
    root.mainloop()
