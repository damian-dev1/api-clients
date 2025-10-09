import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import json
import time
import threading
import queue
class MiniPostman(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Mini Postman")
        self.geometry("350x450")
        self.style = ttk.Style()
        self.style.configure("Status.TLabel", font=('Segoe UI', 9), padding=2)
        self.style.configure("Success.Status.TLabel", foreground="green")
        self.style.configure("Redirect.Status.TLabel", foreground="blue")
        self.style.configure("ClientError.Status.TLabel", foreground="orange")
        self.style.configure("ServerError.Status.TLabel", foreground="red")
        self.request_queue = queue.Queue()
        self._create_widgets()
        self.after(100, self._process_queue)
    def _create_widgets(self):
        top_frame = ttk.Frame(self, padding=10)
        top_frame.pack(fill=tk.X, side=tk.TOP)
        top_frame.columnconfigure(1, weight=1)
        self.method_var = tk.StringVar(value="GET")
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD"]
        method_menu = ttk.Combobox(top_frame, textvariable=self.method_var, values=methods, state="readonly", width=8)
        method_menu.grid(row=0, column=0, padx=(0, 5))
        self.url_entry = ttk.Entry(top_frame, font=('Segoe UI', 10))
        self.url_entry.grid(row=0, column=1, sticky="ew")
        self.url_entry.bind("<Return>", lambda e: self.send_request())
        send_button = ttk.Button(top_frame, text="Send", command=self.send_request)
        send_button.grid(row=0, column=2, padx=(5, 0))
        paned_window = ttk.PanedWindow(self, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        req_notebook = ttk.Notebook(paned_window, padding=2)
        self.params_text = self._create_scrolled_text(req_notebook)
        self.headers_text = self._create_scrolled_text(req_notebook, is_json=True)
        self.body_text = self._create_scrolled_text(req_notebook, is_json=True)
        req_notebook.add(self.params_text, text="Params")
        req_notebook.add(self.headers_text, text="Headers")
        req_notebook.add(self.body_text, text="Body")
        paned_window.add(req_notebook, weight=1)
        res_frame = ttk.Frame(paned_window)
        res_frame.columnconfigure(0, weight=1)
        res_frame.rowconfigure(1, weight=1)
        self.status_label = ttk.Label(res_frame, text="Status: Idle", style="Status.TLabel")
        self.status_label.grid(row=0, column=0, sticky="w", pady=(5, 5))
        res_notebook = ttk.Notebook(res_frame)
        res_notebook.grid(row=1, column=0, sticky="nsew")
        self.response_body_text = self._create_scrolled_text(res_notebook)
        self.response_headers_text = self._create_scrolled_text(res_notebook)
        res_notebook.add(self.response_body_text, text="Body")
        res_notebook.add(self.response_headers_text, text="Headers")
        paned_window.add(res_frame, weight=2)
    def _create_scrolled_text(self, parent, is_json=False):
        text_widget = scrolledtext.ScrolledText(parent, wrap=tk.WORD, height=5, font=("Consolas", 10))
        if is_json:
            text_widget.bind("<KeyRelease>", lambda e, w=text_widget: self._validate_json(w))
        return text_widget
    def _validate_json(self, widget):
        content = widget.get("1.0", "end-1c").strip()
        default_bg = 'SystemWindow'
        error_bg = ''
        if not content:
            widget.configure(bg=default_bg)
            return
        try:
            json.loads(content)
            widget.configure(bg=default_bg)
        except json.JSONDecodeError:
            widget.configure(bg=error_bg)
    def _parse_input(self, text_widget):
        content = text_widget.get("1.0", "end-1c").strip()
        if not content:
            return {}
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            messagebox.showerror("JSON Error", "Invalid JSON detected in Headers or Body. Please correct it.")
            return None
    def send_request(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "URL cannot be empty.")
            return
        headers = self._parse_input(self.headers_text)
        body = self._parse_input(self.body_text)
        if headers is None or body is None: 
            return
        self.status_label.config(text="Status: Sending...", style="Status.TLabel")
        thread = threading.Thread(target=self._send_request_thread, args=(url, headers, body))
        thread.daemon = True
        thread.start()
    def _send_request_thread(self, url, headers, body):
        try:
            method = self.method_var.get()
            params_str = self.params_text.get("1.0", "end-1c").strip()
            params = dict(p.split('=', 1) for p in params_str.split('&') if '=' in p)
            start_time = time.time()
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                json=body if method not in ["GET", "HEAD"] else None,
                params=params,
                timeout=10 
            )
            duration = time.time() - start_time
            self.request_queue.put(('success', (response, duration)))
        except requests.exceptions.RequestException as e:
            self.request_queue.put(('error', e))
    def _process_queue(self):
        try:
            msg_type, data = self.request_queue.get_nowait()
            if msg_type == 'success':
                response, duration = data
                status_code = response.status_code
                status_style = "ServerError.Status.TLabel" 
                if 100 <= status_code < 300: status_style = "Success.Status.TLabel"
                elif 300 <= status_code < 400: status_style = "Redirect.Status.TLabel"
                elif 400 <= status_code < 500: status_style = "ClientError.Status.TLabel"
                size_kb = len(response.content) / 1024
                self.status_label.config(
                    text=f"Status: {status_code} {response.reason} | Time: {duration:.2f}s | Size: {size_kb:.2f} KB",
                    style=status_style
                )
                self.response_body_text.delete("1.0", tk.END)
                try:
                    pretty_response = json.dumps(response.json(), indent=2)
                    self.response_body_text.insert("1.0", pretty_response)
                except json.JSONDecodeError:
                    self.response_body_text.insert("1.0", response.text)
                pretty_headers = json.dumps(dict(response.headers), indent=2)
                self.response_headers_text.delete("1.0", tk.END)
                self.response_headers_text.insert("1.0", pretty_headers)
            elif msg_type == 'error':
                self.status_label.config(text=f"Status: Error", style="ServerError.Status.TLabel")
                self.response_body_text.delete("1.0", tk.END)
                self.response_body_text.insert("1.0", str(data))
                self.response_headers_text.delete("1.0", tk.END)
        except queue.Empty:
            pass 
        finally:
            self.after(100, self._process_queue)
if __name__ == "__main__":
    app = MiniPostman()
    app.mainloop()
