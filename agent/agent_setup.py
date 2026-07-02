
import ctypes
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
import tkinter as tk
from tkinter import messagebox


APP_NAME = "Mini EDR Agent Setup"
TASK_NAME = "MiniEDR-Agent"


FIXED_SERVER_URL = os.getenv(
    "MINI_EDR_SERVER_URL",
"http://127.0.0.1:8000").rstrip("/")

BASE_DIR = Path(sys.argv[0]).resolve().parent

CONFIG_PATH = BASE_DIR / "config.json"
AGENT_ID_PATH = BASE_DIR / "agent_id.txt"
AGENT_EXE_PATH = BASE_DIR / "agent.exe"

DEFAULT_CONFIG = {
    "server_url": FIXED_SERVER_URL,
    "interval_seconds": 10,
    "response_poll_seconds": 4,
    "country": "Jordan",
    "lab_mode": True,
    "api_key": "",
    "ENABLE_HMAC": False,
    "HMAC_SECRET": "",
}


def is_admin():
    if os.name != "nt":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def relaunch_as_admin():
    if os.name != "nt":
        return False

    try:
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            str(BASE_DIR),
            1,
        )
        return True
    except Exception:
        return False


def run_command(command):
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

    return subprocess.run(
        command,
        cwd=str(BASE_DIR),
        shell=True,
        capture_output=True,
        text=True,
        creationflags=creation_flags,
    )


def load_existing_config():
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)

            merged = {**DEFAULT_CONFIG, **data}
            merged["server_url"] = FIXED_SERVER_URL
            merged["ENABLE_HMAC"] = False
            merged["HMAC_SECRET"] = ""
            return merged

        except Exception:
            return DEFAULT_CONFIG.copy()

    return DEFAULT_CONFIG.copy()


def ensure_agent_id():
    if AGENT_ID_PATH.exists():
        try:
            existing = AGENT_ID_PATH.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except Exception:
            pass

    agent_id = f"mini-edr-{uuid.uuid4()}"
    AGENT_ID_PATH.write_text(agent_id, encoding="utf-8")
    return agent_id


def save_config(config):
    config["server_url"] = FIXED_SERVER_URL
    config["ENABLE_HMAC"] = False
    config["HMAC_SECRET"] = ""

    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4)


def install_startup_task():
    if not AGENT_EXE_PATH.exists():
        raise FileNotFoundError(
            f"agent.exe was not found in:\n{BASE_DIR}\n\n"
            "Put agent.exe in the same folder as MiniEDR-Agent-Setup.exe."
        )

    run_command(f'schtasks /Delete /TN "{TASK_NAME}" /F')

    create_cmd = (
        f'schtasks /Create '
        f'/TN "{TASK_NAME}" '
        f'/TR "\\"{AGENT_EXE_PATH}\\"" '
        f'/SC ONLOGON '
        f'/RL HIGHEST '
        f'/F'
    )

    result = run_command(create_cmd)

    if result.returncode != 0:
        raise RuntimeError(
            "Failed to create startup task.\n\n"
            f"STDOUT:\n{result.stdout}\n\n"
            f"STDERR:\n{result.stderr}"
        )

    return result.stdout.strip()


def start_task_now():
    result = run_command(f'schtasks /Run /TN "{TASK_NAME}"')

    if result.returncode != 0:
        raise RuntimeError(
            "Startup task was created, but failed to start now.\n\n"
            f"STDOUT:\n{result.stdout}\n\n"
            f"STDERR:\n{result.stderr}"
        )

    return result.stdout.strip()


class SetupWizard(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(APP_NAME)
        self.geometry("920x760")
        self.minsize(920, 760)
        self.resizable(True, True)
        self.configure(bg="#08111f")

        self.config_data = load_existing_config()
        self.agent_id = ensure_agent_id()
        self.current_step = 0
        self.install_log = ""

        self.interval_seconds = tk.StringVar(
            value=str(self.config_data.get("interval_seconds", 10))
        )
        self.response_poll_seconds = tk.StringVar(
            value=str(self.config_data.get("response_poll_seconds", 4))
        )
        self.country = tk.StringVar(value=self.config_data.get("country", "Jordan"))
        self.lab_mode = tk.BooleanVar(value=bool(self.config_data.get("lab_mode", True)))

        self.accept_terms = tk.BooleanVar(value=False)
        self.register_auto_start = tk.BooleanVar(value=True)
        self.start_after_install = tk.BooleanVar(value=True)

        self.build_layout()

        self.steps = [
            self.render_welcome,
            self.render_terms,
            self.render_agent_options,
            self.render_install,
            self.render_finish,
        ]

        self.render_current_step()

    def build_layout(self):
        self.footer = tk.Frame(self, bg="#0d1728", height=78)
        self.footer.pack(fill="x", side="bottom")
        self.footer.pack_propagate(False)

        self.back_btn = tk.Button(
            self.footer,
            text="Back",
            command=self.previous_step,
            width=12,
            bg="#13223b",
            fg="#eaf2ff",
            activebackground="#223454",
            activeforeground="#ffffff",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        self.back_btn.pack(side="left", padx=24, pady=20)

        self.next_btn = tk.Button(
            self.footer,
            text="Next",
            command=self.next_step,
            width=16,
            bg="#4f8cff",
            fg="#ffffff",
            activebackground="#3d79eb",
            activeforeground="#ffffff",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2",
        )
        self.next_btn.pack(side="right", padx=24, pady=20)

        self.content = tk.Frame(self, bg="#08111f")
        self.content.pack(fill="both", expand=True, side="top")

    def clear_content(self):
        for widget in self.content.winfo_children():
            widget.destroy()

    def title_label(self, text, subtitle=None):
        tk.Label(
            self.content,
            text=text,
            bg="#08111f",
            fg="#ffffff",
            font=("Segoe UI", 24, "bold"),
        ).pack(anchor="w", padx=42, pady=(30, 8))

        if subtitle:
            tk.Label(
                self.content,
                text=subtitle,
                bg="#08111f",
                fg="#94a3b8",
                font=("Segoe UI", 11),
                wraplength=720,
                justify="left",
            ).pack(anchor="w", padx=42)

    def card(self):
        frame = tk.Frame(
            self.content,
            bg="#101c31",
            highlightbackground="#223454",
            highlightthickness=1,
        )
        frame.pack(fill="both", expand=True, padx=42, pady=24)
        return frame

    def field(self, parent, label, variable, row, col):
        tk.Label(
            parent,
            text=label,
            bg="#101c31",
            fg="#cbd5e1",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=row, column=col, sticky="w", padx=16, pady=(12, 6))

        entry = tk.Entry(
            parent,
            textvariable=variable,
            bg="#08111f",
            fg="#eaf2ff",
            insertbackground="#eaf2ff",
            relief="flat",
            font=("Segoe UI", 11),
            highlightbackground="#223454",
            highlightcolor="#4f8cff",
            highlightthickness=1,
        )
        entry.grid(row=row + 1, column=col, sticky="ew", padx=16, pady=(0, 8), ipady=8)

        return entry

    def checkbox(self, parent, text, variable, row, col):
        tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            bg="#101c31",
            fg="#eaf2ff",
            selectcolor="#08111f",
            activebackground="#101c31",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=row, column=col, sticky="w", padx=16, pady=6)

    def render_current_step(self):
        self.clear_content()
        self.steps[self.current_step]()

        self.back_btn.config(state="normal" if self.current_step > 0 else "disabled")

        if self.current_step == len(self.steps) - 1:
            self.next_btn.config(text="Close")
        elif self.current_step == len(self.steps) - 2:
            self.next_btn.config(text="Install")
        else:
            self.next_btn.config(text="Next")

    def render_welcome(self):
        self.title_label(
            "Welcome to Mini EDR Agent",
            "This wizard installs and starts the endpoint monitoring agent using a preconfigured backend server.",
        )

        frame = self.card()
        admin_text = "Administrator: Yes" if is_admin() else "Administrator: No"

        tk.Label(
            frame,
            text="Mini EDR Agent Setup",
            bg="#101c31",
            fg="#ffffff",
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w", padx=24, pady=(24, 10))

        text = (
            "This setup will:\n\n"
            "• Use a fixed backend server URL\n"
            "• Create or update config.json automatically\n"
            "• Generate a unique agent_id.txt\n"
            "• Register agent.exe in Windows Task Scheduler\n"
            "• Start the agent immediately after installation\n"
            "• Run automatically when the user logs in\n\n"
            f"Backend Server: {FIXED_SERVER_URL}\n"
            f"{admin_text}\n\n"
            "This deployment flow is designed for controlled lab and graduation demo environments."
        )

        tk.Label(
            frame,
            text=text,
            bg="#101c31",
            fg="#bbf7d0" if is_admin() else "#fde68a",
            font=("Segoe UI", 11),
            justify="left",
            wraplength=700,
        ).pack(anchor="w", padx=24, pady=10)

    def render_terms(self):
        self.title_label(
            "Terms and Conditions",
            "Please review and accept the authorized lab usage terms.",
        )

        frame = self.card()

        terms = (
            "Mini EDR Agent is intended for lab, academic, and authorized testing environments only.\n\n"
            "By continuing, you confirm that:\n"
            "• You are installing this agent on a device you own or are authorized to monitor.\n"
            "• The agent collects endpoint telemetry such as process, system, and network metadata.\n"
            "• Response actions remain controlled and safe in Lab Mode.\n"
            "• This tool must not be used for unauthorized monitoring."
        )

        tk.Label(
            frame,
            text=terms,
            bg="#101c31",
            fg="#cbd5e1",
            font=("Segoe UI", 11),
            justify="left",
            wraplength=700,
        ).pack(anchor="w", padx=24, pady=(24, 16))

        tk.Checkbutton(
            frame,
            text="I accept the terms and confirm authorized usage.",
            variable=self.accept_terms,
            bg="#101c31",
            fg="#eaf2ff",
            selectcolor="#08111f",
            activebackground="#101c31",
            activeforeground="#ffffff",
            font=("Segoe UI", 10, "bold"),
        ).pack(anchor="w", padx=24, pady=10)

    def render_agent_options(self):
        self.title_label(
            "Agent Options",
            "Configure endpoint telemetry timing and startup behavior.",
        )

        frame = self.card()
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        tk.Label(
            frame,
            text="Backend Server URL",
            bg="#101c31",
            fg="#cbd5e1",
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        tk.Label(
            frame,
            text=FIXED_SERVER_URL,
            bg="#08111f",
            fg="#bbf7d0",
            font=("Consolas", 11, "bold"),
            anchor="w",
            padx=12,
        ).grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 12), ipady=10)

        self.field(frame, "Telemetry Interval Seconds", self.interval_seconds, 2, 0)
        self.field(frame, "Response Poll Seconds", self.response_poll_seconds, 2, 1)
        self.field(frame, "Country", self.country, 4, 0)

        self.checkbox(frame, "Enable Safe Lab Mode", self.lab_mode, 6, 0)
        self.checkbox(frame, "Register Auto-Start Task", self.register_auto_start, 6, 1)
        self.checkbox(frame, "Start Agent After Install", self.start_after_install, 7, 0)

        tk.Label(
            frame,
            text="The server address is preconfigured and cannot be changed by the endpoint user.",
            bg="#101c31",
            fg="#94a3b8",
            font=("Segoe UI", 9),
        ).grid(row=8, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 20))

    def render_install(self):
        self.title_label(
            "Ready to Install",
            "Review settings before installing the Mini EDR Agent auto-start task.",
        )

        frame = self.card()

        summary = (
            f"Agent ID: {self.agent_id}\n"
            f"Agent EXE: {AGENT_EXE_PATH}\n"
            f"Task Name: {TASK_NAME}\n"
            f"Backend URL: {FIXED_SERVER_URL}\n"
            f"Country: {self.country.get()}\n"
            f"Telemetry Interval: {self.interval_seconds.get()} seconds\n"
            f"Response Poll: {self.response_poll_seconds.get()} seconds\n"
            f"Lab Mode: {'Enabled' if self.lab_mode.get() else 'Disabled'}\n"
            f"Auto-Start Task: {'Enabled' if self.register_auto_start.get() else 'Disabled'}\n"
            f"Start After Install: {'Enabled' if self.start_after_install.get() else 'Disabled'}"
        )

        tk.Label(
            frame,
            text=summary,
            bg="#101c31",
            fg="#eaf2ff",
            font=("Consolas", 10),
            justify="left",
            wraplength=700,
        ).pack(anchor="w", padx=24, pady=(24, 14))

        if not AGENT_EXE_PATH.exists():
            tk.Label(
                frame,
                text="WARNING: agent.exe was not found in the same folder as setup.",
                bg="#101c31",
                fg="#fecaca",
                font=("Segoe UI", 10, "bold"),
            ).pack(anchor="w", padx=24, pady=8)

    def render_finish(self):
        self.title_label(
            "Installation Complete",
            "Mini EDR Agent was configured successfully.",
        )

        frame = self.card()

        message = (
            f"Created/Updated:\n"
            f"• {CONFIG_PATH}\n"
            f"• {AGENT_ID_PATH}\n\n"
            f"Backend Server:\n"
            f"• {FIXED_SERVER_URL}\n\n"
            f"Windows Task Scheduler:\n"
            f"• {TASK_NAME}\n\n"
            f"Install Log:\n{self.install_log or 'No log'}\n\n"
            "You can verify it using Task Scheduler or schtasks /Query."
        )

        tk.Label(
            frame,
            text=message,
            bg="#101c31",
            fg="#bbf7d0",
            font=("Segoe UI", 10, "bold"),
            justify="left",
            wraplength=700,
        ).pack(anchor="w", padx=24, pady=24)

    def validate_step(self):
        if self.current_step == 1 and not self.accept_terms.get():
            messagebox.showwarning(
                "Terms Required",
                "Please accept the terms before continuing.",
            )
            return False

        if self.current_step == 2:
            try:
                interval = int(self.interval_seconds.get())
                poll = int(self.response_poll_seconds.get())

                if interval <= 0 or poll <= 0:
                    raise ValueError

            except Exception:
                messagebox.showwarning(
                    "Invalid Values",
                    "Interval and poll seconds must be positive numbers.",
                )
                return False

        return True

    def install_agent(self):
        if self.register_auto_start.get() and not is_admin():
            answer = messagebox.askyesno(
                "Administrator Required",
                "Registering an Auto-Start task requires Administrator privileges.\n\n"
                "Do you want to restart setup as Administrator?",
            )

            if answer and relaunch_as_admin():
                self.destroy()
                return "relaunched"

            raise PermissionError("Installation requires Administrator privileges.")

        config = {
            "server_url": FIXED_SERVER_URL,
            "interval_seconds": int(self.interval_seconds.get()),
            "response_poll_seconds": int(self.response_poll_seconds.get()),
            "country": self.country.get().strip() or "Jordan",
            "lab_mode": bool(self.lab_mode.get()),
            "api_key": "",
            "ENABLE_HMAC": False,
            "HMAC_SECRET": "",
        }

        save_config(config)

        logs = [
            "Fixed backend server applied.",
            "config.json saved.",
            "agent_id.txt verified.",
        ]

        if self.register_auto_start.get():
            task_output = install_startup_task()
            logs.append("Auto-start task created.")

            if task_output:
                logs.append(task_output)

        if self.start_after_install.get() and self.register_auto_start.get():
            start_output = start_task_now()
            logs.append("Agent started.")

            if start_output:
                logs.append(start_output)

        self.install_log = "\n".join(logs)
        return "installed"

    def next_step(self):
        if self.current_step == len(self.steps) - 1:
            self.destroy()
            return

        if not self.validate_step():
            return

        if self.current_step == len(self.steps) - 2:
            try:
                result = self.install_agent()
                if result == "relaunched":
                    return
            except Exception as e:
                messagebox.showerror("Install Failed", str(e))
                return

        self.current_step += 1
        self.render_current_step()

    def previous_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.render_current_step()


if __name__ == "__main__":
    app = SetupWizard()
    app.mainloop()
