import json
import os
import platform
import socket
import sys
import time
import uuid
from pathlib import Path
from collections import deque
from datetime import datetime

import ctypes
import psutil
import requests

import logging
from logging.handlers import RotatingFileHandler

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)

network_logger = logging.getLogger("network")
network_logger.setLevel(logging.INFO)

agent_logger = logging.getLogger("agent")
agent_logger.setLevel(logging.INFO)


def show_popup(title, message):
    try:
        write_log(f"User popup suppressed: {title} - {message}")
    except Exception:
        pass


SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "mshta.exe",
    "wmic.exe",
    "psexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "schtasks.exe",
    "wevtutil.exe",
    "vssadmin.exe",
    "mimikatz.exe",
    "procdump.exe",
}

SUSPICIOUS_PORTS = {1337, 4444, 5555, 8080, 8081, 8443, 9001, 9999}

ENCODED_KEYWORDS = [
    "-enc",
    "-encodedcommand",
    "encodedcommand",
    "frombase64string",
    "base64",
]

DOWNLOAD_OR_EXEC_KEYWORDS = [
    "downloadstring",
    "invoke-webrequest",
    "iwr ",
    "wget ",
    "curl ",
    "start-process",
    "invoke-expression",
    "iex(",
    "webclient",
    "executionpolicy",
    "bypass",
    "windowstyle",
    "hidden",
    "noprofile",
    "nop",
    "noninteractive",
    "bitsadmin",
    "certutil",
    "wevtutil",
    "clear-eventlog",
    "remove-eventlog",
    "vssadmin",
    "procdump",
    "lsass",
]

CRITICAL_CMD_BEHAVIORS = [
    ("vssadmin delete shadows", "Shadow copy deletion command detected"),
    ("wmic shadowcopy delete", "Shadow copy deletion command detected"),
    ("delete shadows", "Shadow copy deletion command detected"),
    ("wevtutil cl", "Event log clearing command detected"),
    ("clear-eventlog", "Event log clearing command detected"),
    ("remove-eventlog", "Event log clearing command detected"),
    ("reg save hklm\\sam", "Credential registry hive dump command detected"),
    ("reg save hklm\\security", "Credential registry hive dump command detected"),
    ("reg save hklm\\system", "Credential registry hive dump command detected"),
    ("procdump", "Credential dump tooling command detected"),
    ("lsass", "LSASS credential access command detected"),
    ("mimikatz", "Credential theft tooling command detected"),
]

HIGH_RISK_CMD_BEHAVIORS = [
    ("certutil -urlcache", "Certutil download command detected"),
    ("certutil.exe -urlcache", "Certutil download command detected"),
    ("bitsadmin /transfer", "BITSAdmin transfer command detected"),
    ("bitsadmin.exe /transfer", "BITSAdmin transfer command detected"),
    ("schtasks /create", "Scheduled task creation command detected"),
    ("sc create", "Service creation command detected"),
    ("net localgroup administrators", "Local administrator group modification command detected"),
    ("powershell -enc", "PowerShell encoded command launched from cmd.exe"),
    ("powershell.exe -enc", "PowerShell encoded command launched from cmd.exe"),
    ("powershell -encodedcommand", "PowerShell encoded command launched from cmd.exe"),
    ("powershell.exe -encodedcommand", "PowerShell encoded command launched from cmd.exe"),
    ("curl http", "Command-line download command detected"),
    ("curl https", "Command-line download command detected"),
    ("curl.exe http", "Command-line download command detected"),
    ("curl.exe https", "Command-line download command detected"),
    ("wget http", "Command-line download command detected"),
    ("wget https", "Command-line download command detected"),
    ("wget.exe http", "Command-line download command detected"),
    ("wget.exe https", "Command-line download command detected"),
]

OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}

SAFE_TEMP_APPDATA_PROCESSES = {
    "code.exe",
    "discord.exe",
    "chrome.exe",
    "msedge.exe",
    "teams.exe",
    "slack.exe",
    "spotify.exe",
    "notion.exe",
    "python.exe",
}

PROTECTED_PROCESSES = {
    "explorer.exe",
    "winlogon.exe",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "svchost.exe",
    "dwm.exe",
}

EVENT_RETENTION_SECONDS = 120
LIVE_EVENT_DEDUP_SECONDS = 12
SYSTEM_ALERT_DEDUP_SECONDS = 20
GEO_CACHE_TTL_SECONDS = 300
TELEMETRY_EVENT_DEDUP_SECONDS = 20


def get_base_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = Path(get_base_dir())
APP_NAME = "MiniEDR"


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default

    value = value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def env_path(name: str) -> Path | None:
    value = os.getenv(name)
    if not value:
        return None
    try:
        return Path(value).expanduser()
    except Exception:
        return None


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)) or default)
    except Exception:
        return default


ANALYST_MODE = env_bool("MINI_EDR_ANALYST_MODE", True)
LOG_MAX_BYTES = max(64 * 1024, env_int("MINI_EDR_LOG_MAX_BYTES", 1024 * 1024))
LOG_BACKUP_COUNT = max(1, env_int("MINI_EDR_LOG_BACKUP_COUNT", 5))


def resolve_agent_paths():
    
    custom_data_dir = env_path("MINI_EDR_DATA_DIR")
    custom_log_dir = env_path("MINI_EDR_LOG_DIR")
    custom_diagnostics_dir = env_path("MINI_EDR_DIAGNOSTICS_DIR")

    if custom_data_dir:
        data_dir = custom_data_dir
        log_dir = custom_log_dir or data_dir / "logs"
        diagnostics_dir = custom_diagnostics_dir or data_dir / "diagnostics"
    elif ANALYST_MODE:
        data_dir = BASE_DIR
        log_dir = custom_log_dir or BASE_DIR
        diagnostics_dir = custom_diagnostics_dir or BASE_DIR / "diagnostics"
    else:
        if os.name == "nt":
            root = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
            data_dir = root / APP_NAME
        else:
            data_dir = BASE_DIR / "program_data" / APP_NAME

        log_dir = custom_log_dir or data_dir / "logs"
        diagnostics_dir = custom_diagnostics_dir or data_dir / "diagnostics"

    return data_dir, log_dir, diagnostics_dir


PROGRAM_DATA_DIR, LOG_DIR, DIAGNOSTICS_DIR = resolve_agent_paths()


def ensure_agent_data_dirs(data_dir: Path, log_dir: Path, diagnostics_dir: Path):
    
    for folder in (data_dir, log_dir, diagnostics_dir):
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except Exception:
        
            fallback = BASE_DIR / "agent_data"
            fallback_logs = fallback / "logs"
            fallback_diag = fallback / "diagnostics"
            fallback.mkdir(parents=True, exist_ok=True)
            fallback_logs.mkdir(parents=True, exist_ok=True)
            fallback_diag.mkdir(parents=True, exist_ok=True)
            return fallback, fallback_logs, fallback_diag
    return data_dir, log_dir, diagnostics_dir


PROGRAM_DATA_DIR, LOG_DIR, DIAGNOSTICS_DIR = ensure_agent_data_dirs(
    PROGRAM_DATA_DIR,
    LOG_DIR,
    DIAGNOSTICS_DIR,
)
AGENT_ID_PATH = PROGRAM_DATA_DIR / "agent_id.txt"
LOG_FILE_PATH = LOG_DIR / "agent.log"
ISOLATION_REVIEW_LOG_PATH = LOG_DIR / "host_isolation_review.log"
BLOCKLIST_REVIEW_LOG_PATH = LOG_DIR / "blocklist_review.log"


def setup_logging():
    
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    def attach_rotating_file(logger: logging.Logger, path: Path):
        logger.propagate = False
        if logger.handlers:
            return

        handler = RotatingFileHandler(
            path,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    attach_rotating_file(agent_logger, LOG_FILE_PATH)
    attach_rotating_file(security_logger, LOG_DIR / "security.log")
    attach_rotating_file(network_logger, LOG_DIR / "network.log")


setup_logging()


def write_log(message: str):
    try:
        agent_logger.info(str(message))
    except Exception:
        pass

DEFAULT_SERVER_URL = "http://127.0.0.1:8000"

def load_agent_config():
    config_path = BASE_DIR / "config.json"
    if not config_path.exists():
        return {}

    try:
        with config_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        write_log(f"Could not load config.json: {exc}")
        return {}


AGENT_CONFIG = load_agent_config()


def config_bool(name: str, default: bool) -> bool:
    value = AGENT_CONFIG.get(name)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    value = str(value).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return default


def config_int(name: str, default: int) -> int:
    value = AGENT_CONFIG.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def config_str(name: str, default: str) -> str:
    value = AGENT_CONFIG.get(name)
    if value is None:
        return default
    value = str(value).strip()
    return value or default


SERVER_URL = (
    os.getenv("MINI_EDR_SERVER_URL")
    or config_str("server_url", DEFAULT_SERVER_URL)
).rstrip("/")
INTERVAL_SECONDS = max(1, config_int("interval_seconds", 5))
COUNTRY = config_str("country", "Jordan")
RESPONSE_POLL_SECONDS = max(1, config_int("response_poll_seconds", 4))
LAB_MODE = config_bool("lab_mode", True)
MONITOR_LOOP_SECONDS = 0.5
LIVE_EVENTS_ENABLED = True
LIVE_EVENT_DEDUP_SECONDS = max(5, LIVE_EVENT_DEDUP_SECONDS)


HTTP = requests.Session()
HTTP.headers.update({"User-Agent": "Mini-EDR-Agent/2.4"})


_geo_cache = {
    "public_ip": None,
    "geo": {
        "country": COUNTRY,
        "city": None,
        "isp": None,
    },
    "expires_at": 0,
}


def get_local_ip():
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip.startswith("127."):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
        return ip
    except Exception:
        return "unknown"


def get_public_ip():
    candidates = [
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/all.json",
    ]

    for url in candidates:
        try:
            response = HTTP.get(url, timeout=4)
            response.raise_for_status()
            data = response.json()

            if "ip" in data:
                return data["ip"]
            if "ip_addr" in data:
                return data["ip_addr"]
        except Exception:
            continue

    return None


def get_geo_context(public_ip):
    if not public_ip:
        return {
            "country": COUNTRY,
            "city": None,
            "isp": None,
        }

    candidates = [
        f"https://ipwho.is/{public_ip}",
        f"https://ipapi.co/{public_ip}/json/",
    ]

    for url in candidates:
        try:
            response = HTTP.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()

            if "success" in data and data.get("success") is True:
                return {
                    "country": data.get("country") or COUNTRY,
                    "city": data.get("city"),
                    "isp": (data.get("connection") or {}).get("isp"),
                }

            if "ip" in data or "country_name" in data:
                return {
                    "country": data.get("country_name") or COUNTRY,
                    "city": data.get("city"),
                    "isp": data.get("org"),
                }
        except Exception as e:
            write_log(f"Geo lookup failed for {url}: {e}")

    return {
        "country": COUNTRY,
        "city": None,
        "isp": None,
    }


def get_cached_network_identity(force_refresh=False):
    now = time.time()

    if (
        not force_refresh
        and _geo_cache["expires_at"] > now
        and _geo_cache["public_ip"] is not None
    ):
        return _geo_cache["public_ip"], _geo_cache["geo"]

    public_ip = get_public_ip()
    geo = get_geo_context(public_ip)

    _geo_cache["public_ip"] = public_ip
    _geo_cache["geo"] = geo
    _geo_cache["expires_at"] = now + GEO_CACHE_TTL_SECONDS

    return public_ip, geo


def load_or_create_agent_id():
    if AGENT_ID_PATH.exists():
        try:
            with open(AGENT_ID_PATH, "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value:
                    return value
        except Exception as e:
            write_log(f"Failed to read agent_id.txt from ProgramData: {e}")

    new_id = str(uuid.uuid4())
    try:
        with open(AGENT_ID_PATH, "w", encoding="utf-8") as f:
            f.write(new_id)
    except Exception as e:
        write_log(f"Failed to write agent_id.txt to ProgramData: {e}")

    return new_id


def persist_agent_id(agent_id: str):
    value = str(agent_id or "").strip()
    if not value:
        return False

    try:
        with open(AGENT_ID_PATH, "w", encoding="utf-8") as f:
            f.write(value)
        return True
    except Exception as e:
        write_log(f"Failed to write canonical agent_id.txt to ProgramData: {e}")
        return False


def get_process_count():
    try:
        return len(psutil.pids())
    except Exception:
        return 0


def get_parent_process_name(proc):
    """Return parent process name safely on Windows without crashing on AccessDenied."""
    try:
        ppid = proc.ppid()
    except Exception:
        return ""

    if not ppid:
        return ""

    try:
        return psutil.Process(ppid).name()
    except Exception:
        return ""





def safe_process_cmdline(proc):
    """Return process cmdline safely; protected Windows processes may deny access."""
    try:
        parts = proc.cmdline()
        if isinstance(parts, list):
            return [str(x) for x in parts]
        return []
    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
        PermissionError,
        OSError,
    ):
        return []
    except Exception:
        return []


def safe_process_exe(proc):
    
    try:
        return proc.exe() or ""
    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
        PermissionError,
        OSError,
    ):
        return ""
    except Exception:
        return ""

def safe_json_dumps(value):
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return "[]"


def sample_cpu_percent():
    try:
        return round(float(psutil.cpu_percent(interval=0.3)), 1)
    except Exception:
        return 0.0


def get_memory_percent():
    try:
        return round(float(psutil.virtual_memory().percent), 1)
    except Exception:
        return 0.0


def get_top_cpu_processes(limit=12):
    processes = []
    cpu_count = max(psutil.cpu_count(logical=True) or 1, 1)

    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                proc.cpu_percent(interval=None)
            except Exception:
                continue

        time.sleep(0.3)

        for proc in psutil.process_iter(["pid", "name", "memory_percent"]):
            try:
                pid = proc.info.get("pid")
                name = proc.info.get("name") or ""

                try:
                    raw_cpu = proc.cpu_percent(interval=None)
                except Exception:
                    raw_cpu = 0

                exe_path = safe_process_exe(proc)

                cmd_parts = safe_process_cmdline(proc)
                cmdline = " ".join(cmd_parts) if cmd_parts else ""

                try:
                    parent_process = get_parent_process_name(proc)
                except Exception:
                    parent_process = ""

                processes.append({
                    "pid": pid,
                    "name": name,
                    "cpu_percent": max(0, min(round(raw_cpu / cpu_count, 2), 100)),
                    "memory_percent": round(proc.info.get("memory_percent", 0.0) or 0.0, 2),
                    "command_line": cmdline,
                    "file_path": exe_path,
                    "parent_process": parent_process,
                })

            except Exception:
                continue

    except Exception:
        return []

    processes.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return processes[:limit]


def get_network_connections(limit=40):
    connections = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                remote_ip = conn.raddr.ip if conn.raddr else None
                remote_port = conn.raddr.port if conn.raddr else None

                connections.append(
                    {
                        "local_address": laddr,
                        "remote_address": raddr,
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
            except Exception:
                continue
    except Exception:
        pass

    return connections[:limit]


def should_flag_temp_appdata(name_l: str, command_l: str, parent_l: str, file_l: str = "") -> bool:
    file_l = (file_l or "").lower().replace("/", "\\")

    if name_l in SAFE_TEMP_APPDATA_PROCESSES:
        return False

    trusted_program_paths = [
        "\\appdata\\local\\programs\\python\\",
        "\\appdata\\local\\programs\\microsoft vs code\\",
        "\\appdata\\local\\discord\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\programs\\notion\\",
        "\\appdata\\local\\slack\\",
        "\\appdata\\local\\spotify\\",
    ]

    if any(path in file_l for path in trusted_program_paths):
        return False

    if name_l in SUSPICIOUS_PROCESS_NAMES:
        return True

    if any(k in command_l for k in ENCODED_KEYWORDS):
        return True

    if any(k in command_l for k in DOWNLOAD_OR_EXEC_KEYWORDS):
        return True

    if parent_l in OFFICE_PARENTS:
        return True

    return False


def classify_cmd_command(command_line: str):
    command_l = (command_line or "").lower()

    for pattern, reason in CRITICAL_CMD_BEHAVIORS:
        if pattern in command_l:
            return {
                "event_title": "Critical Command Shell Activity",
                "event_category": "process_execution",
                "severity": "critical",
                "reason": reason,
            }

    for pattern, reason in HIGH_RISK_CMD_BEHAVIORS:
        if pattern in command_l:
            return {
                "event_title": "High-Risk Command Shell Activity",
                "event_category": "process_execution",
                "severity": "high",
                "reason": reason,
            }

    if "net user" in command_l and "/add" in command_l:
        return {
            "event_title": "High-Risk Command Shell Activity",
            "event_category": "process_execution",
            "severity": "high",
            "reason": "Local user creation command detected",
        }

    return None


def get_process_risk_reasons(
    name: str, command_line: str, file_path: str, parent_process: str
):
    reasons = []

    name_l = (name or "").lower()
    command_l = (command_line or "").lower()
    file_l = (file_path or "").lower()
    parent_l = (parent_process or "").lower()
    cmd_risk = classify_cmd_command(command_l) if name_l == "cmd.exe" else None

    if name_l in SUSPICIOUS_PROCESS_NAMES:
        reasons.append("Known suspicious process name")

    if cmd_risk:
        reasons.append(cmd_risk["reason"])

    if any(k in command_l for k in ENCODED_KEYWORDS):
        reasons.append("Encoded or Base64 command pattern detected")

    if any(k in command_l for k in DOWNLOAD_OR_EXEC_KEYWORDS):
        reasons.append("Download-and-execute behavior detected")

    if "mimikatz" in name_l or "mimikatz" in command_l or "mimikatz" in file_l:
        reasons.append("Credential theft tooling indicator detected")

    if ("temp" in file_l or "appdata" in file_l) and should_flag_temp_appdata(
        name_l, command_l, parent_l, file_l
    ):
        reasons.append("Execution from Temp/AppData path")

    if parent_l in OFFICE_PARENTS and (
        name_l in SUSPICIOUS_PROCESS_NAMES
        or any(k in command_l for k in ENCODED_KEYWORDS)
        or any(k in command_l for k in DOWNLOAD_OR_EXEC_KEYWORDS)
    ):
        reasons.append("Office application spawned suspicious child process")

    return reasons


def is_suspicious_process(
    name: str, command_line: str, file_path: str, parent_process: str
) -> bool:
    return (
        len(get_process_risk_reasons(name, command_line, file_path, parent_process)) > 0
    )


def is_suspicious_connection(remote_port):
    try:
        return int(remote_port) in SUSPICIOUS_PORTS
    except Exception:
        return False


def classify_process_event(
    name: str, command_line: str, file_path: str, parent_process: str
):
    name_l = (name or "").lower()
    command_l = (command_line or "").lower()
    file_l = (file_path or "").lower()
    parent_l = (parent_process or "").lower()

    if "mimikatz" in name_l or "mimikatz" in command_l or "mimikatz" in file_l:
        return {
            "event_title": "Credential Theft Tool Execution",
            "event_category": "credential_access",
            "severity": "critical",
        }

    if name_l == "cmd.exe":
        cmd_risk = classify_cmd_command(command_l)
        if cmd_risk:
            return {
                "event_title": cmd_risk["event_title"],
                "event_category": cmd_risk["event_category"],
                "severity": cmd_risk["severity"],
            }

    if parent_l in OFFICE_PARENTS and name_l in SUSPICIOUS_PROCESS_NAMES:
        return {
            "event_title": "Office Spawned Suspicious Shell",
            "event_category": "process_execution",
            "severity": "high",
        }

    if any(k in command_l for k in ENCODED_KEYWORDS):
        return {
            "event_title": "Encoded PowerShell Command",
            "event_category": "script_execution",
            "severity": "high",
        }

    if any(k in command_l for k in DOWNLOAD_OR_EXEC_KEYWORDS):
        return {
            "event_title": "Download and Execute Activity",
            "event_category": "script_execution",
            "severity": "high",
        }

    if (
        ("temp" in file_l or "appdata" in file_l)
        and should_flag_temp_appdata(name_l, command_l, parent_l, file_l)
    ):
        return {
            "event_title": "Suspicious Temp Path Execution",
            "event_category": "process_execution",
            "severity": "medium",
        }

    if name_l in SUSPICIOUS_PROCESS_NAMES:
        return {
            "event_title": "Suspicious Process Execution",
            "event_category": "process_execution",
            "severity": "medium",
        }

    return {
        "event_title": "Suspicious Process Activity",
        "event_category": "process_execution",
        "severity": "medium",
    }


def classify_connection_event(remote_port):
    if int(remote_port) in {4444, 5555, 9001, 1337}:
        return {
            "event_title": "High-Risk Outbound Connection",
            "event_category": "network_connection",
            "severity": "high",
        }

    return {
        "event_title": "Suspicious Outbound Connection",
        "event_category": "network_connection",
        "severity": "medium",
    }


def classify_system_metric_event(
    cpu_percent: float, memory_percent: float, process_count: int
):
    if cpu_percent > 90:
        return {
            "event_title": "Critical CPU Spike Detected",
            "event_category": "system_resource",
            "severity": "critical",
            "reason": f"System CPU usage reached {cpu_percent:.1f}% - above 90%",
        }

    if memory_percent >= 92:
        return {
            "event_title": "Critical Memory Spike Detected",
            "event_category": "system_resource",
            "severity": "high",
            "reason": f"System memory usage reached {memory_percent:.1f}%",
        }

    if process_count >= 380:
        return {
            "event_title": "Abnormally High Process Count",
            "event_category": "system_resource",
            "severity": "medium",
            "reason": f"Process count reached {process_count}",
        }

    if cpu_percent >= 81:
        return {
            "event_title": "High CPU Usage Detected",
            "event_category": "system_resource",
            "severity": "high",
            "reason": f"System CPU usage reached {cpu_percent:.1f}% - 81% to 90%",
        }

    if memory_percent >= 85:
        return {
            "event_title": "High Memory Usage Detected",
            "event_category": "system_resource",
            "severity": "medium",
            "reason": f"System memory usage reached {memory_percent:.1f}%",
        }

    if cpu_percent >= 60:
        return {
            "event_title": "Medium CPU Usage Detected",
            "event_category": "system_resource",
            "severity": "medium",
            "reason": f"System CPU usage reached {cpu_percent:.1f}% - 60% to 80%",
        }

    return None


def process_snapshot():
    
    snapshot = {}

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info.get("pid")
            name = proc.info.get("name") or ""

            file_path = safe_process_exe(proc)

            cmd_parts = safe_process_cmdline(proc)
            cmdline = " ".join(cmd_parts) if cmd_parts else ""

            parent_process = get_parent_process_name(proc)

            snapshot[pid] = {
                "pid": pid,
                "name": name,
                "file_path": file_path,
                "command_line": cmdline,
                "parent_process": parent_process,
            }

        except Exception:
            continue

    return snapshot



def connection_snapshot():
    items = []

    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                if not conn.raddr:
                    continue

                items.append(
                    {
                        "pid": conn.pid,
                        "remote_ip": conn.raddr.ip,
                        "remote_port": conn.raddr.port,
                        "status": conn.status,
                    }
                )
            except Exception:
                continue
    except Exception:
        pass

    return items


def collect_diagnostics():
    public_ip, geo = get_cached_network_identity(force_refresh=True)

    data = {
        "hostname": HOSTNAME,
        "local_ip": LOCAL_IP,
        "public_ip": public_ip,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "time": datetime.now().isoformat(),
        "top_processes": get_top_cpu_processes(limit=12),
        "connections": get_network_connections(limit=30),
        "cpu_percent": sample_cpu_percent(),
        "memory_percent": get_memory_percent(),
        "process_count": get_process_count(),
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = DIAGNOSTICS_DIR / f"diagnostics_snapshot_{timestamp}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    return f"Diagnostics collected successfully: {out_path}"


def handle_kill_process_request(target_value):
    if not target_value:
        return False, "No target process name provided."

    target_value = str(target_value).strip().lower()
    if target_value in PROTECTED_PROCESSES:
        return False, f"Refused to terminate protected process: {target_value}"

    killed = []
    failed = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            proc_name = str(proc.info.get("name") or "").strip().lower()

            if proc_name == target_value and proc_name not in PROTECTED_PROCESSES:
                proc.kill()
                killed.append(f"{proc_name} (PID {proc.info.get('pid')})")

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except psutil.AccessDenied as e:
            failed.append(f"{target_value}: Access denied ({e})")
        except Exception as e:
            failed.append(f"{target_value}: {e}")

    if killed:
        show_popup(
            "Security Action",
            f"A suspicious process was terminated for your safety:\n{target_value}",
        )
        return True, f"Killed process(es): {', '.join(killed)}"

    if failed:
        return False, "Failed to kill process. " + " | ".join(failed)

    return False, f"Process not found: {target_value}"


def handle_mark_host_for_isolation_review(target_value=None):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    review_path = ISOLATION_REVIEW_LOG_PATH

    message = (
        f"[{timestamp}] Host marked for isolation review | "
        f"hostname={HOSTNAME} | agent_id={AGENT_ID} | note={target_value or 'N/A'}\n"
    )

    try:
        with open(review_path, "a", encoding="utf-8") as f:
            f.write(message)
    except Exception as e:
        return False, f"Failed to write isolation review log: {e}"

    show_popup(
        "Mini EDR Alert",
        "This endpoint has been marked for isolation review.\n\nSecurity team review is required.",
    )

    return True, f"Host isolation review recorded successfully: {review_path}"


def handle_blocklisted_ip_review(target_value):
    if not target_value:
        return False, "No target IP provided."

    target_value = str(target_value).strip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    review_path = BLOCKLIST_REVIEW_LOG_PATH

    message = (
        f"[{timestamp}] IP marked for blocklist review | "
        f"hostname={HOSTNAME} | agent_id={AGENT_ID} | target_ip={target_value}\n"
    )

    try:
        with open(review_path, "a", encoding="utf-8") as f:
            f.write(message)
    except Exception as e:
        return False, f"Failed to write blocklist review log: {e}"

    show_popup(
        "Mini EDR Alert",
        f"A remote IP was marked for security blocklist review.\n\nIP: {target_value}",
    )

    return True, f"Blocklist review recorded successfully for IP {target_value}: {review_path}"


def execute_safe_response(action: dict):
    action_type = (action.get("action_type") or "").strip()
    target_value = action.get("target_value")

    if not LAB_MODE:
        return False, "Agent is not in lab_mode. Response execution denied."

    try:
        if action_type == "collect_diagnostics":
            return True, collect_diagnostics()
        if action_type == "mark_host_for_isolation_review":
            return handle_mark_host_for_isolation_review(target_value)
        if action_type == "blocklisted_ip_review":
            return handle_blocklisted_ip_review(target_value)
        if action_type == "kill_process_request":
            return handle_kill_process_request(target_value)

        return False, f"Unsupported safe action: {action_type}"
    except Exception as e:
        return False, f"Execution error for action '{action_type}': {e}"


def poll_response_actions():
    try:
        response = HTTP.get(
            f"{SERVER_URL}/agents/{AGENT_ID}/response-actions/pending",
            timeout=12,
        )
        response.raise_for_status()
        actions = response.json()

        if not isinstance(actions, list):
            write_log("Response actions payload is not a list. Ignoring.")
            return
    except Exception as e:
        write_log(f"Failed to poll response actions: {e}")
        return

    if not actions:
        return

    for action in actions:
        action_id = action.get("id")

        try:
            write_log(
                f"Received response action: id={action_id} | "
                f"type={action.get('action_type')} | target={action.get('target_value')}"
            )

            
            in_progress_resp = HTTP.patch(
                f"{SERVER_URL}/response-actions/{action_id}/result",
                json={
                    "status": "in_progress",
                    "result_message": "Agent received the action and started safe execution.",
                },
                timeout=12,
            )
            in_progress_resp.raise_for_status()

            success, result_message = execute_safe_response(action)

            payload = {
                "status": "executed" if success else "failed",
                "result_message": result_message,
            }

            result_resp = HTTP.patch(
                f"{SERVER_URL}/response-actions/{action_id}/result",
                json=payload,
                timeout=12,
            )
            result_resp.raise_for_status()

            write_log(f"Response action handled successfully: {action_id} -> {payload}")
        except Exception as e:
            write_log(f"Failed handling response action {action_id}: {e}")

            try:
                HTTP.patch(
                    f"{SERVER_URL}/response-actions/{action_id}/result",
                    json={"status": "failed", "result_message": str(e)},
                    timeout=12,
                )
            except Exception:
                pass


AGENT_ID = load_or_create_agent_id()
HOSTNAME = socket.gethostname()
LOCAL_IP = get_local_ip()
OS_NAME = platform.platform()

recent_suspicious_events = deque(maxlen=120)
known_processes = {}
known_connections = set()
recent_live_event_keys = {}
recent_system_alert_keys = {}
last_telemetry_event_key = None
last_telemetry_event_at = 0.0


def cleanup_recent_live_event_keys():
    now = time.time()
    expired = [
        k
        for k, ts in recent_live_event_keys.items()
        if (now - ts) > LIVE_EVENT_DEDUP_SECONDS
    ]
    for k in expired:
        recent_live_event_keys.pop(k, None)


def cleanup_recent_system_alert_keys():
    now = time.time()
    expired = [
        k
        for k, ts in recent_system_alert_keys.items()
        if (now - ts) > SYSTEM_ALERT_DEDUP_SECONDS
    ]
    for k in expired:
        recent_system_alert_keys.pop(k, None)


def build_live_event_key(event: dict):
    return "|".join(
        [
            str(event.get("event_type") or ""),
            str(event.get("event_title") or ""),
            str(event.get("process_name") or ""),
            str(event.get("parent_process") or ""),
            str(event.get("destination_ip") or ""),
            str(event.get("destination_port") or ""),
            str(event.get("reason") or ""),
        ]
    )


def should_emit_live_event(event: dict):
    cleanup_recent_live_event_keys()
    key = build_live_event_key(event)
    now = time.time()

    last_seen = recent_live_event_keys.get(key)
    if last_seen and (now - last_seen) < LIVE_EVENT_DEDUP_SECONDS:
        return False

    recent_live_event_keys[key] = now
    return True


def should_emit_system_alert(alert_key: str):
    cleanup_recent_system_alert_keys()
    now = time.time()

    last_seen = recent_system_alert_keys.get(alert_key)
    if last_seen and (now - last_seen) < SYSTEM_ALERT_DEDUP_SECONDS:
        return False

    recent_system_alert_keys[alert_key] = now
    return True


def push_recent_suspicious_event(event: dict):
    event_copy = dict(event)
    event_copy["created_at"] = time.time()
    recent_suspicious_events.append(event_copy)


def send_live_event(event: dict):
    if not LIVE_EVENTS_ENABLED:
        return False

    if not should_emit_live_event(event):
        return False

    public_ip, geo = get_cached_network_identity()

    payload = {
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "ip_address": LOCAL_IP,
        "public_ip": public_ip,
        "os": OS_NAME,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "timestamp": datetime.now().isoformat(),
        **event,
    }

    try:
        response = HTTP.post(f"{SERVER_URL}/events/live", json=payload, timeout=6)
        if response.status_code in (200, 201):
            write_log(
                f"LIVE event sent: {event.get('event_title')} | "
                f"proc={event.get('process_name')} | severity={event.get('severity')}"
            )
            return True

        write_log(
            f"LIVE event endpoint responded with status {response.status_code}. "
            f"Event kept locally only."
        )
        return False
    except Exception as e:
        write_log(f"LIVE event send failed: {e}")
        return False


def send_agent_connected_event():
    if not LIVE_EVENTS_ENABLED:
        return False

    public_ip, geo = get_cached_network_identity()

    payload = {
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "ip_address": LOCAL_IP,
        "public_ip": public_ip,
        "os": OS_NAME,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "timestamp": datetime.now().isoformat(),
        "event_type": "agent",
        "event_title": "Agent Connected",
        "event_category": "agent_status",
        "severity": "low",
        "process_name": None,
        "pid": None,
        "command_line": None,
        "file_path": None,
        "parent_process": None,
        "destination_ip": None,
        "destination_port": None,
        "connection_status": None,
        "reason": "Endpoint agent started and connected to the Mini EDR server",
        "reason_details": [
            f"hostname={HOSTNAME}",
            f"agent_id={AGENT_ID}",
            f"local_ip={LOCAL_IP}",
            f"os={OS_NAME}",
        ],
    }

    try:
        response = HTTP.post(f"{SERVER_URL}/events/live", json=payload, timeout=6)
        if response.status_code in (200, 201):
            write_log("Agent connected event sent to central server.")
            return True

        write_log(f"Agent connected event failed with status {response.status_code}.")
        return False
    except Exception as e:
        write_log(f"Agent connected event send failed: {e}")
        return False


def register():
    global AGENT_ID

    public_ip, geo = get_cached_network_identity(force_refresh=True)

    payload = {
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "ip_address": LOCAL_IP,
        "public_ip": public_ip,
        "os": OS_NAME,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
    }

    response = HTTP.post(f"{SERVER_URL}/register", json=payload, timeout=10)
    response.raise_for_status()
    result = response.json()
    canonical_agent_id = str(result.get("agent_id") or "").strip()

    if canonical_agent_id and canonical_agent_id != AGENT_ID:
        old_agent_id = AGENT_ID
        AGENT_ID = canonical_agent_id
        persist_agent_id(canonical_agent_id)
        write_log(f"Using canonical Agent ID from server: {old_agent_id} -> {AGENT_ID}")

    return result


def seed_initial_snapshots():
    global known_processes, known_connections
    known_processes = process_snapshot()

    conn_items = connection_snapshot()
    known_connections = {
        (
            item.get("pid"),
            item.get("remote_ip"),
            item.get("remote_port"),
            item.get("status"),
        )
        for item in conn_items
    }


def build_process_event(proc: dict):
    name = proc.get("name") or ""
    command_line = proc.get("command_line") or ""
    file_path = proc.get("file_path") or ""
    parent_process = proc.get("parent_process") or ""

    details = classify_process_event(name, command_line, file_path, parent_process)
    reasons = get_process_risk_reasons(name, command_line, file_path, parent_process)

    return {
        "event_type": "process",
        "event_title": details["event_title"],
        "event_category": details["event_category"],
        "severity": details["severity"],
        "process_name": name.lower(),
        "pid": proc.get("pid"),
        "command_line": command_line,
        "file_path": file_path,
        "parent_process": parent_process.lower() if parent_process else None,
        "destination_ip": None,
        "destination_port": None,
        "reason": reasons[0] if reasons else "Suspicious process behavior detected",
        "reason_details": reasons,
    }


def build_connection_event(pid, remote_ip, remote_port, status):
    related = known_processes.get(pid, {})
    details = classify_connection_event(remote_port)

    reason = f"Connection to monitored high-risk port {remote_port}"

    return {
        "event_type": "connection",
        "event_title": details["event_title"],
        "event_category": details["event_category"],
        "severity": details["severity"],
        "process_name": str(related.get("name") or "").lower() or None,
        "pid": pid,
        "command_line": related.get("command_line"),
        "file_path": related.get("file_path"),
        "parent_process": str(related.get("parent_process") or "").lower() or None,
        "destination_ip": remote_ip,
        "destination_port": remote_port,
        "connection_status": status,
        "reason": reason,
        "reason_details": [reason],
    }


def build_system_metric_event(
    cpu_percent: float, memory_percent: float, process_count: int
):
    details = classify_system_metric_event(cpu_percent, memory_percent, process_count)
    if not details:
        return None

    return {
        "event_type": "system",
        "event_title": details["event_title"],
        "event_category": details["event_category"],
        "severity": details["severity"],
        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(memory_percent, 1),
        "process_count": int(process_count or 0),
        "process_name": None,
        "pid": None,
        "command_line": None,
        "file_path": None,
        "parent_process": None,
        "destination_ip": None,
        "destination_port": None,
        "reason": details["reason"],
        "reason_details": [details["reason"]],
    }


def track_new_suspicious_processes():
    global known_processes

    current = process_snapshot()
    new_pids = set(current.keys()) - set(known_processes.keys())

    for pid in new_pids:
        proc = current[pid]
        name = proc.get("name") or ""
        command_line = proc.get("command_line") or ""
        file_path = proc.get("file_path") or ""
        parent_process = proc.get("parent_process") or ""

        if is_suspicious_process(name, command_line, file_path, parent_process):
            event = build_process_event(proc)
            push_recent_suspicious_event(event)
            send_live_event(event)

            write_log(
                f"Suspicious process captured: "
                f"title={event.get('event_title')} | "
                f"name={name} | parent={parent_process} | cmd={command_line[:120]}"
            )
            security_logger.warning(
                f"Suspicious process detected: {name} | parent={parent_process}"
)
            
    known_processes = current


def track_new_suspicious_connections():
    global known_connections

    conn_items = connection_snapshot()
    current_keys = {
        (
            item.get("pid"),
            item.get("remote_ip"),
            item.get("remote_port"),
            item.get("status"),
        )
        for item in conn_items
    }

    new_items = current_keys - known_connections

    for pid, remote_ip, remote_port, status in new_items:
        if is_suspicious_connection(remote_port):
            event = build_connection_event(pid, remote_ip, remote_port, status)
            push_recent_suspicious_event(event)
            send_live_event(event)

            write_log(
                f"Suspicious connection captured: "
                f"title={event.get('event_title')} | "
                f"pid={pid} | ip={remote_ip} | port={remote_port} | status={status}"
            )

    known_connections = current_keys


def track_system_metric_alerts():
    cpu_percent = sample_cpu_percent()
    memory_percent = get_memory_percent()
    process_count = get_process_count()

    event = build_system_metric_event(cpu_percent, memory_percent, process_count)
    if not event:
        return

    alert_key = f"{event['event_title']}|{event['reason']}"
    if not should_emit_system_alert(alert_key):
        return

    push_recent_suspicious_event(event)
    send_live_event(event)

    write_log(
        f"System metric alert captured: "
        f"title={event.get('event_title')} | "
        f"cpu={cpu_percent:.1f} | mem={memory_percent:.1f} | proc_count={process_count}"
    )


def purge_old_events():
    now = time.time()
    while (
        recent_suspicious_events
        and (now - recent_suspicious_events[0]["created_at"]) > EVENT_RETENTION_SECONDS
    ):
        recent_suspicious_events.popleft()


def get_latest_suspicious_event():
    purge_old_events()
    if recent_suspicious_events:
        return recent_suspicious_events[-1]
    return None


def fallback_current_suspicious_process():
    
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = str(proc.info.get("name") or "")

            cmd_parts = safe_process_cmdline(proc)
            command_line = " ".join(cmd_parts) if cmd_parts else ""

            file_path = str(safe_process_exe(proc))

            parent_process = get_parent_process_name(proc)

            if is_suspicious_process(name, command_line, file_path, parent_process):
                return build_process_event(
                    {
                        "pid": proc.info.get("pid"),
                        "name": name,
                        "command_line": command_line,
                        "file_path": file_path,
                        "parent_process": parent_process,
                    }
                )

        except Exception:
            continue

    return None



def fallback_current_suspicious_connection():
    try:
        for conn in psutil.net_connections(kind="inet"):
            try:
                if conn.raddr and is_suspicious_connection(conn.raddr.port):
                    return build_connection_event(
                        conn.pid,
                        conn.raddr.ip,
                        conn.raddr.port,
                        conn.status,
                    )
            except Exception:
                continue
    except Exception:
        pass

    return None


def build_telemetry_event_key(event: dict):
    if not event:
        return ""

    return "|".join(
        [
            str(event.get("event_type") or ""),
            str(event.get("event_title") or ""),
            str(event.get("process_name") or ""),
            str(event.get("parent_process") or ""),
            str(event.get("destination_ip") or ""),
            str(event.get("destination_port") or ""),
            str(event.get("reason") or ""),
        ]
    )


def should_attach_event_to_telemetry(event: dict):
    global last_telemetry_event_key, last_telemetry_event_at

    if not event:
        return False

    key = build_telemetry_event_key(event)
    now = time.time()

    if (
        key
        and key == last_telemetry_event_key
        and (now - last_telemetry_event_at) < TELEMETRY_EVENT_DEDUP_SECONDS
    ):
        return False

    last_telemetry_event_key = key
    last_telemetry_event_at = now
    return True
def extract_behavior_features(processes, connections):
    suspicious_port_flag = 0
    powershell_flag = 0
    temp_execution_flag = 0

    for proc in processes:
        try:
            name = str(proc.get("name") or "").lower()

           
            path = str(proc.get("exe") or proc.get("file_path") or "").lower().replace("/", "\\")
            cmd_raw = proc.get("cmdline", proc.get("command_line", ""))

            if isinstance(cmd_raw, list):
                cmd = " ".join(str(x) for x in cmd_raw).lower()
            else:
                cmd = str(cmd_raw or "").lower()

            parent = str(proc.get("parent_process") or "").lower()

            is_powershell = "powershell" in name or name == "pwsh.exe" or "pwsh" in name
            has_encoded = any(k in cmd for k in ENCODED_KEYWORDS)
            has_download_exec = any(k in cmd for k in DOWNLOAD_OR_EXEC_KEYWORDS)

            if is_powershell and (has_encoded or has_download_exec):
                powershell_flag = 1

            if ("\\temp\\" in path or "\\appdata\\local\\temp\\" in path) and should_flag_temp_appdata(
                name, cmd, parent, path
            ):
                temp_execution_flag = 1

        except Exception:
            continue

    for conn in connections:
        try:
            port = conn.get("remote_port") or conn.get("laddr_port") or conn.get("port")
            if port and int(port) in SUSPICIOUS_PORTS:
                suspicious_port_flag = 1
        except Exception:
            continue

    return {
        "suspicious_port": suspicious_port_flag,
        "powershell_flag": powershell_flag,
        "temp_execution": temp_execution_flag,
    }


def collect_all_processes():
    
    items = []

    for proc in psutil.process_iter(["pid", "name"]):
        try:
            pid = proc.info.get("pid")
            name = proc.info.get("name") or ""

            cmdline = safe_process_cmdline(proc)

            exe_path = safe_process_exe(proc)

            items.append(
                {
                    "pid": pid,
                    "name": name,
                    "cmdline": cmdline,
                    "exe": exe_path,
                    "parent_process": get_parent_process_name(proc),
                }
            )

        except Exception:
            continue

    return items



def send_telemetry():
    public_ip, geo = get_cached_network_identity()

    cpu_percent = sample_cpu_percent()
    memory_percent = get_memory_percent()
    process_count = get_process_count()

    top_processes = get_top_cpu_processes()
    all_processes = collect_all_processes()
    network_connections = get_network_connections()

    features = extract_behavior_features(all_processes, network_connections)

    suspicious_event = (
        get_latest_suspicious_event()
        or fallback_current_suspicious_process()
        or fallback_current_suspicious_connection()
        or {}
    )

    if not should_attach_event_to_telemetry(suspicious_event):
        suspicious_event = {}

    payload = {
        "agent_id": AGENT_ID,
        "hostname": HOSTNAME,
        "ip_address": LOCAL_IP,
        "public_ip": public_ip,
        "os": OS_NAME,
        "country": geo["country"],
        "city": geo["city"],
        "isp": geo["isp"],
        "timestamp": datetime.now().isoformat(),

        "cpu_percent": round(cpu_percent, 1),
        "memory_percent": round(memory_percent, 1),
        "process_count": process_count,
        "connections_count": len(network_connections),

        "top_cpu_processes": safe_json_dumps(top_processes),
        "network_connections": safe_json_dumps(network_connections),

        "process_name": suspicious_event.get("process_name"),
        "command_line": suspicious_event.get("command_line"),
        "file_path": suspicious_event.get("file_path"),
        "parent_process": suspicious_event.get("parent_process"),
        "destination_ip": suspicious_event.get("destination_ip"),
        "destination_port": suspicious_event.get("destination_port"),

        "suspicious_port": features["suspicious_port"],
        "powershell_flag": features["powershell_flag"],
        "temp_execution": features["temp_execution"],
    }

    response = HTTP.post(f"{SERVER_URL}/telemetry", json=payload, timeout=15)
    response.raise_for_status()

    return response.json(), payload


def register_with_retry(max_attempts=20, sleep_seconds=3):
    for attempt in range(1, max_attempts + 1):
        try:
            reg_result = register()
            write_log(f"Register success: {reg_result}")
            return True
        except Exception as e:
            write_log(f"Register failed (attempt {attempt}/{max_attempts}): {e}")
            time.sleep(sleep_seconds)

    return False


def main():
    write_log("Starting Mini EDR Agent...")
    write_log(f"Agent ID: {AGENT_ID}")
    write_log(f"Hostname: {HOSTNAME}")
    write_log(f"Local IP: {LOCAL_IP}")
    write_log(f"OS: {OS_NAME}")
    write_log(f"Server URL: {SERVER_URL}")
    write_log(f"Telemetry Interval Seconds: {INTERVAL_SECONDS}")
    write_log(f"Response Poll Seconds: {RESPONSE_POLL_SECONDS}")
    write_log(f"Monitor Loop Seconds: {MONITOR_LOOP_SECONDS}")
    write_log(f"Live Events Enabled: {LIVE_EVENTS_ENABLED}")
    write_log(f"Lab Mode: {LAB_MODE}")
    write_log(f"Analyst Mode: {ANALYST_MODE}")
    write_log(f"Install/Base Directory: {BASE_DIR}")
    write_log(f"ProgramData Directory: {PROGRAM_DATA_DIR}")
    write_log(f"Log Path: {LOG_FILE_PATH}")

    try:
        sample_cpu_percent()
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(interval=None)
            except Exception:
                continue
    except Exception:
        pass

    registered = register_with_retry()
    if not registered:
        write_log(
            "Could not register agent. Make sure backend is running on the configured server_url."
        )
        return
    
    send_agent_connected_event()

    seed_initial_snapshots()

    last_response_poll = 0
    last_telemetry_send = 0
    last_system_metrics_check = 0

    while True:
        loop_started = time.time()

        try:
            track_new_suspicious_processes()
        except Exception as e:
            write_log(f"Process tracking error: {e}")

        try:
            track_new_suspicious_connections()
        except Exception as e:
            write_log(f"Connection tracking error: {e}")

        now = time.time()

        if now - last_system_metrics_check >= 3:
            try:
                track_system_metric_alerts()
            except Exception as e:
                write_log(f"System metrics tracking error: {e}")
            last_system_metrics_check = now

        if now - last_telemetry_send >= INTERVAL_SECONDS:
            try:
                result, payload = send_telemetry()
                write_log(
                    f"Telemetry sent successfully: "
    f"cpu={payload.get('cpu_percent')} | "
    f"mem={payload.get('memory_percent')} | "
    f"proc_count={payload.get('process_count')} | "
    f"conn_count={payload.get('connections_count')} | "
    f"susp_port={payload.get('suspicious_port')} | "
    f"powershell={payload.get('powershell_flag')} | "
    f"temp_exec={payload.get('temp_execution')}"
      
                    
                
                )
                network_logger.info(
                    f"Connections={payload.get('connections_count')} | "
                    f"suspicious_port={payload.get('suspicious_port')}"
                )
            except Exception as e:
                write_log(f"Telemetry send failed: {e}")

            last_telemetry_send = now

        if now - last_response_poll >= RESPONSE_POLL_SECONDS:
            try:
                poll_response_actions()
            except Exception as e:
                write_log(f"Response polling error: {e}")
            last_response_poll = now

        elapsed = time.time() - loop_started
        sleep_for = max(0.1, MONITOR_LOOP_SECONDS - elapsed)
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
