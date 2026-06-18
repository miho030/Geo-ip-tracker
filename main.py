import os
import sys
import json
import ctypes
import pygeoip
import tempfile
import webbrowser
import ipaddress
import subprocess
import logging
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

try:
    import keyring
except ImportError:
    keyring = None

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QOpenGLWidget, QWidget, QVBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QHBoxLayout, QDialog,
    QFileDialog
)
from PyQt5.QtCore import Qt, QTimer, QPoint, QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from OpenGL.GL import *
from OpenGL.GLU import *
from PIL import Image
from ipwhois import IPWhois


# =============================================================================
# Constants
# =============================================================================

SOFTWARE_VERSION = "v0.3.4"
GEODB_VERSION = "v0.0.1"

APP_USER_MODEL_ID = "aoi.geoipaddrtracker.v033"

VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
VT_API_VALIDATION_TARGET_IP = "8.8.8.8"

KEYRING_SERVICE_NAME = "GeoIpAddrTracker"
KEYRING_USERNAME = "virustotal_api_key"

APP_SETTINGS_FILE_NAME = "geo_ip_tracker_settings.json"

GOOGLE_EARTH_DEFAULT_PATHS = [
    r"C:\Program Files\Google\Google Earth Pro\client\googleearth.exe",
    r"C:\Program Files (x86)\Google\Google Earth Pro\client\googleearth.exe",
]

GOOGLE_EARTH_REGISTRY_PATHS = [
    r"SOFTWARE\Google\Google Earth Pro",
    r"SOFTWARE\WOW6432Node\Google\Google Earth Pro",
]

CURRENCY_MAP = {
    "USA": "USD $",
    "KOR": "KRW ₩",
    "JPN": "JPY ¥",
    "CHN": "CNY ¥",
    "TPE": "TWD $",
    "UKR": "UAH ₴",
    "RUS": "RUB ₽",
}


# =============================================================================
# App Config / Path helpers
# =============================================================================

@dataclass(frozen=True)
class AppConfig:
    vt_api_key: str
    geo_db_path: str
    kml_file_path: str
    software_version: str
    geodb_version: str


def get_app_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(file_path: str) -> str:
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, file_path)
    return os.path.join(os.path.abspath("."), file_path)


def get_geo_db_file_path() -> str:
    return resource_path("resource/GeoLiteCity.dat")


def get_legacy_vt_api_key_file_path() -> str:
    return os.path.join(get_app_dir(), "user_vt_api.key")


def get_app_settings_file_path() -> str:
    return os.path.join(get_app_dir(), APP_SETTINGS_FILE_NAME)


def load_app_settings() -> dict:
    settings_path = get_app_settings_file_path()

    if not os.path.exists(settings_path):
        return {}

    try:
        with open(settings_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if isinstance(data, dict):
            return data

    except Exception:
        logging.exception("Failed to load app settings file.")

    return {}


def save_app_settings(settings: dict) -> bool:
    settings_path = get_app_settings_file_path()

    try:
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=4, ensure_ascii=False)
        return True

    except Exception:
        logging.exception("Failed to save app settings file.")
        return False


def setup_logging() -> None:
    try:
        log_path = os.path.join(get_app_dir(), "geo_ip_tracker.log")
        logging.basicConfig(
            filename=log_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            encoding="utf-8",
        )
    except Exception:
        logging.basicConfig(level=logging.INFO)


def ensure_geodb_exists_or_exit(geo_db_path: str) -> None:
    if not os.path.isfile(geo_db_path):
        logging.error("GeoDB file not found: %s", geo_db_path)
        sys.exit(1)


# =============================================================================
# Validation / Secure API key storage
# =============================================================================

def classify_ip_address(ip_text: str) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Classify user input as public/private/unsupported IPv4.

    Returns:
        (normalized_ip, status_code, message)

    status_code values:
        - PUBLIC_IPV4
        - PRIVATE_IPV4
        - INVALID
        - UNSUPPORTED
    """
    try:
        ip_obj = ipaddress.ip_address(ip_text.strip())

        if ip_obj.version != 4:
            return None, "UNSUPPORTED", "IPv4 only is currently supported."

        normalized_ip = str(ip_obj)

        if ip_obj.is_private:
            return normalized_ip, "PRIVATE_IPV4", "Private IPv4 addresses are not supported."
        if ip_obj.is_loopback:
            return normalized_ip, "UNSUPPORTED", "Loopback IPv4 addresses are not supported."
        if ip_obj.is_multicast:
            return normalized_ip, "UNSUPPORTED", "Multicast IPv4 addresses are not supported."
        if ip_obj.is_unspecified:
            return normalized_ip, "UNSUPPORTED", "Unspecified IPv4 addresses are not supported."
        if ip_obj.is_reserved:
            return normalized_ip, "UNSUPPORTED", "Reserved IPv4 addresses are not supported."

        return normalized_ip, "PUBLIC_IPV4", None

    except ValueError:
        return None, "INVALID", "Invalid IP address format."


def parse_ip_address(ip_text: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Backward-compatible public IPv4 validator.
    """
    ip_addr, status_code, message = classify_ip_address(ip_text)
    if status_code == "PUBLIC_IPV4":
        return ip_addr, None
    return None, message


def load_vt_api_key_from_secure_store() -> str:
    if keyring is None:
        return ""

    try:
        return keyring.get_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME) or ""
    except Exception:
        logging.exception("Failed to load VirusTotal API key from keyring.")
        return ""


def save_vt_api_key_to_secure_store(api_key: str) -> bool:
    if keyring is None:
        return False

    try:
        keyring.set_password(KEYRING_SERVICE_NAME, KEYRING_USERNAME, api_key)
        return True
    except Exception:
        logging.exception("Failed to save VirusTotal API key to keyring.")
        return False


def migrate_legacy_api_key_to_keyring() -> str:
    """
    Migrates the old plaintext API key file to keyring.
    The legacy file is removed only when secure-store save succeeds.
    """
    legacy_path = get_legacy_vt_api_key_file_path()

    if not os.path.exists(legacy_path):
        return ""

    try:
        with open(legacy_path, "r", encoding="utf-8") as f:
            api_key = f.read().strip()

        if not api_key:
            return ""

        if save_vt_api_key_to_secure_store(api_key):
            try:
                os.remove(legacy_path)
            except Exception:
                logging.exception("Failed to remove legacy plaintext API key file.")
            return api_key

    except Exception:
        logging.exception("Failed to migrate legacy plaintext API key file.")

    return ""


def validate_vt_api_key(
    api_key: str,
    test_ip: str = VT_API_VALIDATION_TARGET_IP,
) -> Tuple[bool, str]:
    url = f"{VT_API_BASE_URL}/ip_addresses/{test_ip}"
    req = Request(url, headers={
        "x-apikey": api_key,
        "accept": "application/json",
    })

    try:
        with urlopen(req, timeout=10) as resp:
            if resp.status == 200:
                return True, "Valid API key"
            return False, f"Unexpected response: HTTP {resp.status}"

    except HTTPError as e:
        if e.code == 401:
            return False, "Invalid VirusTotal API key."
        if e.code == 403:
            return False, "VirusTotal API key is valid, but access is forbidden."
        if e.code == 429:
            return True, "Valid API key, but rate limit has been reached."
        return False, f"VirusTotal API check failed: HTTP {e.code}"

    except URLError:
        return False, "Network error. Cannot connect to VirusTotal."

    except Exception as e:
        logging.exception("VirusTotal API validation failed.")
        return False, f"VirusTotal API check failed.\n\n{e}"


# =============================================================================
# Dialog
# =============================================================================

class VtApiKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_window()
        self._build_ui()

    def _setup_window(self) -> None:
        self.setWindowTitle("VirusTotal API Key")
        self.setFixedSize(420, 180)
        self.setModal(True)
        self.setStyleSheet("""
            QDialog {
                background-color: rgb(30, 30, 30);
                color: white;
            }

            QLabel {
                color: white;
                font-size: 14px;
                background: transparent;
            }

            QLineEdit {
                background-color: rgb(55, 55, 55);
                color: white;
                border: 1px solid rgb(90, 90, 90);
                border-radius: 6px;
                padding: 8px;
                font-size: 13px;
            }

            QLineEdit:focus {
                border: 1px solid rgb(80, 160, 255);
            }

            QPushButton {
                background-color: rgb(70, 70, 70);
                color: white;
                border: 1px solid rgb(100, 100, 100);
                border-radius: 6px;
                padding: 7px 14px;
                font-size: 13px;
            }

            QPushButton:hover {
                background-color: rgb(95, 95, 95);
            }

            QPushButton:pressed {
                background-color: rgb(50, 50, 50);
            }

            QPushButton#okButton {
                background-color: rgb(150, 120, 20);
                border: 1px solid rgb(220, 180, 40);
                color: white;
            }

            QPushButton#okButton:hover {
                background-color: rgb(190, 150, 30);
            }
        """)

    def _build_ui(self) -> None:
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(18, 18, 18, 18)
        root_layout.setSpacing(12)

        self.label = QLabel("Enter your VirusTotal API key:", self)

        self.api_key_input = QLineEdit(self)
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setPlaceholderText("VirusTotal API Key")

        self.cancel_button = QPushButton("Cancel", self)
        self.ok_button = QPushButton("OK", self)
        self.ok_button.setObjectName("okButton")

        self.cancel_button.clicked.connect(self.reject)
        self.ok_button.clicked.connect(self.accept)
        self.api_key_input.returnPressed.connect(self.accept)

        button_layout = QHBoxLayout()
        button_layout.addStretch()
        button_layout.addWidget(self.cancel_button)
        button_layout.addWidget(self.ok_button)

        root_layout.addWidget(self.label)
        root_layout.addWidget(self.api_key_input)
        root_layout.addLayout(button_layout)

    def get_api_key(self) -> str:
        return self.api_key_input.text().strip()


def load_or_prompt_vt_api_key(parent=None) -> str:
    api_key = load_vt_api_key_from_secure_store()
    if api_key:
        return api_key

    api_key = migrate_legacy_api_key_to_keyring()
    if api_key:
        return api_key

    if keyring is None:
        QMessageBox.warning(
            parent,
            "Keyring Module Missing",
            "The 'keyring' module is not installed.\n\n"
            "VirusTotal API key will not be saved in plaintext.\n"
            "Install it with: pip install keyring"
        )

    while True:
        dialog = VtApiKeyDialog(parent)

        if dialog.exec_() != QDialog.Accepted:
            QMessageBox.warning(
                parent,
                "VirusTotal API Key",
                "VirusTotal API key was not entered. VirusTotal lookup will be disabled.",
            )
            return ""

        api_key = dialog.get_api_key()

        if not api_key:
            QMessageBox.warning(parent, "VirusTotal API Key", "API key cannot be empty.")
            continue

        is_valid, validation_message = validate_vt_api_key(api_key)

        if not is_valid:
            QMessageBox.warning(
                parent,
                "VirusTotal API Key Validation Failed",
                validation_message,
            )
            continue

        if save_vt_api_key_to_secure_store(api_key):
            QMessageBox.information(
                parent,
                "VirusTotal API Key",
                "VirusTotal API key has been validated and saved securely.",
            )
        else:
            QMessageBox.warning(
                parent,
                "VirusTotal API Key",
                "VirusTotal API key has been validated, but it could not be saved securely.\n"
                "It will be used for this session only.",
            )

        return api_key


# =============================================================================
# Workers
# =============================================================================

class VirusTotalWorker(QThread):
    result_ready = pyqtSignal(dict)

    def __init__(self, ip_addr: str, vt_api_key: str, request_id: int, parent=None):
        super().__init__(parent)
        self.ip_addr = ip_addr
        self.vt_api_key = vt_api_key
        self.request_id = request_id

    def _emit_result(self, payload: dict) -> None:
        payload["request_id"] = self.request_id
        payload["ip_addr"] = self.ip_addr
        self.result_ready.emit(payload)

    @staticmethod
    def _format_vt_date(ts) -> str:
        if not ts:
            return "No data"
        try:
            return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y.%m.%d")
        except Exception:
            return "No data"

    def run(self) -> None:
        if not self.vt_api_key or self.vt_api_key == "YOUR_VIRUSTOTAL_API_KEY":
            self._emit_result({
                "status_text": "No API key",
                "detect_name": "No data",
                "recent_activity": "No data",
            })
            return

        url = f"{VT_API_BASE_URL}/ip_addresses/{self.ip_addr}"
        req = Request(url, headers={
            "x-apikey": self.vt_api_key,
            "accept": "application/json",
        })

        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

        except HTTPError as e:
            self._emit_result(self._format_http_error(e))
            return

        except URLError:
            self._emit_result({
                "status_text": "Network error",
                "detect_name": "No data",
                "recent_activity": "No data",
            })
            return

        except Exception:
            logging.exception("VirusTotal lookup failed.")
            self._emit_result({
                "status_text": "Lookup failed",
                "detect_name": "No data",
                "recent_activity": "No data",
            })
            return

        self._emit_result(self._parse_vt_response(data))

    @staticmethod
    def _format_http_error(error: HTTPError) -> dict:
        if error.code == 401:
            return {
                "status_text": "Unauthorized",
                "detect_name": "Invalid API key",
                "recent_activity": "No data",
            }
        if error.code == 404:
            return {
                "status_text": "0/0 (VirusTotal)",
                "detect_name": "No data",
                "recent_activity": "No data",
            }
        if error.code == 429:
            return {
                "status_text": "Rate limited",
                "detect_name": "Try again later",
                "recent_activity": "No data",
            }

        return {
            "status_text": "Error",
            "detect_name": f"HTTP {error.code}",
            "recent_activity": "No data",
        }

    def _parse_vt_response(self, data: dict) -> dict:
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        results = attributes.get("last_analysis_results", {})

        harmless = int(stats.get("harmless", 0))
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        undetected = int(stats.get("undetected", 0))
        timeout = int(stats.get("timeout", 0))

        total = harmless + malicious + suspicious + undetected + timeout
        detected = malicious + suspicious

        detect_name = "No data"
        for result_obj in results.values():
            category = str(result_obj.get("category", "")).lower()
            result_name = result_obj.get("result")
            if category in ("malicious", "suspicious") and result_name:
                detect_name = str(result_name)
                break

        recent_ts = attributes.get("last_analysis_date") or attributes.get("last_modification_date")

        return {
            "status_text": f"{detected}/{total} (VirusTotal)",
            "detect_name": detect_name,
            "recent_activity": self._format_vt_date(recent_ts),
        }


class VirusTotalIpOwnerWorker(QThread):
    result_ready = pyqtSignal(dict)

    def __init__(self, ip_addr: str, vt_api_key: str, request_id: int, parent=None):
        super().__init__(parent)
        self.ip_addr = ip_addr
        self.vt_api_key = vt_api_key
        self.request_id = request_id

    def _emit_result(self, payload: dict) -> None:
        payload["request_id"] = self.request_id
        payload["ip_addr"] = self.ip_addr
        self.result_ready.emit(payload)

    @staticmethod
    def _extract_owner_from_whois_text(whois_text: str) -> str:
        if not whois_text:
            return ""

        preferred_keys = (
            "OrgName",
            "org-name",
            "Organization",
            "owner",
            "descr",
            "netname",
        )

        for line in whois_text.splitlines():
            if ":" not in line:
                continue

            key, value = line.split(":", 1)
            key = key.strip()
            value = value.strip()

            if key in preferred_keys and value:
                return value

        return ""

    def _parse_owner(self, data: dict) -> str:
        attributes = data.get("data", {}).get("attributes", {})

        owner = (
            attributes.get("as_owner")
            or attributes.get("owner")
            or attributes.get("network_owner")
            or ""
        )

        if owner:
            return str(owner)

        whois_owner = self._extract_owner_from_whois_text(str(attributes.get("whois") or ""))
        if whois_owner:
            return whois_owner

        registry = attributes.get("regional_internet_registry")
        if registry:
            return f"No owner data / RIR: {registry}"

        return "No data"

    def run(self) -> None:
        if not self.vt_api_key or self.vt_api_key == "YOUR_VIRUSTOTAL_API_KEY":
            self._emit_result({
                "ok": False,
                "owner": "No API key",
                "message": "VirusTotal API key is not configured.",
            })
            return

        url = f"{VT_API_BASE_URL}/ip_addresses/{self.ip_addr}"
        req = Request(url, headers={
            "x-apikey": self.vt_api_key,
            "accept": "application/json",
        })

        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            self._emit_result({
                "ok": True,
                "owner": self._parse_owner(data),
                "message": "OK",
            })

        except HTTPError as e:
            if e.code == 401:
                owner = "Invalid API key"
            elif e.code == 404:
                owner = "No data"
            elif e.code == 429:
                owner = "Rate limited"
            else:
                owner = f"HTTP {e.code}"

            self._emit_result({
                "ok": False,
                "owner": owner,
                "message": f"VirusTotal lookup failed: HTTP {e.code}",
            })

        except URLError:
            self._emit_result({
                "ok": False,
                "owner": "Network error",
                "message": "Cannot connect to VirusTotal.",
            })

        except Exception:
            logging.exception("VirusTotal IP owner lookup failed.")
            self._emit_result({
                "ok": False,
                "owner": "Lookup failed",
                "message": "VirusTotal lookup failed.",
            })


class WhoisWorker(QThread):
    result_ready = pyqtSignal(dict)

    def __init__(self, ip_addr: str, request_id: int, parent=None):
        super().__init__(parent)
        self.ip_addr = ip_addr
        self.request_id = request_id

    def _emit_result(self, payload: dict) -> None:
        payload["request_id"] = self.request_id
        payload["ip_addr"] = self.ip_addr
        self.result_ready.emit(payload)

    def run(self) -> None:
        try:
            whois_obj = IPWhois(self.ip_addr)
            whois_res = whois_obj.lookup_rdap()
            network = whois_res.get("network") or {}

            self._emit_result({
                "ok": True,
                "asn_description": whois_res.get("asn_description", "No data"),
                "ip_version": network.get("ip_version", "No data"),
                "asn_registry": whois_res.get("asn_registry", "No data"),
                "asn_cidr": whois_res.get("asn_cidr", "No data"),
                "asn_date": whois_res.get("asn_date", "No data"),
            })

        except Exception:
            logging.exception("RDAP lookup failed.")
            self._emit_result({
                "ok": False,
                "asn_description": "No data",
                "ip_version": "No data",
                "asn_registry": "No data",
                "asn_cidr": "No data",
                "asn_date": "No data",
            })


# =============================================================================
# OpenGL Earth Widget
# =============================================================================

class EarthWidget(QOpenGLWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        self.rotation = 110
        self.rotation_x = -75
        self.rotation_y = 40
        self.rotation_z = -90
        self.last_mouse_x = 0
        self.last_mouse_y = 0
        self.zoom_level = -2.8

        self.texture = None
        self.quadric = None

        self.raw_lat = ""
        self.raw_lon = ""

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_rotation)
        self.timer.start(20)

    def initializeGL(self) -> None:
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_TEXTURE_2D)
        glEnable(GL_MULTISAMPLE)
        glClearColor(0.06, 0.06, 0.06, 1.0)

        self.texture = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, self.texture)
        self.load_texture(resource_path("resource/earth_texture.jpg"))

        self.quadric = gluNewQuadric()
        gluQuadricTexture(self.quadric, GL_TRUE)

    def load_texture(self, texture_path: str) -> None:
        try:
            image = Image.open(texture_path)
            image = image.transpose(Image.FLIP_TOP_BOTTOM)
            image = image.transpose(Image.FLIP_LEFT_RIGHT)
            image = image.convert("RGB")
            img_data = image.tobytes()

            glPixelStorei(GL_UNPACK_ALIGNMENT, 1)
            glTexImage2D(
                GL_TEXTURE_2D,
                0,
                GL_RGB,
                image.width,
                image.height,
                0,
                GL_RGB,
                GL_UNSIGNED_BYTE,
                img_data,
            )
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE)
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE)
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR)
            glGenerateMipmap(GL_TEXTURE_2D)

        except Exception:
            logging.exception("Failed to load earth texture.")

    def update_rotation(self) -> None:
        self.rotation = (self.rotation + 0.2) % 360
        self.update()

    def resizeGL(self, w: int, h: int) -> None:
        glViewport(0, 0, w, h)
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        gluPerspective(45.0, w / h if h != 0 else 1, 1.0, 100.0)
        glMatrixMode(GL_MODELVIEW)

    def paintGL(self) -> None:
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()

        gluLookAt(0.0, 0.0, self.zoom_level, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0)

        if self.texture:
            glBindTexture(GL_TEXTURE_2D, self.texture)

        glRotatef(self.rotation, 0.0, 1.0, 0.0)
        glRotatef(self.rotation_x, 1.0, 0.0, 0.0)
        glRotatef(self.rotation_y, 0.0, 1.0, 0.0)
        glRotatef(self.rotation_z, 0.0, 0.0, 1.0)

        if self.quadric:
            gluSphere(self.quadric, 1.0, 100, 100)

    def cleanup_gl_resources(self) -> None:
        if self.quadric:
            try:
                gluDeleteQuadric(self.quadric)
            except Exception:
                logging.exception("Failed to delete OpenGL quadric.")
            self.quadric = None

    def mousePressEvent(self, event) -> None:
        self.last_mouse_x = event.x()
        self.last_mouse_y = event.y()

    def mouseMoveEvent(self, event) -> None:
        dx = event.x() - self.last_mouse_x
        dy = event.y() - self.last_mouse_y

        self.rotation_x += dy * 0.5
        self.rotation_y += dx * 0.5

        self.last_mouse_x = event.x()
        self.last_mouse_y = event.y()

        self.update()

    def wheelEvent(self, event) -> None:
        delta = event.angleDelta().y() / 120
        self.zoom_level += delta * 0.5
        self.zoom_level = max(-8.0, min(-2.2, self.zoom_level))
        self.update()


# =============================================================================
# Google Earth Pro path discovery
# =============================================================================

def is_valid_google_earth_path(exe_path: str) -> bool:
    if not exe_path:
        return False

    normalized_path = os.path.abspath(os.path.expandvars(os.path.expanduser(exe_path)))
    return (
        os.path.isfile(normalized_path)
        and os.path.basename(normalized_path).lower() == "googleearth.exe"
    )


def find_google_earth_from_settings() -> Optional[str]:
    settings = load_app_settings()
    saved_path = settings.get("google_earth_path", "")

    if is_valid_google_earth_path(saved_path):
        return os.path.abspath(os.path.expandvars(os.path.expanduser(saved_path)))

    return None


def find_google_earth_from_registry() -> Optional[str]:
    if os.name != "nt":
        return None

    try:
        import winreg
    except ImportError:
        return None

    registry_roots = [
        winreg.HKEY_LOCAL_MACHINE,
        winreg.HKEY_CURRENT_USER,
    ]

    value_names = [
        "InstallLocation",
        "InstallDir",
    ]

    for root in registry_roots:
        for reg_path in GOOGLE_EARTH_REGISTRY_PATHS:
            try:
                with winreg.OpenKey(root, reg_path) as key:
                    for value_name in value_names:
                        try:
                            install_dir, _ = winreg.QueryValueEx(key, value_name)
                        except OSError:
                            continue

                        candidate_paths = [
                            os.path.join(install_dir, "client", "googleearth.exe"),
                            os.path.join(install_dir, "googleearth.exe"),
                        ]

                        for candidate in candidate_paths:
                            if is_valid_google_earth_path(candidate):
                                return os.path.abspath(candidate)

            except OSError:
                continue

    return None


def find_google_earth_from_default_paths() -> Optional[str]:
    for candidate in GOOGLE_EARTH_DEFAULT_PATHS:
        if is_valid_google_earth_path(candidate):
            return os.path.abspath(candidate)

    return None


def find_google_earth_from_path_env() -> Optional[str]:
    candidate = shutil.which("googleearth.exe")
    if is_valid_google_earth_path(candidate):
        return os.path.abspath(candidate)

    return None


def save_google_earth_path(exe_path: str) -> None:
    if not is_valid_google_earth_path(exe_path):
        return

    settings = load_app_settings()
    settings["google_earth_path"] = os.path.abspath(exe_path)
    save_app_settings(settings)


def auto_detect_google_earth_path() -> Optional[str]:
    finders = [
        find_google_earth_from_settings,
        find_google_earth_from_registry,
        find_google_earth_from_default_paths,
        find_google_earth_from_path_env,
    ]

    for finder in finders:
        try:
            exe_path = finder()
        except Exception:
            logging.exception("Google Earth path finder failed: %s", finder.__name__)
            continue

        if is_valid_google_earth_path(exe_path):
            save_google_earth_path(exe_path)
            return os.path.abspath(exe_path)

    return None


# =============================================================================
# Main Window
# =============================================================================

class MainWindow(QMainWindow):
    SECTION_STYLE = "color: yellow; font-size: 16px; font-weight: bold; background: transparent;"
    TEXT_STYLE = "color: white; font-size: 12px; background: transparent;"
    MALICIOUS_TITLE_STYLE = "color: red; font-size: 16px; font-weight: bold; background: transparent;"
    MALICIOUS_TEXT_STYLE = "color: lightgrey; font-size: 14px; background: transparent;"

    BUTTON_STYLE = """
        QPushButton {
            background-color: rgb(90, 90, 90);
            color: white;
            border: 1px solid rgb(120, 120, 120);
            padding: 6px;
        }
        QPushButton:hover {
            background-color: rgb(110, 110, 110);
        }
    """

    def __init__(self, config: AppConfig, geoip_reader):
        super().__init__()

        self.config = config
        self.gi = geoip_reader

        self.drag_pos = QPoint()
        self.current_ip_addr = ""

        self.vt_worker = None
        self.whois_worker = None
        self.private_ip_owner_worker = None
        self.vt_request_id = 0
        self.whois_request_id = 0
        self.private_ip_owner_request_id = 0
        self._active_workers = []

        self._setup_window()
        self._build_ui()
        self._initialize_state()

    # -------------------------------------------------------------------------
    # UI construction
    # -------------------------------------------------------------------------

    def _setup_window(self) -> None:
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("Geo IP Addr Tracker - github.com/miho030")
        self.setWindowIcon(QIcon(resource_path("resource/AOI_icon.ico")))
        self.setGeometry(100, 100, 1200, 600)

    def _build_ui(self) -> None:
        self._create_root_layout()
        self._create_title_bar()
        self._create_earth_view()
        self._create_overlays()
        self._create_left_panel()
        self._create_right_panel()

        self.title_bar.raise_()
        self.left_overlay.raise_()
        self.right_overlay.raise_()

    def _create_root_layout(self) -> None:
        self.main_widget = QWidget(self)
        self.main_widget.setStyleSheet("background-color: rgba(0, 0, 0, 140);")
        self.setCentralWidget(self.main_widget)

        self.root_layout = QVBoxLayout(self.main_widget)
        self.root_layout.setContentsMargins(0, 0, 0, 0)
        self.root_layout.setSpacing(0)

    def _create_title_bar(self) -> None:
        self.title_bar = QWidget(self)
        self.title_bar.setFixedHeight(36)
        self.title_bar.setStyleSheet("background-color: rgb(20, 20, 20);")

        title_layout = QHBoxLayout(self.title_bar)
        title_layout.setContentsMargins(10, 0, 6, 0)
        title_layout.setSpacing(6)

        self.title_label = QLabel("Geo IP Addr Tracker - github.com/miho030", self.title_bar)
        self.title_label.setStyleSheet("""
            background-color: rgb(20, 20, 20);
            color: white;
            font-size: 13px;
            font-weight: bold;
            padding-left: 2px;
            padding-right: 2px;
        """)

        self.btn_minimize = QPushButton("—", self.title_bar)
        self.btn_close = QPushButton("✕", self.title_bar)

        self.btn_minimize.setFixedSize(32, 24)
        self.btn_close.setFixedSize(32, 24)

        self.btn_minimize.setStyleSheet("""
            QPushButton {
                background-color: rgb(80, 80, 80);
                color: white;
                border: none;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgb(120, 120, 120);
            }
        """)

        self.btn_close.setStyleSheet("""
            QPushButton {
                background-color: rgb(120, 30, 30);
                color: white;
                border: none;
                font-size: 13px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: rgb(200, 40, 40);
            }
        """)

        self.btn_minimize.clicked.connect(self.showMinimized)
        self.btn_close.clicked.connect(self.close)

        title_layout.addWidget(self.title_label)
        title_layout.addStretch()
        title_layout.addWidget(self.btn_minimize)
        title_layout.addWidget(self.btn_close)

        self.root_layout.addWidget(self.title_bar)

    def _create_earth_view(self) -> None:
        self.content_widget = QWidget(self)
        self.content_widget.setStyleSheet("background-color: transparent;")
        self.root_layout.addWidget(self.content_widget)

        earth_layout = QVBoxLayout(self.content_widget)
        earth_layout.setContentsMargins(0, 0, 0, 0)

        self.earth_widget = EarthWidget(self)
        earth_layout.addWidget(self.earth_widget)

    def _create_overlays(self) -> None:
        self.left_overlay = QWidget(self)
        self.left_overlay.setGeometry(0, self.title_bar.height(), 220, self.height() - self.title_bar.height())
        self.left_overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self._set_overlay_background(self.left_overlay)

        self.right_overlay = QWidget(self)
        self.right_overlay.setGeometry(self.width() - 220, self.title_bar.height(), 220, self.height() - self.title_bar.height())
        self.right_overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self._set_overlay_background(self.right_overlay)

    def _create_left_panel(self) -> None:
        left_layout = QVBoxLayout(self.left_overlay)
        left_layout.setContentsMargins(10, 8, 10, 8)
        left_layout.setSpacing(2)

        self.geodb_title = self._make_label("* GeoDB info", self.left_overlay, self.SECTION_STYLE)
        self.geodb_status = self._make_label("  > GeoDB Status : No data\n - GeoDB Version : No data", self.left_overlay)

        self.sfInfo = self._make_label("* Software Info", self.left_overlay, self.SECTION_STYLE)
        self.sfVersion_info = self._make_label(
            f"  > Software version : {self.config.software_version}",
            self.left_overlay,
        )

        self.ip_detail_title = self._make_label("* Target IP details", self.left_overlay, self.SECTION_STYLE)
        self.ipAddr_label = self._make_label("  > IP Address : No data", self.left_overlay)
        self.domain_info_label = self._make_label("  > Domain : No data", self.left_overlay)
        self.target_owner_label = self._make_label("  > IP Owner : No data", self.left_overlay)
        self.ip_version_dat = self._make_label("  > IP version : No data", self.left_overlay)
        self.ip_phone_dat = self._make_label("  > Phone : No data", self.left_overlay)
        self.ip_email_dat = self._make_label("  > Email : No data", self.left_overlay)

        self.network_detail_title = self._make_label("* Target network details", self.left_overlay, self.SECTION_STYLE)
        self.asn_info_label = self._make_label("  > ASN registry: No data", self.left_overlay)
        self.asn_cidr_dat = self._make_label("  > ASN CIDR : No data", self.left_overlay)
        self.asn_date = self._make_label("  > ASN date : No data", self.left_overlay)
        self.network_type = self._make_label("  > Network type : No data", self.left_overlay)

        self.malicious_title = self._make_label("* Malicious?", self.left_overlay, self.MALICIOUS_TITLE_STYLE)
        self.target_ip_malicious_level = self._make_label("  > status : No data", self.left_overlay, self.MALICIOUS_TEXT_STYLE)
        self.target_source = self._make_label(
            "  > detect name : No data\n  > recent activity : No data",
            self.left_overlay,
            self.MALICIOUS_TEXT_STYLE,
        )

        self._set_left_label_heights()

        left_layout.addWidget(self.geodb_title)
        left_layout.addWidget(self.geodb_status)
        left_layout.addSpacing(8)

        left_layout.addWidget(self.sfInfo)
        left_layout.addWidget(self.sfVersion_info)
        left_layout.addSpacing(16)

        left_layout.addWidget(self.ip_detail_title)
        left_layout.addWidget(self.ipAddr_label)
        left_layout.addWidget(self.domain_info_label)
        left_layout.addWidget(self.target_owner_label)
        left_layout.addWidget(self.ip_version_dat)
        left_layout.addWidget(self.ip_phone_dat)
        left_layout.addWidget(self.ip_email_dat)

        left_layout.addWidget(self.network_detail_title)
        left_layout.addWidget(self.asn_info_label)
        left_layout.addWidget(self.asn_cidr_dat)
        left_layout.addWidget(self.asn_date)
        left_layout.addWidget(self.network_type)
        left_layout.addSpacing(16)

        left_layout.addWidget(self.malicious_title)
        left_layout.addWidget(self.target_ip_malicious_level)
        left_layout.addWidget(self.target_source)
        left_layout.addStretch()

    def _create_right_panel(self) -> None:
        right_layout = QVBoxLayout(self.right_overlay)
        right_layout.setContentsMargins(10, 8, 10, 8)
        right_layout.setSpacing(2)

        self.ip_input_title = self._make_label(
            "[ Enter Target IP IPv4 ]",
            self.right_overlay,
            "color: yellow; font-size: 16px; font-weight: bold; background: transparent;",
        )
        right_layout.setSpacing(4)


        self.ip_input = QLineEdit(self.right_overlay)
        self.ip_input.setPlaceholderText("Enter public IPv4 address")
        self.ip_input.returnPressed.connect(self.check_ip_address)
        self.ip_input.setStyleSheet("""
            QLineEdit {
                background-color: rgb(85, 85, 85);
                color: white;
                border: 1px solid rgb(110, 110, 110);
                padding: 6px;
            }
        """)

        self.ip_input_confirm_button = QPushButton("Confirm", self.right_overlay)
        self.ip_input_confirm_button.clicked.connect(self.check_ip_address)
        self.ip_input_confirm_button.setStyleSheet(self.BUTTON_STYLE)

        self.geo_title = self._make_label("* Physical Location Info", self.right_overlay, self.SECTION_STYLE)
        self.geo_country = self._make_label("  > Country : No data", self.right_overlay)
        self.geo_timezone = self._make_label("  > Timezone : No data", self.right_overlay)
        self.geo_city = self._make_label("  > City : No data", self.right_overlay)
        self.geo_postal = self._make_label("  > Postal code : No data", self.right_overlay)
        self.geo_lat = self._make_label("  > Latitude : No data", self.right_overlay)
        self.geo_long = self._make_label("  > Longitude : No data", self.right_overlay)
        self.geo_lang = self._make_label("  > Language : No data", self.right_overlay)
        self.geo_currency = self._make_label("  > Currency : No data", self.right_overlay)
        self.geo_region_code = self._make_label("  > Region code : No data", self.right_overlay)
        self.geo_region_num = self._make_label("  > Region number : No data", self.right_overlay)

        self.btn_online_ge = QPushButton("[On-line mode] Check locate", self.right_overlay)
        self.btn_offline_ge = QPushButton("[Off-line mode] Check locate", self.right_overlay)

        self.btn_online_ge.clicked.connect(self.online_ge_api)
        self.btn_offline_ge.clicked.connect(self.offline_ge_api)

        self.btn_online_ge.setStyleSheet(self.BUTTON_STYLE)
        self.btn_offline_ge.setStyleSheet(self.BUTTON_STYLE)

        self._set_right_label_heights()

        right_layout.addWidget(self.ip_input_title)
        right_layout.addWidget(self.ip_input)
        right_layout.addWidget(self.ip_input_confirm_button)
        right_layout.addSpacing(6)

        right_layout.addWidget(self.geo_title)
        right_layout.addWidget(self.geo_country)
        right_layout.addWidget(self.geo_timezone)
        right_layout.addWidget(self.geo_city)
        right_layout.addWidget(self.geo_postal)
        right_layout.addWidget(self.geo_lat)
        right_layout.addWidget(self.geo_long)
        right_layout.addWidget(self.geo_currency)
        right_layout.addWidget(self.geo_lang)
        right_layout.addWidget(self.geo_region_code)
        right_layout.addWidget(self.geo_region_num)
        right_layout.addSpacing(30)

        right_layout.addWidget(self.btn_online_ge)
        right_layout.addWidget(self.btn_offline_ge)
        right_layout.addStretch()

    def _make_label(self, text: str, parent: QWidget, style: Optional[str] = None) -> QLabel:
        label = QLabel(text, parent)
        label.setStyleSheet(style or self.TEXT_STYLE)
        return label

    def _set_left_label_heights(self) -> None:
        fixed_22 = [
            self.geodb_title,
            self.sfInfo,
            self.sfVersion_info,
            self.ip_detail_title,
            self.ipAddr_label,
            self.domain_info_label,
            self.target_owner_label,
            self.ip_version_dat,
            self.ip_phone_dat,
            self.ip_email_dat,
            self.network_detail_title,
            self.asn_info_label,
            self.asn_cidr_dat,
            self.asn_date,
            self.network_type,
            self.malicious_title,
        ]

        for label in fixed_22:
            label.setFixedHeight(22)

        self.geodb_status.setFixedHeight(42)
        self.target_ip_malicious_level.setMinimumHeight(22)
        self.target_source.setMinimumHeight(42)

    def _set_right_label_heights(self) -> None:
        fixed_22 = [
            self.geo_country,
            self.geo_timezone,
            self.geo_city,
            self.geo_lat,
            self.geo_long,
            self.geo_lang,
            self.geo_postal,
            self.geo_currency,
            self.geo_region_code,
            self.geo_region_num,
        ]

        for label in fixed_22:
            label.setFixedHeight(22)

        self.ip_input_title.setFixedHeight(24)
        self.geo_title.setFixedHeight(34)

    def _set_overlay_background(self, overlay_widget: QWidget) -> None:
        overlay_widget.setStyleSheet("""
            background-color: rgb(65, 65, 65);
            border-radius: 8px;
        """)

    def _initialize_state(self) -> None:
        self.set_geodb_active_status()
        self.reset_result_fields()

    # -------------------------------------------------------------------------
    # Window events
    # -------------------------------------------------------------------------

    def resizeEvent(self, event) -> None:
        title_h = self.title_bar.height()
        panel_margin = 8
        panel_width = 220
        panel_height = self.height() - title_h - panel_margin * 2

        self.title_bar.setGeometry(0, 0, self.width(), title_h)
        self.left_overlay.setGeometry(panel_margin, title_h + panel_margin, panel_width, panel_height)
        self.right_overlay.setGeometry(
            self.width() - panel_width - panel_margin,
            title_h + panel_margin,
            panel_width,
            panel_height,
        )

        self.title_bar.raise_()
        self.left_overlay.raise_()
        self.right_overlay.raise_()

        super().resizeEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton and event.y() <= self.title_bar.height():
            self.drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event) -> None:
        if event.buttons() == Qt.LeftButton and not self.drag_pos.isNull():
            self.move(event.globalPos() - self.drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event) -> None:
        self.drag_pos = QPoint()
        event.accept()

    def closeEvent(self, event) -> None:
        self.vt_request_id += 1
        self.whois_request_id += 1
        self.private_ip_owner_request_id += 1

        for worker in list(self._active_workers):
            if worker is not None and worker.isRunning():
                worker.requestInterruption()
                worker.wait(1500)

        self.earth_widget.cleanup_gl_resources()
        self.delete_kml_file()
        event.accept()

    # -------------------------------------------------------------------------
    # State / field updates
    # -------------------------------------------------------------------------

    def reset_result_fields(self) -> None:
        self.earth_widget.raw_lat = ""
        self.earth_widget.raw_lon = ""

        self.ipAddr_label.setText("  > IP Address : No data")
        self.domain_info_label.setText("  > Domain : No data")
        self.target_owner_label.setText("  > IP Owner : No data")
        self.ip_version_dat.setText("  > IP version : No data")
        self.ip_phone_dat.setText("  > Phone : No data")
        self.ip_email_dat.setText("  > Admin Email : No data")
        self.asn_info_label.setText("  > ASN Registry : No data")
        self.asn_cidr_dat.setText("  > ASN CIDR : No data")
        self.asn_date.setText("  > ASN Date : No data")
        self.network_type.setText("  > Network type : No data")
        self.target_ip_malicious_level.setText("  > status : No data")
        self.target_source.setText("  > detect name : No data\n  > recent activity : No data")

        self.geo_country.setText("  > Country : No data")
        self.geo_timezone.setText("  > Timezone : No data")
        self.geo_city.setText("  > City : No data")
        self.geo_postal.setText("  > Postal code : No data")
        self.geo_lat.setText("  > Latitude : No data")
        self.geo_long.setText("  > Longitude : No data")
        self.geo_lang.setText("  > Language : No data")
        self.geo_currency.setText("  > Currency : No data")
        self.geo_region_code.setText("  > Region code : No data")
        self.geo_region_num.setText("  > Region number : No data")

    def set_geodb_active_status(self) -> None:
        self.geodb_status.setText(
            f"  > GeoDB Status : Activate\n  > GeoDB Version : {self.config.geodb_version}"
        )

    def _track_worker(self, worker: QThread) -> None:
        self._active_workers.append(worker)
        worker.finished.connect(lambda w=worker: self._cleanup_worker(w))

    def _cleanup_worker(self, worker: QThread) -> None:
        try:
            if worker in self._active_workers:
                self._active_workers.remove(worker)
        except ValueError:
            pass
        worker.deleteLater()

    # -------------------------------------------------------------------------
    # Lookup flow
    # -------------------------------------------------------------------------

    def check_ip_address(self) -> None:
        input_ip_data = self.ip_input.text().strip()
        self.reset_result_fields()

        ip_addr, status_code, message = classify_ip_address(input_ip_data)

        if status_code == "PRIVATE_IPV4":
            self.current_ip_addr = ip_addr
            self.ipAddr_label.setText(f"  > IP Address : {ip_addr}")
            self.start_private_ip_owner_lookup(ip_addr, message)
            return

        if status_code != "PUBLIC_IPV4":
            QMessageBox.warning(self, "IP Validation", message)
            return

        self.current_ip_addr = ip_addr
        self.ipAddr_label.setText(f"  > IP Address : {ip_addr}")

        self.trace_ip_addr_info(ip_addr)
        self.start_whois_lookup(ip_addr)
        self.start_virustotal_lookup(ip_addr)

    def trace_ip_addr_info(self, ip_addr: str) -> None:
        self.earth_widget.raw_lat = ""
        self.earth_widget.raw_lon = ""

        try:
            rec = self.gi.record_by_name(ip_addr)
        except Exception:
            logging.exception("GeoIP lookup failed.")
            rec = None

        if not rec:
            QMessageBox.information(self, "No GeoIP Data", f"No GeoIP data found for {ip_addr}.")
            self.ipAddr_label.setText(f"  > IP Address : {ip_addr}")
            return

        country = rec.get("country_name", "No data")
        continent = rec.get("continent", "No data")
        total_country = f"{country}({continent})"

        time_zone = rec.get("time_zone", "No data")
        city = rec.get("city", "No data")
        language = rec.get("country_code", "No data")
        postal_code = rec.get("postal_code", "No data")
        region_code = rec.get("country_code3", "No data")
        region_num = rec.get("area_code", "No data")
        lat = rec.get("latitude", "No data")
        lon = rec.get("longitude", "No data")

        self.earth_widget.raw_lat = lat if lat is not None else ""
        self.earth_widget.raw_lon = lon if lon is not None else ""

        self.geo_country.setText(f"  > Country : {total_country}")
        self.geo_city.setText(f"  > City : {city}")
        self.geo_timezone.setText(f"  > Timezone : {time_zone}")
        self.geo_lat.setText(f"  > Latitude : {lat}")
        self.geo_long.setText(f"  > Longitude : {lon}")
        self.geo_postal.setText(f"  > Postal code : {postal_code}")
        self.geo_lang.setText(f"  > Language : {language}")
        self.geo_region_code.setText(f"  > Region code : {region_code}")
        self.geo_region_num.setText(f"  > Region number : {region_num}")
        self.geo_currency.setText(f"  > Currency : {CURRENCY_MAP.get(region_code, 'No data')}")

        if lat not in (None, "No data") and lon not in (None, "No data"):
            self.write_kml_file(lat, lon)

    def start_virustotal_lookup(self, ip_addr: str) -> None:
        self.vt_request_id += 1
        request_id = self.vt_request_id

        self.target_ip_malicious_level.setText("  > status : Checking VirusTotal...")
        self.target_source.setText("  > detect name : No data\n  > recent activity : No data")

        worker = VirusTotalWorker(ip_addr, self.config.vt_api_key, request_id, self)
        worker.result_ready.connect(self.on_vt_result)
        self._track_worker(worker)

        self.vt_worker = worker
        worker.start()

    def on_vt_result(self, vt_info: dict) -> None:
        if vt_info.get("request_id") != self.vt_request_id:
            return
        if vt_info.get("ip_addr") != self.current_ip_addr:
            return

        self.target_ip_malicious_level.setText(f"  > status : {vt_info['status_text']}")
        self.target_source.setText(
            f"  > detect name : {vt_info['detect_name']}\n"
            f"  > recent activity : {vt_info['recent_activity']}"
        )

    def start_private_ip_owner_lookup(self, ip_addr: str, validation_message: str) -> None:
        self.private_ip_owner_request_id += 1
        request_id = self.private_ip_owner_request_id

        self.target_ip_malicious_level.setText("  > status : Private IPv4 / VT owner check...")
        self.target_source.setText("  > detect name : No data\n  > recent activity : No data")

        worker = VirusTotalIpOwnerWorker(ip_addr, self.config.vt_api_key, request_id, self)
        worker.result_ready.connect(
            lambda result, msg=validation_message: self.on_private_ip_owner_result(result, msg)
        )
        self._track_worker(worker)

        self.private_ip_owner_worker = worker
        worker.start()

    def on_private_ip_owner_result(self, vt_info: dict, validation_message: str) -> None:
        if vt_info.get("request_id") != self.private_ip_owner_request_id:
            return
        if vt_info.get("ip_addr") != self.current_ip_addr:
            return

        owner = vt_info.get("owner") or "No data"

        self.target_ip_malicious_level.setText(" - status : Private IPv4")
        self.target_source.setText(f"  > detect name : No data\n  > recent activity : No data")

        QMessageBox.warning(
            self,
            "Private IPv4",
            f"{validation_message}\nIP provider : {owner}",
        )

    def start_whois_lookup(self, ip_addr: str) -> None:
        self.whois_request_id += 1
        request_id = self.whois_request_id

        self.target_owner_label.setText("  > IP Owner : Checking RDAP...")
        self.ip_version_dat.setText("  > IP version : Checking RDAP...")
        self.asn_info_label.setText("  > ASN Registry : Checking RDAP...")
        self.asn_cidr_dat.setText("  > ASN CIDR : Checking RDAP...")
        self.asn_date.setText("  > ASN Date : Checking RDAP...")

        worker = WhoisWorker(ip_addr, request_id, self)
        worker.result_ready.connect(self.on_whois_result)
        self._track_worker(worker)

        self.whois_worker = worker
        worker.start()

    def on_whois_result(self, whois_info: dict) -> None:
        if whois_info.get("request_id") != self.whois_request_id:
            return
        if whois_info.get("ip_addr") != self.current_ip_addr:
            return

        self.target_owner_label.setText(f" - IP Owner : {whois_info['asn_description']}")
        self.ip_version_dat.setText(f" - IP version : {whois_info['ip_version']}")
        self.asn_info_label.setText(f" - ASN Registry : {whois_info['asn_registry']}")
        self.asn_cidr_dat.setText(f" - ASN CIDR : {whois_info['asn_cidr']}")
        self.asn_date.setText(f" - ASN Date : {whois_info['asn_date']}")

    # -------------------------------------------------------------------------
    # KML / external open
    # -------------------------------------------------------------------------

    def write_kml_file(self, lat, lon) -> None:
        try:
            kml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
    <Placemark>
        <name>Target Location</name>
        <Point>
            <coordinates>{lon},{lat},0</coordinates>
        </Point>
    </Placemark>
</kml>
"""
            with open(self.config.kml_file_path, "w", encoding="utf-8") as f:
                f.write(kml_content)

        except Exception:
            logging.exception("Failed to write KML file.")

    def delete_kml_file(self) -> None:
        if os.path.exists(self.config.kml_file_path):
            try:
                os.remove(self.config.kml_file_path)
            except Exception as e:
                logging.exception("Failed to delete KML file.")
                QMessageBox.warning(self, "KML File Delete Error", f"{e}")

    def online_ge_api(self) -> None:
        lat = self.earth_widget.raw_lat
        lon = self.earth_widget.raw_lon

        if lat == "" or lon == "":
            QMessageBox.warning(self, "Input Data Error", "Cannot find latitude/longitude data.")
            return

        online_ge_api_path = f"https://earth.google.com/web/@{lat},{lon},1000a,35y,0h,0t,0r"
        webbrowser.open(online_ge_api_path)

    def offline_ge_api(self) -> None:
        lat = self.earth_widget.raw_lat
        lon = self.earth_widget.raw_lon

        if lat == "" or lon == "":
            QMessageBox.warning(self, "Input Data Error", "Cannot find latitude/longitude data.")
            return

        google_earth_path = auto_detect_google_earth_path()

        if not google_earth_path:
            google_earth_path = self.prompt_google_earth_path()

        if not google_earth_path:
            QMessageBox.warning(
                self,
                "Google Earth",
                "Google Earth Pro was not found. Offline mode cannot be used."
            )
            return

        try:
            subprocess.Popen([google_earth_path, os.path.abspath(self.config.kml_file_path)])
        except Exception as e:
            logging.exception("Failed to launch Google Earth Pro.")
            QMessageBox.warning(self, "Google Earth Error", f"{e}")

    def prompt_google_earth_path(self) -> Optional[str]:
        selected_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Google Earth Pro executable",
            "",
            "Google Earth executable (googleearth.exe);;Executable (*.exe);;All files (*.*)",
        )

        if not selected_path:
            return None

        if not is_valid_google_earth_path(selected_path):
            QMessageBox.warning(
                self,
                "Google Earth",
                "The selected file is not a valid googleearth.exe file."
            )
            return None

        selected_path = os.path.abspath(selected_path)
        save_google_earth_path(selected_path)

        return selected_path


# =============================================================================
# Entrypoint
# =============================================================================

def main() -> None:
    setup_logging()

    if os.name == "nt":
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
        except Exception:
            logging.exception("Failed to set Windows AppUserModelID.")

    geo_db_path = get_geo_db_file_path()
    ensure_geodb_exists_or_exit(geo_db_path)

    try:
        geoip_reader = pygeoip.GeoIP(geo_db_path)
    except Exception:
        logging.exception("Failed to open GeoIP database.")
        sys.exit(1)

    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon(resource_path("resource/AOI_icon.ico")))

    vt_api_key = load_or_prompt_vt_api_key()

    config = AppConfig(
        vt_api_key=vt_api_key,
        geo_db_path=geo_db_path,
        kml_file_path=os.path.join(tempfile.gettempdir(), "target_geo_location.kml"),
        software_version=SOFTWARE_VERSION,
        geodb_version=GEODB_VERSION,
    )

    window = MainWindow(config, geoip_reader)
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
