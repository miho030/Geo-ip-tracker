import os
import sys
import re
import json
import pygeoip
import webbrowser
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QOpenGLWidget, QWidget, QVBoxLayout,
    QLabel, QLineEdit, QPushButton, QMessageBox, QHBoxLayout
)
from PyQt5.QtCore import Qt, QTimer, QPoint, QThread, pyqtSignal
from OpenGL.GL import *
from OpenGL.GLU import *
from PIL import Image
from ipwhois import IPWhois


VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"


def resource_attr(file_path):
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, file_path)
    return os.path.join(os.path.abspath("."), file_path)


db_file_path = resource_attr("resource/GeoLiteCity.dat")
gi = pygeoip.GeoIP(db_file_path)
kml_file = "./target_geo_location.kml"
sfVersion = "v0.1.0"
geodbVersion = "v0.0.1"


class VirusTotalWorker(QThread):
    result_ready = pyqtSignal(dict)

    def __init__(self, ip_addr, parent=None):
        super().__init__(parent)
        self.ip_addr = ip_addr

    def format_vt_date(self, ts):
        if not ts:
            return "No data"
        try:
            return datetime.utcfromtimestamp(int(ts)).strftime("%Y.%m.%d")
        except Exception:
            return "No data"

    def run(self):
        if not VT_API_KEY or VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY":
            self.result_ready.emit({
                "status_text": "No API key",
                "detect_name": "No data",
                "recent_activity": "No data"
            })
            return

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{self.ip_addr}"
        req = Request(url, headers={
            "x-apikey": VT_API_KEY,
            "accept": "application/json"
        })

        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except HTTPError as e:
            if e.code == 401:
                self.result_ready.emit({
                    "status_text": "Unauthorized",
                    "detect_name": "Invalid API key",
                    "recent_activity": "No data"
                })
                return
            if e.code == 404:
                self.result_ready.emit({
                    "status_text": "0/0 (VirusTotal)",
                    "detect_name": "No data",
                    "recent_activity": "No data"
                })
                return
            if e.code == 429:
                self.result_ready.emit({
                    "status_text": "Rate limited",
                    "detect_name": "Try again later",
                    "recent_activity": "No data"
                })
                return
            self.result_ready.emit({
                "status_text": "Error",
                "detect_name": f"HTTP {e.code}",
                "recent_activity": "No data"
            })
            return
        except URLError:
            self.result_ready.emit({
                "status_text": "Network error",
                "detect_name": "No data",
                "recent_activity": "No data"
            })
            return
        except Exception:
            self.result_ready.emit({
                "status_text": "Lookup failed",
                "detect_name": "No data",
                "recent_activity": "No data"
            })
            return

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
        for _, result_obj in results.items():
            category = str(result_obj.get("category", "")).lower()
            result_name = result_obj.get("result")
            if category in ("malicious", "suspicious") and result_name:
                detect_name = str(result_name)
                break

        recent_ts = attributes.get("last_analysis_date") or attributes.get("last_modification_date")
        recent_activity = self.format_vt_date(recent_ts)

        self.result_ready.emit({
            "status_text": f"{detected}/{total} (VirusTotal)",
            "detect_name": detect_name,
            "recent_activity": recent_activity
        })


class EarthWidget(QOpenGLWidget):
    def __init__(self, parent=None):
        super(EarthWidget, self).__init__(parent)
        self.rotation = 110
        self.rotation_x = -75
        self.rotation_y = 40
        self.rotation_z = -90
        self.last_mouse_x = 0
        self.last_mouse_y = 0
        self.zoom_level = -2.8

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_rotation)
        self.timer.start(20)
        self.raw_lat = ""
        self.raw_lon = ""

    def initializeGL(self):
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_TEXTURE_2D)
        glEnable(GL_MULTISAMPLE)
        glClearColor(0.06, 0.06, 0.06, 1.0)
        self.texture = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, self.texture)
        self.load_texture(resource_attr("resource/earth_texture.jpg"))

    def load_texture(self, texture_path):
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
            img_data
        )
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR)
        glGenerateMipmap(GL_TEXTURE_2D)

    def update_rotation(self):
        self.rotation = (self.rotation + 0.2) % 360
        self.update()

    def resizeGL(self, w, h):
        glViewport(0, 0, w, h)
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        gluPerspective(45.0, w / h if h != 0 else 1, 1.0, 100.0)
        glMatrixMode(GL_MODELVIEW)

    def paintGL(self):
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()
        gluLookAt(0.0, 0.0, self.zoom_level, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0)
        glBindTexture(GL_TEXTURE_2D, self.texture)
        glRotatef(self.rotation, 0.0, 1.0, 0.0)
        glRotatef(self.rotation_x, 1.0, 0.0, 0.0)
        glRotatef(self.rotation_y, 0.0, 1.0, 0.0)
        glRotatef(self.rotation_z, 0.0, 0.0, 1.0)
        quadric = gluNewQuadric()
        gluQuadricTexture(quadric, GL_TRUE)
        gluSphere(quadric, 1.0, 100, 100)
        gluDeleteQuadric(quadric)

    def mousePressEvent(self, event):
        self.last_mouse_x = event.x()
        self.last_mouse_y = event.y()

    def mouseMoveEvent(self, event):
        dx = event.x() - self.last_mouse_x
        dy = event.y() - self.last_mouse_y
        self.rotation_x += dy * 0.5
        self.rotation_y += dx * 0.5
        self.last_mouse_x = event.x()
        self.last_mouse_y = event.y()
        self.update()

    def wheelEvent(self, event):
        delta = event.angleDelta().y() / 120
        self.zoom_level += delta * 0.5
        self.zoom_level = max(-8.0, min(-2.2, self.zoom_level))
        self.update()


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setWindowTitle("Geo IP Addr Tracker - github.com/miho030")
        self.setGeometry(100, 100, 1200, 600)
        self.drag_pos = QPoint()
        self.vt_worker = None

        main_widget = QWidget(self)
        main_widget.setStyleSheet("background-color: rgba(0, 0, 0, 140);")
        self.setCentralWidget(main_widget)

        root_layout = QVBoxLayout(main_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

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

        root_layout.addWidget(self.title_bar)

        content_widget = QWidget(self)
        content_widget.setStyleSheet("background-color: transparent;")
        root_layout.addWidget(content_widget)

        earth_layout = QVBoxLayout(content_widget)
        earth_layout.setContentsMargins(0, 0, 0, 0)
        self.earth_widget = EarthWidget(self)
        earth_layout.addWidget(self.earth_widget)

        self.left_overlay = QWidget(self)
        self.left_overlay.setGeometry(0, self.title_bar.height(), 220, self.height() - self.title_bar.height())
        self.left_overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.left_overlay.raise_()

        self.right_overlay = QWidget(self)
        self.right_overlay.setGeometry(self.width() - 220, self.title_bar.height(), 220, self.height() - self.title_bar.height())
        self.right_overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.right_overlay.raise_()

        self.title_bar.raise_()

        left_layout = QVBoxLayout(self.left_overlay)
        left_layout.setContentsMargins(10, 8, 10, 8)
        left_layout.setSpacing(2)

        right_layout = QVBoxLayout(self.right_overlay)
        right_layout.setContentsMargins(10, 8, 10, 8)
        right_layout.setSpacing(2)

        self.left_spacer = QLabel(" ", self.left_overlay)
        self.right_spacer = QLabel(" ", self.right_overlay)
        self.left_spacer.setFixedHeight(34)
        self.right_spacer.setFixedHeight(30)

        self.geodb_title = QLabel("* GeoDB info", self.left_overlay)
        self.geodb_status = QLabel(" - GeoDB Status : No data\n - GeoDB Version : No data", self.left_overlay)
        self.sfInfo = QLabel("* Software Info", self.left_overlay)
        self.sfVersion_info = QLabel(f" - Software version : {sfVersion}", self.left_overlay)

        self.geodb_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold; background: transparent;")
        self.geodb_status.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.sfInfo.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold; background: transparent;")
        self.sfVersion_info.setStyleSheet("color: white; font-size: 14px; background: transparent;")

        self.ip_detail_title = QLabel("* Target IP details", self.left_overlay)
        self.ipAddr_label = QLabel(" - IP Address : No data", self.left_overlay)
        self.domain_info_label = QLabel(" - Domain : No data", self.left_overlay)
        self.target_owner_label = QLabel(" - IP Owner : No data", self.left_overlay)
        self.ip_version_dat = QLabel(" - IP version : No data", self.left_overlay)
        self.ip_phone_dat = QLabel(" - Phone : No data", self.left_overlay)
        self.ip_email_dat = QLabel(" - Email : No data", self.left_overlay)

        self.ip_detail_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold; background: transparent;")
        self.ipAddr_label.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.domain_info_label.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.target_owner_label.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.ip_version_dat.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.ip_phone_dat.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.ip_email_dat.setStyleSheet("color: white; font-size: 14px; background: transparent;")

        self.network_detail_title = QLabel("* Target network details", self.left_overlay)
        self.asn_info_label = QLabel(" - ASN registry: No data", self.left_overlay)
        self.asn_cidr_dat = QLabel(" - ASN cidr : No data", self.left_overlay)
        self.asn_date = QLabel(" - ASN date : No data", self.left_overlay)
        self.network_type = QLabel(" - Network type : No data", self.left_overlay)

        self.malicious_title = QLabel("* Malicious?", self.left_overlay)
        self.target_ip_malicious_level = QLabel(" - status : No data", self.left_overlay)
        self.target_source = QLabel(" - detect name : No data\n - recent activity : No data", self.left_overlay)

        self.network_detail_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold; background: transparent;")
        self.asn_info_label.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.asn_cidr_dat.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.asn_date.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.network_type.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.malicious_title.setStyleSheet("color: red; font-size: 16px; font-weight: bold; background: transparent;")
        self.target_ip_malicious_level.setStyleSheet("color: lightgrey; font-size: 14px; background: transparent;")
        self.target_source.setStyleSheet("color: lightgrey; font-size: 14px; background: transparent;")

        self.ip_input_title = QLabel("Enter Target IP address", self.right_overlay)
        self.ip_input_title.setStyleSheet("color: yellow; font-size: 15px; font-weight: bold; background: transparent;")

        self.ip_input = QLineEdit(self.right_overlay)
        self.ip_input.setPlaceholderText("Enter IP address")
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
        self.ip_input_confirm_button.setStyleSheet("""
            QPushButton {
                background-color: rgb(90, 90, 90);
                color: white;
                border: 1px solid rgb(120, 120, 120);
                padding: 6px;
            }
            QPushButton:hover {
                background-color: rgb(110, 110, 110);
            }
        """)

        self.geo_title = QLabel("* Physical Location Info", self.right_overlay)
        self.geo_country = QLabel(" - Country : No data", self.right_overlay)
        self.geo_timezone = QLabel(" - Timezone : No data", self.right_overlay)
        self.geo_city = QLabel(" - City : No data", self.right_overlay)
        self.geo_postal = QLabel(" - Postal code : No data", self.right_overlay)
        self.geo_lat = QLabel(" - Latitude : No data", self.right_overlay)
        self.geo_long = QLabel(" - Longitude : No data", self.right_overlay)
        self.geo_lang = QLabel(" - Language : No data", self.right_overlay)
        self.geo_currency = QLabel(" - Currency : No data", self.right_overlay)
        self.geo_region_code = QLabel(" - Region code : No data", self.right_overlay)
        self.geo_region_num = QLabel(" - Region number : No data", self.right_overlay)

        self.geo_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold; background: transparent;")
        self.geo_country.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_timezone.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_city.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_postal.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_lat.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_long.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_lang.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_currency.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_region_code.setStyleSheet("color: white; font-size: 14px; background: transparent;")
        self.geo_region_num.setStyleSheet("color: white; font-size: 14px; background: transparent;")

        self.btn_offline_ge = QPushButton("[Off-line mode] Check locate", self.right_overlay)
        self.btn_online_ge = QPushButton("[On-line mode] Check locate", self.right_overlay)
        self.btn_offline_ge.clicked.connect(self.offline_ge_api)
        self.btn_online_ge.clicked.connect(self.online_ge_api)

        btn_style = """
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
        self.btn_offline_ge.setStyleSheet(btn_style)
        self.btn_online_ge.setStyleSheet(btn_style)

        self.geodb_title.setFixedHeight(22)
        self.geodb_status.setFixedHeight(42)
        self.sfInfo.setFixedHeight(22)
        self.sfVersion_info.setFixedHeight(22)

        self.ip_detail_title.setFixedHeight(22)
        self.ipAddr_label.setFixedHeight(22)
        self.domain_info_label.setFixedHeight(22)
        self.target_owner_label.setFixedHeight(22)
        self.ip_version_dat.setFixedHeight(22)
        self.ip_phone_dat.setFixedHeight(22)
        self.ip_email_dat.setFixedHeight(22)

        self.network_detail_title.setFixedHeight(22)
        self.asn_info_label.setFixedHeight(22)
        self.asn_cidr_dat.setFixedHeight(22)
        self.asn_date.setFixedHeight(22)
        self.network_type.setFixedHeight(22)

        self.malicious_title.setFixedHeight(22)
        self.target_ip_malicious_level.setMinimumHeight(22)
        self.target_source.setMinimumHeight(42)

        self.ip_input_title.setFixedHeight(24)

        self.geo_title.setFixedHeight(34)
        self.geo_country.setFixedHeight(22)
        self.geo_timezone.setFixedHeight(22)
        self.geo_city.setFixedHeight(22)
        self.geo_lat.setFixedHeight(22)
        self.geo_long.setFixedHeight(22)
        self.geo_lang.setFixedHeight(22)
        self.geo_postal.setFixedHeight(22)
        self.geo_currency.setFixedHeight(22)
        self.geo_region_code.setFixedHeight(22)
        self.geo_region_num.setFixedHeight(22)

        self.set_overlay_background(self.left_overlay)
        self.set_overlay_background(self.right_overlay)

        left_layout.addWidget(self.geodb_title)
        left_layout.addWidget(self.geodb_status)
        left_layout.addWidget(self.left_spacer)
        left_layout.addWidget(self.sfInfo)
        left_layout.addWidget(self.sfVersion_info)
        left_layout.addWidget(self.left_spacer)

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

        left_layout.addWidget(self.malicious_title)
        left_layout.addWidget(self.target_ip_malicious_level)
        left_layout.addWidget(self.target_source)
        left_layout.addStretch()

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
        right_layout.addWidget(self.right_spacer)

        right_layout.addWidget(self.btn_online_ge)
        right_layout.addWidget(self.btn_offline_ge)
        right_layout.addStretch()

        self.check_db_file()
        self.h_geo = pygeoip.GeoIP(db_file_path)
        self.reset_result_fields()

    def set_overlay_background(self, overlay_widget):
        overlay_widget.setStyleSheet("""
            background-color: rgb(65, 65, 65);
            border-radius: 8px;
        """)

    def resizeEvent(self, event):
        title_h = self.title_bar.height()
        panel_margin = 8
        panel_width = 220
        panel_height = self.height() - title_h - panel_margin * 2
        self.title_bar.setGeometry(0, 0, self.width(), title_h)
        self.left_overlay.setGeometry(panel_margin, title_h + panel_margin, panel_width, panel_height)
        self.right_overlay.setGeometry(self.width() - panel_width - panel_margin, title_h + panel_margin, panel_width, panel_height)
        self.title_bar.raise_()
        self.left_overlay.raise_()
        self.right_overlay.raise_()
        super(MainWindow, self).resizeEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.y() <= self.title_bar.height():
            self.drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton and not self.drag_pos.isNull():
            self.move(event.globalPos() - self.drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self.drag_pos = QPoint()
        event.accept()

    def reset_result_fields(self):
        self.earth_widget.raw_lat = ""
        self.earth_widget.raw_lon = ""
        self.ipAddr_label.setText(" - IP Address : No data")
        self.domain_info_label.setText(" - Domain : No data")
        self.target_owner_label.setText(" - IP Owner : No data")
        self.ip_version_dat.setText(" - IP version : No data")
        self.ip_phone_dat.setText(" - Phone : No data")
        self.ip_email_dat.setText(" - Admin Email : No data")
        self.asn_info_label.setText(" - ASN Registry : No data")
        self.asn_cidr_dat.setText(" - ASN cidr : No data")
        self.asn_date.setText(" - ASN Date : No data")
        self.network_type.setText(" - Network type : No data")
        self.target_ip_malicious_level.setText(" - status : No data")
        self.target_source.setText(" - detect name : No data\n - recent activity : No data")
        self.geo_country.setText(" - Country : No data")
        self.geo_timezone.setText(" - Timezone : No data")
        self.geo_city.setText(" - City : No data")
        self.geo_postal.setText(" - Postal code : No data")
        self.geo_lat.setText(" - Latitude : No data")
        self.geo_long.setText(" - Longitude : No data")
        self.geo_lang.setText(" - Language : No data")
        self.geo_currency.setText(" - Currency : No data")
        self.geo_region_code.setText(" - Region code : No data")
        self.geo_region_num.setText(" - Region number : No data")

    def check_db_file(self):
        if not os.path.exists(db_file_path):
            QMessageBox.warning(self, "DB Not Found", "The GeoDB file does not exist.")
            self.geodb_status.setText(f" - GeoDB Status : Inactivate\n - GeoDB Version : No data")
        else:
            self.geodb_status.setText(f" - GeoDB Status : Activate\n - GeoDB Version : {geodbVersion}")

    def start_virustotal_lookup(self, ip_addr):
        if self.vt_worker is not None and self.vt_worker.isRunning():
            self.vt_worker.quit()
            self.vt_worker.wait()

        self.target_ip_malicious_level.setText(" - status : Checking VirusTotal...")
        self.target_source.setText(" - detect name : No data\n - recent activity : No data")

        self.vt_worker = VirusTotalWorker(ip_addr)
        self.vt_worker.result_ready.connect(self.on_vt_result)
        self.vt_worker.start()

    def on_vt_result(self, vt_info):
        self.target_ip_malicious_level.setText(f" - status : {vt_info['status_text']}")
        self.target_source.setText(
            f" - detect name : {vt_info['detect_name']}\n - recent activity : {vt_info['recent_activity']}"
        )

    def trace_ip_addr_info(self, strIpAddr):
        self.earth_widget.raw_lat = ""
        self.earth_widget.raw_lon = ""

        try:
            rec = gi.record_by_name(strIpAddr)
        except Exception:
            rec = None

        if not rec:
            QMessageBox.information(self, "No GeoIP Data", f"No GeoIP data found for {strIpAddr}.")
            self.ipAddr_label.setText(f" - IP Address : {strIpAddr}")
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

        self.geo_country.setText(f" - Country : {total_country}")
        self.geo_city.setText(f" - City : {city}")
        self.geo_timezone.setText(f" - Timezone : {time_zone}")
        self.geo_lat.setText(f" - Latitude : {lat}")
        self.geo_long.setText(f" - Longitude : {lon}")
        self.geo_postal.setText(f" - Postal code : {postal_code}")
        self.geo_lang.setText(f" - Language : {language}")
        self.geo_region_code.setText(f" - Region code : {region_code}")
        self.geo_region_num.setText(f" - Region number : {region_num}")

        self.geo_currency.setText(" - Currency : No data")
        if region_code == "USA":
            self.geo_currency.setText(" - Currency : USD $")
        elif region_code == "KOR":
            self.geo_currency.setText(" - Currency : KRW ₩")
        elif region_code == "JPN":
            self.geo_currency.setText(" - Currency : JPY ¥")
        elif region_code == "CHN":
            self.geo_currency.setText(" - Currency : CNY ¥")
        elif region_code == "TPE":
            self.geo_currency.setText(" - Currency : TWD $")
        elif region_code == "UKR":
            self.geo_currency.setText(" - Currency : UAH ₴")
        elif region_code == "RUS":
            self.geo_currency.setText(" - Currency : RUB ₽")

        try:
            whois_obj = IPWhois(strIpAddr)
            whois_res = whois_obj.lookup_rdap()

            asn_description = whois_res.get("asn_description", "No data")
            ip_version_dat = whois_res.get("network", {}).get("ip_version", "No data")
            asn_registry = whois_res.get("asn_registry", "No data")
            asn_cidr = whois_res.get("asn_cidr", "No data")
            asn_date = whois_res.get("asn_date", "No data")

            self.target_owner_label.setText(f" - IP Owner : {asn_description}")
            self.ip_version_dat.setText(f" - IP version : {ip_version_dat}")
            self.asn_info_label.setText(f" - ASN Registry : {asn_registry}")
            self.asn_cidr_dat.setText(f" - ASN cidr : {asn_cidr}")
            self.asn_date.setText(f" - ASN Date : {asn_date}")
        except Exception:
            self.target_owner_label.setText(" - IP Owner : No data")
            self.ip_version_dat.setText(" - IP version : No data")
            self.asn_info_label.setText(" - ASN Registry : No data")
            self.asn_cidr_dat.setText(" - ASN cidr : No data")
            self.asn_date.setText(" - ASN Date : No data")

        if lat not in (None, "No data") and lon not in (None, "No data"):
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
                with open(kml_file, "w", encoding="utf-8") as f:
                    f.write(kml_content)
            except Exception:
                pass

    def online_ge_api(self):
        lat = self.earth_widget.raw_lat
        lon = self.earth_widget.raw_lon
        if lat == "" or lon == "":
            QMessageBox.warning(self, "Input Data Error", "Cannot find latitude/longitude data.")
        else:
            online_ge_api_path = f"https://earth.google.com/web/@{lat},{lon},1000a,35y,0h,0t,0r"
            webbrowser.open(online_ge_api_path)

    def offline_ge_api(self):
        lat = self.earth_widget.raw_lat
        lon = self.earth_widget.raw_lon
        if lat == "" or lon == "":
            QMessageBox.warning(self, "Input Data Error", "Cannot find latitude/longitude data.")
        else:
            google_earth_path = r"C:\Program Files\Google\Google Earth Pro\client\googleearth.exe"
            if not os.path.exists(google_earth_path):
                QMessageBox.warning(self, "Input Data Error", "Cannot find earth.")
            else:
                offline_ge_api_path = f'"{google_earth_path}" {os.path.abspath(kml_file)}'
                os.system(offline_ge_api_path)

    def check_ip_address(self):
        input_ip_data = self.ip_input.text().strip()
        self.reset_result_fields()

        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", input_ip_data):
            octets = input_ip_data.split(".")
            if all(0 <= int(octet) <= 255 for octet in octets):
                self.ipAddr_label.setText(f" - IP Address : {input_ip_data}")
                self.trace_ip_addr_info(input_ip_data)
                self.start_virustotal_lookup(input_ip_data)
            else:
                QMessageBox.warning(self, "IP Validation", "Invalid IP address format.")
        else:
            QMessageBox.warning(self, "IP Validation", "Invalid IP address format.")

    def closeEvent(self, event):
        if self.vt_worker is not None and self.vt_worker.isRunning():
            self.vt_worker.quit()
            self.vt_worker.wait()
        self.delete_kml_file()
        event.accept()

    def delete_kml_file(self):
        if os.path.exists(kml_file):
            try:
                os.remove(kml_file)
            except Exception as e:
                QMessageBox.warning(self, "KML File Delete Error", f"{e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())