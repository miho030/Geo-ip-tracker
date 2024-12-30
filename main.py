"""
* author : github.com/miho030
* repo : https://github.com/miho030/OpenipTr4ck3r
"""

import os, sys, re, pygeoip, webbrowser
from PyQt5.QtWidgets import QApplication, QMainWindow, QOpenGLWidget, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QColor, QPalette, QPixmap, QBrush
from OpenGL.GL import *
from OpenGL.GLU import *
from PIL import Image
from ipwhois import IPWhois


def resource_attr(file_path):
    if hasattr(sys, '_MEIPASS'): # pyinstaller 배포 환경에서 resource 파일들의 절대경로
        return os.path.join(sys._MEIPASS, file_path)
    return os.path.join(os.path.abspath("."), file_path)

db_file_path = resource_attr('resource/GeoLiteCity.dat')
gi = pygeoip.GeoIP(db_file_path)
kml_file = "./target_geo_location.kml"
sfVersion = "v0.1.0"
geodbVersion = "v0.0.1"


class EarthWidget(QOpenGLWidget):
    def __init__(self, parent=None):
        super(EarthWidget, self).__init__(parent)
        self.rotation = 0
        self.rotation_x = 0
        self.rotation_y = 0
        self.last_mouse_x = 0
        self.last_mouse_y = 0
        self.zoom_level = -5.0
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_rotation)
        self.timer.start(20)

        self.raw_lat = ""
        self.raw_lon = ""
        self.online_ge_api_path = ""
        self.offline_ge_api_path = ""

    def initializeGL(self):
        glEnable(GL_DEPTH_TEST)
        glEnable(GL_TEXTURE_2D)
        self.texture = glGenTextures(1)
        glBindTexture(GL_TEXTURE_2D, self.texture)
        self.load_texture(resource_attr('resource/earth_texture.jpg'))

    def load_texture(self, texture_path):
        image = Image.open(texture_path)
        image = image.transpose(Image.FLIP_TOP_BOTTOM)
        img_data = image.convert("RGB").tobytes()
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, image.width, image.height, 0, GL_RGB, GL_UNSIGNED_BYTE, img_data)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR)
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR)

    def update_rotation(self):
        self.rotation = (self.rotation + 0.5) % 360
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
        quadric = gluNewQuadric()
        gluQuadricTexture(quadric, GL_TRUE)
        gluSphere(quadric, 1.0, 50, 50)
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
        self.update()


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.setWindowTitle("Geo IP Addr Tracker - github.com/miho030")
        self.setGeometry(100, 100, 1200, 600)
        main_widget = QWidget(self)
        self.setCentralWidget(main_widget)
        earth_layout = QVBoxLayout(main_widget)
        earth_layout.setContentsMargins(0, 0, 0, 0)
        self.earth_widget = EarthWidget(self)
        earth_layout.addWidget(self.earth_widget)

        ### 좌측, 우측 오버레이 위젯 생성 ###
        self.left_overlay = QWidget(self)
        self.left_overlay.setGeometry(0, 0, 200, self.height())
        self.left_overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.left_overlay.raise_()

        self.right_overlay = QWidget(self)
        self.right_overlay.setGeometry(self.width() - 200, 0, 200, self.height())
        self.right_overlay.setAttribute(Qt.WA_TransparentForMouseEvents, False)
        self.right_overlay.raise_()


        ### 좌측, 우측 레이아웃 생성 및 설정 ###
        left_layout = QVBoxLayout(self.left_overlay)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        right_layout = QVBoxLayout(self.right_overlay)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)


        ###  양측 레이아웃 별 내용 레이블 및 내용 선언 및 작성  ###
        self.left_spacer = QLabel(" ", self.left_overlay)
        self.right_spacer = QLabel(" ", self.right_overlay)
        self.left_spacer.setFixedHeight(60)
        self.right_spacer.setFixedHeight(50)


        ## 내용들은 조회되는 동시에 변수에 저장하고, 이를 setText 하는 과정으로 수정하도록 함. f"{}" 사용X
        ## ==> 좌측 오버레이 내용
        self.geodb_title = QLabel("* GeoDB info", self.left_overlay)
        self.geodb_status = QLabel(" - GeoDB Status : No data\n - GeoDB Version : No data", self.left_overlay)
        self.sfInfo = QLabel("* Software Info", self.left_overlay)
        self.sfVersion_info = QLabel(f" - Software version : {sfVersion}", self.left_overlay)
        self.geodb_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold;")
        self.geodb_status.setStyleSheet("color: white; font-size: 14px;")
        self.sfInfo.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold;")
        self.sfVersion_info.setStyleSheet("color: white; font-size: 14px;")

        ## ==> 좌측 중간 네트워크 정보 내용
        self.ip_detail_title = QLabel("* Target IP details", self.left_overlay)
        self.ipAddr_label = QLabel(" - IP Address : No data", self.left_overlay)
        self.domain_info_label = QLabel(" - Domain : No data", self.left_overlay)
        self.target_owner_label = QLabel(" - IP Owner : No data", self.left_overlay)
        self.ip_version_dat = QLabel(" - IP version : No data", self.left_overlay)
        self.ip_phone_dat = QLabel(" - Phone : No data", self.left_overlay)
        self.ip_email_dat = QLabel(" - Email : No data", self.left_overlay)

        self.ip_detail_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold;")
        self.ipAddr_label.setStyleSheet("color: white; font-size: 14px;")
        self.domain_info_label.setStyleSheet("color: white; font-size: 14px;")
        self.target_owner_label.setStyleSheet("color: white; font-size: 14px;")
        self.ip_version_dat.setStyleSheet("color: white; font-size: 14px;")
        self.ip_phone_dat.setStyleSheet("color: white; font-size: 14px;")
        self.ip_email_dat.setStyleSheet("color: white; font-size: 14px;")

        ## ==> 좌측 하단 내용
        self.network_detail_title = QLabel("* Target network details", self.left_overlay)
        self.asn_info_label = QLabel(" - ASN registry: No data", self.left_overlay)
        self.asn_cidr_dat = QLabel(" - ASN cidr : No data", self.left_overlay)
        self.asn_date = QLabel(" - ASN date : No data", self.left_overlay)
        self.network_type = QLabel(" - Network type : No data", self.left_overlay)

        self.malicious_title = QLabel("* MALICIOUS ?", self.left_overlay)
        self.target_ip_malicious_level = QLabel(" - status : No data", self.left_overlay)
        self.target_source = QLabel(" - source : No data", self.left_overlay)

        self.network_detail_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold;")
        self.asn_info_label.setStyleSheet("color: white; font-size: 14px;")
        self.asn_cidr_dat.setStyleSheet("color: white; font-size: 14px;")
        self.asn_date.setStyleSheet("color: white; font-size: 14px;")
        self.network_type.setStyleSheet("color: white; font-size: 14px;")
        self.malicious_title.setStyleSheet("color: red; font-size: 16px; font-weight: bold;")
        self.target_ip_malicious_level.setStyleSheet("color: grey; font-size: 14px;")
        self.target_source.setStyleSheet("color: grey; font-size: 14px;")


        ### 우측 레이아웃 ###
        self.ip_input_title = QLabel("Enter Target IP address", self.right_overlay)
        self.ip_input_title.setStyleSheet("color: yellow; font-size: 15px; font-weight: bold;")
        self.ip_input = QLineEdit(self.right_overlay)
        self.ip_input.setPlaceholderText("Enter IP address")
        self.ip_input_confirm_button = QPushButton("Confirm", self.right_overlay)
        self.ip_input_confirm_button.clicked.connect(self.check_ip_address)


        ## ==> 우측 중간
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

        self.geo_title.setStyleSheet("color: yellow; font-size: 16px; font-weight: bold;")
        self.geo_country.setStyleSheet("color: white; font-size: 14px;")
        self.geo_timezone.setStyleSheet("color: white; font-size: 14px;")
        self.geo_city.setStyleSheet("color: white; font-size: 14px;")
        self.geo_postal.setStyleSheet("color: white; font-size: 14px;")
        self.geo_lat.setStyleSheet("color: white; font-size: 14px;")
        self.geo_long.setStyleSheet("color: white; font-size: 14px;")
        self.geo_lang.setStyleSheet("color: white; font-size: 14px;")
        self.geo_currency.setStyleSheet("color: white; font-size: 14px;")
        self.geo_region_code.setStyleSheet("color: white; font-size: 14px;")
        self.geo_region_num.setStyleSheet("color: white; font-size: 14px;")

        self.btn_offline_ge = QPushButton("[Off-line mode] Check locate", self.right_overlay)
        self.btn_online_ge = QPushButton("[On-line mode] Check locate", self.right_overlay)
        self.btn_offline_ge.clicked.connect(self.offline_ge_api)
        self.btn_online_ge.clicked.connect(self.online_ge_api)


        ### Qlabel간 간격 맞춤 ###
        ## ==> 좌측 오버레이
        self.geodb_title.setFixedHeight(20)
        self.geodb_status.setFixedHeight(40)
        self.sfInfo.setFixedHeight(20)
        self.sfVersion_info.setFixedHeight(20)

        self.ip_detail_title.setFixedHeight(20)
        self.ipAddr_label.setFixedHeight(20)
        self.domain_info_label.setFixedHeight(20)
        self.target_owner_label.setFixedHeight(20)
        self.ip_version_dat.setFixedHeight(20)
        self.ip_phone_dat.setFixedHeight(20)
        self.ip_email_dat.setFixedHeight(20)

        self.network_detail_title.setFixedHeight(20)
        self.asn_info_label.setFixedHeight(20)
        self.asn_cidr_dat.setFixedHeight(20)
        self.asn_date.setFixedHeight(20)
        self.network_type.setFixedHeight(20)

        self.malicious_title.setFixedHeight(20)
        self.target_ip_malicious_level.setFixedHeight(20)
        self.target_source.setFixedHeight(20)

        ## ==> 우측 오버레이
        self.ip_input_title.setFixedHeight(20)

        self.geo_title.setFixedHeight(50)
        self.geo_country.setFixedHeight(20)
        self.geo_timezone.setFixedHeight(20)
        self.geo_city.setFixedHeight(20)
        self.geo_lat.setFixedHeight(20)
        self.geo_long.setFixedHeight(20)
        self.geo_lang.setFixedHeight(20)
        self.geo_postal.setFixedHeight(20)
        self.geo_currency.setFixedHeight(20)
        self.geo_region_code.setFixedHeight(20)
        self.geo_region_num.setFixedHeight(20)


        ### 좌측, 우측 오버레이 배경색상 지정 ###
        self.set_overlay_background(self.left_overlay)
        self.set_overlay_background(self.right_overlay)


        # 좌측 상단
        left_layout.addWidget(self.geodb_title)
        left_layout.addWidget(self.geodb_status)
        left_layout.addWidget(self.left_spacer)
        left_layout.addWidget(self.sfInfo)
        left_layout.addWidget(self.sfVersion_info)
        left_layout.addWidget(self.left_spacer)

        # 좌측 중간
        left_layout.addWidget(self.ip_detail_title)
        left_layout.addWidget(self.ipAddr_label)
        left_layout.addWidget(self.domain_info_label)
        left_layout.addWidget(self.target_owner_label)
        left_layout.addWidget(self.ip_version_dat)
        left_layout.addWidget(self.ip_phone_dat)
        left_layout.addWidget(self.ip_email_dat)

        # 좌측 하단
        left_layout.addWidget(self.network_detail_title)
        left_layout.addWidget(self.asn_info_label)
        left_layout.addWidget(self.asn_cidr_dat)
        left_layout.addWidget(self.asn_date)
        left_layout.addWidget(self.network_type)

        left_layout.addWidget(self.malicious_title)
        left_layout.addWidget(self.target_ip_malicious_level)
        left_layout.addWidget(self.target_source)


        ## 우측 상단
        right_layout.addWidget(self.ip_input_title)
        right_layout.addWidget(self.ip_input)
        right_layout.addWidget(self.ip_input_confirm_button)

        ## 우측 중간
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

        ## 우측 하단
        right_layout.addWidget(self.btn_online_ge)
        right_layout.addWidget(self.btn_offline_ge)

        self.check_db_file()
        self.h_geo = pygeoip.GeoIP(db_file_path)


    def set_overlay_background(self, overlay_widget):
        overlay_widget.setAutoFillBackground(True)
        palette = overlay_widget.palette()
        palette.setColor(QPalette.Window, QColor(0, 0, 0, 100))
        overlay_widget.setPalette(palette)

    def resizeEvent(self, event):
        self.left_overlay.setGeometry(0, 0, 200, self.height())
        self.right_overlay.setGeometry(self.width() - 200, 0, 200, self.height())
        super(MainWindow, self).resizeEvent(event)

    def check_db_file(self):
        if not os.path.exists(db_file_path):
            QMessageBox.warning(self, "DB Not Found", "The GeoDB file does not exist.")
            self.geodb_status.setText(f" - GeoDB Status : Inactivate\n - GeoDB Version : No data")
        else:
            self.geodb_status.setText(f" - GeoDB Status : Activate\n - GeoDB Version : {geodbVersion}")

    def trace_ip_addr_info(self, strIpAddr):
        rec = gi.record_by_name(strIpAddr)

        country = rec['country_name']
        continent = rec['continent']

        total_country = str(country) + f"({str(continent)})"
        time = rec['time_zone']
        city = rec['city']
        language = rec['country_code']
        postal_code = rec['postal_code']
        region_code = rec['country_code3']
        region_num = rec['area_code']
        lat = rec['latitude']
        lon = rec['longitude']

        self.raw_lat = lat
        self.raw_lon = lon

        self.geo_country.setText(f" - country : {total_country}")
        self.geo_city.setText(f" - city : {city}")
        self.geo_timezone.setText(f" - Timezone : {time}")
        self.geo_lat.setText(f" - Latitude : {lat}")
        self.geo_long.setText(f" - Longitude : {lon}")
        self.geo_postal.setText(f' - Postal code :  {postal_code}')
        self.geo_lang.setText(f" - Language : {language}")
        #self.geo_currency.setText(f" - Currency : {currency}")
        self.geo_region_code.setText(f" - Region code : {region_code}")
        self.geo_region_num.setText(f" - Region number : {region_num}")

        ## ==> ip 정보, network 정보 가져오기
        whois_obj = IPWhois(strIpAddr)
        whois_res = whois_obj.lookup_rdap()

        asn_description = whois_res.get('asn_description')
        ip_version_dat = whois_res.get('network', {}).get('ip_version')

        asn_registry = whois_res.get('asn_registry')
        asn_cidr = whois_res.get('asn_cidr')
        asn_date = whois_res.get('asn_date')

        self.target_owner_label.setText(f" - IP Owner : {asn_description}")
        self.ip_version_dat.setText(f" - IP version : {ip_version_dat}")

        self.asn_info_label.setText(f" - ASN Registry : {asn_registry}")
        self.asn_cidr_dat.setText(f" - ASN cidr : {asn_cidr}")
        self.asn_date.setText(f" - ASN Date : {asn_date}")

        if region_code == "USA":
            self.geo_currency.setText(" - Currency : USD $")
        elif region_code == "KOR":
            self.geo_currency.setText(" - Currency : KWR '\'")
        elif region_code == "JPN":
            self.geo_currency.setText(" - Currency : JPY ¥")
        elif region_code == "CHN":
            self.geo_currency.setText(" - Currency : CNY ¥")
        elif region_code == "TPE":
            self.geo_country.setText(" - Currency :  TWD $")
        elif region_code == "UKR":
            self.geo_currency.setText(" - Currency :  UAH ₴")
        elif region_code == "RUS":
            self.geo_currency.setText(" - Currency :  RUS ₽")

        # kml 파일은 경도, 위도 순으로 작성되어야함;;;;
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


    def online_ge_api(self):
        if self.raw_lat == "":
            QMessageBox.warning(self, "Input Data Error", "Cannot find latitude/longitude data.")
        else:
            online_ge_api_path = f"https://earth.google.com/web/@{self.raw_lat},{self.raw_lon},1000a,35y,0h,0t,0r"
            webbrowser.open(online_ge_api_path)

    def offline_ge_api(self):
        if self.raw_lat == "":
            QMessageBox.warning(self, "Input Data Error", "Cannot find latitude/longitude data.")
        else:
            google_earth_path = r'C:\Program Files\Google\Google Earth Pro\client\googleearth.exe'
            if not os.path.exists(google_earth_path):
                QMessageBox.warning(self, "Input Data Error", "Cannot find earth.")
            else:
                offline_ge_api_path = f'"{google_earth_path}" {os.path.abspath(kml_file)}'
                print(offline_ge_api_path)
                os.system(offline_ge_api_path)

    def check_ip_address(self):
        input_ip_data = self.ip_input.text()
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_ip_data):
            octets = input_ip_data.split('.')
            if all(0 <= int(octet) <= 255 for octet in octets):
                #QMessageBox.information(self, "Found trace info!", f"Successfully found info: {input_ip_data}")
                self.ipAddr_label.setText(f" - IP Address : {input_ip_data}")
                self.trace_ip_addr_info(input_ip_data)
            else:
                QMessageBox.warning(self, "IP Validation", "Invalid IP address format.")
        else:
            QMessageBox.warning(self, "IP Validation", "Invalid IP address format.")

    def closeEvent(self, event):
        self.delete_kml_file()
        event.accept()

    def delete_kml_file(self):
        if os.path.exists(kml_file):
            try:
                os.remove(kml_file)
            except Exception as e:
                QMessageBox.warning(self, "KML File Delete Error", f"{e}")
        else:
            pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
