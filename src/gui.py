import asyncio
import datetime
import enzyme
import xml.etree.ElementTree as ET
import functools
import hashlib
import httpx
import orjson
import plexapi
import re
import shutil
import sys
import tomllib
import traceback
import yaml
import zlib

from plexapi.exceptions import TwoFactorRequired as PlexApiTwoFactorRequired, Unauthorized as PlexApiUnauthorized
from plexapi.myplex import MyPlexAccount
from pathlib import Path
from multiprocessing import freeze_support

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QCheckBox, QComboBox, QTextEdit, QProgressBar,
    QGroupBox, QMessageBox, QInputDialog
)
from PySide6.QtCore import Qt
import PySide6.QtAsyncio as QtAsyncio

async def run_sync(func, *args, **kwargs):
    loop = kwargs.pop("loop") if "loop" in kwargs else asyncio.get_event_loop()
    executor = kwargs.pop("executor") if "executor" in kwargs else None
    return await loop.run_in_executor(executor, functools.partial(func, *args, **kwargs))

async def read_chunks(file, loop=None):
    if loop == None:
        loop = asyncio.get_event_loop()

    with file.open(mode='rb') as f:
        while chunk := await run_sync(f.read, 1024 * 1024, loop=loop):
            yield chunk

async def glob(file, pattern):
    for path in await run_sync(file.glob, pattern):
        yield path

async def async_blake2s_16(video_file, loop=None):
    if loop == None:
        loop = asyncio.get_event_loop()

    h = hashlib.blake2s()

    async for chunk in read_chunks(video_file, loop):
        await run_sync(h.update, chunk, loop=loop)

    res = (await run_sync(h.hex_digest, loop=loop))[:16]
    return res.lower()

async def async_crc32(video_file, loop=None):
    if loop == None:
        loop = asyncio.get_event_loop()

    crc_value = 0

    async for chunk in read_chunks(video_file, loop):
        crc_value = await run_sync(zlib.crc32, chunk, crc_value, loop=loop)

    res = f"{crc_value & 0xFFFFFFFF:08x}"
    return res.upper()

def bundle_file(*args):
    in_bundle = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
    local_path = Path(".", *args)

    if not local_path.exists() and in_bundle:
        return Path(sys._MEIPASS, *args)

    return local_path

class Input:
    def __init__(self, layout, label, prop, btn="", btn_connect=None, set=False, width=250):
        self.layout = QHBoxLayout()
        self.label = QLabel(label)

        font_metrics = self.label.fontMetrics()
        label_width = font_metrics.boundingRect(label).width()
        if label_width > width:
            width = label_width

        self.label.setFixedWidth(width + 10)
        self.layout.addWidget(self.label)

        self.prop = prop
        self.layout.addWidget(self.prop, stretch=1)

        if btn != "":
            self.btn = QPushButton(btn)
            if btn_connect != None:
                self.btn.clicked.connect(btn_connect)

            self.layout.addWidget(self.btn)
        else:
            self.btn = None

        layout.addLayout(self.layout)

    def setVisible(self, is_visible):
        self.label.setVisible(is_visible)
        self.prop.setVisible(is_visible)
        if self.btn != None:
            self.btn.setVisible(is_visible)

class OnePaceOrganizer(QWidget):
    def __init__(self):
        super().__init__()

        self.tvshow = {}
        self.episodes = {}
        self.seasons = {}

        self.plex_width = 125
        self.version = "?"
        self.spacer = "------------------------------------------------------------------"
        self.config_file = Path(".", "config.json")

        self.posters_path = bundle_file("data", "posters").resolve()
        if not self.posters_path.is_dir():
            self.posters_path = bundle_file("posters").resolve()

        self.input_path = ""
        self.output_path = ""

        self.plexapi_account = None
        self.plexapi_server = None
        self.plex_config_enabled = False
        self.plex_config_url = "http://127.0.0.1:32400"

        self.plex_config_servers = {}
        self.plex_config_server_id = ""

        self.plex_config_libraries = {}
        self.plex_config_library_key = None

        self.plex_config_shows = {}
        self.plex_config_show_guid = None

        self.plex_config_use_token = False
        self.plex_config_auth_token = ""
        self.plex_config_username = ""
        self.plex_config_password = ""
        self.plex_config_remember = True

        self.load_config()

        self.setWindowTitle(f"One Pace Organizer v{self.version} - github.com/ladyisatis/OnePaceOrganizer")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def load_config(self):
        toml_path = bundle_file("pyproject.toml")
        if toml_path.exists():
            with toml_path.open(mode="rb") as f:
                self.version = tomllib.load(f)["project"]["version"]

        if self.config_file.exists():
            config = orjson.loads(self.config_file.read_bytes())

            self.input_path = Path(config["path_to_eps"]).resolve()
            self.output_path = Path(config["episodes"]).resolve()

            self.plex_config_enabled = config["plex"]["enabled"]
            self.plex_config_url = config["plex"]["url"]

            self.plex_config_servers = config["plex"]["servers"]
            for server_id, item in self.plex_config_servers.items():
                if item["selected"]:
                    self.plex_config_server_id = server_id
                    break

            self.plex_config_libraries = config["plex"]["libraries"]
            for library_key, item in self.plex_config_libraries.items():
                if item["selected"]:
                    self.plex_config_library_key = library_key
                    break

            self.plex_config_shows = config["plex"]["shows"]
            for show_guid, item in self.plex_config_shows.items():
                if item["selected"]:
                    self.plex_config_show_guid = show_guid
                    break

            self.plex_config_use_token = config["plex"]["use_token"]
            self.plex_config_auth_token = config["plex"]["token"]
            self.plex_config_username = config["plex"]["username"]
            self.plex_config_password = config["plex"]["password"]
            self.plex_config_remember = config["plex"]["remember"]

    def save_config(self):
        self.config_file.write_bytes(orjson.dumps({
            "path_to_eps": str(self.input_path),
            "episodes": str(self.output_path),
            "plex": {
                "enabled": self.plex_config_enabled,
                "url": self.plex_config_url,

                "servers": self.plex_config_servers,
                "libraries": self.plex_config_libraries,
                "shows": self.plex_config_shows,

                "use_token": self.plex_config_use_token,
                "token": self.plex_config_auth_token,
                "username": self.plex_config_username,
                "password": self.plex_config_password,
                "remember": self.plex_config_remember
            }
        }, option=orjson.OPT_NON_STR_KEYS ))

    def setup_ui(self):
        layout = QVBoxLayout()

        self.input = Input(
            layout, 
            "Directory of unsorted One Pace .mkv/.mp4 files:",
            QLineEdit(),
            btn="Browse...",
            btn_connect=self.browse_input_folder
        )
        self.input.prop.setText(str(self.input_path))
        self.input.prop.setPlaceholderText(str(Path(".", "in").resolve()))

        self.output = Input(
            layout,
            "Move the sorted/renamed files to:",
            QLineEdit(),
            btn="Browse...",
            btn_connect=self.browse_output_folder
        )
        self.output.prop.setText(str(self.output_path))
        self.output.prop.setPlaceholderText(str(Path("/", "path", "to", "plex_or_jellyfin", "Anime", "One Pace").resolve()))

        self.method = Input(layout, "I'm watching via...", QComboBox())
        self.method.prop.addItems(["Jellyfin", "Plex"])
        self.method.prop.setCurrentIndex(1 if self.plex_config_enabled else 0)
        self.method.prop.currentTextChanged.connect(self.set_method)

        self.plex_group = QGroupBox("Plex")
        self.plex_group_layout = QVBoxLayout()

        self.plex_method = Input(self.plex_group_layout, "Login Method:", QComboBox(), width=self.plex_width)
        self.plex_method.prop.addItems(["Username and Password", "Authentication Token"])
        self.plex_method.prop.currentTextChanged.connect(self.switch_plex_method)
        self.plex_method.prop.setCurrentText("Authentication Token" if self.plex_config_use_token else "Username and Password")

        self.plex_token = Input(self.plex_group_layout, "Authentication Token:", QLineEdit(), width=self.plex_width)
        self.plex_token.prop.setEchoMode(QLineEdit.EchoMode.Password)
        self.plex_token.prop.setText(self.plex_config_auth_token)
        self.plex_token.setVisible(self.plex_config_use_token == True)

        self.plex_username = Input(self.plex_group_layout, "Username:", QLineEdit(), width=self.plex_width)
        self.plex_username.prop.setText(self.plex_config_username)
        self.plex_username.setVisible(self.plex_config_use_token == False)

        self.plex_password = Input(self.plex_group_layout, "Password:", QLineEdit(), width=self.plex_width)
        self.plex_password.prop.setEchoMode(QLineEdit.EchoMode.Password)
        self.plex_password.prop.setText(self.plex_config_password)
        self.plex_password.setVisible(self.plex_config_use_token == False)

        self.plex_remember_login = Input(
            self.plex_group_layout, 
            " ", 
            QCheckBox("Remember"), 
            btn="Login", 
            btn_connect=lambda: asyncio.create_task(self.plex_login()), 
            width=self.plex_width
        )
        self.plex_remember_login.prop.setChecked(self.plex_config_remember)

        self.plex_server = Input(self.plex_group_layout, "Plex Server:", QComboBox(), width=self.plex_width)
        self.plex_server.prop.addItem("")

        for server_id, item in self.plex_config_servers.items():
            self.plex_server.prop.addItem(item["name"])
            if server_id == self.plex_config_server_id:
                self.plex_server.prop.setCurrentText(item["name"])

        self.plex_server.prop.currentTextChanged.connect(lambda: asyncio.create_task(self.select_plex_server()))
        self.plex_server.setVisible(self.plex_config_enabled == True and len(self.plex_config_servers) > 0)

        self.plex_library = Input(self.plex_group_layout, "Library:", QComboBox(), width=self.plex_width)
        self.plex_library.prop.addItem("")

        for library_key, item in self.plex_config_libraries.items():
            self.plex_library.prop.addItem(item["title"])
            if library_key == self.plex_config_library_key:
                self.plex_library.prop.setCurrentText(item["title"])

        self.plex_library.prop.currentTextChanged.connect(lambda: asyncio.create_task(self.select_plex_library()))
        self.plex_library.setVisible(self.plex_config_library_key != "" and len(self.plex_config_libraries) > 0)

        self.plex_show = Input(self.plex_group_layout, "Show:", QComboBox(), width=self.plex_width)
        self.plex_show.prop.addItem("")

        for show_guid, item in self.plex_config_shows.items():
            self.plex_show.prop.addItem(item["title"])
            if show_guid == self.plex_config_show_guid:
                self.plex_show.prop.setCurrentText(item["title"])

        self.plex_show.prop.currentTextChanged.connect(lambda: asyncio.create_task(self.select_plex_show()))
        self.plex_show.setVisible(self.plex_config_show_guid != "" and len(self.plex_config_shows) > 0)

        self.plex_group.setLayout(self.plex_group_layout)
        layout.addWidget(self.plex_group)
        
        if not self.plex_config_enabled:
            self.plex_group.hide()

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(lambda: asyncio.create_task(self.start_process()))
        self.start_button.setEnabled(self.plex_config_enabled == False)
        layout.addWidget(self.start_button)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        layout.addWidget(self.log_output, stretch=1)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

        if self.plex_config_enabled and self.plex_config_remember and (self.plex_config_use_token and self.plex_config_auth_token != "") or (not self.plex_config_use_token and self.plex_config_auth_token != "" and self.plex_config_username != "" and self.plex_config_password != ""):
            try:
                self.plexapi_account = MyPlexAccount(token=self.plex_config_auth_token)

                resources = self.plexapi_account.resources()
                for resource in resources:
                    if resource.clientIdentifier == self.plex_config_server_id:
                        self.plexapi_server = resource.connect()
                        break

                self.plex_token.prop.setVisible(False)
                self.plex_username.setVisible(False)
                self.plex_password.setVisible(False)
                self.plex_remember_login.prop.setVisible(False)
                self.plex_remember_login.btn.setText("Disconnect")
                self.plex_method.setVisible(False)
                self.start_button.setEnabled(True)
            except:
                self.plex_token.prop.setVisible(True)
                self.plex_username.setVisible(True)
                self.plex_password.setVisible(True)
                self.plex_remember_login.prop.setVisible(True)
                self.plex_remember_login.btn.setText("Login")
                self.plex_method.setVisible(True)

    def browse_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Input Folder")
        if folder:
            self.input.prop.setText(folder)
            self.input_path = Path(folder).resolve()

    def browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if folder:
            self.output.prop.setText(folder)
            self.output_path = Path(folder).resolve()

    def set_method(self, text):
        self.plex_config_enabled = text == "Plex"
        self.plex_group.setVisible(self.plex_config_enabled)

    def switch_plex_method(self, text):
        self.plex_config_use_token = text == "Authentication Token"

        self.plex_token.setVisible(self.plex_config_use_token)
        self.plex_username.setVisible(self.plex_config_use_token == False)
        self.plex_password.setVisible(self.plex_config_use_token == False)

    async def plex_login(self):
        if self.plexapi_account != None:
            self.plexapi_account = None

            if not self.plex_config_use_token and self.plex_config_auth_token != "":
                self.plex_config_auth_token = ""

            self.plex_config_servers = {}
            self.plex_config_server_id = ""

            self.plex_config_libraries = {}
            self.plex_config_library_key = ""

            self.plex_config_shows = {}
            self.plex_config_show_guid = ""

            self.plex_method.setVisible(True)
            self.plex_token.setVisible(self.plex_config_use_token)
            self.plex_username.setVisible(self.plex_config_use_token == False)
            self.plex_password.setVisible(self.plex_config_use_token == False)
            self.plex_remember_login.btn.setEnabled(True)
            self.plex_remember_login.prop.setVisible(True)
            self.plex_remember_login.btn.setText("Login")
            self.plex_server.setVisible(False)
            self.plex_library.setVisible(False)
            self.plex_show.setVisible(False)
            self.start_button.setEnabled(False)
            return

        use_token = self.plex_method.prop.currentText() == "Authentication Token"
        remember = self.plex_remember_login.prop.checkState() == Qt.Checked

        if use_token:
            self.plex_remember_login.btn.setEnabled(False)
            self.plex_token.prop.setEnabled(False)

            try:
                self.plexapi_account = await run_sync(MyPlexAccount, token=token)

            except PlexApiUnauthorized:
                QMessageBox.warning(None, f"One Pace Organizer v{self.version}", "Invalid Plex account token, please try again.")
                self.plex_token.prop.setEnabled(True)
                self.plex_remember_login.btn.setEnabled(True)
                return

            except:
                self.log_output.append(self.spacer)
                self.log_output.append(traceback.format_exc())

        else:
            self.plex_remember_login.btn.setEnabled(False)
            self.plex_username.prop.setEnabled(False)
            self.plex_password.prop.setEnabled(False)

            try:
                self.plexapi_account = await run_sync(
                    MyPlexAccount,
                    username=self.plex_username.prop.text(),
                    password=self.plex_password.prop.text(),
                    remember=remember
                )
            except PlexApiTwoFactorRequired:
                unauthorized = True

                while unauthorized:
                    code, ok = QInputDialog.getText(
                        None,
                        f"One Pace Organizer v{self.version}",
                        "Enter the 2-Factor Authorization Code for your Plex Account:"
                    )

                    if not ok or code == "":
                        self.plex_remember_login.btn.setEnabled(True)
                        self.plex_username.prop.setEnabled(True)
                        self.plex_password.prop.setEnabled(True)
                        return

                    try:
                        self.plexapi_account = await run_sync(
                            MyPlexAccount,
                            username=self.plex_username.prop.text(),
                            password=self.plex_password.prop.text(),
                            remember=remember,
                            code=int(code)
                        )
                        unauthorized = False
                    except:
                        QMessageBox.warning(None, f"One Pace Organizer v{self.version}", "Invalid 2-Factor Auth code, please try again.")

            except PlexApiUnauthorized:
                QMessageBox.warning(None, f"One Pace Organizer v{self.version}", "Invalid username or password, please try again.")
                self.plex_remember_login.btn.setEnabled(True)
                self.plex_username.prop.setEnabled(True)
                self.plex_password.prop.setEnabled(True)
                return

            except:
                self.log_output.append(self.spacer)
                self.log_output.append(traceback.format_exc())

            self.plex_config_remember = remember

        if remember:
            self.plex_config_auth_token = self.plex_token.prop.text() if use_token else self.plexapi_account.authenticationToken
            self.plex_config_username = self.plex_username.prop.text()
            self.plex_config_password = self.plex_password.prop.text()
            self.plex_config_remember = True

        resources = await run_sync(self.plexapi_account.resources)

        self.plex_method.setVisible(False)
        self.plex_token.setVisible(False)
        self.plex_username.setVisible(False)
        self.plex_password.setVisible(False)
        self.plex_remember_login.prop.setVisible(False)
        self.plex_remember_login.btn.setEnabled(True)
        self.plex_remember_login.btn.setText("Disconnect")

        self.plex_config_servers = {}

        self.plex_server.prop.clear()
        self.plex_server.prop.addItem("")

        for i, resource in enumerate(resources):
            self.plex_server.prop.addItem(resource.name)

            self.plex_config_servers[resource.clientIdentifier] = {
                "name": resource.name,
                "selected": self.plex_config_server_id == resource.clientIdentifier
            }

        self.plex_server.setVisible(True)

    async def select_plex_server(self):
        self.plex_server.prop.setEnabled(False)

        try:
            server_name = self.plex_server.prop.currentText()
            if server_name == "":
                self.plex_server.prop.setEnabled(True)
                self.start_button.setEnabled(False)
                self.plex_library.setVisible(False)
                self.plex_show.setVisible(False)
                return

            self.plexapi_server = None

            resources = await run_sync(self.plexapi_account.resources)
            for resource in resources:
                if resource.name == server_name:
                    self.plexapi_server = await run_sync(resource.connect)
                    self.plex_config_server_id = resource.clientIdentifier
                    self.plex_config_servers[resource.clientIdentifier]["selected"] = True
                    break
                else:
                    self.plex_config_servers[resource.clientIdentifier]["selected"] = False

            if self.plexapi_server == None:
                self.plex_server.prop.setEnabled(True)
                self.start_button.setEnabled(False)
                self.plex_library.setVisible(False)
                self.plex_show.setVisible(False)
                return

            self.plex_config_libraries = {}

            self.plex_library.prop.clear()
            self.plex_library.prop.addItem("")

            sections = await run_sync(self.plexapi_server.library.sections)
            for section in sections:
                if section.type == 'show':
                    self.plex_library.prop.addItem(section.title)

                    self.plex_config_libraries[section.key] = {
                        "title": section.title,
                        "selected": self.plex_config_library_key == section.key
                    }

            self.plex_library.setVisible(True)

        except:
            self.log_output.append(self.spacer)
            self.log_output.append(traceback.format_exc())

        finally:
            self.plex_server.prop.setEnabled(True)

    async def select_plex_library(self):
        self.plex_library.prop.setEnabled(False)

        try:
            library_name = self.plex_library.prop.currentText()
            if library_name == "":
                self.plex_library.prop.setEnabled(True)
                self.start_button.setEnabled(False)
                self.plex_show.setVisible(False)
                return

            self.plex_config_library_key = ""

            for key, item in self.plex_config_libraries.items():
                if library_name == item["title"]:
                    self.plex_config_library_key = key
                    self.plex_config_libraries[key]["selected"] = True
                    break
                else:
                    self.plex_config_libraries[key]["selected"] = False

            if self.plex_config_library_key == "":
                self.plex_library.prop.setEnabled(True)
                self.start_button.setEnabled(False)
                self.plex_show.setVisible(False)
                return

            self.plex_config_shows = {}

            self.plex_show.prop.clear()
            self.plex_show.prop.addItem("")

            section = await run_sync(self.plexapi_server.library.sectionByID, self.plex_config_library_key)
            shows = await run_sync(section.all)

            for show in shows:
                self.plex_show.prop.addItem(show.title)

                self.plex_config_shows[show.guid] = {
                    "title": show.title,
                    "selected": self.plex_config_show_guid == show.guid
                }

            self.plex_show.setVisible(True)

        except:
            self.log_output.append(self.spacer)
            self.log_output.append(traceback.format_exc())

        finally:
            self.plex_library.prop.setEnabled(True)

    async def select_plex_show(self):
        show_name = self.plex_show.prop.currentText()
        if show_name == "":
            self.start_button.setEnabled(False)
            return

        self.plex_config_show_guid = ""

        for key, item in self.plex_config_shows.items():
            if show_name == item["title"]:
                self.plex_config_show_guid = key
                self.plex_config_shows[key]["selected"] = True
                break
            else:
                self.plex_config_shows[key]["selected"] = False

        self.start_button.setEnabled(self.plex_config_show_guid != "")

    async def start_process(self):
        try:
            self.start_button.setEnabled(False)

            self.input_path = Path(self.input.prop.text()).resolve()
            self.output_path = Path(self.output.prop.text()).resolve()

            has_data = await self.cache_episode_data()
            if has_data:
                self.log_output.append(self.spacer)
                self.log_output.append(f"{self.tvshow['title']} metadata loaded: {len(self.seasons)} seasons, {len(self.episodes)} episodes")
            else:
                self.log_output.append("Exiting due to a lack of metadata - grab data.json and put it in the same directory.")
                self.start_button.setEnabled(True)
                return

            video_files = await self.glob_video_files()

            if self.plex_config_enabled:
                await self.start_process_plex(video_files)
            else:
                await self.start_process_jellyfin(video_files)

        except:
            self.log_output.append(self.spacer)
            self.log_output.append(traceback.format_exc())

        finally:
            self.start_button.setEnabled(True)

    async def cache_episode_data(self):
        yml_loaded = await self.cache_yml()

        self.log_output.append("Checking episode metadata file (data.json)...")

        data_file = Path(".", "data.json")
        data = {}
        now = datetime.datetime.now()

        if data_file.exists():
            data = await run_sync(data_file.read_bytes)
            data = await run_sync(orjson.loads, data)

            if "last_update" in data and data["last_update"] != "":
                last_update = datetime.datetime.fromisoformat(data["last_update"])

                if now - last_update < datetime.timedelta(hours=12):
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.seasons = data["seasons"] if "seasons" in data else {}
                    self.episodes = data["episodes"] if "episodes" in data else {}
                    return True

            last_update = datetime.datetime.fromtimestamp(data_file.stat().st_mtime)
            if now - last_update < datetime.timedelta(hours=1):
                self.tvshow = data["tvshow"] if "tvshow" in data else {}
                self.seasons = data["seasons"] if "seasons" in data else {}
                self.episodes = data["episodes"] if "episodes" in data else {}
                return True

        if yml_loaded == False or len(self.tvshow) == 0 or len(self.seasons) == 0 or len(self.episodes) == 0:
            url = "https://raw.githubusercontent.com/ladyisatis/onepaceorganizer/refs/heads/main/data.json"

            self.log_output.append(f"Downloading: {url}")
            #self.progress_bar.setValue(0)

            try:
                # AsyncClient would be more straightforward but
                # "QAsyncioEventLoop.getaddrinfo() is not implemented yet"
                resp = await run_sync(httpx.get, url, follow_redirects=True)
                if len(resp) == 0:
                    return False

                data = await run_sync(orjson.loads, resp.content)
                if len(data) > 0:
                    await run_sync(data_file.write_bytes, resp.content)

                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.seasons = data["seasons"] if "seasons" in data else {}
                    self.episodes = data["episodes"] if "episodes" in data else {}
      
            except:
                self.log_output.append(f"Unable to download new metadata: {traceback.format_exc()}")

        return len(self.tvshow) > 0 and len(self.seasons) > 0 and len(self.episodes) > 0

    async def cache_yml(self):
        try:
            data_folder = Path(".", "data")
            episodes_folder = Path(data_folder, "episodes")

            if not episodes_folder.is_dir():
                return False

            self.log_output.append("data/episodes folder detected, loading metadata from folder")

            episode_files = []
            async for file in glob(episodes_folder, "*.yml"):
                episode_files.append(file)

            tvshow_yml = Path(data_folder, "tvshow.yml")
            if tvshow_yml.exists():
                episode_files.append(tvshow_yml)

            seasons_yml = Path(data_folder, "seasons.yml")
            if seasons_yml.exists():
                episode_files.append(seasons_yml)

            total_files = len(episode_files)

            if total_files == 0:
                return False

            self.progress_bar.setValue(0)

            for index, file in enumerate(episode_files):
                crc32 = file.name.replace(".yml", "")

                with file.open(mode='r', encoding='utf-8') as f:
                    parsed = await run_sync(yaml.safe_load, stream=f)

                if file == tvshow_yml:
                    self.tvshow = parsed

                elif file == seasons_yml:
                    self.seasons = parsed

                elif "reference" in parsed:
                    ref = parsed["reference"]

                    if ref in self.episodes and isinstance(self.episodes[ref], dict):
                        self.episodes[crc32] = self.episodes[ref]
                    else:
                        with Path(file.parent, f"{ref}.yml").open(mode='r', encoding='utf-8') as f:
                            self.episodes[crc32] = await run_sync(yaml.safe_load, stream=f)

                elif len(crc32) == 8:
                    self.episodes[crc32] = parsed

                else:
                    crc32 = crc32.split("_")[0]

                    if crc32 in self.episodes and isinstance(self.episodes[crc32], list):
                        self.episodes[crc32].append(parsed)
                    else:
                        self.episodes[crc32] = [parsed]

                self.progress_bar.setValue(int((index + 1 / total_files) * 100))

            self.progress_bar.setValue(100)

        except:
            self.progress_bar.setValue(0)
            self.log_output.append(f"Skipping using data/episodes for metadata: {traceback.format_exc()}")
            return False

        return True

    async def glob_video_files(self):
        self.log_output.append(self.spacer)
        self.log_output.append("Searching for .mkv and .mp4 files...")

        crc_pattern = re.compile(r'\[([A-Fa-f0-9]{8})\](?=\.(mkv|mp4))')

        video_files = []
        filelist = []

        async for file in glob(self.input_path, "**/*.[mM][kK][vV]"):
            filelist.append(file)

        async for file in glob(self.input_path, "**/*.[mM][pP]4"):
            filelist.append(file)

        self.progress_bar.setValue(0)

        num_found = 0
        num_calced = 0
        filelist_total = len(filelist)

        for index, file in enumerate(filelist):
            match = crc_pattern.search(file.name)
            file_path = file.resolve()

            if match:
                crc32 = match.group(1)
                num_found = num_found + 1
            else:
                self.log_output.append(f"Calculating for {file_path}...")
                crc32 = await async_crc32(file_path)
                num_calced = num_calced + 1

            self.progress_bar.setValue(int((index + 1 / filelist_total) * 100))

            if crc32 in self.episodes:
                video_files.append((crc32, file_path))

            elif file.suffix.lower() == '.mkv':
                try:
                    with file_path.open(mode='rb') as f:
                        mkv = await run_sync(enzyme.MKV, f)

                    if mkv == None or mkv.info == None or mkv.info.title == None or mkv.info.title == "":
                        self.log_output.append(f"Skipping {file.name}: Episode metadata missing, infering information from MKV also failed")
                        continue

                    title = mkv.info.title.split(" - ")
                    match = re.match(r'^(.*\D)?\s*(\d+)$', title[0])

                    ep_title = " - ".join(title[1:]) if len(title) > 1 else title[0]
                    ep_date = mkv.info.date if mkv.info.date != None else datetime.date.fromtimestamp(file_path.stat().st_ctime)

                    m_season = 0
                    m_episode = 0

                    if match:
                        arc_name = match.group(1).strip()
                        ep_num = int(match.group(2))

                        for season, season_info in self.seasons.items():
                            if season_info["title"] == arc_name and crc32 not in self.episodes:
                                m_season = season
                                m_episode = ep_num

                    if m_season != 0 and m_episode != 0:
                        found_existing = False

                        for j, episode_info in self.episodes.items():
                            if episode_info["season"] == m_season and episode_info["episode"] == m_episode:
                                self.episodes[crc32] = episode_info
                                found_existing = True

                        if not found_existing:
                            self.episodes[crc32] = {
                                "season": m_season,
                                "episode": m_episode,
                                "title": ep_title,
                                "description": "",
                                "manga_chapters": "",
                                "anime_episodes": "",
                                "released": ep_date.isoformat()
                            }

                        video_files.append((crc32, file_path))

                    else:
                        self.log_output.append(f"Skipping {file.name}: Episode metadata missing, infering information from MKV also failed")

                except:
                    self.log_output.append(f"Skipping {file.name}: Episode metadata missing, infering information from MKV also failed")

            else:
                self.log_output.append(f"Skipping {file.name}: Episode metadata missing")

        self.progress_bar.setValue(100)
        self.log_output.append(f"Found: {num_found}, Calculated: {num_calced}, Total: {filelist_total}")

        return video_files

    async def start_process_plex(self, video_files):
        self.progress_bar.setValue(0)
        self.output_path.mkdir(exist_ok=True)

        section = await run_sync(self.plexapi_server.library.sectionByID, int(self.plex_config_library_key))
        show = await run_sync(section.getGuid, self.plex_config_show_guid)

        if show.title != self.tvshow["title"]:
            show.editTitle(self.tvshow["title"])

        if show.originalTitle != self.tvshow["originaltitle"]:
            show.editOriginalTitle(self.tvshow["originaltitle"])
            show.editSortTitle(self.tvshow["sorttitle"])

        if show.summary != self.tvshow["plot"]:
            show.editSummary(self.tvshow["plot"])
            show.editOriginallyAvailable(self.tvshow["premiered"].isoformat() if isinstance(self.tvshow["premiered"], datetime.date) else self.tvshow["premiered"])
            await run_sync(
                show.uploadPoster,
                filepath=str(Path(self.posters_path, "tvshow.png").resolve())
            )

        if show.contentRating != self.tvshow["rating"]:
            show.editContentRating(self.tvshow["rating"])

        i = 0
        queue = []
        num_complete = 0
        num_skipped = 0

        for crc32, file_path in video_files:
            episode_info = self.episodes[crc32]

            if isinstance(episode_info, list):
                stop = True

                for v in episode_info:
                    if "hashes" not in episode_info or "blake2" not in episode_info["hashes"] or not episode_info["hashes"]["blake2"]:
                        self.log_output.append(f"Skipping {file_path.name}: Blake2s 16-character hash is required but not provided")

                    elif await async_blake2s_16(file_path) == episode_info["hashes"]["blake2"]:
                        stop = False
                        episode_info = v
                        break

                if stop:
                    i = i + 1
                    num_skipped = num_skipped + 1
                    self.progress_bar.setValue(int((i / len(video_files)) * 100))
                    continue

            season = episode_info["season"]
            episode = episode_info["episode"]

            season_path = Path(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")

            if not season_path.is_dir():
                await run_sync(season_path.mkdir, exist_ok=True)

            if not "title" in episode_info or episode_info["title"] == "":
                self.log_output.append(f"Skipping {file_path.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                i = i + 1
                num_skipped = num_skipped + 1
                self.progress_bar.setValue(int((i / len(video_files)) * 100))
                continue

            prefix = f"One Pace - S{season:02d}E{episode_info['episode']:02d} - "
            safe_title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"])

            new_video_file_path = Path(season_path, f"{prefix}{safe_title}{file_path.suffix}")

            try:
                await run_sync(file_path.rename, new_video_file_path)
            except:
                await run_sync(shutil.move, str(file_path), str(new_video_file_path))

            queue.append((new_video_file_path, episode_info))

            i = i + 1
            self.progress_bar.setValue(int((i / len(video_files)) * 100))

        self.progress_bar.setValue(100)

        QMessageBox.information(None, "One Pace Organizer",
            (
                f"All of the One Pace files have been created in:\n"
                f"{str(self.output_path)}\n\n"
                f"Please move the\"{self.output_path.name}\" folder to the Plex library folder you've selected, "
                "and make sure that it appears in Plex. Seasons and episodes will temporarily "
                "have incorrect information, and the next step will correct them.\n\n"
                "Click OK once this has been done and you can see the One Pace video files in Plex."
            )
        )

        done = []

        self.progress_bar.setValue(0)

        for i, item in enumerate(queue):
            new_video_file_path = item[0]
            episode_info = item[1]

            season = episode_info["season"]

            if not season in done:
                done.append(season)

                plex_season = await run_sync(show.season, season=season)

                if season in self.seasons:
                    season_info = self.seasons[season]
                else:
                    season_info = self.seasons[f"{season}"]

                new_title = season_info["title"] if season == 0 else f"{season}. {season_info['title']}"

                if plex_season.title != new_title or plex_season.summary != season_info["description"]:
                    self.log_output.append("Updating Season: {new_title}")

                    plex_season.editTitle(new_title)
                    plex_season.editSummary(season_info["description"])
                    await run_sync(plex_season.uploadPoster, filepath=str(Path(self.posters_path, f"season{season}-poster.png")))

            plex_episode = await run_sync(show.episode, season=season, episode=episode_info["episode"])

            if plex_episode.title != episode_info["title"]:
                self.log_output.append("Updating Season: {season} Episode: {episode_info['episode']}")

                plex_episode.editTitle(episode_info["title"])
                plex_episode.editContentRating(episode_info["rating"] if "rating" in episode_info else self.tvshow["rating"])
                plex_episode.editSortTitle(episode_info["sorttitle"] if "sorttitle" in episode_info else episode_info["title"].replace("The ", "", 1))

                if "released" in episode_info:
                    if isinstance(episode_info["released"], datetime.date):
                        plex_episode.editOriginallyAvailable(episode_info["released"].isoformat())
                    else:
                        plex_episode.editOriginallyAvailable(str(episode_info["released"]))

                manga_anime = ""
                if episode_info["manga_chapters"] != "" and episode_info["anime_episodes"] != "":
                    manga_anime = f"Manga Chapter(s): {episode_info['manga_chapters']}\n\nAnime Episode(s): {episode_info['anime_episodes']}"

                if not "description" in episode_info or episode_info["description"] == "":
                    description = manga_anime
                else:
                    description = f"{episode_info['description']}\n\n{manga_anime}"

                plex_episode.editSummary(description)

                num_complete = num_complete + 1

            self.progress_bar.setValue(int((i+1 / len(queue)) * 100))

        self.progress_bar.setValue(100)

        self.log_output.append(self.spacer)
        self.log_output.append(f"Completed: {len(done)} seasons updated, {num_complete} episodes updated, {num_skipped} skipped")

    async def start_process_jellyfin(self, video_files):
        self.progress_bar.setValue(0)
        self.output_path.mkdir(exist_ok=True)

        tvshow_nfo = Path(self.output_path, "tvshow.nfo")

        if not tvshow_nfo.exists():
            root = ET.Element("tvshow")

            for k, v in self.tvshow.items():
                if isinstance(v, datetime.date):
                    ET.SubElement(root, k).text = v.isoformat()
                elif k == "plot":
                    ET.SubElement(root, "plot").text = v
                    ET.SubElement(root, "outline").text = v
                else:
                    ET.SubElement(root, str(k)).text = str(v)

            for k, v in dict(sorted(self.seasons.items())).items():
                ET.SubElement(root, "namedseason", attrib={"number": str(k)}).text = str(v["title"]) if k == 0 else f"{k}. {v['title']}"

            src = str(Path(self.posters_path, "tvshow.png").resolve())
            dst = str(Path(self.output_path, "poster.png").resolve())

            self.log_output.append(f"Copying {src} to: {dst}")
            await run_sync(shutil.copy, src, dst)

            art = ET.SubElement(root, "art")
            ET.SubElement(art, "poster").text = dst

            ET.indent(root)

            self.log_output.append(f"Writing tvshow.nfo to: {tvshow_nfo.resolve()}")

            tree = ET.ElementTree(root)
            await run_sync(
                tree.write,
                str(tvshow_nfo.resolve()),
                encoding='utf-8',
                xml_declaration=True
            )

        i = 0
        num_complete = 0
        num_skipped = 0

        for crc32, file_path in video_files:
            episode_info = self.episodes[crc32]

            if isinstance(episode_info, list):
                stop = True

                for v in episode_info:
                    if not "hashes" in episode_info or not "blake2" in episode_info["hashes"] or episode_info["hashes"]["blake2"] == "":
                        self.log_output.append(f"Skipping {file_path.name}: Blake2s 16-character hash is required but not provided")

                    elif await async_blake2s_16(file_path) == episode_info["hashes"]["blake2"]:
                        stop = False
                        episode_info = v
                        break

                if stop:
                    i = i + 1
                    num_skipped = num_skipped + 1
                    self.progress_bar.setValue(int((i / len(video_files)) * 100))
                    continue

            season = episode_info["season"]
            season_path = Path(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")

            if not season_path.is_dir():
                await run_sync(season_path.mkdir, exist_ok=True)

                root = ET.Element("season")

                if season in self.seasons:
                    season_info = self.seasons[season]
                else:
                    season_info = self.seasons[f"{season}"]

                title_text = season_info['title'] if season == 0 else f"{season}. {season_info['title']}"

                ET.SubElement(root, "title").text = title_text
                ET.SubElement(root, "plot").text = season_info["description"]
                ET.SubElement(root, "outline").text = season_info["description"]
                ET.SubElement(root, "seasonnumber").text = f"{season}"

                src = str(Path(self.posters_path, f"season{season}-poster.png").resolve())
                dst = str(Path(season_path, "poster.png").resolve())

                self.log_output.append(f"Copying {src} to: {dst}")
                await run_sync(shutil.copy, src, dst)

                art = ET.SubElement(root, "art")
                ET.SubElement(art, "poster").text = dst

                ET.indent(root)
                tree = ET.ElementTree(root)
                await run_sync(
                    tree.write,
                    str(Path(season_path, "season.nfo").resolve()),
                    encoding='utf-8',
                    xml_declaration=True
                )

            episodedetails = ET.Element("episodedetails")

            if not "title" in episode_info or episode_info["title"] == "":
                self.log_output.append(f"Skipping {file_path.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                i = i + 1
                num_skipped = num_skipped + 1
                self.progress_bar.setValue(int((i / len(video_files)) * 100))
                continue

            prefix = f"One Pace - S{season:02d}E{episode_info['episode']:02d} - "
            safe_title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"])

            new_video_file_path = Path(season_path, f"{prefix}{safe_title}{file_path.suffix}")

            self.log_output.append(f"Creating metadata and moving {file_path.name} to: {new_video_file_path}")

            ET.SubElement(episodedetails, "title").text = episode_info["title"]
            ET.SubElement(episodedetails, "showtitle").text = self.tvshow["title"]
            ET.SubElement(episodedetails, "season").text = f"{season}"
            ET.SubElement(episodedetails, "episode").text = f"{episode_info['episode']}"
            ET.SubElement(episodedetails, "rating").text = episode_info["rating"] if "rating" in episode_info else self.tvshow["rating"]

            manga_anime = ""
            if episode_info["manga_chapters"] != "" and episode_info["anime_episodes"] != "":
                manga_anime = f"Manga Chapter(s): {episode_info['manga_chapters']}\n\nAnime Episode(s): {episode_info['anime_episodes']}"

            if not "description" in episode_info or episode_info["description"] == "":
                description = manga_anime
            else:
                description = f"{episode_info['description']}\n\n{manga_anime}"

            ET.SubElement(episodedetails, "plot").text = description

            if "released" in episode_info:
                if isinstance(episode_info["released"], datetime.date):
                    date = episode_info["released"].isoformat()
                else:
                    date = episode_info["released"]

                ET.SubElement(episodedetails, "premiered").text = date
                ET.SubElement(episodedetails, "aired").text = date

            ET.indent(episodedetails)

            season_nfo = str(Path(season_path, f"{prefix}{safe_title}.nfo").resolve())
            ET.ElementTree(episodedetails).write(
                season_nfo, 
                encoding='utf-8', 
                xml_declaration=True
            )

            try:
                await run_sync(file_path.rename, new_video_file_path)
            except:
                await run_sync(shutil.move, str(file_path), str(new_video_file_path))

            i = i + 1
            num_complete = num_complete + 1
            self.progress_bar.setValue(int((i / len(video_files)) * 100))

        self.progress_bar.setValue(100)

        self.log_output.append(self.spacer)
        self.log_output.append(f"Completed: {num_complete} episodes updated, {num_skipped} skipped")

if __name__ == "__main__":
    try:
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            freeze_support()

        app = QApplication(sys.argv)
        opo = OnePaceOrganizer()
        opo.show()

        QtAsyncio.run(handle_sigint=True)

    except asyncio.CancelledError:
        pass

    except Exception:
        QMessageBox.critical(None, f"One Pace Organizer", traceback.format_exc())

    finally:
        opo.save_config()
