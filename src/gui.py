import asyncio
import concurrent.futures
import sys
import traceback
import webbrowser

from functools import partial as func_partial
from os import process_cpu_count
from pathlib import Path
from loguru import logger
from qasync import QEventLoop, QThreadExecutor, asyncWrap, asyncClose, asyncSlot
from src import utils, organizer

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QFileDialog, QCheckBox, QComboBox, QTextEdit, QProgressBar,
    QGroupBox, QMessageBox, QInputDialog, QMainWindow
)
from PySide6.QtGui import QAction
from PySide6.QtCore import Qt, Signal

class Input:
    def __init__(self, layout, label, prop, width=250, button="", connect=None):
        self.layout = QHBoxLayout()
        self.label = QLabel(label)
        self.prop = prop

        label_width = self.label.fontMetrics().boundingRect(label).width()
        self.label.setFixedWidth((label_width if label_width > width else width) + 10)

        self.layout.addWidget(self.label)
        self.layout.addWidget(prop, stretch=1)

        if button != "":
            self.button = QPushButton(button)
            self.layout.addWidget(self.button)

            if connect != None:
                self.button.clicked.connect(connect)
        else:
            self.button = None

        layout.addLayout(self.layout)

    def setVisible(self, is_visible):
        self.label.setVisible(is_visible)
        self.prop.setVisible(is_visible)

        if self.button is not None:
            self.button.setVisible(is_visible)

    def setEnabled(self, is_enabled):
        self.label.setEnabled(is_enabled)
        self.prop.setEnabled(is_enabled)

        if self.button is not None:
            self.button.setEnabled(is_enabled)

class GUI(QMainWindow):
    _log_signal = Signal(str)

    def __init__(self, organizer=None, log_level="info"):
        super().__init__()

        self.log_level = log_level.upper()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self._log_scrollbar = self.log_output.verticalScrollBar()
        self._log_signal.connect(self._log_output_append)
        self._logger_id = None

        self.organizer = organizer.OnePaceOrganizer() if organizer is None else organizer
        self.setWindowTitle(self.organizer.window_title)
        self.setMinimumSize(800, 600)

        self.organizer.message_dialog_func = self._message_dialog
        self.organizer.input_dialog_func = self._input_dialog
        self.plex_width = 125
        self.spacer = "------------------------------------------------------------------"

        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget)
        self.lock = asyncio.Lock()

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.organizer.progress_bar_func = self.progress_bar.setValue

        self.input = Input(layout, "Directory of unsorted One Pace .mkv/.mp4 files:", QLineEdit(), button="Browse...", connect=self.browse_input_folder)
        self.input.prop.setText(str(self.organizer.input_path))
        self.input.prop.setPlaceholderText(str(Path.home() / "Downloads"))

        self.output = Input(layout, "Move the sorted and renamed files to:", QLineEdit(), button="Browse...", connect=self.browse_output_folder)
        self.output.prop.setText(str(self.organizer.output_path))
        self.output.prop.setPlaceholderText(str(Path("/", "path", "to", "plex_or_jellyfin", "Anime", "One Pace").resolve()))
        self.output.setVisible(self.organizer.file_action != 4)
        self._output_label_txt()

        self.method = Input(layout, "I'm watching via...", QComboBox())
        self.method.prop.addItems(["Jellyfin/Emby (.nfo mode)", "Plex"])
        self.method.prop.setCurrentIndex(1 if self.organizer.plex_config_enabled else 0)
        self.method.prop.currentTextChanged.connect(self.set_method)

        self.plex_group = QGroupBox("Plex")
        self.plex_group_layout = QVBoxLayout()
        _plex_remembered_login = not self.organizer.plex_config_use_token and self.organizer.plex_config_auth_token != "" and self.organizer.plex_config_remember

        self.plex_url = Input(self.plex_group_layout, "Plex URL:", QLineEdit(), width=self.plex_width)
        self.plex_url.prop.setText(self.organizer.plex_config_url)
        self.plex_url.prop.setPlaceholderText("http://127.0.0.1:32400")
        self.plex_url.prop.textEdited.connect(self.edit_plex_url)
        self.plex_url.setVisible(not _plex_remembered_login)

        self.plex_method = Input(self.plex_group_layout, "Login Method:", QComboBox(), width=self.plex_width)
        self.plex_method.prop.addItems(["Username and Password", "Authentication Token"])
        self.plex_method.prop.currentTextChanged.connect(self.switch_plex_method)
        self.plex_method.prop.setCurrentText("Authentication Token" if self.organizer.plex_config_use_token else "Username and Password")
        self.plex_method.setVisible(not _plex_remembered_login)

        self.plex_token = Input(self.plex_group_layout, "Authentication Token:", QLineEdit(), width=self.plex_width)
        self.plex_token.prop.setEchoMode(QLineEdit.EchoMode.Password)
        self.plex_token.prop.setText(self.organizer.plex_config_auth_token)
        self.plex_token.setVisible(self.organizer.plex_config_use_token)
        self.plex_token.setVisible(self.organizer.plex_config_use_token and not _plex_remembered_login)

        self.plex_username = Input(self.plex_group_layout, "Username:", QLineEdit(), width=self.plex_width)
        self.plex_username.prop.setText(self.organizer.plex_config_username)
        self.plex_username.setVisible(not self.organizer.plex_config_use_token and not _plex_remembered_login)

        self.plex_password = Input(self.plex_group_layout, "Password:", QLineEdit(), width=self.plex_width)
        self.plex_password.prop.setEchoMode(QLineEdit.EchoMode.Password)
        self.plex_password.prop.setText(self.organizer.plex_config_password)
        self.plex_password.setVisible(not self.organizer.plex_config_use_token and not _plex_remembered_login)

        self.plex_remember_login = Input(
            self.plex_group_layout, 
            "", 
            QCheckBox("Remember"), 
            button="Disconnect" if _plex_remembered_login else "Login",
            connect=self.plex_login
        )
        self.plex_remember_login.prop.setChecked(self.organizer.plex_config_remember)

        self.plex_server = Input(self.plex_group_layout, "Plex Server:", QComboBox(), width=self.plex_width)
        self.plex_server.prop.addItem("", userData=None)

        i = 1
        for server_id, item in self.organizer.plex_config_servers.items():
            self.plex_server.prop.addItem(item["name"], userData=server_id)
            if server_id == self.organizer.plex_config_server_id:
                self.plex_server.prop.setCurrentIndex(i)
            i += 1

        self.plex_server.prop.activated.connect(self.select_plex_server)
        self.plex_server.setVisible(_plex_remembered_login and len(self.organizer.plex_config_servers) > 0)

        self.plex_library = Input(self.plex_group_layout, "Library:", QComboBox(), width=self.plex_width)
        self.plex_library.prop.addItem("", userData=None)

        i = 1
        for library_key, item in self.organizer.plex_config_libraries.items():
            self.plex_library.prop.addItem(item["title"], userData=library_key)
            if library_key == self.organizer.plex_config_library_key:
                self.plex_library.prop.setCurrentIndex(i)
            i += 1

        self.plex_library.prop.activated.connect(self.select_plex_library)
        self.plex_library.setVisible(_plex_remembered_login and self.organizer.plex_config_server_id != "" and len(self.organizer.plex_config_libraries) > 0)

        self.plex_show = Input(self.plex_group_layout, "Show:", QComboBox(), width=self.plex_width)
        self.plex_show.prop.addItem("", userData=None)

        i = 1
        for show_guid, item in self.organizer.plex_config_shows.items():
            self.plex_show.prop.addItem(item["title"], userData=show_guid)
            if show_guid == self.organizer.plex_config_show_guid:
                self.plex_show.prop.setCurrentIndex(i)
            i += 1

        self.plex_show.prop.activated.connect(self.select_plex_show)
        self.plex_show.setVisible(_plex_remembered_login and self.organizer.plex_config_library_key != "" and len(self.organizer.plex_config_shows) > 0)

        self.plex_group.setLayout(self.plex_group_layout)
        layout.addWidget(self.plex_group)

        if not self.organizer.plex_config_enabled:
            self.plex_group.hide()

        menu = self.menuBar()
        menu_file = menu.addMenu("&File")
        menu_configuration = menu.addMenu("&Configuration")

        action_exit = QAction("Exit", self)
        action_exit.triggered.connect(self.exit)
        menu_file.addAction(action_exit)

        action_after_sort = menu_configuration.addMenu("Action after Sorting/Renaming")

        self.action_after_sort_move = QAction("Move (recommended)", self)
        self.action_after_sort_move.setCheckable(True)
        self.action_after_sort_move.setChecked(self.organizer.file_action == 0)
        self.action_after_sort_move.triggered.connect(func_partial(self.set_action, 0))
        action_after_sort.addAction(self.action_after_sort_move)

        self.action_after_sort_copy = QAction("Copy", self)
        self.action_after_sort_copy.setCheckable(True)
        self.action_after_sort_copy.setChecked(self.organizer.file_action == 1)
        self.action_after_sort_copy.triggered.connect(func_partial(self.set_action, 1))
        action_after_sort.addAction(self.action_after_sort_copy)

        self.action_after_sort_symlink = QAction("Symlink", self)
        self.action_after_sort_symlink.setCheckable(True)
        self.action_after_sort_symlink.setChecked(self.organizer.file_action == 2)
        self.action_after_sort_symlink.triggered.connect(func_partial(self.set_action, 2))
        action_after_sort.addAction(self.action_after_sort_symlink)

        self.action_after_sort_hardlink = QAction("Hardlink", self)
        self.action_after_sort_hardlink.setCheckable(True)
        self.action_after_sort_hardlink.setChecked(self.organizer.file_action == 3)
        self.action_after_sort_hardlink.triggered.connect(func_partial(self.set_action, 3))
        action_after_sort.addAction(self.action_after_sort_hardlink)

        self.action_after_sort_metadata = QAction("Sort and update metadata only", self)
        self.action_after_sort_metadata.setVisible(not self.organizer.plex_config_enabled)
        self.action_after_sort_metadata.setCheckable(True)
        self.action_after_sort_metadata.setChecked(self.organizer.file_action == 4)
        self.action_after_sort_metadata.triggered.connect(func_partial(self.set_action, 4))
        action_after_sort.addAction(self.action_after_sort_metadata)

        self.action_season = menu_configuration.addMenu("Set Season Folder Names")
        self.action_season.menuAction().setVisible(not self.organizer.plex_config_enabled)
        #menu_configuration.addAction(self.action_season)

        self.action_season_0 = QAction("Season 01-09, 10-... (recommended)", self)
        self.action_season_0.setCheckable(True)
        self.action_season_0.setChecked(self.organizer.folder_action == 0)
        self.action_season_0.triggered.connect(func_partial(self.set_season, 0))
        self.action_season.addAction(self.action_season_0)

        self.action_season_1 = QAction("Season 1-9, 10-...", self)
        self.action_season_1.setCheckable(True)
        self.action_season_1.setChecked(self.organizer.folder_action == 1)
        self.action_season_1.triggered.connect(func_partial(self.set_season, 1))
        self.action_season.addAction(self.action_season_1)

        self.action_season_2 = QAction("Do not create folders", self)
        self.action_season_2.setCheckable(True)
        self.action_season_2.setChecked(self.organizer.folder_action == 2)
        self.action_season_2.triggered.connect(func_partial(self.set_season, 2))
        self.action_season.addAction(self.action_season_2)

        self.action_edit_output_tmpl = QAction("Set Output Filenames", self)
        self.action_edit_output_tmpl.setVisible(not self.organizer.plex_config_enabled)
        self.action_edit_output_tmpl.triggered.connect(self.edit_output_template)
        menu_configuration.addAction(self.action_edit_output_tmpl)

        menu_log_level = menu_configuration.addMenu("Log Level")

        self.action_log_level_0 = QAction("Critical", self)
        self.action_log_level_0.setCheckable(True)
        self.action_log_level_0.setChecked(self.log_level == "CRITICAL")
        self.action_log_level_0.triggered.connect(func_partial(self._set_logger, "CRITICAL"))
        menu_log_level.addAction(self.action_log_level_0)

        self.action_log_level_1 = QAction("Errors", self)
        self.action_log_level_1.setCheckable(True)
        self.action_log_level_1.setChecked(self.log_level == "ERROR")
        self.action_log_level_1.triggered.connect(func_partial(self._set_logger, "ERROR"))
        menu_log_level.addAction(self.action_log_level_1)

        self.action_log_level_2 = QAction("Warning", self)
        self.action_log_level_2.setCheckable(True)
        self.action_log_level_2.setChecked(self.log_level == "WARNING")
        self.action_log_level_2.triggered.connect(func_partial(self._set_logger, "WARNING"))
        menu_log_level.addAction(self.action_log_level_2)

        self.action_log_level_3 = QAction("Success", self)
        self.action_log_level_3.setCheckable(True)
        self.action_log_level_3.setChecked(self.log_level == "SUCCESS")
        self.action_log_level_3.triggered.connect(func_partial(self._set_logger, "SUCCESS"))
        menu_log_level.addAction(self.action_log_level_3)

        self.action_log_level_4 = QAction("Information", self)
        self.action_log_level_4.setCheckable(True)
        self.action_log_level_4.setChecked(self.log_level == "INFO")
        self.action_log_level_4.triggered.connect(func_partial(self._set_logger, "INFO"))
        menu_log_level.addAction(self.action_log_level_4)

        self.action_log_level_5 = QAction("Debug", self)
        self.action_log_level_5.setCheckable(True)
        self.action_log_level_5.setChecked(self.log_level == "DEBUG")
        self.action_log_level_5.triggered.connect(func_partial(self._set_logger, "DEBUG"))
        menu_log_level.addAction(self.action_log_level_5)

        self.action_log_level_6 = QAction("Trace (slow)", self)
        self.action_log_level_6.setCheckable(True)
        self.action_log_level_6.setChecked(self.log_level == "TRACE")
        self.action_log_level_6.triggered.connect(func_partial(self._set_logger, "TRACE"))
        menu_log_level.addAction(self.action_log_level_6)

        self.start_button = QPushButton("Start")
        self.start_button.clicked.connect(self.start)
        layout.addWidget(self.start_button)

        layout.addWidget(self.log_output, stretch=1)
        layout.addWidget(self.progress_bar)
        widget.setLayout(layout)

        self._set_logger(log_level)

    def _log_output_append(self, obj):
        self.log_output.setUpdatesEnabled(False)
        self.log_output.append(obj)
        self._log_scrollbar.setValue(self._log_scrollbar.maximum())
        self.log_output.setUpdatesEnabled(True)

    def _log(self, msg):
        m = msg.split(",")
        text = " ".join(m[2:]).rstrip("\n")
        self._log_signal.emit(f"[{m[0]}] [{m[1].replace(' ','')}] {text}")

    def _set_logger(self, level):
        if self._logger_id is not None:
            logger.remove(self._logger_id)

        self.log_level = level.upper()
        self._logger_id = logger.add(
            self._log,
            level=self.log_level, 
            format="{time:YYYY-MM-DD HH:mm:ss.SSS},{level: <8},{message}", 
            colorize=False, 
            enqueue=False
        )

        self.action_log_level_0.setChecked(self.log_level == "CRITICAL")
        self.action_log_level_1.setChecked(self.log_level == "ERROR")
        self.action_log_level_2.setChecked(self.log_level == "WARNING")
        self.action_log_level_3.setChecked(self.log_level == "SUCCESS")
        self.action_log_level_4.setChecked(self.log_level == "INFO")
        self.action_log_level_5.setChecked(self.log_level == "DEBUG")
        self.action_log_level_6.setChecked(self.log_level == "TRACE")

    def _output_label_txt(self):
        _action = "Move"
        if self.organizer.file_action == 1:
            _action = "Copy"
        elif self.organizer.file_action == 2:
            _action = "Symlink"
        elif self.organizer.file_action == 3:
            _action = "Hardlink"

        self.output.label.setText(f"{_action} the sorted and renamed files to:")
        self.output.setVisible(self.organizer.file_action != 4)

    async def _input_dialog(self, text, default=""):
        res, ok = await asyncWrap(
            lambda: QInputDialog.getText(None, self.organizer.window_title, text, QLineEdit.Normal, default)
        )
        if ok:
            return res

        return ""

    async def _message_dialog(self, text):
        return await asyncWrap(
            lambda: QMessageBox.information(None, self.organizer.window_title, text) 
        ) == QMessageBox.StandardButtons.Ok

    def browse_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Input Folder")
        if not folder or folder == "":
            return

        logger.debug(f"input folder set: {folder}")

        if Path(folder).resolve() == Path(self.output.prop.text()).resolve() and self.organizer.file_action != 4:
            QMessageBox.information(None, self.organizer.window_title, "The input folder should not be the same as the output folder.")
            return

        if len(folder) > 2 and (folder[:2] == "\\\\" or folder[:2] == "//"):
            yn = QMessageBox.question(
                None,
                self.organizer.window_title,
                "Network storage has less support with this application and thus may be " +
                "prone to errors or data corruption in case of data loss in transport. " +
                "Do you still want to continue?"
            ) == QMessageBox.StandardButton.Yes

            if not yn:
                return

        self.organizer.input_path = Path(folder).resolve()
        self.input.prop.setText(str(self.organizer.input_path))

        if self.organizer.file_action == 4:
            self.output.prop.setText(self.input.prop.text())
            self.organizer.output_path = self.organizer.input_path

    def browse_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if not folder or folder == "":
            return

        if Path(self.input.prop.text()).resolve() == Path(folder).resolve() and self.organizer.file_action != 4:
            QMessageBox.information(None, self.organizer.window_title, "The input folder should not be the same as the output folder.")
            return

        if len(folder) > 2 and (folder[:2] == "\\\\" or folder[:2] == "//"):
            yn = QMessageBox.question(
                None,
                self.organizer.window_title,
                "Network storage has less support with this application and thus may be " +
                "prone to errors or data corruption in case of data loss in transport. " +
                "Do you still want to continue?"
            ) == QMessageBox.StandardButton.Yes

            if not yn:
                return

        self.organizer.output_path = Path(folder).resolve()
        self.output.prop.setText(str(self.organizer.output_path))

    def edit_plex_url(self, text):
        self.organizer.plex_config_url = text

    def _update_start_btn(self):
        self.start_button.setEnabled(
            not self.organizer.plex_config_enabled or (
                self.organizer.plex_config_enabled and 
                self.organizer.plex_config_server_id != "" and 
                self.organizer.plex_config_library_key != "" and 
                self.organizer.plex_config_show_guid != ""
            )
        )

    def set_method(self, text):
        self.organizer.plex_config_enabled = text == "Plex"
        self._update_start_btn()

        self.plex_group.setVisible(self.organizer.plex_config_enabled)
        self.action_after_sort_metadata.setVisible(not self.organizer.plex_config_enabled)
        self.action_season.menuAction().setVisible(not self.organizer.plex_config_enabled)
        self.action_edit_output_tmpl.setVisible(not self.organizer.plex_config_enabled)

        if self.organizer.plex_config_enabled and self.organizer.file_action == 4:
            self.set_action(0)

    def switch_plex_method(self, text):
        self.organizer.plex_config_use_token = text == "Authentication Token"

        self.plex_token.setVisible(self.organizer.plex_config_use_token)
        self.plex_username.setVisible(not self.organizer.plex_config_use_token)
        self.plex_password.setVisible(not self.organizer.plex_config_use_token)

    def _plex_toggle_enabled(self, enable_all: bool):
        self.plex_method.prop.setEnabled(enable_all)
        self.plex_token.prop.setEnabled(enable_all)
        self.plex_username.prop.setEnabled(enable_all)
        self.plex_password.prop.setEnabled(enable_all)
        self.plex_remember_login.prop.setEnabled(enable_all)
        self.plex_remember_login.button.setEnabled(enable_all)
        self.plex_server.prop.setEnabled(enable_all)
        self.plex_library.prop.setEnabled(enable_all)
        self.plex_show.prop.setEnabled(enable_all)
        self.plex_url.prop.setEnabled(enable_all)

    def _plex_toggle_login(self, is_visible: bool):
        self.plex_url.setVisible(is_visible)
        self.plex_method.setVisible(is_visible)
        if self.organizer.plex_config_use_token:
            self.plex_token.setVisible(is_visible)
        else:
            self.plex_username.setVisible(is_visible)
            self.plex_password.setVisible(is_visible)

    @asyncSlot()
    async def plex_login(self):
        if not self.plex_remember_login.button.isEnabled():
            return

        if self.plex_remember_login.button.text() == "Disconnect":
            self._plex_toggle_login(True)
            self._plex_toggle_enabled(True)
            self.plex_server.prop.setEnabled(False)
            self.plex_server.setVisible(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_library.setVisible(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_show.setVisible(False)
            self.plex_remember_login.button.setText("Login")
            self.plex_remember_login.button.setEnabled(True)
            self.start_button.setEnabled(False)
            return

        self._plex_toggle_enabled(False)
        await self.organizer.save_config()

        self.organizer.plex_config_use_token = self.plex_method.prop.currentText() == "Authentication Token"
        self.organizer.plex_config_remember = self.plex_remember_login.prop.checkState() == Qt.Checked
        self.organizer.plex_config_auth_token = self.plex_token.prop.text()
        self.organizer.plex_config_username = self.plex_username.prop.text()
        self.organizer.plex_config_password = self.plex_password.prop.text()

        self.organizer.logger.info(f"Logging in to Plex")
        if not await self.organizer.plex_login(True):
            self.organizer.logger.info("Login failed")
            await self.organizer.save_config()
            self._plex_toggle_login(True)
            self._plex_toggle_enabled(True)
            self.plex_server.prop.setEnabled(False)
            self.plex_server.setVisible(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_library.setVisible(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_show.setVisible(False)
            self.plex_remember_login.button.setText("Login")
            self.plex_remember_login.button.setEnabled(True)
            return

        self.organizer.logger.info(f"Logged in")
        self.plex_remember_login.button.setText("Disconnect")
        self._plex_toggle_login(False)
        self.start_button.setEnabled(False)

        self.plex_server.prop.setEnabled(True)
        await self.plex_get_servers()

    @asyncSlot()
    async def plex_get_servers(self):
        if not self.plex_server.prop.isEnabled():
            return

        self.organizer.logger.info("Fetching Plex Servers")
        self.plex_server.prop.setEnabled(False)

        self.plex_server.setVisible(True)
        self.plex_library.setVisible(False)
        self.plex_show.setVisible(False)

        self.plex_server.prop.clear()
        self.plex_server.prop.addItem("Loading...", userData=None)

        if not await self.organizer.plex_get_servers():
            self.plex_server.prop.clear()
            self.plex_server.prop.addItem("", userData=None)
            await self.organizer.save_config()
            self.plex_server.prop.setEnabled(True)
            return

        self.plex_server.prop.clear()
        self.plex_server.prop.addItem("", userData=None)

        for identifier, item in self.organizer.plex_config_servers.items():
            self.plex_server.prop.addItem(item["name"], userData=identifier)

        await self.organizer.save_config()
        self._update_start_btn()
        self.plex_server.prop.setEnabled(True)
        self.plex_remember_login.button.setEnabled(True)

        #if len(self.organizer.plex_config_servers) == 1:
        #    self.plex_server.prop.setCurrentIndex(1)
        #    await self.select_plex_server()

    @asyncSlot()
    async def select_plex_server(self):
        if not self.plex_server.prop.isEnabled():
            return

        _id = self.plex_server.prop.currentData()
        if _id is None or _id == "":
            self.organizer.logger.debug("Reset server")
            self.organizer.plexapi_server = None
            self.organizer.plex_config_server_id = ""
            await self.plex_get_servers()
            self.plex_server.setVisible(True)
            self.plex_library.setVisible(False)
            self.plex_show.setVisible(False)
            self.start_button.setEnabled(False)
            return

        self.organizer.logger.debug("Verifying Plex login")
        if not await self.organizer.plex_login():
            self.organizer.logger.debug("Reset login")
            await self.organizer.save_config()
            self._plex_toggle_login(True)
            self._plex_toggle_enabled(True)
            self.plex_server.prop.setEnabled(False)
            self.plex_server.setVisible(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_library.setVisible(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_show.setVisible(False)
            self.plex_remember_login.button.setText("Login")
            self.plex_remember_login.button.setEnabled(True)
            return

        self.organizer.logger.debug("Selecting Plex server")
        if self.organizer.plexapi_server is None and self.organizer.plex_config_server_id == "" and not await self.organizer.select_plex_server(_id):
            self.organizer.plexapi_server = None
            self.organizer.plex_config_server_id = ""
            await self.organizer.save_config()
            self.plex_server.setVisible(True)
            self.plex_library.setVisible(False)
            self.plex_show.setVisible(False)
            self.start_button.setEnabled(False)
            return

        self.plex_server.setVisible(True)
        self.plex_library.setVisible(True)
        self.plex_show.setVisible(False)

        self.plex_library.prop.setEnabled(False)
        self.plex_library.prop.clear()
        self.plex_library.prop.addItem("Loading...", userData=None)

        if not await self.organizer.plex_get_libraries():
            await self.organizer.save_config()
            self.plex_library.prop.clear()
            self.plex_library.prop.addItem("", userData=None)
            self.plex_library.prop.setEnabled(True)
            return

        self.plex_library.prop.clear()
        self.plex_library.prop.addItem("", userData=None)

        for identifier, item in self.organizer.plex_config_libraries.items():
            self.plex_library.prop.addItem(item["title"], userData=identifier)

        await self.organizer.save_config()
        self._update_start_btn()
        self.plex_library.prop.setEnabled(True)

        #if len(self.organizer.plex_config_libraries) == 1:
        #    self.plex_library.prop.setCurrentIndex(1)
        #    await self.select_plex_library()

    @asyncSlot()
    async def select_plex_library(self):
        if not self.plex_library.prop.isEnabled():
            return

        _id = self.plex_library.prop.currentData()
        if _id is None or _id == "":
            await self.organizer.save_config()
            self.plex_server.setVisible(True)
            self.plex_library.setVisible(True)
            self.plex_show.setVisible(False)
            self.start_button.setEnabled(False)
            return

        if not await self.organizer.plex_login():
            self.organizer.logger.debug("Reset login")
            await self.organizer.save_config()
            self._plex_toggle_login(True)
            self._plex_toggle_enabled(True)
            self.plex_server.prop.setEnabled(False)
            self.plex_server.setVisible(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_library.setVisible(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_show.setVisible(False)
            self.plex_remember_login.button.setText("Login")
            self.plex_remember_login.button.setEnabled(True)
            return

        await self.organizer.plex_select_library(int(_id))
        self.plex_server.setVisible(True)
        self.plex_library.setVisible(True)
        self.plex_show.setVisible(True)

        self.plex_show.prop.setEnabled(False)
        self.plex_show.prop.clear()
        self.plex_show.prop.addItem("Loading...", userData=None)

        if not await self.organizer.plex_get_shows():
            self.plex_show.prop.clear()
            self.plex_show.prop.addItem("", userData=None)
            self.plex_show.prop.setEnabled(True)
            return

        self.plex_show.prop.clear()
        self.plex_show.prop.addItem("", userData=None)

        for identifier, item in self.organizer.plex_config_shows.items():
            self.plex_show.prop.addItem(item["title"], userData=identifier)

        await self.organizer.save_config()
        self._update_start_btn()
        self.plex_show.prop.setEnabled(True)

        #if len(self.organizer.plex_config_shows) == 1:
        #    self.plex_show.prop.setCurrentIndex(1)

    @asyncSlot()
    async def select_plex_show(self):
        if not self.plex_show.prop.isEnabled():
            return

        _id = self.plex_show.prop.currentData()
        if _id is None or _id == "":
            self.plex_server.setVisible(True)
            self.plex_library.setVisible(True)
            self.plex_show.setVisible(True)
            self.start_button.setEnabled(False)
            return

        if not await self.organizer.plex_login():
            self.organizer.logger.debug("Reset login")
            await self.organizer.save_config()
            self._plex_toggle_login(True)
            self._plex_toggle_enabled(True)
            self.plex_server.prop.setEnabled(False)
            self.plex_server.setVisible(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_library.setVisible(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_show.setVisible(False)
            self.plex_remember_login.button.setText("Login")
            self.plex_remember_login.button.setEnabled(True)
            return

        await self.organizer.plex_select_show(_id)
        await self.organizer.save_config()
        self._update_start_btn()

    @asyncClose
    async def exit(self, event=None):
        await self.organizer.save_config()
        if event is None:
            self.close()

    def set_action(self, action):
        self.organizer.file_action = action
        self.action_after_sort_move.setChecked(action == 0)
        self.action_after_sort_copy.setChecked(action == 1)
        self.action_after_sort_symlink.setChecked(action == 2)
        self.action_after_sort_hardlink.setChecked(action == 3)
        self.action_after_sort_metadata.setChecked(action == 4)
        self._output_label_txt()

    def set_season(self, season):
        self.organizer.folder_action = season
        self.action_season_0.setChecked(season == 0)
        self.action_season_1.setChecked(season == 1)
        self.action_season_2.setChecked(season == 2)

    def edit_output_template(self):
        _sp = " " * 100
        _fn = self._input_dialog(f"Enter the template for the filename:{_sp}", self.organizer.filename_tmpl)
        if _fn is not None and _fn != "":
            self.organizer.filename_tmpl = _fn

    @asyncSlot()
    async def start(self):
        self.start_button.setEnabled(False)
        self.log_output.append(self.spacer)

        self.organizer.input_path = Path(self.input.prop.text())
        self.organizer.output_path = Path(self.output.prop.text())

        if self.organizer.plex_config_enabled:
            self.plex_server.prop.setEnabled(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_remember_login.button.setEnabled(False)
            self.plex_remember_login.prop.setEnabled(False)

            self.organizer.logger.info("Checking Plex connection")
            if not await self.organizer.plex_login():
                self.organizer.logger.info("Plex credentials have expired - please re-login")
                await self.organizer.save_config()
                self._plex_toggle_login(True)
                self._plex_toggle_enabled(True)
                self.plex_server.prop.setEnabled(False)
                self.plex_server.setVisible(False)
                self.plex_library.prop.setEnabled(False)
                self.plex_library.setVisible(False)
                self.plex_show.prop.setEnabled(False)
                self.plex_show.setVisible(False)
                self.plex_remember_login.button.setText("Login")
                self.plex_remember_login.button.setEnabled(True)
                return

            if self.organizer.plexapi_server is None:
                self.organizer.logger.info("Connecting to Plex server")
                await self.organizer.plex_get_servers()

            res = await asyncio.create_task(self.organizer.start())
            if isinstance(res, tuple):
                success, queue, completed, skipped = res

                if not success:
                    self.plex_server.prop.setEnabled(True)
                    self.plex_library.prop.setEnabled(True)
                    self.plex_show.prop.setEnabled(True)
                    self.plex_remember_login.button.setEnabled(True)
                    self.plex_remember_login.prop.setEnabled(True)
                    await self.organizer.save_config()
                    self.start_button.setEnabled(True)
                    return

                if len(queue) > 0:
                    QMessageBox.information(None, self.organizer.window_title,
                        (
                            f"All of the One Pace files have been created in:\n"
                            f"{str(self.organizer.output_path)}\n\n"
                            f"Please move the\"{self.organizer.output_path.name}\" folder to the Plex library folder you've selected, "
                            "and make sure that it appears in Plex. Seasons and episodes will temporarily "
                            "have incorrect information, and the next step will correct them.\n\n"
                            "Click OK once this has been done and you can see the One Pace video files in Plex."
                        )
                    )

                    res = asyncio.create_task(self.organizer.process_plex_episodes(queue))
                    success, queue, completed, skipped = await res
                    self.log_output.append(f"Completed: {completed} processed, {skipped} skipped")
                else:
                    self.log_output.append(self.spacer)
                    self.log_output.append("Nothing to do")

            self.plex_server.prop.setEnabled(True)
            self.plex_library.prop.setEnabled(True)
            self.plex_show.prop.setEnabled(True)
            self.plex_remember_login.button.setEnabled(True)
            self.plex_remember_login.prop.setEnabled(True)
            await self.organizer.save_config()
            self.start_button.setEnabled(True)
            return

        res = await asyncio.create_task(self.organizer.start())
        if isinstance(res, tuple) and res[0]:
            success, data, completed, skipped = res
            self.log_output.append(f"Completed: {completed} processed, {skipped} skipped")

        await self.organizer.save_config()
        self.start_button.setEnabled(True)

def main(organizer, log_level):
    try:
        app = QApplication(sys.argv)
        close_event = asyncio.Event()
        app.aboutToQuit.connect(close_event.set)

        async def _run():
            await organizer.load_config()
            organizer.executor_func = concurrent.futures.ThreadPoolExecutor

            gui = GUI(organizer, log_level)
            gui.setWindowTitle(organizer.window_title)
            gui.show()

            is_latest, latest_vers = await utils.run(utils.is_up_to_date, organizer.toml["version"], organizer.base_path)
            if not is_latest:
                do_update = await asyncWrap(
                    QMessageBox.question(
                        None,
                        self.organizer.window_title,
                        "There is a newer version of this application. Do you wish to open up " +
                        "GitHub in order to download the new version?" +
                        "\n\n" +
                        f"Installed: v{organizer.toml['version']}\n" +
                        f"Latest: v{latest_vers}"
                    ) == QMessageBox.StandardButton.Yes
                )

                if do_update:
                    await utils.run(webbrowser.open_new_tab, "https://github.com/ladyisatis/OnePaceOrganizer/releases/latest")

            await close_event.wait()

        asyncio.run(_run(), loop_factory=QEventLoop)

    except:
        print(traceback.format_exc())
        QMessageBox.critical(None, organizer.window_title, traceback.format_exc())

    finally:
        asyncio.run(organizer.save_config())
