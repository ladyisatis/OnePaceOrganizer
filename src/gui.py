import asyncio
import concurrent.futures
import platform
import sys
import traceback
import webbrowser

from datetime import datetime
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
from PySide6.QtGui import QAction, QIcon
from PySide6.QtCore import Qt, Signal, QEvent

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

        _has_gui_x = "gui_x" in self.organizer.extra_fields and isinstance(self.organizer.extra_fields["gui_x"], int)
        _has_gui_y = "gui_y" in self.organizer.extra_fields and isinstance(self.organizer.extra_fields["gui_y"], int)
        _has_gui_width = "gui_width" in self.organizer.extra_fields and isinstance(self.organizer.extra_fields["gui_width"], int)
        _has_gui_height = "gui_height" in self.organizer.extra_fields and isinstance(self.organizer.extra_fields["gui_height"], int)

        if _has_gui_x and _has_gui_y and _has_gui_width and _has_gui_height:
            self.setGeometry(
                self.organizer.extra_fields["gui_x"],
                self.organizer.extra_fields["gui_y"],
                self.organizer.extra_fields["gui_width"],
                self.organizer.extra_fields["gui_height"]
            )

        try:
            current_os = platform.system()
            base_path = Path(sys._MEIPASS if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS') else 'misc')

            if current_os == "Windows" and Path(base_path, "icon.ico").is_file():
                self.setWindowIcon(QIcon(str(Path(base_path, "icon.ico").resolve())))
            elif current_os == "Darwin" and Path(base_path, "icon.icns").is_file():
                self.setWindowIcon(QIcon(str(Path(base_path, "icon.icns").resolve())))
            elif Path(base_path, "icon.png").is_file():
                self.setWindowIcon(QIcon(str(Path(base_path, "icon.png").resolve())))

        except:
            print(f"Skipping setting app icon:\n{traceback.format_exc()}")

        self.organizer.message_dialog_func = self._message_dialog
        self.organizer.input_dialog_func = self._input_dialog
        self.organizer.plex_jwt_func = self._plex_jwt
        self.plex_width = 125
        self.spacer = "------------------------------------------------------------------"

        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget)
        self.lock = asyncio.Lock()

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.organizer.progress_bar_func = self.progress_bar.setValue

        self.input_nometadata_str = "Directory of unsorted One Pace .mkv/.mp4 files:"
        self.input_metadata_str = "Directory of your One Pace collection:"
        self.input = Input(layout, self.input_nometadata_str, QLineEdit(), button="Browse...", connect=self.browse_input_folder)
        self.input.prop.setPlaceholderText(str(Path.home() / "Downloads"))
        self.input.setVisible(self.organizer.file_action != 4 if self.organizer.mode != 0 else True)
        if self.organizer.input_path != "":
            self.input.prop.setText(str(self.organizer.input_path))

        self.output = Input(layout, "Move the sorted and renamed files to:", QLineEdit(), button="Browse...", connect=self.browse_output_folder)
        self.output.prop.setPlaceholderText(str(Path("/", "path", "to", "plex_or_jellyfin", "Anime", "One Pace").resolve()))
        self.output.setVisible(self.organizer.file_action != 4)
        self._output_label_txt()
        if self.organizer.output_path != "":
            self.output.prop.setText(str(self.organizer.output_path))

        self.method = Input(layout, "I'm watching via...", QComboBox())
        self.method.prop.addItems([
            ".nfo (Jellyfin, Emby, etc.)",
            "Plex: Username and Password",
            "Plex: External Login",
            "Plex: Authorization Token"
        ])
        self.method.prop.setCurrentIndex(self.organizer.mode)
        self.method.prop.currentIndexChanged.connect(self.set_method)

        self.plex_group = QGroupBox("Plex")
        self.plex_group_layout = QVBoxLayout()
        _plex_remembered_login = self._plex_authenticated

        self.plex_token = Input(self.plex_group_layout, "Authorization Token:", QLineEdit(), width=self.plex_width)
        self.plex_token.prop.setEchoMode(QLineEdit.EchoMode.Password)
        self.plex_token.prop.setText(self.organizer.plex_config_auth_token)
        self.plex_token.setVisible(self.organizer.mode == 3)

        self.plex_status = Input(self.plex_group_layout, "Status:", QLabel(self.plex_status_text()), width=self.plex_width, button="Cancel", connect=self.plex_jwt_cancel)
        self.plex_status.setVisible(self.organizer.mode == 2)
        self.plex_status.button.setEnabled(False)

        self.plex_username = Input(self.plex_group_layout, "Username:", QLineEdit(), width=self.plex_width)
        self.plex_username.prop.setText(self.organizer.plex_config_username)
        self.plex_username.setVisible(self.organizer.mode == 1)

        self.plex_password = Input(self.plex_group_layout, "Password:", QLineEdit(), width=self.plex_width)
        self.plex_password.prop.setEchoMode(QLineEdit.EchoMode.Password)
        self.plex_password.prop.setText(self.organizer.plex_config_password)
        self.plex_password.setVisible(self.organizer.mode == 1)

        self.plex_remember_login = Input(
            self.plex_group_layout, 
            "", 
            QCheckBox("Remember"), 
            button="Disconnect" if _plex_remembered_login else "Login",
            connect=self.plex_login
        )
        self.plex_remember_login.prop.setChecked(self.organizer.plex_config_remember)

        self.plex_server = Input(self.plex_group_layout, "Server:", QComboBox(), width=self.plex_width)
        self.plex_server.prop.addItem("", userData="")

        i = 1
        for server_id, item in self.organizer.plex_config_servers.items():
            self.plex_server.prop.addItem(item["name"], userData=server_id)
            if item["selected"]:
                self.plex_server.prop.setCurrentIndex(i)
                self.organizer.plex_config_server_id = server_id
            i += 1

        self.plex_server.prop.activated.connect(self.select_plex_server)
        self.plex_server.setVisible(_plex_remembered_login)

        self.plex_library = Input(self.plex_group_layout, "Library:", QComboBox(), width=self.plex_width, button="Refresh", connect=self.refresh_plex_library)
        self.plex_library.prop.addItem("", userData=None)

        i = 1
        for library_key, item in self.organizer.plex_config_libraries.items():
            self.plex_library.prop.addItem(item["title"], userData=library_key)
            if item["selected"]:
                self.plex_library.prop.setCurrentIndex(i)
                if "key" in item:
                    self.organizer.plex_config_library_key = item["key"]
                else:
                    self.organizer.plex_config_library_key = library_key
            i += 1

        self.plex_library.prop.activated.connect(self.select_plex_library)
        self.plex_library.setVisible(_plex_remembered_login and self.organizer.plex_config_server_id != "")

        self.plex_show = Input(self.plex_group_layout, "Show:", QComboBox(), width=self.plex_width)
        self.plex_show.prop.addItem("(show not listed)", userData="")

        i = 1
        for show_guid, item in self.organizer.plex_config_shows.items():
            self.plex_show.prop.addItem(item["title"], userData=show_guid)
            if item["selected"]:
                self.plex_show.prop.setCurrentIndex(i)
                self.organizer.plex_config_show_guid = show_guid
            i += 1

        self.plex_show.prop.activated.connect(self.select_plex_show)
        self.plex_show.setVisible(_plex_remembered_login and not (self.organizer.plex_config_library_key is None or self.organizer.plex_config_library_key == "") and self.organizer.plex_config_server_id != "" and len(self.organizer.plex_config_servers) > 0 and len(self.organizer.plex_config_libraries) > 0)

        self.plex_group.setLayout(self.plex_group_layout)
        layout.addWidget(self.plex_group)

        if self.organizer.mode == 0:
            self.plex_group.hide()

        menu = self.menuBar()
        menu_file = menu.addMenu("&File")
        menu_configuration = menu.addMenu("&Configuration")
        self.menu_lang = menu.addMenu("&Language")
        menu_help = menu.addMenu("&Help")

        action_exit = QAction("Exit", self)
        action_exit.triggered.connect(self.exit)
        menu_file.addAction(action_exit)

        action_after_sort = menu_configuration.addMenu("Action after Scanning")

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

        self.action_after_sort_metadata = QAction("Update metadata only", self)
        self.action_after_sort_metadata.setCheckable(True)
        self.action_after_sort_metadata.setChecked(self.organizer.file_action == 4)
        self.action_after_sort_metadata.triggered.connect(func_partial(self.set_action, 4))
        action_after_sort.addAction(self.action_after_sort_metadata)

        self.action_season = menu_configuration.addMenu("Set Season Folder Names")
        self.action_season.menuAction().setVisible(self.organizer.mode == 0)
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
        self.action_edit_output_tmpl.setVisible(self.organizer.mode == 0)
        self.action_edit_output_tmpl.triggered.connect(self.edit_output_template)
        menu_configuration.addAction(self.action_edit_output_tmpl)

        self.action_edit_plex_url = QAction("Edit Plex Server URL", self)
        self.action_edit_plex_url.setVisible(self.organizer.mode != 0)
        self.action_edit_plex_url.triggered.connect(self.edit_plex_url)
        menu_configuration.addAction(self.action_edit_plex_url)

        self.action_overwrite_nfo = QAction("Overwrite .nfo Files", self)
        self.action_overwrite_nfo.setCheckable(True)
        self.action_overwrite_nfo.setChecked(self.organizer.overwrite_nfo)
        self.action_overwrite_nfo.setVisible(self.organizer.mode == 0)
        self.action_overwrite_nfo.triggered.connect(self.set_overwrite_nfo)
        menu_configuration.addAction(self.action_overwrite_nfo)

        self.action_set_show = QAction("Overwrite Show Information", self)
        self.action_set_show.setCheckable(True)
        self.action_set_show.setChecked(self.organizer.plex_set_show_edits)
        self.action_set_show.setVisible(self.organizer.mode != 0)
        self.action_set_show.triggered.connect(self.set_show_edits)
        menu_configuration.addAction(self.action_set_show)

        self.action_lockdata = QAction("Lock Fields after Edits", self)
        self.action_lockdata.setCheckable(True)
        self.action_lockdata.setChecked(self.organizer.lockdata)
        self.action_lockdata.triggered.connect(self.set_lockdata)
        menu_configuration.addAction(self.action_lockdata)

        self.action_fetch_posters = QAction("Fetch Posters if Missing", self)
        self.action_fetch_posters.setCheckable(True)
        self.action_fetch_posters.setChecked(self.organizer.fetch_posters)
        self.action_fetch_posters.triggered.connect(self.set_fetch_posters)
        menu_configuration.addAction(self.action_fetch_posters)


        menu_configuration.addSeparator()

        menu_advanced = menu_configuration.addMenu("Advanced")

        menu_advanced.addSeparator()

        self.action_edit_plex_retry_times = QAction("(Plex) Edit Maximum Retries", self)
        self.action_edit_plex_retry_times.setVisible(self.organizer.mode != 0)
        self.action_edit_plex_retry_times.triggered.connect(self.edit_plex_retry_times)
        menu_advanced.addAction(self.action_edit_plex_retry_times)

        self.action_edit_plex_retry_secs = QAction("(Plex) Edit Seconds Between Retries", self)
        self.action_edit_plex_retry_secs.setVisible(self.organizer.mode != 0)
        self.action_edit_plex_retry_secs.triggered.connect(self.edit_plex_retry_secs)
        menu_advanced.addAction(self.action_edit_plex_retry_secs)

        action_edit_workers = QAction("Edit Number of Workers", self)
        action_edit_workers.triggered.connect(self.edit_workers)
        menu_advanced.addAction(action_edit_workers)

        action_edit_metadata_url = QAction("Edit Metadata URL", self)
        action_edit_metadata_url.triggered.connect(self.edit_metadata_url)
        menu_advanced.addAction(action_edit_metadata_url)

        action_edit_download_path = QAction("Edit Download Path", self)
        action_edit_download_path.triggered.connect(self.edit_download_path)
        menu_advanced.addAction(action_edit_download_path)

        menu_advanced.addSeparator()

        menu_log_level = menu_advanced.addMenu("Log Level")

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

        self.action_log_level_6 = QAction("Trace", self)
        self.action_log_level_6.setCheckable(True)
        self.action_log_level_6.setChecked(self.log_level == "TRACE")
        self.action_log_level_6.triggered.connect(func_partial(self._set_logger, "TRACE"))
        menu_log_level.addAction(self.action_log_level_6)

        action_report_issue = QAction("Report Issue", self)
        action_report_issue.triggered.connect(lambda: webbrowser.open_new_tab("https://github.com/ladyisatis/OnePaceOrganizer/issues"))
        menu_help.addAction(action_report_issue)

        action_wiki = QAction("Wiki", self)
        action_wiki.triggered.connect(lambda: webbrowser.open_new_tab("https://github.com/ladyisatis/OnePaceOrganizer/wiki"))
        menu_help.addAction(action_wiki)

        action_about = QAction("About", self)
        action_about.triggered.connect(lambda: webbrowser.open_new_tab("https://github.com/ladyisatis/OnePaceOrganizer?tab=readme-ov-file#one-pace-organizer"))
        menu_help.addSeparator()
        menu_help.addAction(action_about)

        self.menu_lang.aboutToShow.connect(self.open_lang_menu)

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
        text = ",".join(m[2:]).rstrip("\n")
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
        self.input.label.setText(self.input_metadata_str if self.organizer.file_action == 4 else self.input_nometadata_str)
        self.input.setVisible(self.organizer.file_action != 4 if self.organizer.mode != 0 else True)

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

    def moveEvent(self, event):
        if not self.isMaximized():
            _pos = event.pos()
            self.organizer.extra_fields["gui_x"] = _pos.x()
            self.organizer.extra_fields["gui_y"] = _pos.y()

        super().moveEvent(event)

    def resizeEvent(self, event):
        if not self.isMaximized():
            _size = event.size()
            self.organizer.extra_fields["gui_width"] = _size.width()
            self.organizer.extra_fields["gui_height"] = _size.height()

        super().resizeEvent(event)

    def changeEvent(self, event):
        if event.type() == QEvent.Type.WindowStateChange:
            _maximized = self.isMaximized()
            self.organizer.extra_fields["gui_maximized"] = _maximized
            if _maximized:
                _geo = self.normalGeometry()
                self.organizer.extra_fields["gui_x"] = _geo.x()
                self.organizer.extra_fields["gui_y"] = _geo.y()
                self.organizer.extra_fields["gui_width"] = _geo.width()
                self.organizer.extra_fields["gui_height"] = _geo.height()

        super().changeEvent(event)

    def browse_input_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Input Folder")
        if not folder or folder == "":
            return

        if Path(folder).resolve() == Path(self.output.prop.text()).resolve() and self.organizer.file_action != 4:
            QMessageBox.information(None, self.organizer.window_title, "The input folder should not be the same as the output folder.")
            return

        if len(folder) > 2 and (folder.startswith("\\\\") or folder.startswith("//")):
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

        if len(folder) > 2 and (folder.startswith("\\\\") or folder.startswith("//")):
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

    @asyncSlot()
    async def refresh_plex_library(self):
        self.plex_server.prop.setEnabled(False)
        self.plex_library.prop.setEnabled(False)
        self.plex_show.prop.setEnabled(False)
        logger.info("Refreshing list of libraries...")

        try:
            self.plex_library.prop.clear()
            self.plex_library.prop.addItem("Loading...", userData=None)

            if not await self.organizer.plex_get_libraries():
                await self.organizer.save_config()
                self.plex_library.prop.clear()
                self.plex_library.prop.addItem("", userData=None)
                return

            self.plex_library.prop.clear()
            self.plex_library.prop.addItem("", userData=None)

            for identifier, item in self.organizer.plex_config_libraries.items():
                self.plex_library.prop.addItem(item["title"], userData=identifier)

            logger.info("Reloaded all Plex libraries")

        finally:
            await self.organizer.save_config()
            self._update_start_btn()
            self.plex_server.prop.setEnabled(True)
            self.plex_library.prop.setEnabled(True)
            self.plex_show.prop.setEnabled(False)

    def _update_start_btn(self):
        self.start_button.setEnabled(
            self.organizer.mode == 0 or (
                self.organizer.mode != 0 and
                self.organizer.plex_config_server_id != "" and 
                self.organizer.plex_config_library_key != None
            )
        )

    def set_method(self, mode):
        self.organizer.mode = mode
        self._update_start_btn()
        plex_enabled = self.organizer.mode != 0

        self._plex_toggle_login(plex_enabled)
        self.plex_group.setVisible(plex_enabled)
        self.action_season.menuAction().setVisible(not plex_enabled)
        self.action_edit_output_tmpl.setVisible(not plex_enabled)
        self.action_edit_plex_url.setVisible(plex_enabled)
        self.action_edit_plex_retry_times.setVisible(plex_enabled)
        self.action_edit_plex_retry_secs.setVisible(plex_enabled)
        self.action_overwrite_nfo.setVisible(not plex_enabled)
        self.action_set_show.setVisible(plex_enabled)
        self.output.setVisible(self.organizer.file_action != 4)
        self.input.label.setText(self.input_metadata_str if self.organizer.file_action == 4 else self.input_nometadata_str)
        self.input.setVisible(self.organizer.file_action != 4 if plex_enabled else True)

    def set_lockdata(self):
        self.organizer.lockdata = not self.organizer.lockdata
        self.action_lockdata.setChecked(self.organizer.lockdata)

    def _plex_toggle_enabled(self, enable_all: bool):
        self.plex_token.prop.setEnabled(enable_all)
        self.plex_username.prop.setEnabled(enable_all)
        self.plex_password.prop.setEnabled(enable_all)
        self.plex_remember_login.prop.setEnabled(enable_all)
        self.plex_remember_login.button.setEnabled(enable_all)
        self.plex_server.prop.setEnabled(enable_all)
        self.plex_library.prop.setEnabled(enable_all)
        self.plex_show.prop.setEnabled(enable_all)

    def _plex_toggle_login(self, is_visible: bool):
        if is_visible:
            self.plex_token.setVisible(self.organizer.mode == 3)
            self.plex_status.setVisible(self.organizer.mode == 2)
            self.plex_username.setVisible(self.organizer.mode == 1)
            self.plex_password.setVisible(self.organizer.mode == 1)
        else:
            self.plex_token.setVisible(False)
            self.plex_status.setVisible(False)
            self.plex_username.setVisible(False)
            self.plex_password.setVisible(False)

    def set_lang(self, lang):
        if isinstance(lang, str):
            logger.info(f"Setting language to: {lang}")
        else:
            logger.info(f"Setting language to: {lang.autonym()} ({lang.display_name()})")

        self.organizer.store.language = lang

    @asyncSlot()
    async def open_lang_menu(self):
        if len(self.organizer.store.langs) == 0:
            self.menu_lang.clear()
            loading_action = QAction("Loading...", self)
            loading_action.setEnabled(False)
            self.menu_lang.addAction(loading_action)

        if not self.organizer.opened:
            data_file = Path(self.organizer.base_path, "metadata", "data.db")
            if await utils.is_file(data_file):
                try:
                    await self.organizer.open_db(data_file)
                finally:
                    await self.organizer.store.close()

        self.menu_lang.clear()
        if len(self.organizer.store.langs) == 0:
            default_action = QAction("English", self)
            default_action.setCheckable(True)
            default_action.setChecked(self.organizer.store.language.startswith("en"))
            default_action.triggered.connect(func_partial(self.set_lang, "en"))
            self.menu_lang.addAction(default_action)
            return

        for lang in self.organizer.store.langs:
            action = QAction(lang.autonym(), self)
            action.setCheckable(True)
            action.setChecked(self.organizer.store.lang == lang)
            action.triggered.connect(func_partial(self.set_lang, lang))
            self.menu_lang.addAction(action)

    @property
    def _plex_authenticated(self):
        if self.organizer.plexapi_account is not None or self.organizer.plexapi_server is not None:
            return True

        if self.organizer.plex_last_login is not None and datetime.now() >= self.organizer.plex_last_login:
            return False

        if self.organizer.plex_config_remember and (self.organizer.mode == 1 or self.organizer.mode == 3) and self.organizer.plex_config_auth_token != "":
            return True

        if self.organizer.mode == 2 and self.organizer.plex_jwt_token != "":
            return True

        return False

    def plex_jwt_cancel(self):
        if self.plex_status.button.isEnabled():
            try:
                self.plex_status.prop.setText("Cancelling...")
                if self.organizer._jwtlogin is not None:
                    self.organizer._jwtlogin.stop()

            except Exception as e:
                logger.trace(e)
            finally:
                self.organizer.plex_jwt_token = ""
                self.organizer.plex_last_login = None
                self.plex_status.button.setEnabled(False)
                self.plex_status.prop.setText("Cancelled")

    def _plex_jwt(self, step, data):
        if step == 0:
            self.plex_status.prop.setText(f"Logging into Plex...")
        elif step == 1:
            self.plex_status.prop.setText(f"Setting up authorization...")
        elif step == 2:
            self.plex_status.prop.setText(f"Opened web browser, waiting {self.organizer.plex_jwt_timeout}s for authorization...")
            webbrowser.open_new_tab(data)
        elif step == 3:
            if data:
                self.plex_status.prop.setText(f"Logged in, retrieving credentials...")
            else:
                self.plex_status.prop.setText("Unable to log in to Plex")

    def plex_status_text(self):
        if self.organizer.plexapi_account is not None:
            return f"Logged in as {self.organizer.plexapi_account.username}"

        if self.organizer.plex_jwt_token != "":
            return "Logged in"

        return "Not logged in"

    @asyncSlot()
    async def plex_login(self):
        if not self.plex_remember_login.button.isEnabled():
            return

        if self.plex_remember_login.button.text() == "Disconnect":
            self.plex_remember_login.button.setEnabled(False)

            self.organizer.plex_config_servers = {}
            self.organizer.plex_config_server_id = ""
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""

            if self.organizer.plexapi_account is not None:
                await utils.run(self.organizer.plexapi_account.signout)
                self.organizer.plexapi_account = None

            if self.organizer.plexapi_server is not None:
                self.organizer.plexapi_server = None

            self.organizer.plex_config_auth_token = ""
            self.organizer.plex_jwt_token = ""
            self.organizer.plex_last_login = None

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
            self.plex_status.prop.setText(self.plex_status_text())
            return

        self._plex_toggle_enabled(False)
        await self.organizer.save_config()

        self.organizer.plex_config_remember = self.plex_remember_login.prop.checkState() == Qt.Checked

        if self.organizer.mode == 3:
            self.organizer.plex_config_auth_token = self.plex_token.prop.text()
        elif self.organizer.mode == 1:
            self.organizer.plex_config_username = self.plex_username.prop.text()
            self.organizer.plex_config_password = self.plex_password.prop.text()

        self.plex_status.prop.setText(self.plex_status_text())
        self.plex_status.button.setEnabled(True)
        if not await self.organizer.plex_login(True):
            self.plex_status.button.setEnabled(False)

            logger.info("Could not log in, please try again")
            self.organizer.plex_config_servers = {}
            self.organizer.plex_config_server_id = ""
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""

            if self.organizer.plexapi_account is not None:
                self.organizer.plexapi_account = None

            if self.organizer.plexapi_server is not None:
                self.organizer.plexapi_server = None

            self.organizer.plex_config_auth_token = ""
            self.organizer.plex_jwt_token = ""
            self.organizer.plex_last_login = None
            self.plex_status.prop.setText(self.plex_status_text())

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

        logger.info("Logged in")
        self.plex_status.button.setEnabled(False)
        logger.trace(self.organizer.plexapi_account.authenticationToken)
        self.plex_status.prop.setText(self.plex_status_text())
        self.plex_remember_login.button.setText("Disconnect")
        self.plex_remember_login.button.setEnabled(True)
        self._plex_toggle_login(False)
        self.start_button.setEnabled(False)

        self.plex_server.prop.setEnabled(True)
        await self.plex_get_servers()

    @asyncSlot()
    async def plex_get_servers(self):
        if not self.plex_server.prop.isEnabled():
            return

        logger.debug("Verifying Plex login")
        if not await self.organizer.plex_login():
            self.organizer.plex_config_servers = {}
            self.organizer.plex_config_server_id = ""
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""

            if self.organizer.plexapi_account is not None:
                self.organizer.plexapi_account = None

            if self.organizer.plexapi_server is not None:
                self.organizer.plexapi_server = None

            self.organizer.plex_config_auth_token = ""
            self.organizer.plex_jwt_token = ""
            self.organizer.plex_last_login = None

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

        self.plex_status.prop.setText(self.plex_status_text())
        logger.info("Fetching Plex Servers")
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
            self.plex_library.setVisible(False)
            self.plex_show.setVisible(False)
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

        self.plex_server.setEnabled(False)

        _id = self.plex_server.prop.currentData()
        if _id is None or _id == "":
            self.plex_server.setEnabled(True)
            logger.debug("No Plex server is selected")
            self.organizer.plexapi_server = None
            self.organizer.plex_config_server_id = ""
            await self.plex_get_servers()
            self.plex_server.setVisible(True)
            self.plex_library.setVisible(False)
            self.plex_show.setVisible(False)
            self.start_button.setEnabled(False)
            return

        logger.debug("Verifying Plex login")
        if not await self.organizer.plex_login():
            self.organizer.plex_config_servers = {}
            self.organizer.plex_config_server_id = ""
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""

            if self.organizer.plexapi_account is not None:
                self.organizer.plexapi_account = None

            if self.organizer.plexapi_server is not None:
                self.organizer.plexapi_server = None

            self.organizer.plex_config_auth_token = ""
            self.organizer.plex_jwt_token = ""
            self.organizer.plex_last_login = None

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
            self.plex_status.prop.setText(self.plex_status_text())
            return

        self.plex_status.prop.setText(self.plex_status_text())

        logger.debug("Selecting Plex server")
        if not await self.organizer.plex_select_server(_id):
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""
            await self.organizer.save_config()
            self.plex_server.setVisible(True)
            self.plex_server.setEnabled(True)
            self.plex_library.setVisible(False)
            self.plex_show.setVisible(False)
            self.start_button.setEnabled(False)
            return

        self.plex_server.setEnabled(True)
        self.plex_server.setVisible(True)
        self.plex_library.setVisible(True)
        self.plex_show.setVisible(False)

        self.plex_library.prop.setEnabled(False)
        self.plex_library.prop.clear()
        self.plex_library.prop.addItem("Loading...", userData=None)

        if not await self.organizer.plex_get_libraries():
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""
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
            self.organizer.plex_config_servers = {}
            self.organizer.plex_config_server_id = ""
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""

            if self.organizer.plexapi_account is not None:
                self.organizer.plexapi_account = None

            if self.organizer.plexapi_server is not None:
                self.organizer.plexapi_server = None

            self.organizer.plex_config_auth_token = ""
            self.organizer.plex_jwt_token = ""
            self.organizer.plex_last_login = None

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
            self.plex_status.prop.setText(self.plex_status_text())
            return

        self.plex_status.prop.setText(self.plex_status_text())
        await self.organizer.plex_select_library(int(_id))
        self.plex_server.setVisible(True)
        self.plex_library.setVisible(True)
        self.plex_show.setVisible(True)

        self.plex_show.prop.setEnabled(False)
        self.plex_show.prop.clear()
        self.plex_show.prop.addItem("Loading...", userData=None)

        if not await self.organizer.plex_get_shows():
            self.plex_show.prop.clear()
            self.plex_show.prop.addItem("", userData="")
            self.plex_show.prop.setEnabled(True)
            return

        self.plex_show.prop.clear()
        self.plex_show.prop.addItem("(show not listed)", userData="")

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

        if not await self.organizer.plex_login():
            self.organizer.plex_config_servers = {}
            self.organizer.plex_config_server_id = ""
            self.organizer.plex_config_libraries = {}
            self.organizer.plex_config_library_key = None
            self.organizer.plex_config_shows = {}
            self.organizer.plex_config_show_guid = ""

            if self.organizer.plexapi_account is not None:
                self.organizer.plexapi_account = None

            if self.organizer.plexapi_server is not None:
                self.organizer.plexapi_server = None

            self.organizer.plex_config_auth_token = ""
            self.organizer.plex_jwt_token = ""
            self.organizer.plex_last_login = None

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
            self.plex_status.prop.setText(self.plex_status_text())
            return

        await self.organizer.plex_select_show(_id)
        await self.organizer.save_config()
        self._update_start_btn()
        self.plex_status.prop.setText(self.plex_status_text())

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

    @asyncSlot()
    async def edit_output_template(self):
        _sp = " " * 100
        _fn = await self._input_dialog(f"Enter the template for the filename:{_sp}", self.organizer.filename_tmpl)
        if _fn is not None and _fn != "":
            self.organizer.filename_tmpl = _fn

    @asyncSlot()
    async def edit_plex_retry_times(self):
        _sp = " " * 100
        _fn = await self._input_dialog(f"Enter maximum number of retries:{_sp}", str(self.organizer.plex_retry_times))
        if _fn is not None and _fn != "":
            self.organizer.plex_retry_times = int(_fn)

    @asyncSlot()
    async def edit_plex_retry_secs(self):
        _sp = " " * 100
        _fn = await self._input_dialog(f"Enter seconds to wait before retries:{_sp}", str(self.organizer.plex_retry_secs))
        if _fn is not None and _fn != "":
            self.organizer.plex_retry_secs = int(_fn)

    @asyncSlot()
    async def edit_plex_url(self):
        _sp = " " * 100
        _fn = await self._input_dialog(f"Enter Plex URL to directly connect to: (leave blank to go via Plex's servers instead){_sp}", self.organizer.plex_config_url)
        if _fn is not None:
            if "://app.plex.tv/" in _fn or "://plex.tv/" in _fn:
                await self._message_dialog("Plex URL is invalid as it should be a direct URL to the instance. " +
                    "(You should probably leave this blank to go through Plex's servers automatically.)")
            else:
                self.organizer.plex_config_url = _fn

    @asyncSlot()
    async def edit_workers(self):
        _sp = " " * 100
        _workers = "0" if self.organizer.workers is None else str(self.organizer.workers)
        _fn = await self._input_dialog(f"Enter number of workers for threads/processes: (0 = Auto){_sp}", _workers)
        if _fn is not None and _fn != "":
            _fn = int(_fn)
            self.organizer.workers = None if _fn < 1 else _fn

    @asyncSlot()
    async def edit_metadata_url(self):
        _sp = " " * 100
        _fn = await self._input_dialog(f"Enter metadata URL:{_sp}", self.organizer.metadata_url)
        if _fn is not None and _fn != "":
            self.organizer.metadata_url = _fn

    @asyncSlot()
    async def edit_download_path(self):
        _sp = " " * 100
        _fn = await self._input_dialog(f"Enter download path:{_sp}", self.organizer.download_path)
        if _fn is not None and _fn != "":
            self.organizer.download_path = _fn

    def set_fetch_posters(self):
        self.organizer.fetch_posters = not self.organizer.fetch_posters
        self.action_fetch_posters.setChecked(self.organizer.fetch_posters)

    def set_overwrite_nfo(self):
        self.organizer.overwrite_nfo = not self.organizer.overwrite_nfo
        self.action_overwrite_nfo.setChecked(self.organizer.overwrite_nfo)

    def set_show_edits(self):
        self.organizer.plex_set_show_edits = not self.organizer.plex_set_show_edits
        self.action_set_show.setChecked(self.organizer.plex_set_show_edits)

    @asyncSlot()
    async def start(self):
        self.start_button.setEnabled(False)
        self.log_output.append(self.spacer)

        self.organizer.input_path = Path(self.input.prop.text())
        self.organizer.output_path = Path(self.output.prop.text())

        if self.organizer.mode != 0:
            guid = self.organizer.plex_config_show_guid
            self.plex_server.prop.setEnabled(False)
            self.plex_library.prop.setEnabled(False)
            self.plex_show.prop.setEnabled(False)
            self.plex_remember_login.button.setEnabled(False)
            self.plex_remember_login.prop.setEnabled(False)

            logger.debug("Checking Plex connection")
            if not await self.organizer.plex_login():
                logger.info("Plex credentials have expired - please re-login")
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
                logger.info("Connecting to Plex server")
                await self.organizer.plex_get_servers()

                if self.organizer.plexapi_server is None and self.organizer.plex_config_server_id is not None and self.organizer.plex_config_server_id != "":
                    await self.organizer.plex_select_server(self.organizer.plex_config_server_id)

            if "new_show" in self.organizer.extra_fields and guid != "":
                del self.organizer.extra_fields["new_show"]
                old_file_action = self.organizer.file_action
                self.organizer.file_action = 4 # Set metadata only mode

                res = asyncio.create_task(self.process_plex_episodes([], True))
                success, queue, completed, skipped = await res
                self.log_output.append(self.spacer)
                self.log_output.append(f"Completed: {completed} processed, {skipped} skipped")

                self.organizer.file_action = old_file_action

            else:
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

                    if guid != "":
                        if isinstance(queue, list) and len(queue) > 0:
                            QMessageBox.information(None, self.organizer.window_title,
                                (
                                    "All of the One Pace files have been created in:\n"
                                    f"{str(self.organizer.output_path)}\n\n"
                                    f"Please move the\"{self.organizer.output_path.name}\" folder to the Plex library folder you've selected, "
                                    "and make sure that it appears in Plex. Seasons and episodes will temporarily "
                                    "have incorrect information, and the next step will correct them.\n\n"
                                    "Click OK once this has been done and you can see the One Pace video files in Plex."
                                )
                            )

                            res = asyncio.create_task(self.organizer.process_plex_episodes(queue))
                            success, queue, completed, skipped = await res
                            self.log_output.append(self.spacer)
                            self.log_output.append(f"Completed: {completed} processed, {skipped} skipped")
                        else:
                            self.log_output.append(self.spacer)
                            self.log_output.append("Nothing to do")

                    elif guid == "":
                        self.organizer.extra_fields["new_show"] = True
                        self.log_output.append(self.spacer)
                        self.log_output.append((
                            "All of the One Pace files have been created in:\n"
                            f"{str(self.organizer.output_path)}\n\n"
                            f"Please move the\"{self.organizer.output_path.name}\" folder to the Plex library folder you've selected, "
                            "and make sure that it appears in Plex. When all seasons and episodes appear in Plex, click Refresh to the "
                            "right of the selected library and select the show, then click Start again."
                        ))

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

            if "gui_maximized" in organizer.extra_fields and isinstance(organizer.extra_fields["gui_maximized"], bool) and organizer.extra_fields["gui_maximized"]:
                gui.showMaximized()
            else:
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
