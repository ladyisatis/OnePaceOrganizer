import asyncio
import sys
import traceback

from functools import partial as func_partial
from pathlib import Path
from loguru import logger
from src import utils, organizer

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import message_dialog, input_dialog, yes_no_dialog, radiolist_dialog, button_dialog
from prompt_toolkit.application import Application
from prompt_toolkit.layout.containers import HSplit
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.layout import Layout
from prompt_toolkit.key_binding.defaults import load_key_bindings
from prompt_toolkit.key_binding.bindings.focus import focus_next, focus_previous
from prompt_toolkit.key_binding.key_bindings import KeyBindings, merge_key_bindings
from prompt_toolkit.widgets import (
    Box,
    Button,
    Dialog,
    Label,
    ProgressBar,
    TextArea,
)

class Console:
    def __init__(self, organizer=None, log_level="info"):
        self.log_level = log_level.upper()
        self.logger_id = 0
        self.log_output = TextArea(
            focusable=False,
            height=Dimension(preferred=10**10)
        )
        self.dialog_label = Label(text="")

        self.organizer = organizer.OnePaceOrganizer() if organizer is None else organizer
        self.organizer.message_dialog_func = self._message_dialog
        self.organizer.input_dialog_func = self._input_dialog
        self.window_title = self.organizer.window_title
        self.pb_lock = asyncio.Lock()

    def _set_logger_sink(self, sink):
        if sink is None:
            sink = sys.stderr

        if self.logger_id != 0:
            logger.remove(self.logger_id)

        self.logger_id = logger.add(
            sink=sink,
            level=self.log_level,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
            enqueue=True
        )

    def _message_dialog(self, text=""):
        return message_dialog(
            title=self.window_title,
            text=text
        ).run()

    def _input_dialog(self, text, default=""):
        return input_dialog(
            title=self.window_title,
            text=text,
            default=default
        ).run()

    async def run(self):
        self._set_logger_sink(sys.stderr)
        await self.organizer.load_config()

        is_latest, latest_vers = await utils.run(utils.is_up_to_date, self.organizer.toml["version"], self.organizer.base_path)
        if not is_latest:
            await message_dialog(
                title=self.window_title,
                text=
                    "Note: There is a new version of this application available, and can be downloaded from GitHub.\n\n" +
                    f"Installed: {self.organizer.toml['version']}\n" +
                    f"Latest: {latest_vers}"
            ).run_async()

        c = Path(self.organizer.base_path, "config.json")
        if await utils.run(c.is_file):
            _action = "Action after Sorting: Move"
            if self.organizer.file_action == 1:
                _action = "Action after Sorting: Copy"
            elif self.organizer.file_action == 2:
                _action = "Action after Sorting: Symlink"
            elif self.organizer.file_action == 3:
                _action = "Action after Sorting: Hardlink"
            elif self.organizer.file_action == 4:
                if self.organizer.plex_config_enabled:
                    _action = "Action after Sorting: Copy"
                    self.organizer.file_action = 1
                else:
                    _action = "After Scan: Generate metadata only"

            text = (
                f"Path to One Pace Files: {self.organizer.input_path}\n"
                f"Where to Place After Renaming: {self.organizer.output_path}\n"
                f"Action after Sorting: {_action}\n"
            )

            if self.organizer.plex_config_enabled:
                if self.organizer.plex_config_use_token:
                    plex_method = (
                        f"Plex Login Method: Authentication Token\n"
                        f"Plex Token: {'*'*len(self.organizer.plex_config_auth_token) if self.organizer.plex_config_auth_token != '' else '(not set)'}\n"
                        f"Remember Token: {'Yes' if self.organizer.plex_config_remember else 'No'}\n"
                    )
                else:
                    plex_method = (
                        f"Plex Login Method: Username and Password\n"
                        f"Plex Username: {self.organizer.plex_config_username if self.organizer.plex_config_username != '' else '(not set)'}\n"
                        f"Plex Password: {'*'*len(self.organizer.plex_config_password) if self.organizer.plex_config_password != '' else '(not set)'}\n"
                        f"Remember Username and Password: {'Yes' if self.organizer.plex_config_remember else 'No'}\n"
                    )

                if len(self.organizer.plex_config_servers) > 0 and self.organizer.plex_config_server_id in self.organizer.plex_config_servers:
                    plex_server = f"Plex Server: {self.organizer.plex_config_servers[self.organizer.plex_config_server_id]['name']}\n"
                else:
                    plex_server = ""

                if len(self.organizer.plex_config_libraries) > 0 and self.organizer.plex_config_library_key in self.organizer.plex_config_libraries:
                    plex_library = f"Plex Library: {self.organizer.plex_config_libraries[self.organizer.plex_config_library_key]['title']}\n"
                else:
                    plex_library = ""

                if len(self.organizer.plex_config_shows) > 0 and self.organizer.plex_config_show_guid in self.organizer.plex_config_shows:
                    plex_show = f"Plex Show: {self.organizer.plex_config_shows[self.organizer.plex_config_show_guid]['title']}\n"
                else:
                    plex_show = ""
                
                text = (
                    f"{text}"
                    "Mode: Plex\n"
                    f"{plex_method}"
                    f"{plex_server}"
                    f"{plex_library}"
                    f"{plex_show}"
                )
            else:
                text = (
                    f"{text}"
                    "Mode: .nfo (Jellyfin)\n"
                )

            yn = await button_dialog(
                title=self.window_title,
                text=f"A prior configuration was found. Do you want to use this?\n\n{text}",
                buttons=[
                    ("Yes", True),
                    ("No", False),
                    ("Exit", None)
                ]
            ).run_async()

            if yn == None:
                return 0

            elif yn:
                if self.organizer.plex_config_enabled:
                    logged_in = await self.organizer.plex_login()

                    if not logged_in:
                        success = await self.run_plex_wizard()
                        if not success:
                            return 1

                return await self.start_process()

        await message_dialog(
            title=self.window_title,
            text='Make sure to create a folder that has all of the One Pace video\nfiles! The next step will ask for the path to that directory.'
        ).run_async()

        if self.organizer.fetch_posters and not Path(".", "metadata", "posters").is_dir() and not Path(".", "posters").is_dir():
            self.organizer.fetch_posters = await yes_no_dialog(
                title=self.window_title,
                text="The posters folder is missing. Do you want to download the posters automatically?"
            ).run_async()

        proceed = False

        while not proceed:
            if self.organizer.input_path == "":
                self.organizer.input_path = Path(".", "in").resolve()

            self.organizer.input_path = await input_dialog(
                title=self.window_title,
                text='Directory of unsorted One Pace .mkv/mp4 files:',
                default=str(self.organizer.input_path)
            ).run_async()

            if self.organizer.input_path is None:
                return 0

            self.organizer.input_path = Path(self.organizer.input_path).resolve()

            if self.organizer.output_path == "":
                self.organizer.output_path = Path(".", "out").resolve()

            self.organizer.output_path = await input_dialog(
                title=self.window_title,
                text='Move the sorted/renamed files to:',
                default=str(self.organizer.output_path)
            ).run_async()

            if self.organizer.output_path is None:
                return 0

            self.organizer.output_path = Path(self.organizer.output_path).resolve()

            if str(self.organizer.input_path) == str(self.organizer.output_path):
                await message_dialog(
                    title=self.window_title,
                    text='The input folder should not be a subfolder of the output folder or vice-versa.'
                ).run_async()
            else:
                proceed = True

        self.organizer.plex_config_enabled = await yes_no_dialog(
            title=self.window_title,
            text='Are you watching via Plex?'
        ).run_async()

        yn = await yes_no_dialog(
            title=self.window_title,
            text='Show advanced settings?'
        ).run_async()

        if yn:
            values = [
                (0, "Move (recommended)"),
                (1, "Copy"),
                (2, "Symlink"),
                (3, "Hardlink")
            ]

            if not self.organizer.plex_config_enabled:
                values.append((4, "Generate metadata only (skip renames)"))

            self.organizer.file_action = await radiolist_dialog(
                title=self.window_title,
                text="What should be done with the One Pace video files after sorting?",
                values=values,
                default=self.organizer.file_action
            ).run_async()

            self.organizer.folder_action = await radiolist_dialog(
                title=self.window_title,
                text="How should seasons be created?",
                values=[
                    (0, "Season 01-09, 10-... (recommended)"),
                    (1, "Season 1-9, 10-..."),
                    (2, "Do not create season folders")
                ],
                default=self.organizer.folder_action
            ).run_async()

            if not self.organizer.plex_config_enabled:
                self.organizer.filename_tmpl = await input_dialog(
                    title=self.window_title,
                    text="Filename template: (see wiki for details)",
                    default=self.organizer.filename_tmpl
                ).run_async()

        if self.organizer.plex_config_enabled:
            success = await self.run_plex_wizard()
            if not success:
                return 1

        return await self.start_process()

    async def run_plex_wizard():
        authenticated = False

        self.organizer.plex_config_url = await input_dialog(
            title=self.window_title,
            text='URL to your Plex instance:',
            default=self.organizer.plex_config_url
        ).run_async()

        self.organizer.plex_config_use_token = await yes_no_dialog(
            title=self.window_title,
            text='Choose your Plex login method:',
            yes_text="Auth Token",
            no_text="User/Pass"
        ).run_async()

        while not authenticated:
            if self.organizer.plex_config_use_token:
                self.organizer.plex_config_auth_token = await input_dialog(
                    title=self.window_title,
                    text='Enter the authentication token:',
                    default=self.organizer.plex_config_auth_token,
                    password=True
                ).run_async()

                if self.organizer.plex_config_auth_token is None:
                    return False

                self.organizer.plex_config_username = str(await input_dialog(
                    title=self.window_title,
                    text='Plex Account Username:',
                    default=self.organizer.plex_config_username
                ).run_async())

                if self.organizer.plex_config_username is None:
                    return False

                self.organizer.plex_config_password = str(await input_dialog(
                    title=self.window_title,
                    text='Plex Account Password:',
                    default=self.plex_config_password,
                    password=True
                ).run_async())

                if self.organizer.plex_config_password is None:
                    return False

            self.organizer.plex_config_remember = await yes_no_dialog(
                title=self.window_title,
                text="Do you want to remember your Plex credentials?"
            ).run_async()

            authorized = await self.organizer.plex_login(True)

        if not await self.organizer.plex_get_servers():
            yn = await yes_no_dialog(
                title=self.window_title,
                text='Do you want to switch to Jellyfin (NFO) mode instead?',
            ).run_async()

            if yn:
                self.organizer.plex_config_enabled = False
                return True
            else:
                return False

        values = []
        default = None

        for id, server in self.organizer.plex_config_servers.items():
            values.append((id, server["name"]))

            if self.organizer.plex_config_server_id == id or server["selected"]:
                default = id

        server_id = await radiolist_dialog(
            title=self.window_title,
            text="Select the Plex Server:",
            values=values,
            default=default
        ).run_async()

        if server_id is None:
            return False

        if not await self.organizer.plex_select_server(server_id) or not await self.organizer.plex_get_libraries():
            return False

        values = []
        default = None

        for id, library in self.organizer.plex_config_libraries.items():
            values.append((id, library["title"]))

            if self.organizer.plex_config_library_key == id or library["selected"]:
                default = id

        library_key = await radiolist_dialog(
            title=self.window_title,
            text="Select the Plex Library:",
            values=values,
            default=default
        ).run_async()

        if library_key is None:
            return False

        await self.organizer.plex_select_library(library_key)

        if not await self.organizer.plex_get_shows():
            return False

        values = []
        default = None
        
        for id, show in self.organizer.plex_config_shows.items():
            values.append((id, show["title"]))

            if self.organizer.plex_config_show_guid == id or show["selected"]:
                default = id

        show_guid = await radiolist_dialog(
            title=self.window_title,
            text="Select the Plex show:",
            values=values,
            default=default
        ).run_async()

        if show_guid is None:
            return False

        await self.organizer.plex_select_show(show_guid)
        return True

    def progress_dialog(self):
        self.progress_bar = ProgressBar()

        def _btnpress():
            if self.button.text == "Continue" or self.process_task.done():
                self.pb_task.cancel()
            else:
                self.process_task.cancel()

        self.button = Button(text="Cancel", handler=_btnpress)

        bindings = KeyBindings()
        bindings.add("tab")(focus_next)
        bindings.add("s-tab")(focus_previous)

        _dialog = Dialog(
            body=HSplit(
                [
                    Box(self.dialog_label),
                    Box(self.log_output, padding=Dimension.exact(1)),
                    self.progress_bar,
                    Box(self.button)
                ]
            ),
            title=self.window_title,
            with_background=True
        )

        self.dialog = Application(
            layout=Layout(_dialog),
            key_bindings=merge_key_bindings([load_key_bindings(), bindings]),
            mouse_support=True,
            style=None,
            full_screen=True
        )
        
        return self.dialog

    def pb_progress(self, val):
        val = int(val)
        if val < 0 or val > 100:
            return

        self.progress_bar.percentage = val
        self.dialog.invalidate()

    def pb_label(self, text):
        level, text = text.split("|")

        if level.startswith("SUCCESS"):
            self.dialog_label.text = text
            self.dialog.invalidate()

    def pb_button_text(self, text):
        self.button.text = text
        self.dialog.invalidate()

    def pb_log_output(self, val):
        self.log_output.buffer.insert_text(val)
        self.dialog.invalidate()

    async def pb_exit(self):
        async with self.pb_lock:
            if self.pb_task:
                await self.pb_task

            if self.dialog.future is not None:
                await utils.run(self.dialog.exit, result=True)

    async def start_process(self):
        async with self.pb_lock:
            self.pb_task = asyncio.create_task(self.progress_dialog().run_async())

        self._set_logger_sink(self.pb_log_output)
        logger.add(sink=self.pb_label, level='SUCCESS', format='{level}|{message}', colorize=False)
        self.organizer.progress_bar_func = self.pb_progress

        self.process_task = asyncio.create_task(self.organizer.start())

        try:
            if self.organizer.plex_config_enabled and self.dialog.future is not None:
                success, queue, completed, skipped = await self.process_task

                if len(queue) > 0:
                    await utils.run(self.pb_log_output, f"Completed: {completed} processed, {skipped} skipped")
                    await utils.run(self.pb_log_output, "--------------")
                    await self.pb_exit()

                    await message_dialog(
                        title=self.window_title,
                        text=(
                                f"All of the One Pace files have been created in:\n"
                                f"{str(self.organizer.output_path)}\n\n"
                                f"Please move the\"{self.organizer.output_path.name}\" folder to the Plex library folder you've selected, "
                                "and make sure that it appears in Plex. Seasons and episodes will temporarily "
                                "have incorrect information, and the next step will correct them.\n\n"
                                "Click OK once this has been done and you can see the One Pace video files in Plex."
                            )
                    ).run_async()

                    async with self.pb_lock:
                        self.pb_task = asyncio.create_task(self.progress_dialog().run_async())

                    self.process_task = asyncio.create_task(self.organizer.process_plex_episodes(res))

            success, queue, completed, skipped = await self.process_task
            await utils.run(self.pb_log_output, f"Completed: {completed} processed, {skipped} skipped")

            async with self.pb_lock:
                if self.pb_task:
                    await self.pb_task

                if self.dialog.future is not None:
                    await utils.run(self.dialog.exit, result=True)

        except asyncio.CancelledError:
            if self.dialog.future is not None:
                await utils.run(self.pb_label, "Cancelled")
                await utils.run(self.pb_button_text, "Exit")

        finally:
            await self.organizer.save_config()

def main(organizer, log_level):
    code = asyncio.run(Console(organizer, log_level).run())
    sys.exit(code)