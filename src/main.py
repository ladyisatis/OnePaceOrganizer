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
    if isinstance(file, str):
        file = Path(file)

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

class OnePaceOrganizer():
    def __init__(self):
        self.tvshow = {}
        self.episodes = {}
        self.seasons = {}

        self.version = "?"
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

        self.window_title = f"One Pace Organizer v{self.version} - github.com/ladyisatis/OnePaceOrganizer"

        self.pb_task = None
        self.process_task = None
        self.progress_bar = None
        self.dialog_label = None
        self.log_output = None
        self.button = None
        self.dialog = None
        self.pb_lock = asyncio.Lock()

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

    def check_none(self, val):
        if val == None:
            print("User clicked Cancel")
            sys.exit(1)

    async def run(self):
        if self.input_path != "" and self.output_path != "":
            text = (
                "A prior configuration was found. Do you want to use this?\n\n"
                f"Path to One Pace Files: {self.input_path}\n"
                f"Where to Place After Renaming: {self.output_path}\n"
            )

            if self.plex_config_enabled:
                if self.plex_config_use_token:
                    plex_method = (
                        f"Plex Login Method: Authentication Token\n"
                        f"Plex Token: {'*'*len(self.plex_config_auth_token) if self.plex_config_auth_token != '' else '(not set)'}\n"
                        f"Remember Token: {'Yes' if self.plex_config_remember else 'No'}\n"
                    )
                else:
                    plex_method = (
                        f"Plex Login Method: Username and Password\n"
                        f"Plex Username: {self.plex_config_username if self.plex_config_username != '' else '(not set)'}\n"
                        f"Plex Password: {'*'*len(self.plex_config_password) if self.plex_config_password != '' else '(not set)'}\n"
                        f"Remember Username and Password: {'Yes' if self.plex_config_remember else 'No'}\n"
                    )

                if len(self.plex_config_servers) > 0 and self.plex_config_server_id in self.plex_config_servers:
                    plex_server = f"Plex Server: {self.plex_config_servers[self.plex_config_server_id]['name']}\n"
                else:
                    plex_server = ""

                if len(self.plex_config_libraries) > 0 and self.plex_config_library_key in self.plex_config_libraries:
                    plex_library = f"Plex Library: {self.plex_config_libraries[self.plex_config_library_key]['title']}\n"
                else:
                    plex_library = ""

                if len(self.plex_config_shows) > 0 and self.plex_config_show_guid in self.plex_config_shows:
                    plex_show = f"Plex Show: {self.plex_config_shows[self.plex_config_show_guid]['title']}\n"
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

            yn = await yes_no_dialog(
                title=self.window_title,
                text=text
            ).run_async()

            if yn:
                if self.plex_config_enabled:
                    logged_in = await self.plex_login()

                    if not logged_in:
                        await self.run_plex_wizard()

                await self.start_process()
                return

        else:
            await message_dialog(
                title=self.window_title,
                text='Make sure to create a folder that has all of the One Pace video\nfiles! The next step will ask for the path to that directory.'
            ).run_async()

        if self.input_path == "":
            self.input_path = str(Path(".", "in").resolve())

        self.input_path = Path(await input_dialog(
            title=self.window_title,
            text='Directory of unsorted One Pace .mkv/mp4 files:',
            default=self.input_path
        ).run_async()).resolve()

        self.check_none(self.input_path)

        if self.output_path == "":
            self.output_path = str(Path(".", "out").resolve())
        
        self.output_path = Path(await input_dialog(
            title=self.window_title,
            text='Move the sorted/renamed files to:',
            default=self.output_path
        ).run_async()).resolve()

        self.check_none(self.output_path)

        self.plex_config_enabled = await yes_no_dialog(
            title=self.window_title,
            text='Are you watching via Plex?'
        ).run_async()

        if self.plex_config_enabled:
            await self.run_plex_wizard()

        await self.start_process()

    async def run_plex_wizard(self):
        self.plex_config_use_token = await yes_no_dialog(
            title=self.window_title,
            text='Choose your Plex login method:',
            yes_text="Auth Token",
            no_text="User/Pass"
        ).run_async()

        authorized = False

        while not authorized:
            if self.plex_config_use_token:
                self.plex_config_auth_token = await input_dialog(
                    title=self.window_title,
                    text='Enter the authentication token:',
                    default=self.plex_config_auth_token,
                    password=True
                ).run_async()

                self.check_none(self.plex_config_auth_token)

            else:
                self.plex_config_username = await input_dialog(
                    title=self.window_title,
                    text='Plex Account Username:',
                    default=self.plex_config_username
                ).run_async()

                self.check_none(self.plex_config_username)

                self.plex_config_password = await input_dialog(
                    title=self.window_title,
                    text='Plex Account Password:',
                    default=self.plex_config_password,
                    password=True
                ).run_async()

                self.check_none(self.plex_config_password)

            self.plex_config_remember = await yes_no_dialog(
                title=self.window_title,
                text="Do you want to remember your Plex credentials?"
            ).run_async()

            authorized = await self.plex_login()

        if len(self.plex_config_servers) == 0:
            yn = await yes_no_dialog(
                title=self.window_title,
                text='Error: There are no Plex servers to choose from. Do you want to switch to Jellyfin (NFO) mode instead?',
            ).run_async()

            if yn:
                self.plex_config_enabled = False
                return
            else:
                await message_dialog(
                    title=self.window_title,
                    text="Please ensure there's at least one Plex server available."
                ).run_async()
                sys.exit(1)

        if self.plexapi_server == None:
            values = []
            default = None

            for id, server in self.plex_config_servers.items():
                values.append((id, server["name"]))

                if self.plex_config_server_id == id or server["selected"]:
                    default = id

            self.plex_config_server_id = await radiolist_dialog(
                title=self.window_title,
                text="Select the Plex Server:",
                values=values,
                default=default
            ).run_async()

            self.check_none(self.plex_config_server_id)

            resources = await run_sync(self.plexapi_account.resources)
            for resource in resources:
                if resource.clientIdentifier == self.plex_config_server_id:
                    self.plexapi_server = await run_sync(resource.connect)
                    self.plex_config_servers[resource.clientIdentifier]["selected"] = True
                else:
                    self.plex_config_servers[resource.clientIdentifier]["selected"] = False

        self.plex_config_libraries = {}

        values = []
        default = None

        sections = await run_sync(self.plexapi_server.library.sections)
        for section in sections:
            if section.type == 'show':
                values.append((section.key, section.title))

                selected = self.plex_config_library_key == section.key
                self.plex_config_libraries[section.key] = {
                    "title": section.title,
                    "selected": selected
                }

                if selected:
                    default = section.key

        self.plex_config_library_key = await radiolist_dialog(
            title=self.window_title,
            text="Select the Plex Library:",
            values=values,
            default=default
        ).run_async()

        self.check_none(self.plex_config_library_key)

        self.plex_config_libraries[self.plex_config_library_key]["selected"] = True

        self.plex_config_shows = {}

        values = []
        default = None

        section = await run_sync(self.plexapi_server.library.sectionByID, self.plex_config_library_key)
        shows = await run_sync(section.all)

        for show in shows:
            values.append((show.guid, show.title))

            selected = self.plex_config_show_guid == show.guid
            self.plex_config_shows[show.guid] = {
                "title": show.title,
                "selected": selected
            }

            if selected:
                default = show.guid

        self.plex_config_show_guid = await radiolist_dialog(
            title=self.window_title,
            text="Select the Plex show:",
            values=values,
            default=default
        ).run_async()

        self.check_none(self.plex_config_show_guid)

        self.plex_config_shows[self.plex_config_show_guid]["selected"] = True

    async def plex_login(self):
        if self.plexapi_account != None:
            self.plexapi_account = None

            if not self.plex_config_use_token and self.plex_config_auth_token != "":
                self.plex_config_auth_token = ""

        if self.plex_config_auth_token != '' and self.plex_config_remember:
            try:
                self.plexapi_account = await run_sync(MyPlexAccount, token=self.plex_config_auth_token)
            except:
                self.plexapi_account = None

        if self.plexapi_account == None:
            self.plex_config_servers = {}
            self.plex_config_libraries = {}
            self.plex_config_shows = {}

            if self.plex_config_use_token:
                try:
                    self.plexapi_account = await run_sync(MyPlexAccount, token=self.plex_config_auth_token)

                except PlexApiUnauthorized:
                    await message_dialog(
                        title=self.window_title,
                        text="Invalid Plex account token, please try again."
                    ).run_async()
                    return False

                except:
                    e = traceback.format_exc()
                    await message_dialog(
                        title=self.window_title,
                        text=f"Unknown error: {e}"
                    ).run_async()
                    print(e)
                    return False

            else:
                try:
                    self.plexapi_account = await run_sync(
                        MyPlexAccount,
                        username=self.plex_config_username,
                        password=self.plex_config_password,
                        remember=self.plex_config_remember
                    )

                except PlexApiTwoFactorRequired:
                    unauthorized = True

                    while unauthorized:
                        code = await input_dialog(
                            title=self.window_title,
                            text="Enter the 2-Factor Authorization Code for your Plex Account:"
                        ).run_async()

                        self.check_none(code)

                        if code == "":
                            continue

                        try:
                            self.plexapi_account = await run_sync(
                                MyPlexAccount,
                                username=self.plex_config_username,
                                password=self.plex_config_password,
                                remember=self.plex_config_remember,
                                code=int(code)
                            )
                            unauthorized = False
                        except:
                            await message_dialog(
                                title=self.window_title,
                                text="Invalid 2-Factor Auth code, please try again."
                            ).run_async()

                except PlexApiUnauthorized:
                    return False

                except:
                    e = traceback.format_exc()
                    await message_dialog(
                        title=self.window_title,
                        text=f"Unknown error: {e}"
                    ).run_async()
                    return False

            if self.plex_config_remember:
                self.plex_config_auth_token = self.plexapi_account.authenticationToken
            else:
                self.plex_config_auth_token = ""
                self.plex_config_username = ""
                self.plex_config_password = ""

        resources = await run_sync(self.plexapi_account.resources)

        self.plexapi_server = None
        self.plex_config_servers = {}

        if len(resources) == 1:
            self.plex_config_servers[resources[0].clientIdentifier] = {
                "name": resources[0].name,
                "selected": True
            }

            self.plex_config_server_id = resources[0].clientIdentifier
            self.plexapi_server = resources[0].connect()

        else:
            for i, resource in enumerate(resources):
                selected = self.plex_config_server_id == resource.clientIdentifier

                self.plex_config_servers[resource.clientIdentifier] = {
                    "name": resource.name,
                    "selected": selected
                }

                if selected:
                    self.plexapi_server = await run_sync(resource.connect)

        return True

    def progress_dialog(self):
        self.progress_bar = ProgressBar()
        self.dialog_label = Label(text="")
        self.log_output = TextArea(
            focusable=False,
            height=Dimension(preferred=10**10)
        )

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

    async def pb_progress(self, val):
        val = int(val)
        if val > 100:
            return

        self.progress_bar.percentage = val
        await run_sync(self.dialog.invalidate)

    async def pb_label(self, text):
        self.dialog_label.text = text
        asyncio.get_event_loop().call_soon_threadsafe(self.log_output.buffer.insert_text, f"{text}\n")
        await run_sync(self.dialog.invalidate)

    async def pb_button_text(self, text):
        self.button.text = text
        await run_sync(self.dialog.invalidate)

    async def pb_log_output(self, val):
        asyncio.get_event_loop().call_soon_threadsafe(self.log_output.buffer.insert_text, f"{val}\n")
        await run_sync(self.dialog.invalidate)

    async def start_process(self):
        async with self.pb_lock:
            self.pb_task = asyncio.create_task(self.progress_dialog().run_async())

        self.process_task = asyncio.create_task(self.start_process_task())

        try:
            await self.process_task

            async with self.pb_lock:
                if self.pb_task:
                    await self.pb_task

            if self.dialog.future != None:
                await run_sync(self.dialog.exit, result=True)

        except asyncio.CancelledError:
            if self.dialog.future != None:
                await self.pb_label("Cancelled")
                await self.pb_button_text("Exit")

    async def start_process_task(self):
        try:
            has_data = await self.cache_episode_data()
            if has_data:
                await self.pb_log_output(f"{self.tvshow['title']} metadata loaded: {len(self.seasons)} seasons, {len(self.episodes)} episodes")

                video_files = await self.glob_video_files()

                if self.plex_config_enabled:
                    await self.start_process_plex(video_files)
                else:
                    await self.start_process_jellyfin(video_files)
            else:
                await self.pb_log_output("Exiting due to a lack of metadata - grab data.json and put it in the same directory.")

        except:
            await self.pb_log_output(traceback.format_exc())
        
        finally:
            await self.pb_button_text("Exit")

    async def cache_episode_data(self):
        yml_loaded = await self.cache_yml()

        await self.pb_label("Checking episode metadata file (data.json)...")

        data_file = Path(".", "data.json")
        data = {}
        now = datetime.datetime.now(datetime.timezone.utc)

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

            last_update = datetime.datetime.fromtimestamp(data_file.stat().st_mtime).astimezone(datetime.timezone.utc)
            if now - last_update < datetime.timedelta(hours=1):
                self.tvshow = data["tvshow"] if "tvshow" in data else {}
                self.seasons = data["seasons"] if "seasons" in data else {}
                self.episodes = data["episodes"] if "episodes" in data else {}
                return True

        if yml_loaded == False or len(self.tvshow) == 0 or len(self.seasons) == 0 or len(self.episodes) == 0:
            url = "https://raw.githubusercontent.com/ladyisatis/onepaceorganizer/refs/heads/main/data.json"

            await self.pb_log_output(f"Downloading: {url}")

            try:
                client = httpx.AsyncClient()
                data_file = Path(".", "data.json")

                with data_file.open(mode='w') as f:
                    async with client.stream('GET', url, follow_redirects=True) as resp:
                        #clen = int(resp.headers['Content-Length'])
                        #dl_len = 0

                        async for chunk in resp.aiter_bytes():
                            #dl_len = dl_len + len(chunk)
                            #await self.pb_progress(int((dl_len / clen) * 100))
                            await run_sync(f.write, chunk)

                data = await run_sync(orjson.loads, data_file.read_bytes())
                if len(data) > 0:
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.seasons = data["seasons"] if "seasons" in data else {}
                    self.episodes = data["episodes"] if "episodes" in data else {}
      
            except:
                await self.pb_log_output.append(f"Unable to download new metadata: {traceback.format_exc()}")

        return len(self.tvshow) > 0 and len(self.seasons) > 0 and len(self.episodes) > 0

    async def cache_yml(self):
        try:
            data_folder = Path(".", "data")
            episodes_folder = Path(data_folder, "episodes")

            if not episodes_folder.is_dir():
                return False

            await self.pb_label("data/episodes folder detected, loading metadata from folder")

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

            await self.pb_progress(0)

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

                await self.pb_progress(int((index + 1 / total_files) * 100))

            await self.pb_progress(100)

        except:
            await self.pb_progress(0)
            await self.pb_log_output(f"Skipping using data/episodes for metadata: {traceback.format_exc()}")
            return False

        return True

    async def glob_video_files(self):
        #await self.pb_log_output(self.spacer)
        await self.pb_label("Searching for .mkv and .mp4 files...")

        crc_pattern = re.compile(r'\[([A-Fa-f0-9]{8})\](?=\.(mkv|mp4))')

        video_files = []
        filelist = []

        async for file in glob(self.input_path, "**/*.[mM][kK][vV]"):
            filelist.append(file)

        async for file in glob(self.input_path, "**/*.[mM][pP]4"):
            filelist.append(file)

        await self.pb_progress(0)

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
                await self.pb_log_output(f"Calculating for {file_path}...")
                crc32 = await async_crc32(file_path)
                num_calced = num_calced + 1

            await self.pb_progress(int((index + 1 / filelist_total) * 100))

            if crc32 in self.episodes:
                video_files.append((crc32, file_path))

            elif file.suffix.lower() == '.mkv':
                try:
                    with file_path.open(mode='rb') as f:
                        mkv = await run_sync(enzyme.MKV, f)

                    if mkv == None or mkv.info == None or mkv.info.title == None or mkv.info.title == "":
                        await self.pb_log_output(f"Skipping {file.name}: Episode metadata missing, infering information from MKV also failed")
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
                        await self.pb_log_output(f"Skipping {file.name}: Episode metadata missing, infering information from MKV also failed")

                except:
                    await self.pb_log_output(f"Skipping {file.name}: Episode metadata missing, infering information from MKV also failed")

            else:
                await self.pb_log_output(f"Skipping {file.name}: Episode metadata missing")

        await self.pb_progress(100)
        await self.pb_label(f"Found: {num_found}, Calculated: {num_calced}, Total: {filelist_total}")

        return video_files

    async def start_process_plex(self, video_files):
        await self.pb_progress(0)
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

        await self.pb_label("Moving the video files...")

        for crc32, file_path in video_files:
            episode_info = self.episodes[crc32]

            if isinstance(episode_info, list):
                stop = True

                for v in episode_info:
                    if "hashes" not in episode_info or "blake2" not in episode_info["hashes"] or not episode_info["hashes"]["blake2"]:
                        await self.pb_log_output(f"Skipping {file_path.name}: Blake2s 16-character hash is required but not provided")

                    elif await async_blake2s_16(file_path) == episode_info["hashes"]["blake2"]:
                        stop = False
                        episode_info = v
                        break

                if stop:
                    i = i + 1
                    num_skipped = num_skipped + 1
                    await self.pb_progress(int((i / len(video_files)) * 100))
                    continue

            season = episode_info["season"]
            episode = episode_info["episode"]

            season_path = Path(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")

            if not season_path.is_dir():
                await run_sync(season_path.mkdir, exist_ok=True)

            if not "title" in episode_info or episode_info["title"] == "":
                await self.pb_log_output(f"Skipping {file_path.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                i = i + 1
                num_skipped = num_skipped + 1
                await self.pb_progress(int((i / len(video_files)) * 100))
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
            await self.pb_progress(int((i / len(video_files)) * 100))

        await self.pb_progress(100)
        await self.pb_label("")
        await self.pb_button_text("Continue")

        await self.pb_log_output(
            (
                f"All of the One Pace files have been created in:\n"
                f"{str(self.output_path)}\n\n"
                f"Please move the\"{self.output_path.name}\" folder to the Plex library folder you've selected, "
                "and make sure that it appears in Plex. Seasons and episodes will temporarily "
                "have incorrect information, and the next step will correct them.\n\n"
                "Click OK once this has been done and you can see the One Pace video files in Plex."
            )
        )

        # New progress bar
        try:
            async with self.pb_lock:
                await self.pb_task
        except:
            pass
        finally:
            if self.dialog.future != None:
                await run_sync(self.dialog.exit, result=None)

        async with self.pb_lock:
            self.pb_task = asyncio.create_task(self.progress_dialog().run_async())

        done = []

        await self.pb_progress(0)
        await self.pb_label("Setting information for all seasons and episodes...")

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
                    await self.pb_log_output("Updating Season: {new_title}")

                    plex_season.editTitle(new_title)
                    plex_season.editSummary(season_info["description"])
                    await run_sync(plex_season.uploadPoster, filepath=str(Path(self.posters_path, f"season{season}-poster.png")))

            plex_episode = await run_sync(show.episode, season=season, episode=episode_info["episode"])

            if plex_episode.title != episode_info["title"]:
                await self.pb_log_output("Updating Season: {season} Episode: {episode_info['episode']}")

                plex_episode.editTitle(episode_info["title"])
                plex_episode.editContentRating(episode_info["rating"] if "rating" in episode_info else self.tvshow["rating"])
                plex_episode.editSortTitle(episode_info["sorttitle"] if "sorttitle" in episode_info else episode_info["title"].replace("The ", "", 1))

                if "released" in episode_info:
                    if isinstance(episode_info["released"], datetime.date):
                        plex_episode.editOriginallyAvailable(episode_info["released"].isoformat())
                    else:
                        plex_episode.editOriginallyAvailable(str(episode_info["released"]))

                desc_str = episode_info["description"] if "description" in episode_info and episode_info["description"] != "" else ""
                manga_str = ""
                anime_str = ""

                if episode_info["manga_chapters"] != "":
                    if desc_str != "":
                        manga_str = f"\n\nManga Chapter(s): {episode_info['manga_chapters']}"
                    else:
                        manga_str = f"Manga Chapter(s): {episode_info['manga_chapters']}"

                if episode_info["anime_episodes"] != "":
                    if desc_str != "" or manga_str != "":
                        anime_str = f"\n\nAnime Episode(s): {episode_info['anime_episodes']}"
                    else:
                        anime_str = f"Anime Episode(s): {episode_info['anime_episodes']}"

                description = f"{desc_str}{manga_str}{anime_str}"

                plex_episode.editSummary(description)

                num_complete = num_complete + 1

            await self.pb_progress(int((i+1 / len(queue)) * 100))

        await self.pb_progress(100)
        #await self.pb_log_output(self.spacer)
        await self.pb_label(f"Completed: {len(done)} seasons updated, {num_complete} episodes updated, {num_skipped} skipped")

    async def start_process_jellyfin(self, video_files):
        await self.pb_progress(0)
        self.output_path.mkdir(exist_ok=True)

        await self.pb_label("Creating episode metadata and moving the video files...")

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

            await self.pb_log_output(f"Copying {src} to: {dst}")
            await run_sync(shutil.copy, src, dst)

            art = ET.SubElement(root, "art")
            ET.SubElement(art, "poster").text = dst

            ET.indent(root)

            await self.pb_log_output(f"Writing tvshow.nfo to: {tvshow_nfo.resolve()}")

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
                        await self.pb_log_output(f"Skipping {file_path.name}: Blake2s 16-character hash is required but not provided")

                    elif await async_blake2s_16(file_path) == episode_info["hashes"]["blake2"]:
                        stop = False
                        episode_info = v
                        break

                if stop:
                    i = i + 1
                    num_skipped = num_skipped + 1
                    await self.pb_progress(int((i / len(video_files)) * 100))
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

                await self.pb_log_output(f"Copying {src} to: {dst}")
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
                await self.pb_log_output(f"Skipping {file_path.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                i = i + 1
                num_skipped = num_skipped + 1
                await self.pb_progress(int((i / len(video_files)) * 100))
                continue

            prefix = f"One Pace - S{season:02d}E{episode_info['episode']:02d} - "
            safe_title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"])

            new_video_file_path = Path(season_path, f"{prefix}{safe_title}{file_path.suffix}")

            await self.pb_log_output(f"Moving {file_path.name} to: {new_video_file_path}")

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
            await self.pb_progress(int((i / len(video_files)) * 100))

        await self.pb_progress(100)
        #await self.pb_log_output(self.spacer)
        await self.pb_label(f"Completed: {num_complete} episodes updated, {num_skipped} skipped")

if __name__ == "__main__":
    opo = None

    try:
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            freeze_support()

        opo = OnePaceOrganizer()
        asyncio.run(opo.run())

    except asyncio.CancelledError:
        pass

    except Exception:
        print(traceback.format_exc())

    finally:
        if opo != None:
            opo.save_config()
