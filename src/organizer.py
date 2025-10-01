import asyncio
import concurrent.futures
import datetime
import enzyme
import xml.etree.ElementTree as ET
import functools
import hashlib
import httpx
import orjson
import os
import plexapi
import re
import signal
import shutil
import sys
import tomllib
import traceback
import yaml
import zlib

from loguru import logger
from plexapi.exceptions import TwoFactorRequired as PlexApiTwoFactorRequired, Unauthorized as PlexApiUnauthorized, NotFound as PlexApiNotFound
from plexapi.myplex import MyPlexAccount
from plexapi.server import PlexServer
from pathlib import Path, UnsupportedOperation
from multiprocessing import freeze_support
from src import utils

class OnePaceOrganizer:
    def __init__(self):
        self.window_title = "One Pace Organizer"
        self.tvshow = {}
        self.episodes = {}
        self.arcs = []

        self.workers = int(utils.get_env("workers", 0))
        self.base_path = Path(utils.get_env("base_path", Path.cwd().resolve()))
        self.metadata_url = utils.get_env("metadata_url", "https://raw.githubusercontent.com/ladyisatis/one-pace-metadata/refs/heads/main")
        self.download_path = utils.get_env("dl_path", "https://raw.githubusercontent.com/ladyisatis/OnePaceOrganizer/refs/heads/main")
        self.set_executor(utils.get_env("pool_mode", "process") == "process")

        if self.workers == 0:
            self.workers = None

        self.config_file = Path(utils.get_env("config_path", f"{self.base_path}/config.json"))
        self.file_action = int(utils.get_env("file_action", 0))
        self.folder_action = int(utils.get_env("folder_action", 0))
        self.fetch_posters = utils.get_env("fetch_posters", True)
        self.overwrite_nfo = utils.get_env("overwrite_nfo", False)
        self.lockdata = utils.get_env("lockdata", False)

        self.input_path = utils.get_env("input_path")
        self.output_path = utils.get_env("output_path")
        self.filename_tmpl = utils.get_env("filename_tmpl", "One Pace - S{arc:02d}E{episode:02d} - {title}{suffix}")

        self.plexapi_account: MyPlexAccount = None
        self.plexapi_server: PlexServer = None
        self.plex_config_enabled = utils.get_env("plex_enabled", False)
        self.plex_config_url = utils.get_env("plex_url", "http://127.0.0.1:32400")

        self.plex_config_servers = {}
        self.plex_config_server_id = utils.get_env("plex_server")

        self.plex_config_libraries = {}
        self.plex_config_library_key = utils.get_env("plex_library")

        self.plex_config_shows = {}
        self.plex_config_show_guid = utils.get_env("plex_show")

        self.plex_config_use_token = utils.get_env("plex_use_token", False)
        self.plex_config_auth_token = utils.get_env("plex_auth_token")
        self.plex_config_username = utils.get_env("plex_username")
        self.plex_config_password = utils.get_env("plex_password")
        self.plex_config_remember = utils.get_env("plex_remember", False)
        self.plex_config_server_baseurl = utils.get_env("plex_server_baseurl", "")
        self.plex_config_server_token = utils.get_env("plex_server_token", "")
        self.plex_code = utils.get_env("plex_code", "")
        self.plex_retry_secs = utils.get_env("plex_retry_secs", 30)
        self.plex_retry_times = utils.get_env("plex_retry_times", 3)

        self.progress_bar_func = None
        self.message_dialog_func = None
        self.input_dialog_func = None
        self.worker_task = None
        self.toml = None
        self.logger = logger

    async def load_config(self):
        if self.toml is None or self.toml["version"] == "?":
            self.toml = utils.get_toml_info(self.base_path)

        self.window_title = f"One Pace Organizer v{self.toml['version']} - github.com/ladyisatis/OnePaceOrganizer"

        if self.config_file is not None and self.config_file != "" and not isinstance(self.config_file, Path):
            self.config_file = Path(self.config_file)

        if self.config_file is None or self.config_file == "" or not await utils.is_file(self.config_file):
            return False

        config = {}

        if self.config_file.suffix == ".json":
            config = await utils.load_json(self.config_file)
        elif self.config_file.suffix == ".yml" or self.config_file.suffix == ".yaml":
            config = await utils.load_yaml(self.config_file)

        self.logger.trace(config)

        if "path_to_eps" in config:
            self.input_path = await utils.resolve(config["path_to_eps"])

        if "input" in config and config["input"] is not None:
            self.input_path = await utils.resolve(config["input"])

        if "episodes" in config:
            self.output_path = await utils.resolve(config["episodes"])

        if "output" in config and config["output"] is not None:
            self.output_path = await utils.resolve(config["output"])

        if "move_after_sort" in config and config["move_after_sort"] is not None:
            self.file_action = 0 if config["move_after_sort"] else 1
        
        if "file_action" in config and config["file_action"] is not None:
            self.file_action = config["file_action"]

        if "folder_action" in config and config["folder_action"] is not None:
            self.folder_action = config["folder_action"]

        if "fetch_posters" in config and config["fetch_posters"] is not None:
            self.fetch_posters = config["fetch_posters"]

        if "overwrite_nfo" in config and config["overwrite_nfo"] is not None:
            self.overwrite_nfo = config["overwrite_nfo"]

        if "filename_tmpl" in config and config["filename_tmpl"] is not None:
            self.filename_tmpl = config["filename_tmpl"]

        if "plex" in config:
            if "enabled" in config["plex"] and config["plex"]["enabled"] is not None:
                self.plex_config_enabled = config["plex"]["enabled"]

            if "url" in config["plex"] and config["plex"]["url"] is not None:
                self.plex_config_url = config["plex"]["url"]

            if "servers" in config["plex"] and isinstance(config["plex"]["servers"], dict):
                self.plex_config_servers = config["plex"]["servers"]
                for server_id, item in self.plex_config_servers.items():
                    if item["selected"]:
                        self.plex_config_server_id = server_id
                        break

            if "libraries" in config["plex"] and isinstance(config["plex"]["libraries"], dict):
                self.plex_config_libraries = config["plex"]["libraries"]
                for library_key, item in self.plex_config_libraries.items():
                    if item["selected"]:
                        self.plex_config_library_key = library_key
                        break

            if "shows" in config["plex"] and isinstance(config["plex"]["shows"], dict):
                self.plex_config_shows = config["plex"]["shows"]
                for show_guid, item in self.plex_config_shows.items():
                    if item["selected"]:
                        self.plex_config_show_guid = show_guid
                        break

            if "use_token" in config["plex"] and config["plex"]["use_token"] is not None:
                self.plex_config_use_token = config["plex"]["use_token"]

            if "token" in config["plex"] and config["plex"]["token"] is not None:
                self.plex_config_auth_token = config["plex"]["token"]

            if "username" in config["plex"] and config["plex"]["username"] is not None:
                self.plex_config_username = config["plex"]["username"]

            if "password" in config["plex"] and config["plex"]["password"] is not None:
                self.plex_config_password = config["plex"]["password"]

            if "remember" in config["plex"] and config["plex"]["remember"] is not None:
                self.plex_config_remember = config["plex"]["remember"]

            if "server_baseurl" in config["plex"] and config["plex"]["server_baseurl"] is not None:
                self.plex_config_server_baseurl = config["plex"]["server_baseurl"]

            if "server_token" in config["plex"] and config["plex"]["server_token"] is not None:
                self.plex_config_server_token = config["plex"]["server_token"]

        return True

    async def save_config(self):
        if self.config_file is None or self.config_file == "":
            return False

        if self.config_file is not None and not isinstance(self.config_file, Path):
            self.config_file = Path(self.config_file)

        out = {
            "input": str(self.input_path),
            "output": str(self.output_path),
            "file_action": self.file_action,
            "folder_action": self.folder_action,
            "fetch_posters": self.fetch_posters,
            "overwrite_nfo": self.overwrite_nfo,
            "filename_tmpl": self.filename_tmpl,
            "plex": {
                "enabled": self.plex_config_enabled,
                "url": self.plex_config_url,
                "servers": self.plex_config_servers,
                "server_baseurl": self.plex_config_server_baseurl,
                "server_token": self.plex_config_server_token,
                "libraries": self.plex_config_libraries,
                "shows": self.plex_config_shows,
                "use_token": self.plex_config_use_token,
                "token": self.plex_config_auth_token,
                "username": self.plex_config_username,
                "password": self.plex_config_password,
                "remember": self.plex_config_remember
            }
        }

        if self.config_file.suffix == ".yml" or self.config_file.suffix == ".yaml":
            await utils.write_file(self.config_file, await utils.run(yaml.safe_dump, out))
            return

        out = await utils.run(orjson.dumps, out, option=orjson.OPT_NON_STR_KEYS)
        return await utils.write_file(self.config_file, out)

    def set_executor(self, process=True):
        self.executor_func = concurrent.futures.ProcessPoolExecutor if process else concurrent.futures.ThreadPoolExecutor

    async def plex_login(self, force_login=False):
        if force_login:
            self.plexapi_account = None
            self.plexapi_server = None
            self.plex_config_auth_token = ""
            self.plex_config_server_baseurl = ""
            self.plex_config_server_token = ""

        if self.plexapi_account is None and not self.plex_config_use_token and self.plex_config_auth_token != "" and self.plex_config_remember:
            try:
                self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_config_auth_token)
            except:
                self.logger.debug(traceback.format_exc())
                self.plex_config_auth_token = ""
                self.plexapi_account = None

        if self.plexapi_account is None:
            self.plex_config_servers = {}
            self.plex_config_libraries = {}
            self.plex_config_shows = {}

            if self.plex_config_use_token:
                try:
                    self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_config_auth_token)

                except PlexApiUnauthorized:
                    if self.message_dialog_func is not None:
                        self.logger.debug(traceback.format_exc())
                        await utils.run_func(self.message_dialog_func, "Invalid Plex account token, please try again.")
                    else:
                        self.logger.exception("Invalid Plex account token, please try again.")

                    return False

                except:
                    if self.message_dialog_func is not None:
                        await utils.run_func(self.message_dialog_func, f"Unknown error\n\n{traceback.format_exc()}")
                    else:
                        self.logger.exception("Unknown error")

                    return False

            else:
                try:
                    self.plexapi_account = await utils.run(MyPlexAccount,
                        username=self.plex_config_username, 
                        password=self.plex_config_password, 
                        remember=self.plex_config_remember
                    )

                except PlexApiTwoFactorRequired:
                    self.logger.debug(traceback.format_exc())
                    unauthorized = True

                    while unauthorized:
                        if self.input_dialog_func is not None:
                            code = await utils.run_func(self.input_dialog_func, "Enter the 2-Factor Authorization Code for your Plex Account:")
                        else:
                            code = self.plex_code

                        if code == "":
                            return False

                        try:
                            self.plexapi_account = await utils.run(
                                MyPlexAccount,
                                username=self.plex_config_username,
                                password=self.plex_config_password,
                                remember=self.plex_config_remember,
                                code=int(code)
                            )
                            unauthorized = False
                        except:
                            self.logger.trace(traceback.format_exc())

                            if self.input_dialog_func is None or self.message_dialog_func is None:
                                self.logger.error("Invalid 2-Factor Auth code, please try again.")
                                return False
                            else:
                                await utils.run_func(self.message_dialog_func, "Invalid 2-Factor Auth code, please try again.")

                except PlexApiUnauthorized:
                    self.logger.trace(traceback.format_exc())
                    return False

                except:
                    if self.message_dialog_func is None:
                        self.logger.exception("Unknown error")
                    else:
                        await utils.run_func(self.message_dialog_func, f"Unknown error!\n\n{traceback.format_exc()}")

                    return False

            if self.plex_config_remember:
                self.plex_config_auth_token = self.plexapi_account.authenticationToken
            else:
                self.plex_config_auth_token = ""
                self.plex_config_username = ""
                self.plex_config_password = ""

        return self.plexapi_account is not None and self.plexapi_account.authenticationToken != ""

    async def plex_get_servers(self):
        if self.plex_config_remember and self.plex_config_server_baseurl != "" and self.plex_config_server_token != "":
            try:
                self.plexapi_server = await utils.run(PlexServer, baseurl=self.plex_config_server_baseurl, token=self.plex_config_server_token)
            except:
                self.plexapi_server = None
                self.plex_config_server_token = ""
                self.plex_config_server_baseurl = ""
        else:
            self.plexapi_server = None

        if self.plexapi_account is None:
            return self.plexapi_server is not None

        self.plex_config_servers = {}

        try:
            resources = await utils.run(self.plexapi_account.resources)
        except:
            self.logger.exception("Unable to find Plex servers")
            return False

        if len(resources) == 0:
            if self.message_dialog_func is None:
                self.logger.error("Unable to find any Plex servers on this account.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to find any Plex servers on this account.")

            return False

        elif len(resources) == 1:
            self.plex_config_servers[resources[0].clientIdentifier] = {
                "name": resources[0].name,
                "selected": True
            }

            self.plex_config_server_id = resources[0].clientIdentifier

            self.logger.info(f"Connecting to {resources[0].name} ({resources[0].clientIdentifier})")

            try:
                self.plexapi_server = await utils.run(resources[0].connect)
                self.logger.info("Connected")

            except:
                self.logger.exception(f"Unable to connect to Plex server '{resources[0].name}'")
                return False

        else:
            for i, resource in enumerate(resources):
                selected = self.plex_config_server_id == resource.clientIdentifier

                self.logger.trace(f"found: {resource.clientIdentifier} ({resource.name}, selected={selected})")
                self.plex_config_servers[resource.clientIdentifier] = {
                    "name": resource.name,
                    "selected": selected
                }

                if selected:
                    self.logger.info(f"Connecting to {resource.name} ({resource.clientIdentifier})")

                    try:
                        self.plexapi_server = await utils.run(resource.connect)
                        self.logger.info("Connected")

                    except:
                        self.logger.exception(f"Unable to connect to Plex server '{resource.name}'")
                        return False

        if self.plex_config_remember and self.plex_config_server_token == "":
            self.plex_config_server_baseurl = self.plexapi_server._baseurl
            self.plex_config_server_token = self.plexapi_server._token

        return self.plexapi_server is not None

    async def plex_select_server(self, server_id):
        if server_id == "" or server_id is None:
            self.logger.error("Plex server is blank")
            return False

        resources = await utils.run(self.plexapi_account.resources)

        for resource in resources:
            try:
                if resource.clientIdentifier == server_id:
                    self.plexapi_server = await utils.run(resource.connect)
                    self.plex_config_server_id = resource.clientIdentifier

                    for id, item in self.plex_config_servers.items():
                        self.plex_config_servers[id]["selected"] = self.plex_config_server_id == resource.clientIdentifier

                    break
            except:
                self.logger.exception(f"Unable to connect to Plex server '{resource.name}'")
                return False

        return True

    async def plex_get_libraries(self):
        if self.plexapi_server is None:
            connected = await self.plex_select_server(self.plex_config_server_id)
            if not connected:
                return False

        self.plex_config_libraries = {}

        try:
            self.logger.trace("plex_get_libraries: fetching all library sections")
            sections = await utils.run(self.plexapi_server.library.sections)
            self.logger.trace(f"plex_get_libraries: found {len(sections)} total sections")
        except Exception as e:
            self.logger.error(f"plex_get_libraries: Exception occurred: {e}")
            self.logger.error(f"plex_get_libraries: Full traceback: {traceback.format_exc()}")
            if self.message_dialog_func is None:
                self.logger.error("Unable to fetch Plex libraries from this server.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to fetch Plex libraries from this server.")

            return False

        for section in sections:
            self.logger.trace(f"plex_get_libraries: section '{section.title}' (type: {section.type}, key: {section.key})")
            if section.type == 'show':
                section_key_str = str(section.key)
                selected = self.plex_config_library_key == section_key_str
                self.plex_config_libraries[section_key_str] = {
                    "title": section.title,
                    "selected": selected
                }
                self.logger.trace(f"plex_get_libraries: added show library '{section.title}' (key: {section_key_str}, selected: {selected})")

        self.logger.trace(f"plex_get_libraries: available libraries keys: {list(self.plex_config_libraries.keys())}")
        self.logger.trace(f"plex_get_libraries: returning {len(self.plex_config_libraries)} > 0 = {len(self.plex_config_libraries) > 0}")
        return len(self.plex_config_libraries) > 0

    async def plex_select_library(self, library_key):
        self.logger.trace(f"plex_select_library: Looking for key '{library_key}' (type: {type(library_key)})")
        self.logger.trace(f"plex_select_library: Available keys: {list(self.plex_config_libraries.keys())}")

        if library_key not in self.plex_config_libraries:
            self.logger.error(f"plex_select_library: Library key '{library_key}' not found in available libraries")
            return False

        self.plex_config_library_key = library_key

        for k, v in self.plex_config_libraries.items():
            self.plex_config_libraries[k]["selected"] = library_key == k

        self.logger.trace(f"plex_select_library: Selected library '{library_key}'")
        return True

    async def plex_get_shows(self):
        if self.plexapi_server is None or self.plex_config_library_key == "":
            self.logger.trace("plex_get_shows: server is None or library key is empty")
            return False

        self.plex_config_shows = {}

        try:
            self.logger.trace(f"plex_get_shows: getting section by ID {self.plex_config_library_key}")
            section = await utils.run(self.plexapi_server.library.sectionByID, int(self.plex_config_library_key))
            self.logger.trace(f"plex_get_shows: section retrieved: {section.title}")

            self.logger.trace("plex_get_shows: getting all shows from section")
            shows = await utils.run(section.all)
            self.logger.trace(f"plex_get_shows: found {len(shows)} shows")
        except Exception as e:
            self.logger.error(f"plex_get_shows: Exception occurred: {e}")
            self.logger.error(f"plex_get_shows: Full traceback: {traceback.format_exc()}")
            if self.message_dialog_func is None:
                self.logger.error("Unable to fetch Plex shows from this server.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to fetch Plex shows from this server.")

            return False

        if len(shows) == 0:
            self.logger.warning(f"plex_get_shows: No shows found in library '{section.title}' (ID: {self.plex_config_library_key})")
            return False

        for show in shows:
            selected = self.plex_config_show_guid == show.guid
            self.plex_config_shows[show.guid] = {
                "title": show.title,
                "selected": selected
            }
            self.logger.trace(f"plex_get_shows: added show '{show.title}' with GUID '{show.guid}' (selected: {selected})")

        self.logger.trace(f"plex_get_shows: returning {len(self.plex_config_shows)} > 0 = {len(self.plex_config_shows) > 0}")
        return len(self.plex_config_shows) > 0

    async def plex_select_show(self, guid):
        self.logger.trace(f"plex_select_show: Looking for GUID '{guid}' (type: {type(guid)})")
        self.logger.trace(f"plex_select_show: Available GUIDs: {list(self.plex_config_shows.keys())}")

        if guid.startswith("local://"):
            self.logger.debug(f"plex_select_show: GUID '{guid}' is a local:// GUID, skipping lookup in available shows")
            self.plex_config_show_guid = guid
            return True

        if guid not in self.plex_config_shows:
            self.logger.error(f"plex_select_show: Show GUID '{guid}' not found in available shows")
            return False

        self.plex_config_show_guid = guid

        for k, v in self.plex_config_shows.items():
            self.plex_config_shows[k]["selected"] = guid == k

        self.logger.trace(f"plex_select_show: Selected show '{guid}'")
        return True
    
    async def plex_art_set(self, art_file, episode, is_poster=True):
        if not isinstance(art_file, Path):
            art_file = Path(self.base_path, "posters", file)

        if await utils.is_file(art_file):
            arts = await utils.run(episode.posters if is_poster else episode.arts)

            for art in arts:
                if (art.provider is None or art.provider == "local") and art.selected:
                    return False

            self.logger.info(f"Uploading {'poster' if is_poster else 'background'}: {art_file}")
            await utils.run(episode.uploadPoster if is_poster else episode.uploadArt, filepath=str(art_file))

            try:
                await utils.run(episode.saveEdits)
                await utils.run(episode.batchEdits)
            except:
                pass

            arts = await utils.run(episode.posters if is_poster else episode.arts)
            if len(arts) > 0:
                await utils.run(episode.setPoster if is_poster else episode.setArt, arts[len(arts)-1])

            return True

        return False

    async def process_yml_metadata(self, file, crc32):
        parsed = await utils.load_yaml(file)
        self.logger.trace(f"{file}: {parsed}")

        if not isinstance(parsed, dict):
            return None

        if "reference" in parsed:
            ref = parsed["reference"].upper()
            self.logger.trace(f"{crc32}.yml -> {ref}.yml")

            if ref in self.episodes and isinstance(self.episodes[ref], dict):
                return self.episodes[ref]
            else:
                return await self.process_yml_metadata(Path(file.parent, f"{ref}.yml"), ref)

        if "_" in crc32:
            crc32 = crc32.split("_")[0]

            if crc32 in self.episodes and isinstance(self.episodes[crc32], list):
                new_list = [item for item in self.episodes[crc32]]
                new_list.append(parsed)
                self.logger.debug(f"add {file} to list {crc32}: {new_list}")
                return new_list

            self.logger.debug(f"create {crc32} as list: {parsed}")
            return [parsed]

        self.logger.trace(f"loaded {crc32}: {parsed}")
        return parsed

    async def cache_yml(self):
        try:
            data_folder = Path(self.base_path, "metadata")
            episodes_folder = Path(data_folder, "episodes")

            if not await utils.is_dir(episodes_folder):
                return False

            self.logger.info(f"{episodes_folder} detected, loading metadata from folder")

            episode_files = []
            async for file in utils.glob(episodes_folder, "*.yml", rglob=True):
                episode_files.append(file)

            tvshow_yml = Path(data_folder, "tvshow.yml")
            if await utils.is_file(tvshow_yml):
                episode_files.append(tvshow_yml)

            arcs_yml = Path(data_folder, "arcs.yml")
            if await utils.is_file(arcs_yml):
                episode_files.append(arcs_yml)

            total_files = len(episode_files)
            self.logger.trace(episode_files)

            if total_files == 0:
                return False

            await utils.run_func(self.progress_bar_func, 0)

            for index, file in enumerate(episode_files):
                if file == tvshow_yml:
                    self.tvshow = await utils.load_yaml(tvshow_yml)

                elif file == arcs_yml:
                    self.arcs = await utils.load_yaml(arcs_yml)

                else:
                    crc32 = file.name.replace(".yml", "")
                    result = await self.process_yml_metadata(file, crc32)

                    if result is not None:
                        self.episodes[crc32] = result

                await utils.run_func(self.progress_bar_func, int(((index + 1) / total_files) * 100))

            await utils.run_func(self.progress_bar_func, 100)

        except:
            await utils.run_func(self.progress_bar_func, 0)
            self.logger.warning(f"Skipping using metadata/episodes for metadata\n{traceback.format_exc()}")
            return False

        return True

    async def cache_episode_data(self):
        data_file = Path(self.base_path, "metadata", "data.json")
        data = {}

        if await utils.is_file(data_file):
            self.logger.success("Checking episode metadata file (data.json)...")

            data = await utils.load_json(data_file)
            self.logger.trace(data)

            if "last_update" in data and data["last_update"] != "":
                now = datetime.datetime.now(tz=datetime.UTC)
                data_file_stat = await utils.stat(data_file)
                last_update_remote = datetime.datetime.fromisoformat(data["last_update"])
                last_update_local = datetime.datetime.fromtimestamp(data_file_stat.st_mtime, tz=datetime.UTC)

                if now - last_update_remote < datetime.timedelta(hours=12):
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.arcs = data["arcs"] if "arcs" in data else []
                    self.episodes = data["episodes"] if "episodes" in data else {}

                elif now - last_update_local < datetime.timedelta(hours=1):
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.arcs = data["arcs"] if "arcs" in data else []
                    self.episodes = data["episodes"] if "episodes" in data else {}

        yml_loaded = await self.cache_yml()

        if yml_loaded == False or len(self.tvshow) == 0 or len(self.arcs) == 0 or len(self.episodes) == 0:
            try:
                await utils.run(data_file.parent.mkdir, exist_ok=True)

                self.logger.success("Downloading: data.json")
                await utils.download(f"{self.metadata_url}/data.min.json", data_file, self.progress_bar_func)

                data = await utils.load_json(data_file)
                self.logger.trace(data)

                if len(data) > 0:
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.arcs = data["arcs"] if "arcs" in data else []
                    self.episodes = data["episodes"] if "episodes" in data else {}

            except:
                self.logger.exception(f"Unable to download new metadata")

        return len(self.tvshow) > 0 and len(self.arcs) > 0 and len(self.episodes) > 0

    async def glob_video_files(self):
        self.logger.success("Searching for .mkv and .mp4 files...")

        crc_pattern = re.compile(r'\[([A-Fa-f0-9]{8})\](?=\.(mkv|mp4))')
        video_files = []
        filelist = []

        async for file in utils.glob(self.input_path, "**/*.[mM][kK][vV]", rglob=True):
            self.logger.trace(file)
            filelist.append(file)

        async for file in utils.glob(self.input_path, "**/*.[mM][pP]4", rglob=True):
            self.logger.trace(file)
            filelist.append(file)

        num_found = 0
        num_calced = 0
        filelist_total = len(filelist)
        results = []
        self.logger.debug(f"{filelist_total} files found")

        with self.executor_func(max_workers=self.workers) as executor:
            tasks = []
            loop = asyncio.get_running_loop()

            for file in filelist:
                match = await utils.run(crc_pattern.search, file.name)

                if match:
                    num_found += 1
                    results.append((match.group(1), await utils.resolve(file)))

                else:
                    self.logger.trace(f"Add to CRC32 Queue: {file}")
                    tasks.append(loop.run_in_executor(executor, utils.crc32, str(await utils.resolve(file))))

            if len(tasks) > 0:
                await utils.run_func(self.progress_bar_func, 0)
                self.logger.success(f"Calculating CRC32 for {len(tasks)} file(s)...")

                try:
                    i = 0
                    async for result in asyncio.as_completed(tasks):
                        file, error, crc32 = await result
                        file = await utils.resolve(file)
                        i += 1

                        if error != "":
                            self.logger.error(f"[{i}/{len(tasks)}] Unable to calculate {file.name}: {error}")
                        else:
                            self.logger.info(f"[{i}/{len(tasks)}] {file.name}: {crc32}")
                            results.append((crc32, file))
                            num_calced = num_calced + 1

                        await utils.run_func(self.progress_bar_func, int((i / len(tasks)) * 100))

                except (asyncio.CancelledError, KeyboardInterrupt) as e:
                    if sys.version_info >= (3, 14):
                        executor.kill_workers()
                    else:
                        for task in tasks:
                            task.kill()

                    raise e
                    return False

        await utils.run_func(self.progress_bar_func, 0)

        for index, info in enumerate(results):
            if info[0] in self.episodes:
                self.logger.trace(f"Queue: {info[0]} {info[1]}")
                video_files.append(info)

            elif info[1].suffix.lower() == '.mkv':
                crc32, file_path = info

                try:
                    try:
                        f = await utils.run(Path(file_path).open, mode='rb')
                        mkv = await utils.run(enzyme.MKV, f)
                        self.logger.trace(mkv)
                    finally:
                        await utils.run(f.close)

                    if mkv == None or mkv.info == None or mkv.info.title == None or mkv.info.title == "":
                        self.logger.warning(f"Skipping {file_path.name}: Episode metadata missing, infering information from MKV also failed")
                        continue

                    title = mkv.info.title.split(" - ")
                    match = re.match(r'^(.*\D)?\s*(\d+)$', title[0])

                    ep_title = " - ".join(title[1:]) if len(title) > 1 else title[0]
                    _s = await utils.stat(file_path)
                    ep_date = mkv.info.date if mkv.info.date != None else datetime.date.fromtimestamp(_s.st_ctime)

                    m_season = 0
                    m_episode = 0

                    if match:
                        self.logger.trace(match)
                        arc_name = match.group(1).strip()
                        ep_num = int(match.group(2))

                        season_items = self.arcs.items() if isinstance(self.arcs, dict) else enumerate(self.arcs)
                        for season, season_info in season_items:
                            if season_info["title"] == arc_name and crc32 not in self.episodes:
                                self.logger.trace(f"found {season_info['title']} -> s{season} e{ep_num}")
                                m_season = season
                                m_episode = ep_num

                    if m_season != 0 and m_episode != 0:
                        found_existing = False

                        for j, episode_info in self.episodes.items():
                            if episode_info["arc"] == m_season and episode_info["episode"] == m_episode:
                                self.episodes[crc32] = episode_info
                                found_existing = True

                        self.logger.trace(found_existing)
                        if not found_existing:
                            self.episodes[crc32] = {
                                "arc": m_season,
                                "episode": m_episode,
                                "title": ep_title,
                                "description": "",
                                "chapters": "",
                                "episodes": "",
                                "released": ep_date.isoformat()
                            }

                        video_files.append(info)

                    else:
                        self.logger.warning(f"Skipping {file_path.name}: Episode metadata missing, infering information from MKV also failed [3]")

                except:
                    self.logger.warning(f"Skipping {file_path.name}: Episode metadata missing, infering information from MKV also failed [2]")

            else:
                self.logger.warning(f"Skipping {info[0].name}: Episode metadata missing, make sure you have the latest version of this release")

            await utils.run_func(self.progress_bar_func, int(((index + 1) / filelist_total) * 100))

        await utils.run_func(self.progress_bar_func, 100)
        self.logger.success(f"Found: {num_found}, Calculated: {num_calced}, Total: {filelist_total}")

        return video_files

    def get_season_folder(self, season):
        if self.folder_action == 1:
            return Path(self.output_path, "Specials" if season == 0 else f"Season {season}")
        elif self.folder_action == 2:
            return self.output_path
 
        return Path(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")

    def get_season(self, season):
        self.logger.trace(f"get_season {season} (self.arcs is a {type(self.arcs)})")

        if isinstance(self.arcs, dict):
            if int(season) in self.arcs:
                return self.arcs[int(season)]
            elif str(season) in self.arcs:
                return self.arcs[str(season)]

            return None

        return self.arcs[season]

    async def process_plex(self, files):
        completed = 0
        skipped = 0
        show = None

        try:
            section = await utils.run(self.plexapi_server.library.sectionByID, int(self.plex_config_library_key))

            if self.plex_config_show_guid.startswith("local://"):
                rating_key = self.plex_config_show_guid.replace("local://", "")
                try:
                    item = await utils.run(section.fetchItem, int(rating_key))
                    self.logger.debug(f"Found item by rating key: {rating_key} (type: {type(item)})")

                    # Handle case where we get an Episode instead of a Show
                    if hasattr(item, 'type'):
                        if item.type == 'show':
                            show = item
                            self.logger.debug(f"Item is a show: {show.title}")
                        elif item.type == 'episode':
                            self.logger.debug(f"Item is an episode, getting show from episode: {item.title}")
                            show = await utils.run(item.show)
                            self.logger.debug(f"Retrieved show: {show.title}")
                        else:
                            self.logger.error(f"Item with rating key '{rating_key}' is not a show or episode (type: {item.type})")
                            return (False, None, completed, skipped)
                    else:
                        # Fallback: assume it's a show if type attribute is missing
                        show = item
                        self.logger.debug(f"Assuming item is a show: {show.title}")

                except Exception as e:
                    self.logger.error(f"Failed to fetch show by rating key '{rating_key}': {e}")
                    return (False, e, completed, skipped)

            else:
                show = await utils.run(section.getGuid, self.plex_config_show_guid)
                if show is None:
                    self.logger.error(f"Unable to find show with GUID '{self.plex_config_show_guid}'")
                    return (False, None, completed, skipped)

            await utils.run(show.batchEdits)

            if "title" in self.tvshow and self.tvshow["title"] != "" and show.title != self.tvshow["title"]:
                self.logger.info(f"Set Title: {show.title} -> {self.tvshow['title']}")
                await utils.run(show.editTitle, self.tvshow["title"], locked=self.lockdata)

            if "originaltitle" in self.tvshow and self.tvshow["originaltitle"] != "" and show.originalTitle != self.tvshow["originaltitle"]:
                self.logger.info(f"Set Original Title: {show.originalTitle} -> {self.tvshow['originaltitle']}")
                await utils.run(show.editOriginalTitle, self.tvshow["originaltitle"], locked=self.lockdata)

            if "sorttitle" in self.tvshow and self.tvshow["sorttitle"] != "" and show.titleSort != self.tvshow["sorttitle"]:
                self.logger.info(f"Set Sort Title: {show.titleSort} -> {self.tvshow['sorttitle']}")
                await utils.run(show.editSortTitle, self.tvshow["sorttitle"], locked=self.lockdata)

            if "tagline" in self.tvshow and self.tvshow["tagline"] != "" and show.tagline != self.tvshow["tagline"]:
                self.logger.info(f"Set Tagline: {show.tagline} -> {self.tvshow['tagline']}")
                await utils.run(show.editTagline, self.tvshow["tagline"], locked=self.lockdata)

            if "customrating" in self.tvshow and self.tvshow["customrating"] != "" and show.contentRating != self.tvshow["customrating"]:
                self.logger.info(f"Set Rating: {show.contentRating} -> {self.tvshow['customrating']}")
                await utils.run(show.editContentRating, self.tvshow["customrating"], locked=self.lockdata)

            if "genre" in self.tvshow and isinstance(self.tvshow, list):
                _genres = []
                for genre in show.genres:
                    _genres.append(genre.tag)

                for genre in self.tvshow["genre"]:
                    if genre not in _genres:
                        self.logger.info(f"Add Genre: {genre}")
                        await utils.run(show.addGenre, genre)

            if "plot" in self.tvshow and show.summary != self.tvshow["plot"]:
                await utils.run(show.editSummary, self.tvshow["plot"], locked=self.lockdata)
                await utils.run(show.editOriginallyAvailable,
                    self.tvshow["premiered"].isoformat() if isinstance(self.tvshow["premiered"], datetime.date) else self.tvshow["premiered"]
                )

                poster = await utils.run(utils.find_from_list, self.base_path, [
                    ("posters", "poster.*"),
                    ("posters", "folder.*"),
                    (self.input_path, "poster.*")
                ])

                if not poster and self.fetch_posters:
                    poster = Path(self.base_path, "posters", "poster.png")
                    self.logger.info(f"Downloading: posters/{poster.name}")

                    try:
                        dl = await utils.download(f"{self.download_path}/posters/{poster.name}", poster, self.progress_bar_func)
                        if not dl:
                            dl = await utils.download(f"{self.metadata_url}/posters/{poster.name}", poster, self.progress_bar_func)
                            if not dl:
                                self.logger.info("Unable to download (not found), skipping...")
                    except:
                        self.logger.warning("Unable to download, skipping...")

                await self.plex_art_set(poster, show, True)

                background = await utils.run(utils.find_from_list, self.base_path, [
                    ("posters", "background.*"),
                    ("posters", "backdrop.*"),
                    (self.input_path, "background.*")
                ])
                if background is not None:
                    await self.plex_art_set(background, show, False)

            index = 0
            total = len(files)
            res = []
            seasons = []

            self.logger.success("Processing the video files...")

            with self.executor_func(max_workers=self.workers) as executor:
                tasks = []
                loop = asyncio.get_running_loop()

                for crc32, file in files:
                    episode_info = self.episodes[crc32]
                    self.logger.trace(f"{crc32}: {episode_info}")

                    if isinstance(episode_info, list):
                        stop = True

                        for v in episode_info:
                            if "hashes" not in v or "blake2" not in v["hashes"] or v["hashes"]["blake2"] == "":
                                self.logger.warning(f"Skipping {file.name}: blake2s hash is required but not provided")
                                continue

                            _b = v["hashes"]["blake2"]
                            f, err, b2hash = await utils.run(utils.blake2, file)

                            if err != "":
                                self.logger.error(f"Skipping {file.name}: {err}")
                                continue

                            if _b == b2hash[:16] or _b == b2hash:
                                stop = False
                                episode_info = v
                                break

                        if stop:
                            index += 1
                            skipped += 1
                            await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                            continue

                    season = episode_info["arc"]
                    episode = episode_info["episode"]
                    title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"]) if "title" in episode_info and episode_info["title"] != "" else ""

                    if title == "":
                        self.logger.warning(f"Skipping {file.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                        index += 1
                        skipped += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                    season_path = Path(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")
                    if season not in seasons:
                        self.logger.info(f"Season: {season}")
                        seasons.append(season)

                        if not await utils.is_dir(season_path):
                            self.logger.debug(f"Creating directory: {season_path}")
                            await utils.run(season_path.mkdir, exist_ok=True)

                    dst = str(Path(season_path, f"One Pace - S{season:02d}E{episode:02d} - {title}{file.suffix}"))
                    self.logger.debug(f"Queue: file={file}, dst={dst}, info={episode_info} [{self.file_action}]")
                    tasks.append(loop.run_in_executor(executor, utils.move_file_worker, str(file), dst, self.file_action, episode_info))

                if len(tasks) > 0:
                    async for result in asyncio.as_completed(tasks):
                        file, dst, err, episode_info = await result
                        file = Path(file)

                        if err != "":
                            self.logger.error(f"Skipping {file.name}: {err}")
                            skipped += 1
                        else:
                            self.logger.debug(f"Complete: [{crc32}] {dst} ({episode_info})")
                            res.append((crc32, file, dst, episode_info))
                            completed += 1

                        index += 1
                        await utils.run(self.progress_bar_func, int((index / total) * 100))

        except Exception as e:
            return (False, e, completed, skipped)

        finally:
            if show is not None:
                try:
                    await utils.run(show.saveEdits)
                except Exception as e:
                    return (False, e, completed, skipped)

        return (True, res, completed, skipped)

    async def process_plex_episodes(self, queue):
        skipped = 0
        completed = 0
        plex_season = None
        plex_episode = None

        try:
            section = await utils.run(self.plexapi_server.library.sectionByID, int(self.plex_config_library_key))

            self.logger.trace(f"Looking up show with GUID: {self.plex_config_show_guid}")
            if self.plex_config_show_guid.startswith("local://"):
                rating_key = self.plex_config_show_guid.replace("local://", "")
                self.logger.trace(f"Attempting to fetch show by rating key: {rating_key}")

                try:
                    item = await utils.run(section.fetchItem, int(rating_key))
                    self.logger.debug(f"Found item by rating key: {rating_key} (type: {type(item)})")

                    # Handle case where we get an Episode instead of a Show
                    if hasattr(item, 'type'):
                        if item.type == 'show':
                            show = item
                            self.logger.debug(f"Item is a show: {show.title}")
                        elif item.type == 'episode':
                            self.logger.debug(f"Item is an episode, getting show from episode: {item.title}")
                            show = await utils.run(item.show)
                            self.logger.debug(f"Retrieved show: {show.title}")
                        else:
                            self.logger.error(f"Item with rating key '{rating_key}' is not a show or episode (type: {item.type})")
                            return (False, None, completed, skipped)
                    else:
                        # Fallback: assume it's a show if type attribute is missing
                        show = item
                        self.logger.debug(f"Assuming item is a show: {show.title}")

                except Exception as e:
                    self.logger.error(f"Failed to fetch show by rating key '{rating_key}': {e}")
                    return (False, e, completed, skipped)

            else:
                self.logger.trace(f"Attempting to get show by GUID: {self.plex_config_show_guid}")
                show = await utils.run(section.getGuid, self.plex_config_show_guid)
                if show is None:
                    self.logger.error(f"Unable to find show with GUID '{self.plex_config_show_guid}'")
                    return (False, None, completed, skipped)

                if hasattr(show, 'type') and show.type == 'episode':
                    self.logger.debug(f"Retrieved episode instead of show, getting show from episode: {show.title}")
                    show = await utils.run(show.show)

            self.logger.debug(f"Final show object type: {type(show)}")
            if hasattr(show, 'type'):
                self.logger.debug(f"Show object type attribute: {show.type}")
            if hasattr(show, 'title'):
                self.logger.debug(f"Show title: {show.title}")

            seasons_completed = []

            if len(queue) == 0:
                self.logger.info("Metadata-only mode: Fetching all episodes from Plex")
                try:
                    self.logger.debug(f"Show object type: {type(show)}")
                    self.logger.debug(f"Show object attributes: {dir(show)}")

                    all_episodes = []
                    if hasattr(show, 'episodes'):
                        all_episodes = await utils.run(show.episodes)
                    elif hasattr(show, 'all'):
                        all_episodes = await utils.run(show.all)
                    else:
                        all_items = await utils.run(section.all)
                        all_episodes = [item for item in all_items if hasattr(item, 'type') and item.type == 'episode']

                    self.logger.info(f"Found {len(all_episodes)} episodes in Plex")
                    queue = []
                    for plex_ep in all_episodes:
                        season = plex_ep.parentIndex if hasattr(plex_ep, 'parentIndex') else plex_ep.seasonNumber
                        episode = plex_ep.index

                        episode_info = None
                        for crc32, ep_data in self.episodes.items():
                            if isinstance(ep_data, dict) and ep_data.get("arc") == season and ep_data.get("episode") == episode:
                                episode_info = ep_data
                                break

                        if episode_info:
                            queue.append(("metadata_only", plex_ep, None, episode_info))
                        else:
                            self.logger.debug(f"No metadata found for S{season}E{episode}")

                    self.logger.info(f"Matched {len(queue)} episodes with metadata")
                except Exception as e:
                    self.logger.error(f"Failed to fetch episodes from Plex: {e}")
                    return (False, e, completed, skipped)

            index = 0
            total = len(queue)
            max_retries = int(self.plex_retry_times)
            retry_secs = int(self.plex_retry_secs)

            if max_retries < 1:
                max_retries = 1

            if retry_secs < 1:
                retry_secs = 1

            for index, item in enumerate(queue):
                crc32, src, file, episode_info = item
                self.logger.debug(f"Start: [{crc32}] {file} ({episode_info})")

                season = episode_info["arc"]
                season_info = self.get_season(season)
                episode = episode_info["episode"]
                updated = False

                if not season in seasons_completed:
                    seasons_completed.append(season)

                    if season_info is not None:
                        try:
                            self.logger.info(f"Updating: Season {season} ({season_info['title']})")

                            retry_count = 0
                            while retry_count < max_retries:
                                try:
                                    plex_season = await utils.run(show.season, season=season)
                                    break
                                except PlexApiNotFound as e:
                                    self.logger.debug(e)
                                    retry_count += 1

                                    if retry_count == 1:
                                        self.logger.warning(f"Could not fetch season {season} from Plex - this usually means " +
                                            "if it's just transferred, the Plex scanner has not gotten around to it yet. " +
                                            f"Waiting {retry_secs} second(s)... (attempt {retry_count}/{max_retries})")
                                    else:
                                        self.logger.debug(f"Season {season}: Attempt {retry_count}/{max_retries}")

                                    await asyncio.sleep(retry_secs)
                            else:
                                self.logger.error(f"Failed to fetch season {season} from Plex after {max_retries} attempt(s). Skipping season.")
                                plex_season = None

                            if plex_season is not None:
                                season_title = season_info["title"] if season == 0 else f"{season}. {season_info['title']}"
                                season_desc = season_info["description"] if "description" in season_info and season_info["description"] != "" else ""

                                await utils.run(plex_season.batchEdits)

                                if plex_season.title != season_title:
                                    self.logger.debug(f"Season {season} Title: {season_title}")
                                    await utils.run(plex_season.editTitle, season_title, locked=self.lockdata)

                                if season_desc != "" and plex_season.summary != season_desc:
                                    self.logger.debug(f"Season {season} Summary: {season_desc}")
                                    await utils.run(plex_season.editSummary, season_desc, locked=self.lockdata)

                                poster = await utils.run(utils.find_from_list, self.base_path, [
                                    (f"posters/{season}", "poster.*"),
                                    (f"posters/{season}", "folder.*"),
                                    (self.input_path, f"poster-s{season:02d}.*")
                                ])

                                if not poster and self.fetch_posters:
                                    poster = Path(self.base_path, "posters", str(season), "poster.png")
                                    try:
                                        self.logger.info(f"Downloading: posters/{season}/{poster.name}")
                                        dl = await utils.download(f"{self.download_path}/posters/{season}/{poster.name}", poster, self.progress_bar_func)
                                        if not dl:
                                            dl = await utils.download(f"{self.metadata_url}/posters/{season}/{poster.name}", poster, self.progress_bar_func)
                                            if not dl:
                                                self.logger.info(f"Skipping downloading (not found)")
                                    except:
                                        self.logger.warning(f"Skipping downloading")

                                await self.plex_art_set(poster, plex_season, True)

                                background = await utils.run(utils.find_from_list, self.base_path, [
                                    (f"posters/{season}", "background.*"),
                                    (f"posters/{season}", "backdrop.*"),
                                    (self.input_path, f"background-s{season:02d}.*"),
                                ])
                                if background is not None:
                                    await self.plex_art_set(background, plex_season, False)

                        except:
                            self.logger.exception(f"Skipping season {season}")

                        finally:
                            if plex_season is not None:
                                try:
                                    await utils.run(plex_season.saveEdits)
                                except Exception as e:
                                    self.logger.warning(f"Skipping season {season}: {e}")

                            plex_season = None

                    else:
                        self.logger.warning(f"Skipping season {season}: Title not found, metadata might be corrupted?")

                try:
                    if season_info is None:
                        _label = f"Season {season} Episode {episode} ({episode_info['title']})"
                    else:
                        _label = f"{season_info['title']} {episode:02d} (S{season:02d}E{episode:02d} - {episode_info['title']})"

                    self.logger.info(f"Updating: {_label}")

                    if crc32 == "metadata_only":
                        plex_episode = src
                    else:
                        retry_count = 0
                        while retry_count < max_retries:
                            try:
                                plex_episode = await utils.run(show.episode, season=season, episode=episode)
                                break
                            except PlexApiNotFound as e:
                                self.logger.debug(e)
                                retry_count += 1

                                if retry_count == 1:
                                    self.logger.warning(f"Could not fetch S{season:02d}E{episode:02d} from Plex - this " +
                                        "usually means if it's just transferred, the Plex scanner has not gotten around " +
                                        "to it yet. Waiting {retry_secs} second(s)... (attempt {retry_count}/{max_retries})")
                                else:
                                    self.logger.debug(f"S{season:02d}E{episode:02d}: Attempt {retry_count}/{max_retries}")

                                await asyncio.sleep(retry_secs)
                        else:
                            self.logger.error(f"Failed to fetch S{season:02d}E{episode:02d} from Plex after {max_retries} attempt(s). Skipping episode.")
                            skipped += 1
                            plex_episode = None

                    if plex_episode is not None:
                        await utils.run(plex_episode.batchEdits)

                        if plex_episode.title != episode_info["title"]:
                            self.logger.debug(f"S{season}E{episode} Title: {plex_episode.title} -> {episode_info['title']}")
                            await utils.run(plex_episode.editTitle, episode_info["title"], locked=self.lockdata)
                            updated = True

                        if "rating" in episode_info and plex_episode.contentRating != episode_info["rating"]:
                            self.logger.debug(f"S{season}E{episode} Rating: {plex_episode.contentRating} -> {episode_info['rating']}")
                            await utils.run(plex_episode.editContentRating, episode_info["rating"], locked=self.lockdata)
                            updated = True

                        if "sorttitle" in episode_info and plex_episode.titleSort != episode_info["sorttitle"]:
                            self.logger.debug(f"S{season}E{episode} Sort Title: {plex_episode.titleSort} -> {episode_info['sorttitle']}")
                            await utils.run(plex_episode.editSortTitle, episode_info["sorttitle"], locked=self.lockdata)
                            updated = True

                        if "released" in episode_info:
                            r = datetime.datetime.strptime(episode_info["released"], "%Y-%m-%d").date() if isinstance(episode_info["released"], str) else episode_info["released"]

                            needs_update = False
                            if plex_episode.originallyAvailableAt is None:
                                needs_update = True
                            else:
                                if plex_episode.originallyAvailableAt.date() != r:
                                    needs_update = True

                            if needs_update:
                                self.logger.debug(f"S{season}E{episode} Release Date: {plex_episode.originallyAvailableAt} -> {r}")
                                await utils.run(plex_episode.editOriginallyAvailable, r, locked=self.lockdata)
                                updated = True

                        desc_str = episode_info["description"] if "description" in episode_info and episode_info["description"] != "" else ""
                        manga_str = ""
                        anime_str = ""

                        if episode_info["chapters"] != "":
                            if desc_str != "":
                                manga_str = f"\n\nChapter(s): {episode_info['chapters']}"
                            else:
                                manga_str = f"Chapter(s): {episode_info['chapters']}"

                        if episode_info["episodes"] != "":
                            if desc_str != "" or manga_str != "":
                                anime_str = f"\n\nEpisode(s): {episode_info['episodes']}"
                            else:
                                anime_str = f"Episode(s): {episode_info['episodes']}"

                        description = f"{desc_str}{manga_str}{anime_str}"

                        if plex_episode.summary != description:
                            self.logger.debug(f"S{season}E{episode} Description Updated")
                            await utils.run(plex_episode.editSummary, description, locked=self.lockdata)
                            updated = True

                        poster_search_paths = [
                            (f"posters/{season}/{episode}", "poster.*"),
                            (self.input_path, f"poster-s{season:02d}e{episode:02d}.*")
                        ]

                        if hasattr(src, 'stem'):
                            poster_search_paths.extend([
                                (self.input_path, f"{src.stem}-poster.*"),
                                (self.input_path, f"{src.stem}-thumb.*")
                            ])

                        poster = await utils.run(utils.find_from_list, self.base_path, poster_search_paths)

                        background_search_paths = [
                            (f"posters/{season}/{episode}", "background.*"),
                            (self.input_path, f"background-s{season:02d}e{episode:02d}.*")
                        ]

                        if hasattr(src, 'stem'):
                            background_search_paths.extend([
                                (self.input_path, f"{src.stem}-background.*"),
                                (self.input_path, f"{src.stem}-backdrop.*")
                            ])

                        background = await utils.run(utils.find_from_list, self.base_path, background_search_paths)

                        if poster and await self.plex_art_set(poster, plex_episode, True):
                            self.logger.debug(f"S{season}E{episode} Poster Uploaded: {poster}")
                            updated = True

                        if background and await self.plex_art_set(background, plex_episode, False):
                            self.logger.debug(f"S{season}E{episode} Background Uploaded: {background}")
                            updated = True

                        if updated:
                            completed += 1
                        else:
                            skipped += 1

                except:
                    self.logger.exception(f"Skipping season {season} episode {episode}")
                    skipped += 1

                finally:
                    if plex_episode is not None:
                        try:
                            await utils.run(plex_episode.saveEdits)
                        except Exception as e:
                            self.logger.warning(f"Skipping season {season} episode {episode}: {e}")

                    plex_episode = None

                index += 1
                await utils.run_func(self.progress_bar_func, int((index / total) * 100))

            await utils.run_func(self.progress_bar_func, 100)
            return (True, None, completed, skipped)

        except Exception as e:
            return (False, e, completed, skipped)

    async def _nfo_empty_task(self, src, dst, episode_info):
        return (src, dst, episode_info, "")

    async def process_nfo(self, files):
        tvshow_nfo = Path(self.output_path, "tvshow.nfo")
        root = ET.Element("tvshow")

        for k, v in self.tvshow.items():
            if isinstance(v, datetime.date):
                ET.SubElement(root, str(k)).text = v.isoformat()
            elif isinstance(v, list):
                for item in v:
                    ET.SubElement(root, str(k)).text = str(item)
            elif isinstance(v, bool):
                ET.SubElement(root, str(k)).text = "true" if v else "false"
            elif k == "plot":
                ET.SubElement(root, "plot").text = str(v)
                ET.SubElement(root, "outline").text = str(v)
            else:
                self.logger.debug(f"[{tvshow_nfo.name}] {k} = {v}")
                ET.SubElement(root, str(k)).text = str(v)

        _seasons = dict(sorted(self.arcs.items())).items() if isinstance(self.arcs, dict) else enumerate(self.arcs)
        for k, v in _seasons:
            text = str(v["title"]) if k == 0 else f"{k}. {v['title']}"
            self.logger.debug(f"[{tvshow_nfo.name}] season {k} = {text}")
            ET.SubElement(root, "namedseason", attrib={"number": str(k)}).text = text

        src = await utils.run(utils.find_from_list, self.base_path, [
            ("posters", "poster.*"),
            ("posters", "folder.*"),
            (self.input_path, "poster.*")
        ])
        dst = await utils.resolve(self.output_path, src.name if src is not None else "poster.png")
        art = None

        if not await utils.exists(dst):
            if not src and self.fetch_posters:
                try:
                    src = Path(self.base_path, "posters", "poster.png")
                    self.logger.info(f"Downloading: posters/{src.name}")
                    dl = await utils.download(f"{self.download_path}/posters/{src.name}", src, self.progress_bar_func)
                    if not dl:
                        dl = await utils.download(f"{self.metadata_url}/posters/{src.name}", src, self.progress_bar_func)
                        if not dl:
                            self.logger.info(f"Skipping downloading (not found)")
                except:
                    self.logger.warning(f"Skipping downloading\n{traceback.format_exc()}")

            if await utils.is_file(src):
                self.logger.info(f"Copying {src.name} to: {dst}")
                await utils.run(shutil.copy2, str(src), str(dst))

        if await utils.is_file(dst):
            art = ET.SubElement(root, "art")
            ET.SubElement(art, "poster").text = str(dst)

        src = await utils.run(utils.find_from_list, self.base_path, [
            ("posters", "background.*"),
            ("posters", "backdrop.*"),
            (self.input_path, "background.*")
        ])
        dst = await utils.resolve(self.output_path, src.name if src is not None else "background.png")

        if src and not await utils.is_file(dst):
            self.logger.info(f"Copying {src.name} to: {dst}")
            await utils.run(shutil.copy2, str(src), str(dst))

        if await utils.is_file(dst):
            if art is None:
                art = ET.SubElement(root, "art")

            ET.SubElement(art, "fanart").text = str(dst)

        ET.indent(root)

        out = await utils.run(
            ET.tostring,
            root,
            encoding='utf-8',
            xml_declaration=True
        )

        if self.overwrite_nfo:
            txt = ""
            if await utils.is_file(tvshow_nfo):
                txt = await utils.read_file(tvshow_nfo, False)

            if txt != out:
                self.logger.info(f"Writing {tvshow_nfo.name} to: {tvshow_nfo.parent}")
                await utils.write_file(tvshow_nfo, out)
        else:
            if not await utils.is_file(tvshow_nfo):
                self.logger.info(f"Writing {tvshow_nfo.name} to: {tvshow_nfo.parent}")
                await utils.write_file(tvshow_nfo, out)

        index = 0
        completed = 0
        skipped = 0
        total = (len(files) * 2)
        seasons = []

        self.logger.success("Creating episode metadata and moving the video files...")

        with self.executor_func(max_workers=self.workers) as executor:
            tasks = []
            loop = asyncio.get_running_loop()

            for crc32, file in files:
                episode_info = self.episodes[crc32]
                self.logger.debug(f"{crc32}: {episode_info}")

                if isinstance(episode_info, list):
                    stop = True

                    for v in episode_info:
                        if "hashes" not in v or "blake2" not in v["hashes"] or v["hashes"]["blake2"] == "":
                            self.logger.warning(f"Skipping {file.name}: blake2s hash is required but not provided")
                            continue

                        _b = v["hashes"]["blake2"]
                        f, err, b2hash = await utils.run(utils.blake2, file)

                        if err != "":
                            self.logger.info(f"Skipping {file.name}: {err}")
                            continue

                        if _b == b2hash[:16] or _b == b2hash:
                            stop = False
                            episode_info = v
                            break

                    if stop:
                        index += 1
                        skipped += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                if "arc" not in episode_info or "episode" not in episode_info:
                    self.logger.warning(f"Skipping {file.name}: metadata for {crc32} has no arc or part/episode number, please report this as a GitHub issue")
                    index += 1
                    skipped += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                season = episode_info["arc"]
                season_info = self.get_season(season)
                episode = episode_info["episode"]
                title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"]) if "title" in episode_info and episode_info["title"] != "" else ""

                if title == "":
                    self.logger.warning(f"Skipping {file.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                    index += 1
                    skipped += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                season_path = self.get_season_folder(season)
                if self.file_action != 4 and season not in seasons and season_path != self.output_path:
                    seasons.append(season)

                    if not await utils.is_dir(season_path):
                        self.logger.debug(f"Creating directory: {season_path}")
                        await utils.run(season_path.mkdir, exist_ok=True)

                    if season_info is not None:
                        if "title" not in season_info:
                            self.logger.warning(f"Skipping season {season}: Title not found, metadata might be corrupted?")

                        else:
                            art = None
                            root = ET.Element("season")

                            ET.SubElement(root, "title").text = season_info['title'] if season == 0 else f"{season}. {season_info['title']}"

                            if "originaltitle" in season_info and season_info['originaltitle'] != "":
                                ET.SubElement(root, "originaltitle").text = season_info['originaltitle'] if season == 0 else f"{season}. {season_info['originaltitle']}"

                            if "sorttitle" in season_info and season_info['sorttitle'] != "":
                                ET.SubElement(root, "sorttitle").text = str(season_info['sorttitle'])

                            ET.SubElement(root, "seasonnumber").text = str(season)

                            if "description" in season_info and season_info["description"] != "":
                                ET.SubElement(root, "plot").text = season_info["description"]
                                ET.SubElement(root, "outline").text = season_info["description"]

                            ET.SubElement(root, "customrating").text = season_info['rating'] if 'rating' in season_info else self.tvshow['customrating']
                            ET.SubElement(root, "lockdata").text = "true" if self.lockdata else "false"

                            src = await utils.run(utils.find_from_list, self.base_path, [
                                (f"posters/{season}", "poster.*"),
                                (f"posters/{season}", "folder.*"),
                                (self.input_path, f"poster-s{season:02d}.*")
                            ])
                            dst = await utils.resolve(season_path, "poster.png" if src is None else f"poster{src.suffix}")

                            if not await utils.exists(dst):
                                if not src and self.fetch_posters:
                                    src = Path(self.base_path, "posters", str(season), "poster.png")
                                    try:
                                        self.logger.info(f"Downloading: posters/{src.name}")
                                        dl = await utils.download(f"{self.download_path}/posters/{season}/{src.name}", src, self.progress_bar_func)
                                        if not dl:
                                            dl = await utils.download(f"{self.metadata_url}/posters/{season}/{src.name}", src, self.progress_bar_func)
                                            if not dl:
                                                self.logger.info("Skipping downloading (not found)")
                                    except Exception as e:
                                        self.logger.warning(f"Skipping downloading: {e}")

                                if await utils.is_file(src):
                                    self.logger.info(f"Copying {src.name} to: {dst}")
                                    await utils.run(shutil.copy, str(src), str(dst))

                            if await utils.is_file(dst):
                                art = ET.SubElement(root, "art")
                                ET.SubElement(art, "poster").text = str(dst)

                            src = await utils.run(utils.find_from_list, self.base_path, [
                                (f"posters/{season}", "background.*"),
                                (f"posters/{season}", "backdrop.*"),
                                (self.input_path, f"background-s{season:02d}.*")
                            ])
                            dst = await utils.resolve(season_path, "background.png" if src is None else f"background{src.suffix}")

                            if src and not await utils.is_file(dst):
                                self.logger.info(f"Copying {src.name} to: {dst}")
                                await utils.run(shutil.copy2, str(src), str(dst))

                            if await utils.is_file(dst):
                                if art is None:
                                    art = ET.SubElement(root, "art")

                                ET.SubElement(art, "fanart").text = str(dst)

                            ET.indent(root)

                            out = await utils.run(
                                ET.tostring,
                                root,
                                encoding='utf-8',
                                xml_declaration=True
                            )

                            season_nfo = await utils.resolve(season_path, "season.nfo")

                            if self.overwrite_nfo:
                                txt = ""
                                if await utils.is_file(season_nfo):
                                    txt = await utils.read_file(season_nfo, False)

                                if txt != out:
                                    await utils.write_file(season_nfo, out)
                                    self.logger.info(f"Wrote season.nfo to: {season_nfo.parent}")
                            else:
                                if not await utils.is_file(season_nfo):
                                    await utils.write_file(season_nfo, out)
                                    self.logger.info(f"Wrote season.nfo to: {season_nfo.parent}")

                    else:
                        self.logger.warning(f"Skipping season {season}: Season not found in metadata")

                if self.file_action == 4:
                    _s = str(file)
                    self.logger.trace(f"Queue [4]: {_s} ({episode_info})")
                    tasks.append(asyncio.create_task(self._nfo_empty_task(_s, _s, episode_info)))
                else:
                    _filename = self.filename_tmpl.format(
                        season=season,
                        arc=season,
                        episode=episode,
                        title=title,
                        name=file.name,
                        stem=file.stem,
                        suffix=file.suffix,
                        crc32=crc32,
                        arc_title=season_info["title"] if season_info is not None else "",
                        arc_saga=season_info["saga"] if season_info is not None else ""
                    )

                    dst = str(await utils.resolve(season_path, _filename))
                    self.logger.trace(f"Queue [{self.file_action}]: {file} -> {dst} ({episode_info})")
                    tasks.append(loop.run_in_executor(executor, utils.move_file_worker, str(file), dst, self.file_action, episode_info))

            if len(tasks) > 0:
                index = len(files)
                total = len(files) + len(tasks)

                async for result in asyncio.as_completed(tasks):
                    src, dst, err, info = await result

                    src = await utils.resolve(src)
                    dst = await utils.resolve(dst) if dst is not None else src

                    if err != "":
                        self.logger.error(f"Skipping {src.name}: {err}")
                        skipped += 1
                        index += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                    nfo_file = Path(dst.parent, f"{dst.stem}.nfo")
                    season = info["arc"]
                    episode = info["episode"]

                    self.logger.info(f"Updating: Season {season} Episode {episode} ({info['title']})")

                    root = ET.Element("episodedetails")
                    ET.SubElement(root, "title").text = info["title"]

                    if "originaltitle" in info and info["originaltitle"] != "":
                        ET.SubElement(root, "originaltitle").text = info["originaltitle"]

                    if "sorttitle" in info and info["sorttitle"] != "":
                        ET.SubElement(root, "sorttitle").text = info["sorttitle"]

                    ET.SubElement(root, "showtitle").text = self.tvshow["title"]
                    ET.SubElement(root, "season").text = f"{season}"
                    ET.SubElement(root, "episode").text = f"{episode}"
                    ET.SubElement(root, "customrating").text = info["rating"] if "rating" in info else self.tvshow["customrating"]

                    desc_str = info["description"] if "description" in info and info["description"] != "" else ""
                    manga_str = ""
                    anime_str = ""

                    if info["chapters"] != "":
                        if desc_str != "":
                            manga_str = f"\n\nChapter(s): {info['chapters']}"
                        else:
                            manga_str = f"Chapter(s): {info['chapters']}"

                    if info["episodes"] != "":
                        if desc_str != "" or manga_str != "":
                            anime_str = f"\n\nEpisode(s): {info['episodes']}"
                        else:
                            anime_str = f"Episode(s): {info['episodes']}"

                    ET.SubElement(root, "plot").text = f"{desc_str}{manga_str}{anime_str}"

                    if "released" in info:
                        if isinstance(info["released"], datetime.date):
                            date = info["released"].isoformat()
                        else:
                            date = info["released"]

                        year = date.split("-")[0]

                        ET.SubElement(root, "year").text = year
                        ET.SubElement(root, "premiered").text = date
                        ET.SubElement(root, "aired").text = date

                    ET.SubElement(root, "lockdata").text = "true" if self.lockdata else "false"

                    poster = await utils.run(utils.find_from_list, self.base_path, [
                        (f"posters/{season}/{episode}", "poster.*"),
                        (self.input_path, f"poster-s{season:02d}e{episode:02d}.*"),
                        (self.input_path, f"{src.stem}-poster.*"),
                        (self.input_path, f"{src.stem}-thumb.*")
                    ])

                    background = await utils.run(utils.find_from_list, self.base_path, [
                        (f"posters/{season}/{episode}", "background.*"),
                        (self.input_path, f"background-s{season:02d}e{episode:02d}.*"),
                        (self.input_path, f"{src.stem}-background.*"),
                        (self.input_path, f"{src.stem}-backdrop.*")
                    ])

                    if poster is not None:
                        img_dst = await utils.resolve(dst.parent, f"{dst.stem}-thumb{poster.suffix}")

                        if not await utils.is_file(img_dst) and self.file_action != 4:
                            self.logger.info(f"Copying {poster.name} to: {img_dst}")
                            await utils.run(shutil.copy2, str(poster), str(img_dst))

                        if await utils.is_file(img_dst):
                            art = ET.SubElement(root, "art")
                            ET.SubElement(art, "poster").text = str(img_dst)

                    if background is not None:
                        img_dst = await utils.resolve(dst.parent, f"{dst.stem}-background{background.suffix}")

                        if not await utils.is_file(img_dst) and self.file_action != 4:
                            self.logger.info(f"Copying {background.name} to: {img_dst}")
                            await utils.run(shutil.copy2, str(background), str(img_dst))

                        if await utils.is_file(img_dst):
                            art = ET.SubElement(root, "art")
                            ET.SubElement(art, "fanart").text = str(background)

                    ET.indent(root)

                    out = await utils.run(
                        ET.tostring,
                        root,
                        encoding='utf-8',
                        xml_declaration=True
                    )

                    if self.overwrite_nfo:
                        txt = ""
                        if await utils.is_file(nfo_file):
                            txt = await utils.read_file(nfo_file, False)

                        if txt != out:
                            self.logger.debug(f"Writing metadata to: {nfo_file}")
                            await utils.write_file(nfo_file, out)
                            completed += 1
                        else:
                            skipped += 1
                    else:
                        if not await utils.is_file(nfo_file):
                            self.logger.debug(f"Writing metadata to: {nfo_file}")
                            await utils.write_file(nfo_file, out)
                            completed += 1

                    index += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))

        await utils.run_func(self.progress_bar_func, 100)
        return (completed, skipped)

    async def start(self):
        try:
            if not isinstance(self.input_path, Path):
                self.input_path = Path(self.input_path)

            if not isinstance(self.output_path, Path):
                self.output_path = Path(self.output_path)

            if not isinstance(self.base_path, Path):
                self.base_path = Path(self.base_path)

            has_data = await self.cache_episode_data()

            if not has_data:
                self.logger.error("Exiting due to a lack of metadata - create a new directory "+
                    "named metadata and grab a copy of data.json to put in said directory.")
                return (False, None, 0, 0)

            video_files = await self.glob_video_files()
            extra_data = None

            await utils.run(self.output_path.mkdir, exist_ok=True)
            await utils.run_func(self.progress_bar_func, 0)

            if self.plex_config_enabled:
                if self.file_action == 4:
                    self.logger.info("Plex metadata-only mode: Updating existing episodes in Plex")
                    dummy_queue = []
                    return await self.process_plex_episodes(dummy_queue)
                else:
                    return await self.process_plex(video_files)

            completed, skipped = await self.process_nfo(video_files)
            return (True, extra_data, completed, skipped)

        except Exception as e:
            self.logger.error(f"Exiting\n{traceback.format_exc()}")
            return (False, e, 0, 0)

        except RuntimeError as e:
            self.logger.critical(f"RuntimeError\n{traceback.format_exc()}")
            return (False, e, 0, 0)
