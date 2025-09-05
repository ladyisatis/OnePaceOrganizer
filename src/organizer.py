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
from plexapi.exceptions import TwoFactorRequired as PlexApiTwoFactorRequired, Unauthorized as PlexApiUnauthorized
from plexapi.myplex import MyPlexAccount
from plexapi.server import PlexServer
from pathlib import Path, UnsupportedOperation
from aiopath import AsyncPath
from multiprocessing import freeze_support
from src import utils

class OnePaceOrganizer:
    def __init__(self):
        self.window_title = "One Pace Organizer"
        self.tvshow = {}
        self.episodes = {}
        self.seasons = {}

        self.workers = int(utils.get_env("workers", 0))
        self.base_path = AsyncPath(utils.get_env("base_path", Path.cwd().resolve()))
        self.download_path = utils.get_env("dl_path", "https://raw.githubusercontent.com/ladyisatis/onepaceorganizer/refs/heads/main")
        self.set_executor(utils.get_env("pool_mode", "process") == "process")

        if self.workers == 0:
            self.workers = None

        self.config_file = AsyncPath(utils.get_env("config_path", f"{self.base_path}/config.json"))
        self.file_action = int(utils.get_env("file_action", 0))
        self.folder_action = int(utils.get_env("folder_action", 0))
        self.fetch_posters = utils.get_env("fetch_posters", True)
        self.overwrite_nfo = utils.get_env("overwrite_nfo", False)

        self.input_path = utils.get_env("input_path")
        self.output_path = utils.get_env("output_path")
        self.filename_tmpl = utils.get_env("filename_tmpl", "One Pace - S{season:02d}E{episode:02d} - {title}{suffix}")

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

        self.progress_bar_func = None
        self.message_dialog_func = None
        self.input_dialog_func = None
        self.worker_task = None
        self.toml = None

    async def load_config(self):
        if self.toml is None or self.toml["version"] == "?":
            self.toml = utils.get_toml_info()

        self.window_title = f"One Pace Organizer v{self.toml['version']} - github.com/ladyisatis/OnePaceOrganizer"

        if self.config_file is not None and not isinstance(self.config_file, AsyncPath):
            self.config_file = AsyncPath(str(self.config_file))

        if self.config_file is None or self.config_file == "" or not await self.config_file.is_file():
            return False

        config = {}

        if self.config_file.suffix == ".json":
            config = await utils.load_json(self.config_file)
        elif self.config_file.suffix == ".yml" or self.config_file.suffix == ".yaml":
            config = await utils.load_yaml(self.config_file)

        logger.trace(config)

        if "path_to_eps" in config:
            self.input_path = await utils.resolve(config["path_to_eps"])

        if "input" in config:
            self.input_path = await utils.resolve(config["input"])

        if "episodes" in config:
            self.output_path = await utils.resolve(config["episodes"])

        if "output" in config:
            self.output_path = await utils.resolve(config["output"])

        if "move_after_sort" in config:
            self.file_action = 0 if config["move_after_sort"] else 1
        
        if "file_action" in config:
            self.file_action = config["file_action"]

        if "folder_action" in config:
            self.folder_action = config["folder_action"]

        if "fetch_posters" in config:
            self.fetch_posters = config["fetch_posters"]

        if "overwrite_nfo" in config:
            self.overwrite_nfo = config["overwrite_nfo"]

        if "filename_tmpl" in config:
            self.filename_tmpl = config["filename_tmpl"]

        if "plex" in config:
            if "enabled" in config["plex"]:
                self.plex_config_enabled = config["plex"]["enabled"]

            if "url" in config["plex"]:
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

            if "use_token" in config["plex"]:
                self.plex_config_use_token = config["plex"]["use_token"]

            if "token" in config["plex"]:
                self.plex_config_auth_token = config["plex"]["token"]

            if "username" in config["plex"]:
                self.plex_config_username = config["plex"]["username"]

            if "password" in config["plex"]:
                self.plex_config_password = config["plex"]["password"]

            if "remember" in config["plex"]:
                self.plex_config_remember = config["plex"]["remember"]

            if "server_baseurl" in config["plex"]:
                self.plex_config_server_baseurl = config["plex"]["server_baseurl"]

            if "server_token" in config["plex"]:
                self.plex_config_server_token = config["plex"]["server_token"]

    async def save_config(self):
        if self.config_file is not None and not isinstance(self.config_file, AsyncPath):
            self.config_file = AsyncPath(str(self.config_file))

        if self.config_file is None:
            return False

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
            async with self.config_file.open(mode='w', encoding='utf-8') as f:
                await f.write(await utils.run(yaml.safe_dump, out))
            return

        return await self.config_file.write_bytes(orjson.dumps(out, option=orjson.OPT_NON_STR_KEYS))

    def set_executor(self, process=True):
        self.executor_func = concurrent.futures.ProcessPoolExecutor if process else concurrent.futures.ThreadPoolExecutor

    async def plex_login(self, force_login=False):
        if force_login:
            self.plexapi_account = None

        if not self.plex_config_use_token and self.plex_config_auth_token != "" and self.plex_config_remember:
            try:
                self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_config_auth_token)
            except:
                logger.debug(traceback.format_exc())
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
                        logger.debug(traceback.format_exc())
                        await utils.run_func(self.message_dialog_func, "Invalid Plex account token, please try again.")
                    else:
                        logger.exception("Invalid Plex account token, please try again.")

                    return False

                except:
                    if self.message_dialog_func is not None:
                        await utils.run_func(self.message_dialog_func, f"Unknown error\n\n{traceback.format_exc()}")
                    else:
                        logger.exception("Unknown error")

                    return False

            else:
                try:
                    self.plexapi_account = await utils.run(
                        MyPlexAccount,
                        username=self.plex_config_username, 
                        password=self.plex_config_password, 
                        remember=self.plex_config_remember
                    )

                except PlexApiTwoFactorRequired:
                    logger.debug(traceback.format_exc())
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
                            logger.trace(traceback.format_exc())

                            if self.input_dialog_func is None or self.message_dialog_func is None:
                                logger.error("Invalid 2-Factor Auth code, please try again.")
                                return False
                            else:
                                await utils.run_func(self.message_dialog_func, "Invalid 2-Factor Auth code, please try again.")

                except PlexApiUnauthorized:
                    logger.trace(traceback.format_exc())
                    return False

                except:
                    if self.message_dialog_func is None:
                        logger.exception("Unknown error")
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
            logger.exception("Unable to find Plex servers")
            return False

        if len(resources) == 0:
            if self.message_dialog_func is None:
                logger.error("Unable to find any Plex servers on this account.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to find any Plex servers on this account.")

            return False

        elif len(resources) == 1:
            self.plex_config_servers[resources[0].clientIdentifier] = {
                "name": resources[0].name,
                "selected": True
            }

            self.plex_config_server_id = resources[0].clientIdentifier

            logger.info(f"Connecting to {resources[0].name} ({resources[0].clientIdentifier})")

            try:
                self.plexapi_server = await utils.run(resources[0].connect)
                logger.info("Connected")

            except:
                logger.exception(f"Unable to connect to Plex server '{resources[0].name}'")
                return False

        else:
            for i, resource in enumerate(resources):
                selected = self.plex_config_server_id == resource.clientIdentifier

                logger.trace(f"found: {resource.clientIdentifier} ({resource.name}, selected={selected})")
                self.plex_config_servers[resource.clientIdentifier] = {
                    "name": resource.name,
                    "selected": selected
                }

                if selected:
                    logger.info(f"Connecting to {resource.name} ({resource.clientIdentifier})")

                    try:
                        self.plexapi_server = await utils.run(resource.connect)
                        logger.info("Connected")

                    except:
                        logger.exception(f"Unable to connect to Plex server '{resource.name}'")
                        return False

        if self.plex_config_remember and self.plex_config_server_token == "":
            self.plex_config_server_baseurl = self.plexapi_server._baseurl
            self.plex_config_server_token = self.plexapi_server._token

        return self.plexapi_server is not None

    async def plex_select_server(self, server_id):
        if server_id == "" or server_id is None:
            logger.error("Plex server is blank")
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
                logger.exception(f"Unable to connect to Plex server '{resource.name}'")
                return False

        return True

    async def plex_get_libraries(self):
        if self.plexapi_server is None:
            connected = await self.plex_select_server(self.plex_config_server_id)
            if not connected:
                return False

        self.plex_config_libraries = {}

        try:
            sections = await utils.run(self.plexapi_server.library.sections)
        except:
            if self.message_dialog_func is None:
                logger.exception("Unable to fetch Plex libraries from this server.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to fetch Plex libraries from this server.")

            return False

        for section in sections:
            if section.type == 'show':
                selected = self.plex_config_library_key == section.key
                self.plex_config_libraries[section.key] = {
                    "title": section.title,
                    "selected": selected
                }

        return len(self.plex_config_libraries) > 0

    async def plex_select_library(self, library_key):
        self.plex_config_library_key = library_key

        for k, v in self.plex_config_libraries.items():
            self.plex_config_libraries[k]["selected"] = library_key == k

    async def plex_get_shows(self):
        if self.plexapi_server is None or self.plex_config_library_key == "":
            return False

        self.plex_config_shows = {}

        try:
            section = await utils.run(self.plexapi_server.library.sectionByID, self.plex_config_library_key)
            shows = await utils.run(section.all)
        except:
            if self.message_dialog_func is None:
                logger.exception("Unable to fetch Plex shows from this server.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to fetch Plex shows from this server.")

            return False
    
        for show in shows:
            selected = self.plex_config_show_guid == show.guid
            self.plex_config_shows[show.guid] = {
                "title": show.title,
                "selected": selected
            }

    async def plex_select_show(self, guid):
        self.plex_config_show_guid = guid

        for k, v in self.plex_config_shows.items():
            self.plex_config_shows[k]["selected"] = guid == k
    
    async def plex_art_set(self, file, episode, is_poster=True):
        art_file = await utils.find(file)

        if await art_file.is_file():
            arts = await utils.run(episode.posters if is_poster else episode.arts)

            for art in arts:
                if (art.provider == None or art.provider == "local") and art.selected:
                    return False

            logger.info(f"Uploading {'poster' if is_poster else 'background'}: {art_file}")
            await utils.run(episode.uploadPoster if is_poster else episode.uploadArt, filepath=str(art_file))

            arts = await utils.run(episode.posters if is_poster else episode.arts)
            if len(arts) > 1:
                await utils.run(episode.setPoster if is_poster else episode.setArt, arts[len(arts)-1])

            return True

        return False

    async def process_yml_metadata(self, file, crc32):
        parsed = await utils.load_yaml(file)
        logger.trace(f"{file}: {parsed}")

        if not isinstance(parsed, dict):
            return None

        if "reference" in parsed:
            ref = parsed["reference"].upper()
            logger.debug(f"{crc32}.yml -> {ref}.yml")

            if ref in self.episodes and isinstance(self.episodes[ref], dict):
                return self.episodes[ref]
            else:
                return await self.process_yml_metadata(AsyncPath(file.parent, f"{ref}.yml"), ref)

        if "_" in crc32:
            crc32 = crc32.split("_")[0]

            if crc32 in self.episodes and isinstance(self.episodes[crc32], list):
                new_list = [item for item in self.episodes[crc32]]
                new_list.append(parsed)
                logger.debug(f"add {file} to list {crc32}: {new_list}")
                return new_list

            logger.debug(f"create {crc32} as list: {parsed}")
            return [parsed]

        logger.debug(f"loaded {crc32}: {parsed}")
        return parsed

    async def cache_yml(self):
        try:
            data_folder = AsyncPath(self.base_path, "data")
            episodes_folder = AsyncPath(data_folder, "episodes")

            if not await episodes_folder.is_dir():
                return False

            logger.info(f"{episodes_folder} detected, loading metadata from folder")

            episode_files = []
            async for file in episodes_folder.glob("*.yml"):
                episode_files.append(file)

            tvshow_yml = AsyncPath(data_folder, "tvshow.yml")
            if await tvshow_yml.is_file():
                episode_files.append(tvshow_yml)

            seasons_yml = AsyncPath(data_folder, "seasons.yml")
            if await seasons_yml.is_file():
                episode_files.append(seasons_yml)

            total_files = len(episode_files)
            logger.trace(episode_files)

            if total_files == 0:
                return False

            await utils.run_func(self.progress_bar_func, 0)

            for index, file in enumerate(episode_files):
                if file == tvshow_yml:
                    self.tvshow = await utils.load_yaml(tvshow_yml)

                elif file == seasons_yml:
                    self.seasons = await utils.load_yaml(seasons_yml)

                else:
                    crc32 = file.name.replace(".yml", "")
                    result = await self.process_yml_metadata(file, crc32)

                    if result is not None:
                        self.episodes[crc32] = result

                await utils.run_func(self.progress_bar_func, int(((index + 1) / total_files) * 100))

            await utils.run_func(self.progress_bar_func, 100)

        except:
            await utils.run_func(self.progress_bar_func, 0)
            logger.warning(f"Skipping using data/episodes for metadata\n{traceback.format_exc()}")
            return False

        return True

    async def cache_episode_data(self):
        data_file = AsyncPath(self.base_path, "data.json")
        data = {}

        if await data_file.is_file():
            logger.success("Checking episode metadata file (data.json)...")

            data = await utils.load_json(data_file)
            logger.trace(data)

            if "last_update" in data and data["last_update"] != "":
                now = datetime.datetime.now(tz=datetime.UTC)
                data_file_stat = await data_file.stat()
                last_update_remote = datetime.datetime.fromisoformat(data["last_update"])
                last_update_local = datetime.datetime.fromtimestamp(data_file_stat.st_mtime, tz=datetime.UTC)

                if now - last_update_remote < datetime.timedelta(hours=12):
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.seasons = data["seasons"] if "seasons" in data else {}
                    self.episodes = data["episodes"] if "episodes" in data else {}

                elif now - last_update_local < datetime.timedelta(hours=1):
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.seasons = data["seasons"] if "seasons" in data else {}
                    self.episodes = data["episodes"] if "episodes" in data else {}

        yml_loaded = await self.cache_yml()

        if yml_loaded == False or len(self.tvshow) == 0 or len(self.seasons) == 0 or len(self.episodes) == 0:
            try:
                logger.success("Downloading: data.json")
                await utils.download(f"{self.download_path}/data.json", data_file, self.progress_bar_func)

                data = await utils.load_json(data_file)
                logger.trace(data)

                if len(data) > 0:
                    self.tvshow = data["tvshow"] if "tvshow" in data else {}
                    self.seasons = data["seasons"] if "seasons" in data else {}
                    self.episodes = data["episodes"] if "episodes" in data else {}

            except:
                logger.exception(f"Unable to download new metadata")

        return len(self.tvshow) > 0 and len(self.seasons) > 0 and len(self.episodes) > 0

    async def glob_video_files(self):
        logger.success("Searching for .mkv and .mp4 files...")

        crc_pattern = re.compile(r'\[([A-Fa-f0-9]{8})\](?=\.(mkv|mp4))')
        video_files = []
        filelist = []

        async for file in self.input_path.glob("**/*.[mM][kK][vV]"):
            logger.trace(file)
            filelist.append(file)

        async for file in self.input_path.glob("**/*.[mM][pP]4"):
            logger.trace(file)
            filelist.append(file)

        num_found = 0
        num_calced = 0
        filelist_total = len(filelist)
        results = []
        logger.debug(f"{filelist_total} files found")

        with self.executor_func(max_workers=self.workers) as executor:
            tasks = []
            loop = asyncio.get_event_loop()

            for file in filelist:
                match = await utils.run(crc_pattern.search, file.name)

                if match:
                    num_found += 1
                    results.append((match.group(1), await file.resolve()))

                else:
                    logger.debug(f"Add to CRC32 Queue: {file}")
                    tasks.append(loop.run_in_executor(executor, utils.crc32, str(await file.resolve())))

            if len(tasks) > 0:
                await utils.run_func(self.progress_bar_func, 0)
                logger.success(f"Calculating CRC32 for {len(tasks)} file(s)...")

                try:
                    i = 0
                    async for result in asyncio.as_completed(tasks):
                        file, error, crc32 = await result
                        file = await utils.resolve(file)
                        i += 1

                        if error != "":
                            logger.error(f"[{i}/{len(tasks)}] Unable to calculate {file.name}: {error}")
                        else:
                            logger.info(f"[{i}/{len(tasks)}] {file.name}: {crc32}")
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
                logger.debug(f"Queue: {info[0]} {info[1]}")
                video_files.append(info)

            elif info[1].suffix.lower() == '.mkv':
                crc32, file_path = info

                try:
                    with Path(str(file_path)).open(mode='rb') as f:
                        mkv = await utils.run(enzyme.MKV, f)
                        logger.trace(mkv)

                    if mkv == None or mkv.info == None or mkv.info.title == None or mkv.info.title == "":
                        logger.warning(f"Skipping {file_path.name}: Episode metadata missing, infering information from MKV also failed")
                        continue

                    title = mkv.info.title.split(" - ")
                    match = re.match(r'^(.*\D)?\s*(\d+)$', title[0])

                    ep_title = " - ".join(title[1:]) if len(title) > 1 else title[0]
                    _s = await file_path.stat()
                    ep_date = mkv.info.date if mkv.info.date != None else datetime.date.fromtimestamp(_s.st_ctime)

                    m_season = 0
                    m_episode = 0

                    if match:
                        logger.trace(match)
                        arc_name = match.group(1).strip()
                        ep_num = int(match.group(2))

                        season_items = self.seasons.items() if isinstance(self.seasons, dict) else enumerate(self.seasons)
                        for season, season_info in season_items:
                            if season_info["title"] == arc_name and crc32 not in self.episodes:
                                logger.debug(f"found {season_info['title']} -> s{season} e{ep_num}")
                                m_season = season
                                m_episode = ep_num

                    if m_season != 0 and m_episode != 0:
                        found_existing = False

                        for j, episode_info in self.episodes.items():
                            if episode_info["season"] == m_season and episode_info["episode"] == m_episode:
                                self.episodes[crc32] = episode_info
                                found_existing = True

                        logger.trace(found_existing)
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

                        video_files.append(info)

                    else:
                        logger.warning(f"Skipping {file_path.name}: Episode metadata missing, infering information from MKV also failed [3]")

                except:
                    logger.warning(f"Skipping {file_path.name}: Episode metadata missing, infering information from MKV also failed [2]")

            else:
                logger.warning(f"Skipping {info[0].name}: Episode metadata missing, make sure you have the latest version of this release")

            await utils.run_func(self.progress_bar_func, int(((index + 1) / filelist_total) * 100))

        await utils.run_func(self.progress_bar_func, 100)
        logger.success(f"Found: {num_found}, Calculated: {num_calced}, Total: {filelist_total}")

        return video_files

    def get_season_folder(self, season):
        if self.folder_action == 1:
            return AsyncPath(self.output_path, "Specials" if season == 0 else f"Season {season}")
        elif self.folder_action == 2:
            return self.output_path
 
        return AsyncPath(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")

    def get_season(self, season):
        if isinstance(season, dict):
            if season in self.seasons:
                return self.seasons[season]
            elif str(season) in self.seasons:
                return self.seasons[str(season)]

            return None

        return self.seasons[season]

    async def process_plex(self, files):
        section = await utils.run(self.plexapi_server.library.sectionByID, int(self.plex_config_library_key))
        show = await utils.run(section.getGuid, self.plex_config_show_guid)

        if "title" in self.tvshow and self.tvshow["title"] != "" and show.title != self.tvshow["title"]:
            logger.info(f"Set Title: {show.title} -> {self.tvshow['title']}")
            show.editTitle(self.tvshow["title"])

        if "originaltitle" in self.tvshow and self.tvshow["originaltitle"] != "" and show.originalTitle != self.tvshow["originaltitle"]:
            logger.info(f"Set Original Title: {show.originalTitle} -> {self.tvshow['originaltitle']}")
            show.editOriginalTitle(self.tvshow["originaltitle"])

        if "sorttitle" in self.tvshow and self.tvshow["sorttitle"] != "" and show.sortTitle != self.tvshow["sorttitle"]:
            logger.info(f"Set Sort Title: {show.sortTitle} -> {self.tvshow['sorttitle']}")
            show.editSortTitle(self.tvshow["sorttitle"])

        if "rating" in self.tvshow and self.tvshow["rating"] != "" and show.contentRating != self.tvshow["rating"]:
            logger.info(f"Set Rating: {show.contentRating} -> {self.tvshow['rating']}")
            show.editContentRating(self.tvshow["rating"])

        if "plot" in self.tvshow and show.summary != self.tvshow["plot"]:
            show.editSummary(self.tvshow["plot"])
            show.editOriginallyAvailable(self.tvshow["premiered"].isoformat() if isinstance(self.tvshow["premiered"], datetime.date) else self.tvshow["premiered"])

            poster = await utils.find("tvshow.png")
            if not await poster.is_file() and self.fetch_posters:
                logger.info(f"Downloading: data/posters/{poster.name}")
                dl = await utils.download(f"{self.download_path}/data/posters/{poster.name}", poster, self.progress_bar_func)

                if not dl:
                    logger.warning("Unable to download, skipping...")

            await self.plex_art_set("tvshow.png", show, True)
            await self.plex_art_set("background.png", show, False)

        index = 0
        completed = 0
        skipped = 0
        total = len(files)
        res = []
        seasons = []

        logger.success("Processing the video files...")

        with self.executor_func(max_workers=self.workers) as executor:
            tasks = []
            loop = asyncio.get_event_loop()

            for crc32, file in files:
                episode_info = self.episodes[crc32]
                logger.debug(f"{crc32}: {episode_info}")

                if isinstance(episode_info, list):
                    stop = True

                    for v in episode_info:
                        if "hashes" not in v or "blake2" not in v["hashes"] or v["hashes"]["blake2"] == "":
                            logger.warning(f"Skipping {file.name}: blake2s hash is required but not provided")
                            continue

                        _b = v["hashes"]["blake2"]
                        f, err, b2hash = await utils.run(utils.blake2, file)

                        if err != "":
                            logger.error(f"Skipping {file.name}: {err}")
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

                season = episode_info["season"]
                episode = episode_info["episode"]
                title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"]) if "title" in episode_info and episode_info["title"] != "" else ""

                if title == "":
                    logger.warning(f"Skipping {file.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                    index += 1
                    skipped += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                season_path = AsyncPath(self.output_path, "Specials" if season == 0 else "Season {season:02d}")
                if season not in seasons:
                    logger.info(f"Season: {season}")
                    seasons.append(season)

                    if not await season_path.is_dir():
                        logger.debug(f"Creating directory: {season_path}")
                        await season_path.mkdir(exist_ok=True)

                dst = str(Path(season_path, f"One Pace - S{season:02d}E{episode:02d} - {title}{file.suffix}"))
                logger.debug(f"Queue: file={file}, dst={dst}, info={episode_info} [{self.file_action}]")
                tasks.append(loop.run_in_executor(executor, utils.move_file_worker, str(file), dst, self.file_action, episode_info))

            if len(tasks) > 0:
                async for result in asyncio.as_completed(tasks):
                    file, dst, err, episode_info = await result

                    if err != "":
                        logger.error(f"Skipping {Path(file).name}: {err}")
                        skipped += 1
                    else:
                        logger.debug(f"Complete: [{crc32}] {dst} ({episode_info})")
                        res.append((crc32, dst, episode_info))
                        completed += 1

                    index += 1
                    await utils.run(self.progress_bar_func, int((index / total) * 100))

        return (res, completed, skipped)

    async def process_plex_episodes(self, queue):
        section = await utils.run(self.plexapi_server.library.sectionByID, int(self.plex_config_library_key))
        show = await utils.run(section.getGuid, self.plex_config_show_guid)
        seasons_completed = []

        index = 0
        skipped = 0
        completed = 0
        total = len(queue)

        for index, item in enumerate(queue):
            crc32, file, episode_info = item
            logger.debug(f"Start: [{crc32}] {file} ({episode_info})")

            season = episode_info["season"]
            season_info = self.get_season(season)
            episode = episode_info["episode"]
            updated = False

            if not season in seasons_completed:
                seasons_completed.append(season)

                if season_info is not None:
                    try:
                        logger.info(f"Updating: Season {season} ({season_info['title']})")
                        plex_season = await utils.run(show.season, season=season)

                        season_title = season_info["title"] if season == 0 else f"{season}. {season_info['title']}"
                        season_desc = season_info["description"] if "description" in season_info and season_info["description"] != "" else ""

                        if plex_season.title != season_title:
                            logger.debug(f"Season {season} Title: {season_title}")
                            plex_season.editTitle(season_title)

                        if season_desc != "" and plex_season.summary != season_desc:
                            logger.debug(f"Season {season} Summary: {season_desc}")
                            plex_season.editSummary(season_desc)

                        poster = await utils.find(f"poster-season{season}.png")
                        if not await poster.is_file() and self.fetch_posters:
                            try:
                                logger.info(f"Downloading: data/posters/{poster.name}")
                                await utils.download(f"{self.download_path}/data/posters/{poster.name}", poster)
                            except:
                                logger.exception(f"Skipping downloading")

                        await self.plex_art_set(poster, plex_season, True)

                        background = await utils.find(f"background-season{season}.png")
                        if await background.exists():
                            await self.plex_art_set(background, plex_season, False)

                    except:
                        logger.exception(f"Skipping season {season}")

                else:
                    logger.warning(f"Skipping season {season}: Title not found, metadata might be corrupted?")

            try:
                if season_info is None:
                    _label = f"Season {season} Episode {episode} ({episode_info['title']})"
                else:
                    _label = f"{season_info['title']} {episode:02d} (S{season:02d}E{episode:02d} - {episode_info['title']})"

                logger.info(f"Updating: {_label}")
                plex_episode = await utils.run(show.episode, season=season, episode=episode)

                if plex_episode.title != episode_info["title"]:
                    logger.debug(f"S{season}E{episode} Title: {plex_episode.title} -> {episode_info['title']}")
                    plex_episode.editTitle(episode_info["title"])
                    updated = True

                if "rating" in episode_info and plex_episode.contentRating != episode_info["rating"]:
                    logger.debug(f"S{season}E{episode} Rating: {plex_episode.contentRating} -> {episode_info['rating']}")
                    plex_episode.editContentRating(episode_info["rating"])
                    updated = True

                if "sorttitle" in episode_info and plex_episode.sortTitle != episode_info["sorttitle"]:
                    logger.debug(f"S{season}E{episode} Sort Title: {plex_episode.sortTitle} -> {episode_info['sorttitle']}")
                    plex_episode.editSortTitle(episode_info["sorttitle"])
                    updated = True

                if "released" in episode_info:
                    r = datetime.datetime.strptime(episode_info["released"], "%Y-%m-%d") if isinstance(episode_info["released"], str) else episode_info["released"]

                    if plex_episode.originallyAvailableAt.date() != r.date():
                        logger.debug(f"S{season}E{episode} Release Date: {plex_episode.originallyAvailableAt} -> {r}")
                        plex_episode.editOriginallyAvailable(r)
                        updated = True

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

                if plex_episode.summary != description:
                    logger.debug(f"S{season}E{episode} Description Updated")
                    plex_episode.editSummary(description)
                    updated = True

                bp_suffix = f"-s{season:02d}e{episode:02d}.png"
                poster = await utils.find(f"poster{bp_suffix}")
                background = await utils.find(f"background{bp_suffix}")

                if await self.plex_art_set(poster, plex_episode, True):
                    logger.debug(f"S{season}E{episode} Poster Uploaded: {poster}")
                    updated = True

                if await self.plex_art_set(background, plex_episode, False):
                    logger.debug(f"S{season}E{episode} Background Uploaded: {background}")
                    updated = True

                if updated:
                    completed += 1
                else:
                    skipped += 1

            except:
                logger.exception(f"Skipping season {season} episode {episode}")
                skipped += 1

            index += 1
            await utils.run_func(self.progress_bar_func, int((index / total) * 100))

        await utils.run_func(self.progress_bar_func, 100)
        return (completed, skipped)

    async def _nfo_empty_task(self, src, dst, episode_info):
        return (src, dst, episode_info, "")

    async def process_nfo(self, files):
        tvshow_nfo = AsyncPath(self.output_path, "tvshow.nfo")
        root = ET.Element("tvshow")

        for k, v in self.tvshow.items():
            if isinstance(v, datetime.date):
                logger.debug(f"[{tvshow_nfo.name}] {k} = {v.isoformat()}")
                ET.SubElement(root, str(k)).text = v.isoformat()

            elif k == "plot":
                logger.debug(f"[{tvshow_nfo.name}] plot/outline = {v}")
                ET.SubElement(root, "plot").text = str(v)
                ET.SubElement(root, "outline").text = str(v)

            else:
                logger.debug(f"[{tvshow_nfo.name}] {k} = {v}")
                ET.SubElement(root, str(k)).text = str(v)

        _seasons = dict(sorted(self.seasons.items())).items() if isinstance(self.seasons, dict) else enumerate(self.seasons)
        for k, v in _seasons:
            text = str(v["title"]) if k == 0 else f"{k}. {v['title']}"
            logger.debug(f"[{tvshow_nfo.name}] season {k} = {text}")
            ET.SubElement(root, "namedseason", attrib={"number": str(k)}).text = text

        src = await utils.find("tvshow.png")
        dst = await utils.resolve(self.output_path, "poster.png")
        art = None

        if not await dst.exists():
            if not await src.is_file() and self.fetch_posters:
                try:
                    logger.info(f"Downloading: data/posters/{src.name}")
                    await utils.download(f"{self.download_path}/data/posters/{src.name}", src)
                except:
                    logger.warning(f"Skipping downloading\n{traceback.format_exc()}")

            if await src.is_file():
                logger.info(f"Copying {src.name} to: {dst}")
                await utils.run(shutil.copy2, str(src), str(dst))

        if await dst.is_file():
            art = ET.SubElement(root, "art")
            ET.SubElement(art, "poster").text = str(dst)

        src = await utils.find("background.png")
        dst = await utils.resolve(self.output_path, "background.png")

        if await src.is_file() and not await dst.is_file():
            logger.info(f"Copying {src.name} to: {dst}")
            await utils.run(shutil.copy2, str(src), str(dst))

        if await dst.is_file():
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
            if await tvshow_nfo.is_file():
                txt = await tvshow_nfo.read_bytes()

            if txt != out:
                logger.info(f"Writing {tvshow_nfo.name} to: {tvshow_nfo.parent}")
                await tvshow_nfo.write_bytes(out)
        else:
            if not await tvshow_nfo.is_file():
                logger.info(f"Writing {tvshow_nfo.name} to: {tvshow_nfo.parent}")
                await tvshow_nfo.write_bytes(out)

        index = 0
        completed = 0
        skipped = 0
        total = (len(files) * 2)
        seasons = []

        logger.success("Creating episode metadata and moving the video files...")

        with self.executor_func(max_workers=self.workers) as executor:
            tasks = []
            loop = asyncio.get_event_loop()

            for crc32, file in files:
                episode_info = self.episodes[crc32]
                logger.debug(f"{crc32}: {episode_info}")

                if isinstance(episode_info, list):
                    stop = True

                    for v in episode_info:
                        if "hashes" not in v or "blake2" not in v["hashes"] or v["hashes"]["blake2"] == "":
                            logger.warning(f"Skipping {file.name}: blake2s hash is required but not provided")
                            continue

                        _b = v["hashes"]["blake2"]
                        f, err, b2hash = await utils.run(utils.blake2, file)

                        if err != "":
                            logger.info(f"Skipping {file.name}: {err}")
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

                season = episode_info["season"]
                season_info = self.get_season(season)
                episode = episode_info["episode"]
                title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info["title"]) if "title" in episode_info and episode_info["title"] != "" else ""

                if title == "":
                    logger.warning(f"Skipping {file.name}: metadata for {crc32} has no title, please report this issue as a GitHub issue")
                    index += 1
                    skipped += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                season_path = self.get_season_folder(season)
                if self.file_action != 4 and season not in seasons and season_path != self.output_path:
                    seasons.append(season)

                    if not await season_path.is_dir():
                        logger.debug(f"Creating directory: {season_path}")
                        await season_path.mkdir(exist_ok=True)

                    if season_info is not None:
                        if "title" not in season_info:
                            logger.warning(f"Skipping season {season}: Title not found, metadata might be corrupted?")

                        else:
                            art = None
                            root = ET.Element("season")

                            ET.SubElement(root, "title").text = season_info['title'] if season == 0 else f"{season}. {season_info['title']}"
                            ET.SubElement(root, "seasonnumber").text = f"{season}"

                            if "description" in season_info and season_info["description"] != "":
                                ET.SubElement(root, "plot").text = season_info["description"]
                                ET.SubElement(root, "outline").text = season_info["description"]

                            src = await utils.find(f"poster-season{season}.png")
                            dst = await utils.resolve(season_path, "poster.png")

                            if not await dst.exists():
                                if not await src.is_file() and self.fetch_posters:
                                    try:
                                        logger.info(f"Downloading: data/posters/{src.name}")
                                        await utils.download(f"data/posters/{src.name}", src)
                                    except Exception as e:
                                        logger.warning(f"Skipping downloading: {e}")

                                if await src.is_file():
                                    logger.info(f"Copying {src.name} to: {dst}")
                                    await utils.run(shutil.copy, str(src), str(dst))

                            if await dst.is_file():
                                art = ET.SubElement(root, "art")
                                ET.SubElement(art, "poster").text = str(dst)

                            src = await utils.find(f"background-season{season}.png")
                            dst = await utils.resolve(season_path, "background.png")

                            if await src.is_file() and not await dst.is_file():
                                logger.info(f"Copying {src.name} to: {dst}")
                                await utils.run(shutil.copy2, str(src), str(dst))

                            if await dst.is_file():
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
                                if await season_nfo.is_file():
                                    txt = await season_nfo.read_bytes()

                                if txt != out:
                                    await season_nfo.write_bytes(out)
                                    logger.info(f"Wrote season.nfo to: {season_nfo.parent}")
                            else:
                                if not await season_nfo.is_file():
                                    await season_nfo.write_bytes(out)
                                    logger.info(f"Wrote season.nfo to: {season_nfo.parent}")

                    else:
                        logger.warning(f"Skipping season {season}: Season not found in metadata")

                if self.file_action == 4:
                    _s = str(file)
                    logger.trace(f"Queue [4]: {_s} ({episode_info})")
                    tasks.append(asyncio.create_task(self._nfo_empty_task(_s, _s, episode_info)))
                else:
                    _filename = self.filename_tmpl.format(
                        season=season,
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
                    logger.trace(f"Queue [{self.file_action}]: {file} -> {dst} ({episode_info})")
                    tasks.append(loop.run_in_executor(executor, utils.move_file_worker, str(file), dst, self.file_action, episode_info))

            if len(tasks) > 0:
                index = len(files)
                total = len(files) + len(tasks)

                async for result in asyncio.as_completed(tasks):
                    src, dst, err, info = await result

                    src = await utils.resolve(src)
                    dst = await utils.resolve(dst) if dst is not None else src

                    if err != "":
                        logger.error(f"Skipping {src.name}: {err}")
                        skipped += 1
                        index += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                    nfo_file = AsyncPath(dst.parent, f"{dst.stem}.nfo")
                    season = info["season"]
                    episode = info["episode"]

                    logger.info(f"Updating: Season {season} Episode {episode} ({info['title']})")

                    root = ET.Element("episodedetails")
                    ET.SubElement(root, "title").text = info["title"]

                    if "originaltitle" in info and info["originaltitle"] != "":
                        ET.SubElement(root, "originaltitle").text = info["originaltitle"]

                    if "sorttitle" in info and info["sorttitle"] != "":
                        ET.SubElement(root, "sorttitle").text = info["sorttitle"]

                    ET.SubElement(root, "showtitle").text = self.tvshow["title"]
                    ET.SubElement(root, "season").text = f"{season}"
                    ET.SubElement(root, "episode").text = f"{episode}"
                    ET.SubElement(root, "rating").text = info["rating"] if "rating" in info else self.tvshow["rating"]

                    desc_str = info["description"] if "description" in info and info["description"] != "" else ""
                    manga_str = ""
                    anime_str = ""

                    if info["manga_chapters"] != "":
                        if desc_str != "":
                            manga_str = f"\n\nManga Chapter(s): {info['manga_chapters']}"
                        else:
                            manga_str = f"Manga Chapter(s): {info['manga_chapters']}"

                    if info["anime_episodes"] != "":
                        if desc_str != "" or manga_str != "":
                            anime_str = f"\n\nAnime Episode(s): {info['anime_episodes']}"
                        else:
                            anime_str = f"Anime Episode(s): {info['anime_episodes']}"

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

                    # Posters

                    img_src = None
                    art = None
                    img_list = [
                        f"poster-s{season}e{episode}.png",
                        AsyncPath(self.input_path, f"poster-s{season}e{episode}.png"),
                        f"thumb-s{season}e{episode}.png",
                        AsyncPath(self.input_path, f"thumb-s{season}e{episode}.png"),
                        AsyncPath(src.parent, f"{dst.stem}.png")
                    ]

                    for i in img_list:
                        if isinstance(i, str):
                            i = await utils.find(i)

                        if await i.is_file():
                            img_src = i
                            break

                    if img_src is not None:
                        img_dst = await utils.resolve(dst.parent, f"{dst.stem}{img_src.suffix}")

                        if await img_src.is_file() and not await img_dst.is_file() and self.file_action != 4:
                            logger.info(f"Copying {img_src.name} to: {img_dst}")
                            await utils.run(shutil.copy2, str(img_src), str(img_dst))

                        if await img_dst.is_file():
                            art = ET.SubElement(root, "art")
                            ET.SubElement(art, "poster").text = str(img_dst)

                    # Backgrounds

                    img_src = None
                    img_list = [
                        f"background-s{season}e{episode}.png",
                        AsyncPath(self.input_path, f"background-s{season}e{episode}.png"),
                        AsyncPath(src.parent, f"{dst.stem}-background.png")
                    ]

                    for i in img_list:
                        if isinstance(i, str):
                            i = await utils.find(i)

                        if await i.is_file():
                            img_src = i
                            break

                    if img_src is not None:
                        img_dst = await utils.resolve(dst.parent, f"{dst.stem}-background{img_src.suffix}")

                        if await img_src.is_file() and not await img_dst.is_file() and self.file_action != 4:
                            logger.info(f"Copying {img_src.name} to: {img_dst}")
                            await utils.run(shutil.copy2, str(img_src), str(img_dst))

                        if await img_dst.is_file():
                            if art is None:
                                art = ET.SubElement(root, "art")

                            ET.SubElement(art, "fanart").text = str(img_dst)

                    ET.indent(root)

                    out = await utils.run(
                        ET.tostring,
                        root,
                        encoding='utf-8',
                        xml_declaration=True
                    )

                    if self.overwrite_nfo:
                        txt = ""
                        if await nfo_file.is_file():
                            txt = await nfo_file.read_bytes()

                        if txt != out:
                            logger.debug(f"Writing metadata to: {nfo_file}")
                            await nfo_file.write_bytes(out)
                            completed += 1
                        else:
                            skipped += 1
                    else:
                        if not await nfo_file.is_file():
                            logger.debug(f"Writing metadata to: {nfo_file}")
                            await nfo_file.write_bytes(out)
                            completed += 1

                    index += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))

        await utils.run_func(self.progress_bar_func, 100)
        return (completed, skipped)

    async def start(self):
        try:
            if not isinstance(self.input_path, AsyncPath):
                self.input_path = AsyncPath(str(self.input_path))

            if not isinstance(self.output_path, AsyncPath):
                self.output_path = AsyncPath(str(self.output_path))

            if not isinstance(self.base_path, AsyncPath):
                self.base_path = AsyncPath(str(self.base_path))

            has_data = await self.cache_episode_data()

            if not has_data:
                logger.error("Exiting due to a lack of metadata - grab data.json and put it in the same directory.")
                return (False, None, 0, 0)

            video_files = await self.glob_video_files()
            extra_data = None

            await self.output_path.mkdir(exist_ok=True)
            await utils.run_func(self.progress_bar_func, 0)

            if self.plex_config_enabled:
                extra_data, completed, skipped = await self.process_plex(video_files)
            else:
                completed, skipped = await self.process_nfo(video_files)

            return (True, extra_data, completed, skipped)

        except Exception as e:
            logger.critical(f"Exiting\n{traceback.format_exc()}")
            return (False, e, 0, 0)
