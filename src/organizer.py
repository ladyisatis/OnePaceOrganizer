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

from cryptography.hazmat.primitives import serialization, asymmetric
from loguru import logger
from plexapi.exceptions import TwoFactorRequired as PlexApiTwoFactorRequired, Unauthorized as PlexApiUnauthorized, NotFound as PlexApiNotFound
from plexapi.myplex import MyPlexAccount, MyPlexJWTLogin
from plexapi.server import PlexServer
from pathlib import Path, UnsupportedOperation
from multiprocessing import freeze_support
from src import utils, store

class OnePaceOrganizer:
    def __init__(self):
        self.window_title = "One Pace Organizer"

        # Modes:
        # 0: .nfo (Jellyfin, Emby)
        # 1: Plex: Username and Password
        # 2: Plex: External Login
        # 3: Plex: Authorization Token
        self.mode = int(utils.get_env("mode", 0))

        self.workers = int(utils.get_env("workers", 0))
        self.base_path = Path(utils.get_env("base_path", Path.cwd().resolve()))
        self.metadata_url = utils.get_env("metadata_url", "https://raw.githubusercontent.com/ladyisatis/one-pace-metadata/refs/heads/v2")
        self.download_path = utils.get_env("dl_path", "https://raw.githubusercontent.com/ladyisatis/OnePaceOrganizer/refs/heads/main")
        self.set_executor(utils.get_env("pool_mode", "process") == "process")

        if self.workers == 0:
            self.workers = None

        self.config_file = utils.get_env("config_path", f"{self.base_path}/config.json")
        self.file_action = int(utils.get_env("file_action", 0))
        self.folder_action = int(utils.get_env("folder_action", 0))
        self.fetch_posters = utils.get_env("fetch_posters", True)
        self.overwrite_nfo = utils.get_env("overwrite_nfo", False)
        self.lockdata = utils.get_env("lockdata", False)
        self.lang = utils.get_env("lang", "en")

        self.input_path = utils.get_env("input_path")
        self.output_path = utils.get_env("output_path")
        self.filename_tmpl = utils.get_env("filename_tmpl", "One Pace - S{arc:02d}E{episode:02d} - {title}{suffix}")

        self.plexapi_account: MyPlexAccount = None
        self.plexapi_server: PlexServer = None
        self.plex_last_login = None
        self.plex_config_url = utils.get_env("plex_url", "")

        self.plex_config_servers = {}
        self.plex_config_server_id = utils.get_env("plex_server")

        self.plex_config_libraries = {}
        self.plex_config_library_key = utils.get_env("plex_library")

        self.plex_config_shows = {}
        self.plex_config_show_guid = utils.get_env("plex_show")

        self.plex_config_auth_token = utils.get_env("plex_auth_token")

        self.plex_config_username = utils.get_env("plex_username")
        self.plex_config_password = utils.get_env("plex_password")
        self.plex_config_remember = utils.get_env("plex_remember", False)

        self.plex_jwt_privkey = utils.get_env("plex_jwt_privkey", "")
        if isinstance(self.plex_jwt_privkey, str) and len(self.plex_jwt_privkey) > 0:
            self.plex_jwt_privkey = bytes.fromhex(self.plex_jwt_privkey)
        else:
            self.plex_jwt_privkey = None

        self.plex_jwt_pubkey = utils.get_env("plex_jwt_pubkey", "")
        if isinstance(self.plex_jwt_pubkey, str) and len(self.plex_jwt_pubkey) > 0:
            self.plex_jwt_pubkey = bytes.fromhex(self.plex_jwt_pubkey)
        else:
            self.plex_jwt_pubkey = None

        self.plex_jwt_token = utils.get_env("plex_jwt_token", "")
        self.plex_jwt_timeout = int(utils.get_env("plex_jwt_timeout", 120))
        self._jwtlogin = None

        self.plex_code = utils.get_env("plex_code", "")
        self.plex_retry_secs = utils.get_env("plex_retry_secs", 30)
        self.plex_retry_times = utils.get_env("plex_retry_times", 3)
        self.plex_set_show_edits = utils.get_env("plex_set_show_edits", True)

        self.progress_bar_func = None
        self.message_dialog_func = None
        self.input_dialog_func = None
        self.plex_jwt_func = None
        self.worker_task = None
        self.toml = None
        self.extra_fields = {}

        self.logger = logger
        self.store = store.OrganizerStore(lang=self.lang, logger=self.logger)
        self.opened = False
        self.status = {}

    async def load_config(self):
        if self.toml is None or self.toml["version"] == "?":
            self.toml = utils.get_toml_info(self.base_path)

        self.window_title = f"One Pace Organizer v{self.toml['version']} - github.com/ladyisatis/OnePaceOrganizer"

        if self.config_file is None or self.config_file == "" or (isinstance(self.config_file, Path) and not await utils.is_file(self.config_file)):
            return False

        if not isinstance(self.config_file, Path):
            self.config_file = Path(self.config_file)

        if not await utils.is_file(self.config_file):
            return False

        config = {}

        if hasattr(self.config_file, "suffix") and (self.config_file.suffix == ".yml" or self.config_file.suffix == ".yaml"):
            config = await utils.load_yaml(self.config_file)
        else:
            config = await utils.load_json(self.config_file)

        self.logger.trace(config)

        if "input" in config and config["input"] is not None and config["input"] != "":
            self.input_path = await utils.resolve(config["input"])

        if "output" in config and config["output"] is not None and config["output"] != "":
            self.output_path = await utils.resolve(config["output"])

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

        if "extra_fields" in config and isinstance(config["extra_fields"], dict):
            self.extra_fields = config["extra_fields"]

        if "plex" in config:
            if "enabled" in config["plex"] and config["plex"]["enabled"] is not None:
                self.mode = 1

            if "last_login" in config["plex"] and config["plex"]["last_login"] is not None:
                self.plex_last_login = datetime.datetime.fromisoformat(config["plex"]["last_login"])

            if "url" in config["plex"] and config["plex"]["url"] is not None and config["plex"]["url"] != "":
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
                        if "key" in item:
                            self.plex_config_library_key = item["key"]
                        else:
                            self.plex_config_library_key = library_key
                        break

            if "shows" in config["plex"] and isinstance(config["plex"]["shows"], dict):
                self.plex_config_shows = config["plex"]["shows"]
                for show_guid, item in self.plex_config_shows.items():
                    if item["selected"]:
                        self.plex_config_show_guid = show_guid
                        break

            if "use_token" in config["plex"] and config["plex"]["use_token"] is not None:
                self.mode = 3 if config["plex"]["use_token"] else 1

            if "token" in config["plex"] and config["plex"]["token"] is not None and config["plex"]["token"] != "":
                self.plex_config_auth_token = config["plex"]["token"]

            if "username" in config["plex"] and config["plex"]["username"] is not None and config["plex"]["username"] != "":
                self.plex_config_username = config["plex"]["username"]

            if "password" in config["plex"] and config["plex"]["password"] is not None and config["plex"]["password"] != "":
                self.plex_config_password = config["plex"]["password"]

            if "remember" in config["plex"] and config["plex"]["remember"] is not None:
                self.plex_config_remember = config["plex"]["remember"]

            if "jwt" in config["plex"] and isinstance(config["plex"]["jwt"], dict):
                if config["plex"]["jwt"].get("pri", None) is not None:
                    self.plex_jwt_privkey = bytes.fromhex(config["plex"]["jwt"]["pri"])

                if config["plex"]["jwt"].get("pub", None) is not None:
                    self.plex_jwt_pubkey = bytes.fromhex(config["plex"]["jwt"]["pub"])

                if config["plex"]["jwt"].get("token", "") != "":
                    self.plex_jwt_token = config["plex"]["jwt"]["token"]

            if "retry_secs" in config["plex"] and config["plex"]["retry_secs"] is not None:
                self.plex_retry_secs = int(config["plex"]["retry_secs"])

            if "retry_times" in config["plex"] and config["plex"]["retry_times"] is not None:
                self.plex_retry_times = int(config["plex"]["retry_times"])

            if "set_show_edits" in config["plex"] and config["plex"]["set_show_edits"] is not None:
                self.plex_set_show_edits = config["plex"]["set_show_edits"]

        if "mode" in config and config["mode"] is not None and isinstance(config["mode"], int):
            self.mode = config["mode"]

        return True

    async def save_config(self):
        if self.config_file is None or self.config_file == "":
            return False

        if not isinstance(self.config_file, Path):
            self.config_file = Path(self.config_file)

        privkey = None
        if isinstance(self.plex_jwt_privkey, str):
            privkey = self.plex_jwt_privkey
        elif isinstance(self.plex_jwt_privkey, bytes):
            privkey = self.plex_jwt_privkey.hex()

        pubkey = None
        if isinstance(self.plex_jwt_pubkey, str):
            pubkey = self.plex_jwt_pubkey
        elif isinstance(self.plex_jwt_pubkey, bytes):
            pubkey = self.plex_jwt_pubkey.hex()

        out = {
            "mode": int(self.mode),
            "input": str(self.input_path),
            "output": str(self.output_path),
            "file_action": self.file_action,
            "folder_action": self.folder_action,
            "fetch_posters": self.fetch_posters,
            "overwrite_nfo": self.overwrite_nfo,
            "filename_tmpl": self.filename_tmpl,
            "extra_fields": self.extra_fields,
            "plex": {
                "url": self.plex_config_url,
                "last_login": self.plex_last_login.isoformat() if isinstance(self.plex_last_login, datetime.datetime) else None,
                "servers": self.plex_config_servers,
                "libraries": self.plex_config_libraries,
                "shows": self.plex_config_shows,
                "token": self.plex_config_auth_token,
                "username": self.plex_config_username,
                "password": self.plex_config_password,
                "remember": self.plex_config_remember,
                "jwt": {
                    "pri": privkey,
                    "pub": pubkey,
                    "token": self.plex_jwt_token
                },
                "retry_secs": self.plex_retry_secs,
                "retry_times": self.plex_retry_times,
                "set_show_edits": self.plex_set_show_edits
            }
        }

        if not self.plex_config_remember:
            out["plex"]["last_login"] = ""
            out["plex"]["servers"] = {}
            out["plex"]["libraries"] = {}
            out["plex"]["shows"] = {}
            out["plex"]["token"] = ""
            out["plex"]["jwt"]["token"] = ""
            out["plex"]["username"] = ""
            out["plex"]["password"] = ""

        if hasattr(self.config_file, "suffix") and (self.config_file.suffix == ".yml" or self.config_file.suffix == ".yaml"):
            return await utils.write_file(self.config_file, await utils.run(yaml.safe_dump, out))

        out = await utils.run(orjson.dumps, out, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_INDENT_2)
        return await utils.write_file(self.config_file, out)

    async def open_db(self, data_file=None):
        if self.opened or self.store.conn is not None:
            await self.store.close()

        if data_file is None:
            data_file = Path(self.base_path, "metadata", "data.db")

        if await utils.is_file(data_file):
            res = await self.store.open(data_file)
            if res[0]:
                self.opened = True
                self.status = res[1]
            else:
                self.opened = False
                raise res[1]
        else:
            self.opened = False

    def set_executor(self, process=True):
        self.executor_func = concurrent.futures.ProcessPoolExecutor if process else concurrent.futures.ThreadPoolExecutor

    async def plex_login(self, force_login=False):
        if force_login:
            self.plexapi_account = None
            self.plexapi_server = None
            self.plex_config_auth_token = ""

        if self.plexapi_account is None and self.plexapi_server is None and self.mode != 2 and self.plex_config_auth_token != "" and self.plex_config_remember:
            try:
                if self.plex_config_url == "":
                    self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_config_auth_token)
                    self.plex_last_login = self.plexapi_account.rememberExpiresAt
                else:
                    self.plexapi_server = await utils.run(PlexServer, baseurl=self.plex_config_url, token=self.plex_config_auth_token)
                    self.plex_last_login = None
            except:
                self.logger.debug(traceback.format_exc())
                self.plex_config_auth_token = ""
                self.plexapi_account = None
                self.plexapi_server = None
                self.plex_last_login = None

        if self.plexapi_account is None and self.plexapi_server is None:
            self.plex_config_servers = {}
            self.plex_config_libraries = {}
            self.plex_config_shows = {}

            if self.mode == 3:
                try:
                    if self.plex_config_url == "":
                        self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_config_auth_token)
                        self.plex_last_login = self.plexapi_account.rememberExpiresAt
                    else:
                        self.plexapi_server = await utils.run(PlexServer, baseurl=self.plex_config_url, token=self.plex_config_auth_token)
                        self.plex_last_login = None

                except PlexApiUnauthorized:
                    self.logger.debug(traceback.format_exc())
                    if self.message_dialog_func is not None:
                        await utils.run_func(self.message_dialog_func, "Invalid Plex account token, please try again.")
                    else:
                        self.logger.error("Invalid Plex account token, please try again.")

                    self.plex_last_login = None
                    return False

                except:
                    if self.message_dialog_func is not None:
                        await utils.run_func(self.message_dialog_func, f"Unknown error\n\n{traceback.format_exc()}")
                    else:
                        self.logger.exception("Unknown error")

                    return False

            elif self.mode == 2:
                if self.plex_jwt_func is None:
                    raise Exception("plex_jwt_func is None, please report this as a bug")

                if self.plex_jwt_privkey is None:
                    privkey = await utils.run(asymmetric.ed25519.Ed25519PrivateKey.generate)
                    pubkey = await utils.run(privkey.public_key)

                    self.plex_jwt_privkey = await utils.run(privkey.private_bytes,
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PrivateFormat.Raw,
                        encryption_algorithm=serialization.NoEncryption()
                    )

                    self.plex_jwt_pubkey = await utils.run(pubkey.public_bytes,
                        encoding=serialization.Encoding.Raw,
                        format=serialization.PublicFormat.Raw
                    )

                    self.logger.debug(f"Public Key: {self.plex_jwt_pubkey.hex()}")

                if self.plexapi_account is None and self.plex_jwt_token != "":
                    try:
                        await utils.run_func(self.plex_jwt_func, 0, None)

                        self._jwtlogin = MyPlexJWTLogin(
                            jwtToken=self.plex_jwt_token,
                            keypair=(self.plex_jwt_privkey, self.plex_jwt_pubkey),
                            scopes=['username', 'email', 'friendly_name']
                        )

                        if not await utils.run(self._jwtlogin.verifyJWT):
                            self.plex_jwt_token = await utils.run(self._jwtlogin.refreshJWT)

                    except plexapi.exceptions.BadRequest:
                        self.logger.debug(traceback.format_exc())

                    except:
                        if self.message_dialog_func is not None:
                            await utils.run_func(self.message_dialog_func, f"Unknown error\n\n{traceback.format_exc()}")
                        else:
                            self.logger.exception("Unknown error")

                        return False

                    finally:
                        if self.plex_jwt_token != "":
                            self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_jwt_token)
                            self.plex_last_login = self.plexapi_account.rememberExpiresAt

                if self.plex_jwt_token == "":
                    self.logger.debug("No token found, setting up authorization...")
                    await utils.run_func(self.plex_jwt_func, 1, None)

                    self._jwtlogin = MyPlexJWTLogin(
                        oauth=True,
                        keypair=(self.plex_jwt_privkey, self.plex_jwt_pubkey),
                        scopes=['username', 'email', 'friendly_name']
                    )

                    try:
                        await utils.run(self._jwtlogin.run)

                        oauthUrl = self._jwtlogin.oauthUrl()
                        await utils.run_func(self.plex_jwt_func, 2, oauthUrl)

                        success = await utils.run(self._jwtlogin.waitForLogin)
                        await utils.run_func(self.plex_jwt_func, 3, success)

                        if success:
                            self.plex_jwt_token = self._jwtlogin.jwtToken
                            self.plexapi_account = await utils.run(MyPlexAccount, token=self.plex_jwt_token)
                            self.plex_last_login = self.plexapi_account.rememberExpiresAt

                        else:
                            self.plex_jwt_token = ""
                            self.plex_last_login = None
                            return False

                    except asyncio.CancelledError:
                        if self._jwtlogin is not None:
                            self._jwtlogin.stop()
                            self.plex_jwt_token = ""
                            self.plex_last_login = None

                    except:
                        if self.message_dialog_func is not None:
                            await utils.run_func(self.message_dialog_func, f"Unknown error\n\n{traceback.format_exc()}")
                        else:
                            self.logger.exception("Unknown error")

            elif self.mode == 1:
                try:
                    self.plexapi_account = await utils.run(MyPlexAccount,
                        username=self.plex_config_username, 
                        password=self.plex_config_password, 
                        remember=self.plex_config_remember
                    )
                    self.plex_last_login = self.plexapi_account.rememberExpiresAt

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
                    self.plex_last_login = None
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

        return (self.plexapi_account is not None and self.plexapi_account.authenticationToken != "") or self.plexapi_server is not None

    async def plex_get_servers(self):
        self.plex_config_servers = {}

        if self.plexapi_server is None and self.plex_config_url != "" and (self.plexapi_account is not None or self.plex_config_auth_token != ""):
            try:
                self.plexapi_server = await utils.run(
                    PlexServer,
                    baseurl=self.plex_config_url,
                    token=self.plex_config_auth_token if self.plexapi_account is None else self.plexapi_account.authenticationToken
                )

                self.plex_config_servers[self.plexapi_server.machineIdentifier] = {
                    "name": self.plexapi_server.friendlyName,
                    "selected": True
                }

                self.plex_config_server_id = self.plexapi_server.machineIdentifier

                return True
            except:
                self.logger.debug(traceback.format_exc())
                if self.plexapi_account is not None:
                    self.logger.warning(f"Unable to use direct connection to {self.plex_config_url}. Trying fallback...")
                else:
                    self.logger.error(f"Unable to use direct connection to {self.plex_config_url}.")
                    return False

        if self.plexapi_account is None:
            self.logger.error("Not logged in to Plex.")
            return False

        try:
            resources = await utils.run(self.plexapi_account.resources)
        except:
            self.logger.debug(traceback.format_exc())
            self.logger.trace(self.plexapi_account.authenticationToken)
            self.logger.error("Unable to find any Plex servers.")
            return False

        if len(resources) == 0:
            self.plex_config_server_id = ""

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

            except Exception as e:
                self.logger.error(f"Unable to connect to Plex server '{resources[0].name}': {e}")
                return False

        else:
            for i, resource in enumerate(resources):
                selected = self.plex_config_server_id == resource.clientIdentifier

                self.logger.trace(f"found: {resource.clientIdentifier} ({i}. {resource.name}, selected={selected})")
                self.plex_config_servers[resource.clientIdentifier] = {
                    "name": resource.name,
                    "selected": selected
                }

                if selected:
                    self.logger.info(f"Connecting to {resource.name} ({resource.clientIdentifier})")

                    try:
                        self.plexapi_server = await utils.run(resource.connect)
                        self.logger.info("Connected")

                    except Exception as e:
                        self.logger.error(f"Unable to connect to Plex server '{resource.name}': {e}")
                        return False

        return self.plexapi_server is not None

    async def plex_select_server(self, server_id):
        if server_id == "" or server_id is None:
            self.logger.error("Plex server is blank")
            return False

        if self.plex_config_url != "" and (self.plex_config_auth_token != "" or self.plexapi_account is not None):
            try:
                self.plexapi_server = await utils.run(
                    PlexServer,
                    baseurl=self.plex_config_url,
                    token=self.plex_config_auth_token if self.plexapi_account is None else self.plexapi_account.authenticationToken
                )

                self.logger.debug(f"Found Plex server: {server_id}")
                self.plex_config_server_id = server_id
                return self.plexapi_server.machineIdentifier == server_id
            except:
                self.logger.debug(traceback.format_exc())
                self.logger.warning(f"Unable to use direct connection to {self.plex_config_url}. Trying fallback...")

        if self.plexapi_account is None:
            self.logger.error("Not logged in to Plex.")
            return False

        resources = await utils.run(self.plexapi_account.resources)

        for resource in resources:
            try:
                if resource.clientIdentifier == server_id:
                    self.plexapi_server = await utils.run(resource.connect)
                    self.plex_config_server_id = resource.clientIdentifier

                    for id, item in self.plex_config_servers.items():
                        self.plex_config_servers[id]["selected"] = self.plex_config_server_id == id

                    return True

            except Exception as e:
                self.logger.debug(traceback.format_exc())
                self.logger.error(f"Unable to connect to Plex server '{resource.name}': {e}")

        self.plexapi_server = None
        self.plex_config_server_id = ""
        for id in self.plex_config_servers.keys():
            self.plex_config_servers[id]["selected"] = False

        return False

    async def plex_get_libraries(self):
        if self.plexapi_server is None:
            self.logger.info("Reconnecting to Plex server...")
            connected = await self.plex_select_server(self.plex_config_server_id)
            if not connected:
                return False
            else:
                self.logger.info("Reconnected")

        self.plex_config_libraries = {}

        try:
            self.logger.trace("plex_get_libraries: fetching all library sections")
            sections = await utils.run(self.plexapi_server.library.sections)
            self.logger.trace(f"plex_get_libraries: found {len(sections)} total sections")

        except Exception as e:
            self.logger.debug(f"plex_get_libraries: Exception occurred: {e}")
            self.logger.trace(f"plex_get_libraries: Full traceback: {traceback.format_exc()}")
            if self.message_dialog_func is None:
                self.logger.error("Unable to fetch Plex libraries from this server.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to fetch Plex libraries from this server.")

            return False

        for section in sections:
            self.logger.trace(f"plex_get_libraries: section '{section.title}' (type: {section.type}, key: {section.key})")
            if section.type == 'show':
                section_key_str = str(section.key)
                selected = self.plex_config_library_key == section.key or self.plex_config_library_key == section_key_str
                self.plex_config_libraries[section_key_str] = {
                    "key": section.key,
                    "title": section.title,
                    "selected": selected
                }
                self.logger.trace(f"plex_get_libraries: added show library '{section.title}' (key: {section_key_str}, selected: {selected})")

        self.logger.trace(f"plex_get_libraries: available libraries keys: {list(self.plex_config_libraries.keys())}")
        self.logger.debug(f"plex_get_libraries: returning {len(self.plex_config_libraries)} > 0 = {len(self.plex_config_libraries) > 0}")
        return len(self.plex_config_libraries) > 0

    async def plex_select_library(self, library_key):
        if self.plexapi_server is None:
            self.logger.info("Reconnecting to Plex server...")
            connected = await self.plex_select_server(self.plex_config_server_id)
            if not connected:
                return False
            else:
                self.logger.info("Reconnected")

        self.logger.trace(f"plex_select_library: Looking for key '{library_key}' (type: {type(library_key)})")
        self.logger.trace(f"plex_select_library: Available keys: {list(self.plex_config_libraries.keys())}")

        if str(library_key) not in self.plex_config_libraries:
            self.logger.error(f"plex_select_library: Library key '{library_key}' not found in available libraries")
            return False

        self.plex_config_library_key = ""

        for k, v in self.plex_config_libraries.items():
            if "key" in v:
                self.plex_config_libraries[k]["selected"] = library_key == v["key"]
                if self.plex_config_libraries[k]["selected"]:
                    self.plex_config_library_key = v["key"]
            else:
                self.plex_config_libraries[k]["selected"] = library_key == k
                if self.plex_config_libraries[k]["selected"]:
                    self.plex_config_library_key = k

        self.logger.debug(f"plex_select_library: Selected library '{library_key}'")
        return True

    async def plex_get_shows(self):
        if self.plexapi_server is None:
            self.logger.info("Reconnecting to Plex server...")
            connected = await self.plex_select_server(self.plex_config_server_id)
            if not connected:
                return False
            else:
                self.logger.info("Reconnected")

        if not isinstance(self.plex_config_library_key, int) and self.plex_config_library_key == "":
            self.logger.trace("plex_get_shows: library key is empty")
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
            self.logger.debug(f"plex_get_shows: Exception occurred: {e}")
            self.logger.trace(f"plex_get_shows: Full traceback: {traceback.format_exc()}")
            if self.message_dialog_func is None:
                self.logger.error("Unable to fetch Plex shows from this server.")
            else:
                await utils.run_func(self.message_dialog_func, "Unable to fetch Plex shows from this server.")

            return False

        if len(shows) == 0:
            if self.message_dialog_func is None:
                self.logger.warning(f"plex_get_shows: No shows found in library '{section.title}' (ID: {self.plex_config_library_key})")
            else:
                await utils.run_func(self.message_dialog_func, f"Unable to fetch Plex shows from library '{section.title}'.")

            return False

        for show in shows:
            selected = self.plex_config_show_guid == show.guid
            self.plex_config_shows[show.guid] = {
                "title": show.title,
                "selected": selected
            }
            self.logger.trace(f"plex_get_shows: added show '{show.title}' with GUID '{show.guid}' (selected: {selected})")

        self.logger.debug(f"plex_get_shows: returning {len(self.plex_config_shows)} > 0 = {len(self.plex_config_shows) > 0}")
        return len(self.plex_config_shows) > 0

    async def plex_select_show(self, guid):
        if self.plexapi_server is None:
            self.logger.info("Reconnecting to Plex server...")
            connected = await self.plex_select_server(self.plex_config_server_id)
            if not connected:
                return False
            else:
                self.logger.info("Reconnected")

        self.logger.trace(f"plex_select_show: Looking for GUID '{guid}' (type: {type(guid)})")
        self.logger.trace(f"plex_select_show: Available GUIDs: {list(self.plex_config_shows.keys())}")

        if guid.startswith("local://"):
            self.logger.debug(f"plex_select_show: GUID '{guid}' is a local:// GUID, skipping lookup in available shows")
            self.plex_config_show_guid = guid
            return True

        if guid != "" and guid not in self.plex_config_shows:
            self.logger.error(f"plex_select_show: Show GUID '{guid}' not found in available shows")
            return False

        self.plex_config_show_guid = guid

        for k, v in self.plex_config_shows.items():
            self.plex_config_shows[k]["selected"] = guid == k

        self.logger.debug(f"plex_select_show: Selected show '{guid}'")
        return True

    async def cache_episode_data(self):
        data_file = Path(self.base_path, "metadata", "data.db")
        update_data_file = True

        if await utils.is_file(data_file):
            try:
                await self.open_db(data_file)

                if self.opened and self.status.get("last_update_ts", None) is not None:
                    update_data_file = False
                    now = datetime.datetime.now(tz=datetime.timezone.utc)
                    data_file_stat = await utils.stat(data_file)

                    last_update_remote = datetime.datetime.fromtimestamp(self.status["last_update_ts"], tz=datetime.timezone.utc)
                    last_update_local = datetime.datetime.fromtimestamp(data_file_stat.st_mtime, tz=datetime.timezone.utc)
                    self.logger.trace(f"last_update_remote: {last_update_remote} / last_update_local: {last_update_local}")

                    if (now - last_update_remote > datetime.timedelta(seconds=3600)) or (now - last_update_local > datetime.timedelta(seconds=3600)):
                        try:
                            status_resp = await utils.run(httpx.get, f"{self.metadata_url}/metadata/status.json", follow_redirects=True)
                            if status_resp.status_code >= 200 and status_resp.status_code < 400:
                                status_json = await utils.run(orjson.loads, status_resp.content)
                                update_data_file = status_json["last_update_ts"] != self.status["last_update_ts"]

                                self.status["last_update"] = status_json["last_update"]
                                self.status["last_update_ts"] = status_json["last_update_ts"]
                        except:
                            self.logger.debug(f"Skipping status.json check\n{traceback.format_exc()}")
                            update_data_file = True

            except:
                self.logger.warning(f"Danger: {data_file} might be corrupted!\n{traceback.format_exc()}")

        if update_data_file:
            try:
                if self.opened:
                    await self.store.close()

                await utils.run(data_file.parent.mkdir, exist_ok=True)

                self.logger.success("Downloading updated metadata into metadata/data.db...")
                await utils.download(f"{self.metadata_url}/metadata/data.sqlite", data_file, self.progress_bar_func)
                await self.open_db(data_file)

            except Exception as e:
                self.logger.debug(traceback.format_exc())
                self.logger.error(f"Unable to download new metadata: {e}")

        if await utils.is_dir(data_file.parent):
            await self.store.cache_files(data_file.parent)

        self.logger.debug(f"SQLite DB Open: {self.opened}")
        return self.opened or (len(self.store.tvshow) > 0 and len(self.store.arcs) > 0 and len(self.store.episodes) > 0)

    async def glob_video_files(self):
        self.logger.success("Searching for .mkv and .mp4 files...")

        with self.executor_func(max_workers=self.workers) as executor:
            crc_pattern = re.compile(r'\[([A-Fa-f0-9]{8})\](?=\.(mkv|mp4))')
            fname_pattern = re.compile(r'\[(?:One Pace)?\]\[\d+(?:[-,]\d+)*\]\s+(.+?)(?:\s+(\d{2,})(?:\s+(.+?))?)?\s+\[\d+p\](?:\[[^\]]+\])*\[([A-Fa-f0-9]{8})\]\.(?:mkv|mp4)')
            filelist = []

            async for file in utils.iter(self.input_path.rglob, "*.[mM][kK][vV]", case_sensitive=False, recurse_symlinks=True, executor=executor):
                await utils.run(filelist.append, file)

            async for file in utils.iter(self.input_path.rglob, "*.[mM][pP]4", case_sensitive=False, recurse_symlinks=True, executor=executor):
                await utils.run(filelist.append, file)

            num_found = 0
            num_calced = 0
            filelist_total = len(filelist)
            results = []
            self.logger.debug(f"{filelist_total} files found")

            tasks = []
            loop = asyncio.get_running_loop()

            await utils.run_func(self.progress_bar_func, 0)

            for file in filelist:
                file = await utils.resolve(file)
                file_name = f"{file.stem if hasattr(file, 'stem') else ''}{file.suffix.lower() if hasattr(file, 'suffix') else ''}"

                match = await utils.run(crc_pattern.search, file_name, loop=loop, executor=executor)
                if match:
                    episode_id = await self.store.get_episode(file_name=file_name, crc32=match.group(1).upper() if match else None, ids_only=True)
                    if episode_id is not None:
                        num_found += 1
                        results.append((0, episode_id, file, None))
                        await utils.run_func(self.progress_bar_func, int((num_found / len(filelist_total)) * 100))
                        continue

                match = await utils.run(fname_pattern.match, file_name, loop=loop, executor=executor)
                if match:
                    arc_name, ep_num, extra, crc32 = await utils.run(match.groups)

                    if ep_num is None:
                        num_found += 1
                        results.append((3, crc32, file, None))
                        self.logger.warning(f"Skipping {file.name}: This seems to be a Specials/April Fools release, but there is no metadata for it.")
                        await utils.run_func(self.progress_bar_func, int((num_found / len(filelist_total)) * 100))
                        continue

                    arc_res = await self.store.get_arc(title=arc_name)
                    if arc_res is not None:
                        arc_num = arc_res.get("part", 0)

                        episode_id = await self.store.get_episode(arc=arc_num, episode=int(ep_num), crc32=crc32, ids_only=True)
                        if episode_id is not None:
                            num_found += 1
                            results.append((0, episode_id, file, extra))
                            await utils.run_func(self.progress_bar_func, int((num_found / len(filelist_total)) * 100))
                            continue

                file_stem = file.stem if hasattr(file, "stem") else file.name
                key = f"2_{file_stem}"
                if f"2_{file_stem}" in self.store.episodes:
                    num_found += 1
                    results.append((2, key, file, None))
                    await utils.run_func(self.progress_bar_func, int((num_found / len(filelist_total)) * 100))
                    continue

                self.logger.debug(f"Add to Hash Queue: {file}")
                tasks.append(loop.run_in_executor(executor, utils.hash, str(file)))

            if len(tasks) > 0:
                self.logger.success(f"Calculating file hashes for {len(tasks)} file(s)...")

                try:
                    i = 0
                    async for result in asyncio.as_completed(tasks):
                        i += 1
                        try:
                            file, error, crc32, blake2s = await result
                            file = Path(file)

                            if error != "":
                                self.logger.error(f"[{i}/{len(tasks)}] Unable to calculate {file.name}: {error}")
                                continue

                            num_calced = num_calced + 1
                            self.logger.info(f"[{i}/{len(tasks)}] {file.name}: {crc32}/{blake2s}")

                            #1. Check Other Edits table for blake2s (less likely for CRC32 collision)
                            result = await self.store.get_other_edit(blake2s=blake2s, ids_only=True)
                            if result is not None:
                                results.append((1, result, file, None))
                                continue

                            #2. Check official releases [CRC32/Blake2s]
                            result = await self.store.get_episode(crc32=crc32, blake2s=blake2s, ids_only=True)
                            if result is not None:
                                results.append((0, result, file, None))
                                continue

                            #3. Check Other Edits for CRC32
                            result = await self.store.get_other_edit(crc32=crc32, ids_only=True)
                            if result is not None:
                                results.append((1, result, file, None))
                                continue

                            #4. Check local yml
                            key = f"1_{crc32}"
                            if key in self.store.episodes:
                                results.append((2, key, file, None))
                                continue

                            key - f"2_{blake2s}"
                            if key in self.store.episodes:
                                results.append((2, key, file, None))
                                continue

                            #5. Add to the "rejected" pile (show to user)
                            results.append((3, crc32, file, None))
                            self.logger.warning(f"Skipping {file.name}: Episode metadata missing. Make sure you have the latest version of this One Pace release.")

                        finally:
                            await utils.run_func(self.progress_bar_func, int(((num_found + i) / len(filelist_total)) * 100))

                except (asyncio.CancelledError, KeyboardInterrupt) as e:
                    if sys.version_info >= (3, 14):
                        executor.kill_workers()
                    else:
                        for task in tasks:
                            task.kill()

                    raise e
                    return False

        await utils.run_func(self.progress_bar_func, 100)
        self.logger.success(f"Found: {num_found}, Calculated: {num_calced}, Total: {filelist_total}")

        return results

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
            if self.plex_config_show_guid != "":
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

                if self.plex_set_show_edits:
                    tvshow = self.store.tvshow

                    if "tagline" in tvshow and tvshow["tagline"] != "" and show.tagline != tvshow["tagline"]:
                        self.logger.info(f"Set Tagline: {show.tagline} -> {tvshow['tagline']}")
                        await utils.run(show.editTagline, tvshow["tagline"], locked=self.lockdata)

                    if "customrating" in tvshow and tvshow["customrating"] != "" and show.contentRating != tvshow["customrating"]:
                        self.logger.info(f"Set Rating: {show.contentRating} -> {tvshow['customrating']}")
                        await utils.run(show.editContentRating, tvshow["customrating"], locked=self.lockdata)

                    if "genre" in tvshow and isinstance(tvshow["genre"], list):
                        _genres = []
                        for genre in show.genres:
                            _genres.append(genre.tag)

                        for genre in tvshow["genre"]:
                            if genre not in _genres:
                                self.logger.info(f"Add Genre: {genre}")
                                await utils.run(show.addGenre, genre)

                    if "plot" in tvshow and show.summary != tvshow["plot"]:
                        await utils.run(show.editSummary, tvshow["plot"], locked=self.lockdata)

                        if "premiered" in tvshow:
                            if isinstance(tvshow["premiered"], (datetime.date, datetime.datetime)):
                                await utils.run(show.editOriginallyAvailable, str(tvshow["premiered"].isoformat()).split("T")[0])
                            else:
                                await utils.run(show.editOriginallyAvailable, tvshow["premiered"])

            # Poster
            src = await utils.run(utils.find_from_list, self.base_path, [
                ("posters", "poster.*"),
                ("posters", "folder.*"),
                (self.input_path, "poster.*")
            ])

            if not src and self.fetch_posters:
                src = Path(self.base_path, "posters", "poster.png")
                self.logger.info(f"Downloading: posters/{src.name}")

                try:
                    dl = await utils.download(f"{self.download_path}/posters/{src.name}", src, self.progress_bar_func)
                    if not dl:
                        self.logger.info("Unable to download (not found), skipping...")
                except:
                    self.logger.warning("Unable to download, skipping...")

            dst = await utils.resolve(self.output_path, f"poster{src.suffix}" if src is not None else "poster.png")

            if not await utils.exists(dst) and await utils.is_file(src):
                self.logger.info(f"Copying {src.name} to: {dst}")
                await utils.copy_async(src, dst)

            #Background
            src = await utils.run(utils.find_from_list, self.base_path, [
                ("posters", "background.*"),
                ("posters", "backdrop.*"),
                ("posters", "fanart.*"),
                (self.input_path, "background.*")
                (self.input_path, "fanart.*")
            ])
            if src is not None:
                dst = await utils.resolve(self.output_path, f"background{src.suffix}")
                if not await utils.exists(dst) and await utils.is_file(src):
                    self.logger.info(f"Copying {src.name} to: {dst}")
                    await utils.copy_async(src, dst)

            #Square Art
            src = await utils.run(utils.find_from_list, self.base_path, [
                ("posters", "square.*"),
                ("posters", "squareArt.*"),
                ("posters", "backgroundSquare.*"),
                (self.input_path, "square.*"),
                (self.input_path, "squareArt.*"),
                (self.input_path, "backgroundSquare.*")
            ])
            if src is not None:
                dst = await utils.resolve(self.output_path, f"square{src.suffix}")
                if not await utils.exists(dst) and await utils.is_file(src):
                    self.logger.info(f"Copying {src.name} to: {dst}")
                    await utils.copy_async(src, dst)

            #Banners
            src = await utils.run(utils.find_from_list, self.base_path, [
                ("posters", "banner.*"),
                (self.input_path, "banner.*")
            ])
            if src is not None:
                dst = await utils.resolve(self.output_path, f"banner{src.suffix}")
                if not await utils.exists(dst) and await utils.is_file(src):
                    self.logger.info(f"Copying {src.name} to: {dst}")
                    await utils.copy_async(src, dst)

            index = 0
            total = len(files)
            res = []
            seasons = []

            self.logger.success("Processing the video files...")

            with self.executor_func(max_workers=self.workers) as executor:
                tasks = []
                loop = asyncio.get_running_loop()

                for file_type, file_id, file in files:
                    if file_type == 0:
                        episode_info = await self.store.get_episode(id=file_id, with_descriptions=True)
                    elif file_type == 1:
                        episode_info = await self.store.get_other_edit(id=file_id)
                    elif file_type == 2:
                        episode_info = await self.store.episodes.get(file_id, None)
                    elif file_type == 3:
                        skipped += 1
                        index += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                    season = episode_info.get("arc", 0)
                    episode = episode_info.get("episode", 0)
                    title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info.get("title", ""))

                    if title == "":
                        self.logger.warning(f"Skipping {file.name}: metadata for {episode_info['hash_crc32']} has no title, please report this issue as a GitHub issue")
                        skipped += 1
                        index += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                    if episode_info.get("extended", False):
                        title = f"{title} (Extended)"

                    season_path = Path(self.output_path, "Specials" if season == 0 else f"Season {season:02d}")
                    if season not in seasons:
                        seasons.append(season)
                        self.logger.info(f"Season: {season}")

                        if not await utils.is_dir(season_path):
                            self.logger.debug(f"Creating directory: {season_path}")
                            await utils.run(season_path.mkdir, exist_ok=True)

                    dst = str(Path(season_path, f"One Pace - S{season:02d}E{episode:02d} - {title}{file.suffix}"))
                    self.logger.debug(f"Queue: file={file}, dst={dst}, info={episode_info} [{self.file_action}]")
                    tasks.append(loop.run_in_executor(executor, utils.move_file_worker, str(file), dst, self.file_action, file_type, file_id))

                if len(tasks) > 0:
                    async for result in asyncio.as_completed(tasks):
                        src, file, err, file_type, file_id = await result
                        file = await utils.resolve(file)

                        if err != "":
                            self.logger.error(f"Skipping {src}: {err}")
                            skipped += 1

                        else:
                            self.logger.debug(f"Complete: [{file_id}] {file} ({file_type})")
                            res.append((file_type, file_id, file))
                            completed += 1

                        index += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))

        except Exception as e:
            return (False, e, completed, skipped)

        finally:
            if show is not None:
                try:
                    await utils.run(show.saveEdits)
                except Exception as e:
                    return (False, e, completed, skipped)

        return (True, res, completed, skipped)

    async def process_plex_episodes(self, queue, metadata_only=False):
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

            if metadata_only:
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

                    arc_eps = {}
                    for crc32, ep_data in self.episodes.items():
                        _arc = ep_data.get("arc")
                        _episode = ep_data.get("episode")

                        if _arc not in arc_eps:
                            arc_eps[_arc] = {}

                        if _episode not in arc_eps[_arc]:
                            arc_eps[_arc][_episode] = crc32

                    for plex_ep in all_episodes:
                        season = plex_ep.parentIndex if hasattr(plex_ep, 'parentIndex') else plex_ep.seasonNumber
                        ep_id = await self.store.get_episode(arc=season, episode=plex_ep.index, ids_only=True)
                        if ep_id is None:
                            self.logger.debug(f"No metadata found for S{season}E{episode}")
                            continue

                        queue.append((4, ep_id, plex_ep))

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
                file_type, file_id, file = item
                
                if file_type == 0 or file_type == 4:
                    episode_info = await self.store.get_episode(id=file_id, with_descriptions=True)
                elif file_type == 1:
                    episode_info = await self.store.get_other_edit(id=file_id)
                elif file_type == 2:
                    episode_info = self.store.episodes[file_id]
                elif file_type == 3:
                    continue

                self.logger.debug(f"Start: [{file_type}/{file_id}] {file} ({episode_info})")

                season = episode_info["arc"]
                season_info = await self.store.get_arc(part=season)
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
                                season_desc = season_info["description"] if "description" in season_info else ""

                                await utils.run(plex_season.batchEdits)

                                if plex_season.title != season_title:
                                    self.logger.debug(f"Season {season} Title: {season_title}")
                                    await utils.run(plex_season.editTitle, season_title, locked=self.lockdata)

                                if season_desc != "" and plex_season.summary != season_desc:
                                    self.logger.debug(f"Season {season} Summary: {season_desc}")
                                    await utils.run(plex_season.editSummary, season_desc, locked=self.lockdata)

                                # Poster
                                src = await utils.run(utils.find_from_list, self.base_path, [
                                    (f"posters/{season}", "poster.*"),
                                    (f"posters/{season}", "folder.*"),
                                    (self.input_path, f"poster-s{season:02d}.*")
                                ])

                                if not src and self.fetch_posters:
                                    src = Path(self.base_path, "posters", str(season), "poster.png")
                                    self.logger.info(f"Downloading: posters/{season}/{src.name}")

                                    try:
                                        dl = await utils.download(f"{self.download_path}/posters/{season}/{src.name}", src, self.progress_bar_func)
                                        if not dl:
                                            self.logger.info("Unable to download (not found), skipping...")
                                    except:
                                        self.logger.warning("Unable to download, skipping...")

                                dst = await utils.resolve(
                                    self.output_path,
                                    f"Season {season:02d}",
                                    f"Season{season:02d}{src.suffix}" if src is not None else f"Season{season:02d}.png"
                                )

                                if not await utils.exists(dst) and await utils.is_file(src):
                                    self.logger.info(f"Copying {src.name} to: {dst}")
                                    await utils.copy_async(src, dst)

                                #Background
                                src = await utils.run(utils.find_from_list, self.base_path, [
                                    (f"posters/{season}", "background.*"),
                                    (f"posters/{season}", "backdrop.*"),
                                    (f"posters/{season}", "fanart.*"),
                                    (self.input_path, f"background-s{season:02d}.*")
                                ])
                                if src is not None:
                                    dst = await utils.resolve(
                                        self.output_path,
                                        f"Season {season:02d}",
                                        f"season-specials-banner{src.suffix}" if season == 0 else f"Season{season:02d}-banner{src.suffix}"
                                    )
                                    if not await utils.exists(dst) and await utils.is_file(src):
                                        self.logger.info(f"Copying {src.name} to: {dst}")
                                        await utils.copy_async(src, dst)

                                #Theme
                                src = await utils.run(utils.find_from_list, self.base_path, [
                                    (f"posters/{season}", "theme.*"),
                                    (self.input_path, f"theme-s{season:02d}.*")
                                ])
                                if src is not None:
                                    dst = await utils.resolve(
                                        self.output_path,
                                        f"Season {season:02d}",
                                        f"theme{src.suffix}"
                                    )
                                    if not await utils.exists(dst) and await utils.is_file(src):
                                        self.logger.info(f"Copying {src.name} to: {dst}")
                                        await utils.copy_async(src, dst)

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

                    if file_type == 4:
                        plex_episode = file
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
                                        f"to it yet. Waiting {retry_secs} second(s)... (attempt {retry_count}/{max_retries})")
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

                            if episode_info["title"].startswith("The "):
                                await utils.run(plex_episode.editSortTitle, episode_info["title"].replace("The ", "", 1), locked=self.lockdata)

                            updated = True

                        if "rating" in episode_info and plex_episode.contentRating != episode_info["rating"]:
                            self.logger.debug(f"S{season}E{episode} Rating: {plex_episode.contentRating} -> {episode_info['rating']}")
                            await utils.run(plex_episode.editContentRating, episode_info["rating"], locked=self.lockdata)
                            updated = True

                        if "released" in episode_info:
                            if isinstance(episode_info["released"], str):
                                r = episode_info["released"]
                                r = r.split("T")[0]
                                r = r.split(" ")[0]
                                r = datetime.datetime.strptime(r, "%Y-%m-%d").date()
                            else:
                                r = episode_info["released"]

                            if isinstance(r, (datetime.datetime, datetime.date)):
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

                        desc_str = episode_info.get("description", "")
                        manga_str = ""
                        anime_str = ""

                        if str(episode_info["manga_chapters"]) != "":
                            if desc_str != "":
                                manga_str = f"\n\nManga Chapter(s): {episode_info['manga_chapters']}"
                            else:
                                manga_str = f"Manga Chapter(s): {episode_info['manga_chapters']}"

                        if str(episode_info["anime_episodes"]) != "":
                            if desc_str != "" or manga_str != "":
                                anime_str = f"\n\nAnime Episode(s): {episode_info['anime_episodes']}"
                            else:
                                anime_str = f"Anime Episode(s): {episode_info['anime_episodes']}"

                        description = f"{desc_str}{manga_str}{anime_str}"

                        if plex_episode.summary != description:
                            self.logger.debug(f"S{season}E{episode} Description Updated")
                            await utils.run(plex_episode.editSummary, description, locked=self.lockdata)
                            updated = True

                        poster_search_paths = [
                            (f"posters/{season}/{episode}", "background.*"),
                            (self.input_path, f"background-s{season:02d}e{episode:02d}.*"),
                            (f"posters/{season}/{episode}", "poster.*"),
                            (self.input_path, f"poster-s{season:02d}e{episode:02d}.*")
                        ]

                        if hasattr(src, 'stem'):
                            poster_search_paths.extend([
                                (self.input_path, f"{src.stem}-background.*"),
                                (self.input_path, f"{src.stem}-backdrop.*"),
                                (self.input_path, f"{src.stem}-poster.*"),
                                (self.input_path, f"{src.stem}-thumb.*")
                            ])

                        poster = await utils.run(utils.find_from_list, self.base_path, poster_search_paths)

                        if poster is not None and hasattr(poster, 'suffix') and hasattr(src, 'stem'):
                            stem_suffix = f"{src.stem}{poster.suffix}"
                            dst = await utils.resolve(self.output_path, f"Season {season:02d}", stem_suffix)
                            if stem_suffix != "" and not await utils.exists(dst) and await utils.is_file(poster):
                                self.logger.info(f"Copying {poster.name} to: {dst}")
                                await utils.copy_async(poster, dst)
                                updated = True

                        subtitle_search_paths = [
                            (self.input_path, f"subtitle-s{season:02d}e{episode:02d}.*")
                        ]

                        if hasattr(src, 'stem'):
                            subtitle_search_paths.append(
                                (self.input_path, f"{src.stem}-subtitle.*")
                            )

                        subtitle = await utils.run(utils.find_from_list, self.base_path, subtitle_search_paths)

                        if subtitle is not None and hasattr(subtitle, 'suffixes') and hasattr(src, 'stem'):
                            suffixes = "".join(subtitle.suffixes)
                            stem_suffix = f"{src.stem}{suffixes}"
                            dst = await utils.resolve(self.output_path, f"Season {season:02d}", stem_suffix)
                            if stem_suffix != "" and not await utils.exists(dst) and await utils.is_file(poster):
                                self.logger.info(f"Copying {poster.name} to: {dst}")
                                await utils.copy_async(poster, dst)
                                updated = True

                        if updated:
                            completed += 1
                        else:
                            skipped += 1

                except Exception as e:
                    self.logger.debug(traceback.format_exc())
                    self.logger.error(f"Skipping season {season} episode {episode}: {e}")
                    skipped += 1

                finally:
                    if plex_episode is not None:
                        try:
                            await utils.run(plex_episode.saveEdits)
                        except Exception as e:
                            self.logger.warning(f"Failed to save season {season} episode {episode}: {e}")

                    plex_episode = None

                index += 1
                await utils.run_func(self.progress_bar_func, int((index / total) * 100))

            await utils.run_func(self.progress_bar_func, 100)
            return (True, None, completed, skipped)

        except Exception as e:
            return (False, e, completed, skipped)

    async def _nfo_empty_task(self, src, dst, file_type, file_id):
        return (src, dst, "", file_type, file_id)

    async def process_nfo(self, files):
        tvshow = self.store.tvshow
        tvshow_nfo = Path(self.output_path, "tvshow.nfo")
        root = ET.Element("tvshow")

        for k, v in tvshow.items():
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

        _seasons = await self.store.get_arcs()
        for arc_info in _seasons:
            part = arc_info["part"]
            text = arc_info["title"] if part == 0 else f"{part}. {arc_info['title']}"
            self.logger.debug(f"[{tvshow_nfo.name}] season {part} = {text}")
            ET.SubElement(root, "namedseason", attrib={"number": str(part)}).text = text

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
                        self.logger.info(f"Skipping downloading (not found)")
                except:
                    self.logger.warning(f"Skipping downloading\n{traceback.format_exc()}")

            if await utils.is_file(src):
                self.logger.info(f"Copying {src.name} to: {dst}")
                await utils.copy_async(src, dst)

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
            await utils.copy_async(src, dst)

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

        elif not await utils.is_file(tvshow_nfo):
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

            for file_type, file_id, file in files:
                if file_type == 0:
                    episode_info = await self.store.get_episode(id=file_id, with_descriptions=True)
                elif file_type == 1:
                    episode_info = await self.store.get_other_edit(id=file_id)
                elif file_type == 2:
                    episode_info = await self.store.episodes.get(file_id, None)
                elif file_type == 3:
                    skipped += 1
                    index += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                if episode_info is None:
                    self.logger.warning(f"Skipping {file.name}: Episode metadata missing")
                    skipped += 1
                    index += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                season = episode_info.get("arc", 0)
                season_info = await self.store.get_arc(part=season)
                episode = episode_info.get("episode", 0)
                title = re.sub(r'[<>:"/\\|?*\x00-\x1F]', "", episode_info.get("title", ""))

                if title == "":
                    self.logger.warning(f"Skipping {file.name}: metadata for {episode_info['hash_crc32']} has no title, please report this issue as a GitHub issue")
                    index += 1
                    skipped += 1
                    await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                    continue

                if episode_info.get("extended", False):
                    title = f"{title} (Extended)"

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

                            if season_info.get("originaltitle", "") != "":
                                ET.SubElement(root, "originaltitle").text = str(season_info['originaltitle'])

                            if season_info.get("sorttitle", "") != "":
                                ET.SubElement(root, "sorttitle").text = str(season_info['sorttitle'])

                            ET.SubElement(root, "seasonnumber").text = str(season)

                            if season_info.get("description", "") != "":
                                ET.SubElement(root, "plot").text = season_info["description"]
                                ET.SubElement(root, "outline").text = season_info["description"]

                            ET.SubElement(root, "customrating").text = season_info['rating'] if 'rating' in season_info else tvshow['customrating']
                            ET.SubElement(root, "lockdata").text = "true" if self.lockdata else "false"

                            src = await utils.run(utils.find_from_list, self.base_path, [
                                (f"posters/{season}", "poster.*"),
                                (f"posters/{season}", "folder.*"),
                                (self.input_path, f"poster-s{season:02d}.*")
                            ])
                            dst_fn = "season-specials-poster" if season == 0 else f"Season{season:02d}"
                            dst = await utils.resolve(season_path, f"{dst_fn}.png" if src is None else f"{dst_fn}{src.suffix}")

                            if not await utils.exists(dst):
                                if not src and self.fetch_posters:
                                    src = Path(self.base_path, "posters", str(season), "poster.png")
                                    try:
                                        self.logger.info(f"Downloading: posters/{src.name}")
                                        dl = await utils.download(f"{self.download_path}/posters/{season}/{src.name}", src, self.progress_bar_func)
                                        if not dl:
                                            self.logger.info("Skipping downloading (not found)")
                                    except Exception as e:
                                        self.logger.warning(f"Skipping downloading: {e}")

                                if await utils.is_file(src):
                                    self.logger.info(f"Copying {src.name} to: {dst}")
                                    await utils.copy_async(src, dst)

                            if await utils.is_file(dst):
                                art = ET.SubElement(root, "art")
                                ET.SubElement(art, "poster").text = str(dst)

                            src = await utils.run(utils.find_from_list, self.base_path, [
                                (f"posters/{season}", "background.*"),
                                (f"posters/{season}", "backdrop.*"),
                                (self.input_path, f"background-s{season:02d}.*")
                            ])
                            dst_fn = "season-specials" if season == 0 else f"Season{season:02d}"
                            dst = await utils.resolve(season_path, f"{dst_fn}-banner.png" if src is None else f"{dst_fn}-banner{src.suffix}")

                            if src and not await utils.is_file(dst):
                                self.logger.info(f"Copying {src.name} to: {dst}")
                                await utils.copy_async(src, dst)

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

                            elif not await utils.is_file(season_nfo):
                                await utils.write_file(season_nfo, out)
                                self.logger.info(f"Wrote season.nfo to: {season_nfo.parent}")

                    else:
                        self.logger.warning(f"Skipping season {season}: Season not found in metadata")

                if self.file_action == 4:
                    _s = str(file)
                    self.logger.trace(f"Queue [4]: {_s} ({episode_info})")
                    tasks.append(asyncio.create_task(self._nfo_empty_task(_s, _s, file_type, file_id)))
                else:
                    _filename = self.filename_tmpl.format(
                        season=season,
                        arc=season,
                        episode=episode,
                        title=title,
                        name=file.name if hasattr(file, "name") else "",
                        stem=file.stem if hasattr(file, "stem") else "",
                        suffix=file.suffix if hasattr(file, "suffix") else "",
                        crc32=episode_info.get("hash_crc32", ""),
                        blake2s=episode_info.get("hash_blake2s", ""),
                        arc_title=season_info["title"] if season_info is not None else "",
                        arc_saga=season_info["saga"] if season_info is not None else ""
                    )

                    dst = str(await utils.resolve(season_path, _filename))
                    self.logger.trace(f"Queue [{self.file_action}]: {file} -> {dst} ({episode_info})")
                    tasks.append(loop.run_in_executor(executor, utils.move_file_worker, str(file), dst, self.file_action, file_type, file_id))

            if len(tasks) > 0:
                index = len(files)
                total = len(files) + len(tasks)

                async for result in asyncio.as_completed(tasks):
                    src, dst, err, file_type, file_id = await result

                    src = await utils.resolve(src)
                    dst = await utils.resolve(dst) if dst is not None else src

                    if err != "":
                        self.logger.error(f"Skipping {src.name}: {err}")
                        skipped += 1
                        index += 1
                        await utils.run_func(self.progress_bar_func, int((index / total) * 100))
                        continue

                    if file_type == 0:
                        info = await self.store.get_episode(id=file_id, with_descriptions=True)
                    elif file_type == 1:
                        info = await self.store.get_other_edit(id=file_id)
                    elif file_type == 2:
                        info = self.store.episodes[file_id]
                    elif file_type == 3:
                        continue

                    nfo_file = Path(dst.parent, f"{dst.stem}.nfo")
                    season = info.get("arc", 0)
                    episode = info.get("episode", 0)

                    self.logger.info(f"Updating: Season {season} Episode {episode} ({info['title']})")

                    root = ET.Element("episodedetails")
                    title = f"{info['title']} (Extended)" if info.get("extended", False) else f"{info['title']}"
                    ET.SubElement(root, "title").text = title

                    if info.get("originaltitle", "") != "":
                        ET.SubElement(root, "originaltitle").text = str(info["originaltitle"])

                    ET.SubElement(root, "showtitle").text = tvshow["title"]
                    ET.SubElement(root, "season").text = f"{season}"
                    ET.SubElement(root, "episode").text = f"{episode}"
                    ET.SubElement(root, "customrating").text = info["rating"] if "rating" in info else tvshow["customrating"]

                    desc_str = str(info.get("description", ""))
                    manga_str = ""
                    anime_str = ""

                    if str(info.get("manga_chapters", "")) != "":
                        if desc_str != "":
                            manga_str = f"\n\nManga Chapter(s): {info['manga_chapters']}"
                        else:
                            manga_str = f"Manga Chapter(s): {info['manga_chapters']}"

                    if str(info.get("anime_episodes", "")) != "":
                        if desc_str != "" or manga_str != "":
                            anime_str = f"\n\nAnime Episode(s): {info['anime_episodes']}"
                        else:
                            anime_str = f"Anime Episode(s): {info['anime_episodes']}"

                    ET.SubElement(root, "plot").text = f"{desc_str}{manga_str}{anime_str}"

                    if "duration" in info and isinstance(info["duration"], int) and info["duration"] > 0:
                        ET.SubElement(root, "runtime").text = str(info["duration"])

                    if "released" in info:
                        if isinstance(info["released"], str):
                            r = info["released"]
                            r = r.split("T")[0]
                            r = r.split(" ")[0]
                        elif isinstance(info["released"], (datetime.date, datetime.datetime)):
                            r = str(info["released"].isoformat()).split("T")[0]

                        year = r.split("-")[0]
                        ET.SubElement(root, "year").text = year
                        ET.SubElement(root, "premiered").text = r
                        ET.SubElement(root, "aired").text = r

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
                        img_dst = await utils.resolve(dst.parent, f"{dst.stem}{poster.suffix}")

                        if not await utils.is_file(img_dst) and self.file_action != 4:
                            self.logger.info(f"Copying {poster.name} to: {img_dst}")
                            await utils.copy_async(poster, img_dst)

                        if await utils.is_file(img_dst):
                            art = ET.SubElement(root, "art")
                            ET.SubElement(art, "poster").text = str(img_dst)

                    if background is not None:
                        img_dst = await utils.resolve(dst.parent, f"{dst.stem}-background{background.suffix}")

                        if not await utils.is_file(img_dst) and self.file_action != 4:
                            self.logger.info(f"Copying {background.name} to: {img_dst}")
                            await utils.copy_async(background, img_dst)

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

                    elif not await utils.is_file(nfo_file):
                        self.logger.debug(f"Writing metadata to: {nfo_file}")
                        await utils.write_file(nfo_file, out)
                        completed += 1

                    else:
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
                self.logger.error("Exiting due to a lack of metadata - please ensure metadata exists inside the 'metadata' folder or that you are connected to the internet.")
                return (False, None, 0, 0)

            video_files = await self.glob_video_files()
            extra_data = None

            await utils.run(self.output_path.mkdir, exist_ok=True)
            await utils.run_func(self.progress_bar_func, 0)

            if self.mode != 0:
                if self.file_action == 4:
                    self.logger.info("Plex metadata-only mode: Updating existing episodes in Plex")
                    return await self.process_plex_episodes([], True)
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

        finally:
            await self.store.close()
