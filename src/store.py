import asyncio
import aiosqlite
import re

from datetime import date, datetime, timezone
from langcodes import Language as lc_lang
from loguru import logger as default_logger
from pathlib import Path
from src import utils
from yaml import safe_load as YamlLoad

class OrganizerStore:
    def __init__(self, lang="en", logger=None):
        self.lang = lc_lang.get(lang)
        self.langs = []
        self.tvshow = {}
        self.arcs = {}
        self.episodes = {}
        self.conn = None
        self.logger = logger

        if self.logger is None:
            self.logger = default_logger

    async def _merge_dict(self, older, newer):
        if not isinstance(newer, dict):
            return older

        new_dict = dict(**older)
        async for k in utils.iter(newer.keys):
            new_dict[k] = newer[k]

        return new_dict

    async def open(self, file):
        if self.conn is not None:
            await self.close()

        if not isinstance(file, Path):
            file = Path(file)

        db_uri = f"file:{str(await utils.resolve(file))}"

        try:
            self.logger.debug(f"Opening SQLite DB: {file}")
            self.conn = await aiosqlite.connect(db_uri, uri=True)
            self.conn.row_factory = aiosqlite.Row
            self.logger.debug("Opened")

            await self.conn.execute("PRAGMA journal_mode = WAL")
            await self.conn.execute("PRAGMA query_only = ON")

            self.langs = []
            async with self.conn.execute("SELECT DISTINCT d.lang FROM descriptions d LEFT JOIN arcs a ON (a.lang = d.lang) ORDER BY d.lang ASC", tuple([])) as cursor:
                async for row in cursor:
                    self.langs.append(await utils.run(lc_lang.get, row["lang"]))

            self.tvshow = {}
            async with self.conn.execute("SELECT key, value FROM tvshow WHERE lang = ? ORDER BY id ASC", (self.language, )) as cursor:
                async for k, v in cursor:
                    if k in self.tvshow:
                        if isinstance(self.tvshow[k], list):
                            self.tvshow[k].append(v)
                        else:
                            self.tvshow[k] = [self.tvshow[k], v]

                    elif k != "lockdata":
                        self.tvshow[k] = v

            status = {"last_update": None, "last_update_ts": None, "base_url": None, "version": None}
            async with self.conn.execute("SELECT last_update, last_update_ts, base_url, version FROM status WHERE id = ?", (1, )) as cursor:
                async for row in cursor:
                    status = dict(row)

            return (True, status)

        except Exception as e:
            self.logger.exception(e)
            return (False, e)

    async def close(self):
        try:
            if self.conn is not None:
                await self.conn.close()
                self.logger.debug("Closed SQLite DB")

        except Exception as e:
            self.logger.debug(f"Ignoring exception {e}")

        finally:
            self.conn = None

    async def cache_files(self, dir):
        self.arcs = {}
        self.episodes = {}

        if not isinstance(dir, Path):
            dir = Path(dir)

        _arc_dirs = []
        async for file in utils.iter(dir.iterdir):
            if file.name == "arcs" and await utils.is_dir(file):
                self.logger.trace(f"Found arcs directory {file}")
                async for arc_file in utils.iter(file.iterdir):
                    if await utils.is_dir(arc_file) and arc_file.name.isdecimal():
                        self.logger.trace(f"Adding arc directory {arc_file}")
                        _arc_dirs.append(arc_file)

            if not file.name.endswith(".yml") or not await utils.is_file(file):
                continue

            if file.name == "tvshow.yml":
                self.logger.debug(f"Loading tvshow overrides from {file}")
                self.tvshow = await self._merge_dict(self.tvshow, await utils.load_yaml(file))
                continue

            match = re.match(r'([A-Fa-f0-9]{8})\.yml', file.name)
            if match:
                crc32 = str(match.group(1)).upper()
                self.logger.info(f"[{crc32}] Adding local file via CRC32: {file}")
                self.episodes[f"1_{crc32}"] = await utils.load_yaml(file)
                continue

            _id = file.stem if hasattr(file, "stem") else file.name.replace(".yml", "")
            self.logger.info(f"Adding local file via ID: {file}")
            self.episodes[f"2_{_id}"] = await utils.load_yaml(file)

        for arcn_str in _arc_dirs:
            arc_dir = Path(dir, "arcs", arcn_str)
            arc_num = int(arcn_str)

            async for arc_file in utils.iter(arc_dir.rglob, "*.yml", case_sensitive=False):
                if arc_file.name == "arc.yml":
                    self.arcs[arc_num] = await utils.load_yaml(arc_file)
                    continue

                match = re.match(r'episode_(\d+)\.yml', arc_file.name)
                if match:
                    ep_num = match.group(1)
                    if not ep_num.isdecimal():
                        self.logger.warning(f"Skipping {arc_file}: {ep_num} is not a number")
                    else:
                        ep_num = int(ep_num)
                        self.logger.info(f"[S{arc_num:02d}E{ep_num:02d}] Adding local file: {arc_file}")
                        self.episodes[f"0_{arc_num}_{ep_num}"] = await utils.load_yaml(arc_file)

    @property
    def language(self):
        if isinstance(self.lang, lc_lang):
            return str(self.lang).replace("-", "_")

        return self.lang.replace("-", "_")

    @language.setter
    def set_language(self, lang):
        if isinstance(lang, str):
            self.lang = lc_lang.get(lang)
            return

        self.lang = lang

    async def get_arcs(self, id=None, part=None, title=None):
        query = "SELECT id, part, saga, title, originaltitle, description FROM arcs WHERE lang = ?"
        data = [self.language]

        if id is not None or part is not None or title is not None:
            if id is not None:
                query = f"{query} AND id = ?"
                data.append(int(id))
            elif part is not None:
                query = f"{query} AND part = ?"
                data.append(int(part))
            elif title is not None:
                query = f"{query} AND (title = ? OR originaltitle = ?)"
                data.append(title)
                data.append(title)

        query = f"{query} ORDER BY part ASC"
        results = []

        self.logger.debug(f"get_arcs query: '{query}' / Data: {data}")

        async with self.conn.execute(query, tuple(data)) as cursor:
            async for row in cursor:
                row = dict(row)
                part = int(row["part"])
                out = {
                    "id": int(row["id"]),
                    "part": part,
                    "saga": str(row["saga"]).strip(),
                    "title": str(row["title"]).strip(),
                    "originaltitle": str(row["originaltitle"]).strip(),
                    "description": str(row["description"]).strip()
                }

                if part in self.arcs:
                    _arc = self.arcs[part]
                    if isinstance(_arc, dict):
                        for k in _arc.keys():
                            out[k] = _arc[k]

                results.append(out)

        results.sort(key=lambda x: int(x["part"]))
        return results

    async def get_arc(self, id=None, part=None, title=None):
        result = await self.get_arcs(id, part, title)
        return result[0] if len(result) > 0 else None

    async def get_episodes(self, id: int = None, arc=None, episode=None, crc32: str = None, blake2s: str = None, file_name: str = None, with_descriptions: bool = False, ids_only: bool = False):
        where_op = []
        data = []

        if with_descriptions:
            query = (
                "SELECT e.id, e.arc, e.episode, e.manga_chapters, e.anime_episodes, e.released, "
                "e.duration, e.extended, e.hash_crc32, e.hash_blake2s, e.file_name, d.title, "
                "d.originaltitle, d.description FROM episodes e "
                "LEFT JOIN descriptions d ON e.arc = d.arc AND e.episode = d.episode"
            )
            data.append(self.language)
        elif ids_only:
            query = "SELECT e.id FROM episodes e"
        else:
            query = (
                "SELECT e.id, e.arc, e.episode, e.manga_chapters, e.anime_episodes, e.released, "
                "e.duration, e.extended, e.hash_crc32, e.hash_blake2s, e.file_name FROM episodes e"
            )

        if id is not None:
            where_op.append("e.id = ?")
            data.append(id)

        if arc is not None:
            if episode is None:
                raise Exception("episode must be provided alongside arc number")

            where_op.append("(e.arc = ? AND e.episode = ?)")
            data.append(int(arc), int(episode))

        if crc32 is not None:
            where_op.append("e.hash_crc32 = ?")
            data.append(crc32)

        if blake2s is not None:
            where_op.append("e.hash_blake2s = ?")
            data.append(blake2s)

        if file_name is not None:
            where_op.append("e.file_name = ?")
            data.append(file_name)

        if len(where_op) > 0:
            full_where_op = " OR ".join(where_op)
            if with_descriptions:
                query = f"{query} WHERE d.lang = ? AND ({full_where_op})"
            else:
                query = f"{query} WHERE {full_where_op}"

        query = f"{query} ORDER BY e.released DESC"
        results = []

        self.logger.debug(f"get_episodes query: '{query}' / Data: {data}")

        async with self.conn.execute(query, tuple(data)) as cursor:
            async for row in cursor:
                row = dict(row)
                _id = int(row["id"])
                if ids_only:
                    results.append(_id)
                    continue

                _arc = int(row["arc"])
                _episode = int(row["episode"])
                _crc32 = str(row["hash_crc32"]).upper()
                _b2s = str(row["hash_blake2s"]).lower()
                _fn = str(row["file_name"]).strip()
                _fns = _fn.split(".")[0]

                _released = str(row["released"]).strip()
                try:
                    if "T" in _released:
                        _released = datetime.fromisoformat(_released)
                    elif "+" in _released:
                        _released = datetime.fromisoformat(_released.replace(" ", "T"))
                    elif _released.isdecimal():
                        _released = datetime.fromtimestamp(float(_released))
                    elif "-" in _released and " " not in _released:
                        _released = date.fromisoformat(_released)
                    else:
                        _released = ""

                except Exception as e:
                    self.logger.warning(f"[{_id}] Unknown time format: {_released} ({e})")

                out = {
                    "id": _id,
                    "arc": _arc,
                    "episode": _episode,
                    "title": str(row.get("title", "")).strip(),
                    "originaltitle": str(row.get("originaltitle", "")).strip(),
                    "description": str(row.get("description", "")).strip(),
                    "manga_chapters": str(row.get("manga_chapters", "")).strip(),
                    "anime_episodes": str(row.get("anime_episodes", "")).strip(),
                    "released": _released,
                    "duration": int(row["duration"]),
                    "extended": True if int(row["extended"]) == 1 or row["extended"] == "True" else False,
                    "hash_crc32": _crc32,
                    "hash_blake2s": _b2s,
                    "file_name": _fn
                }

                if f"0_{_arc}_{_episode}" in self.episodes:
                    out = await self._merge_dict(out, self.episodes[f"0_{_arc}_{_episode}"])
                elif f"1_{_crc32}" in self.episodes:
                    out = await self._merge_dict(out, self.episodes[f"1_{_crc32}"])
                elif f"2_{_b2s}" in self.episodes:
                    out = await self._merge_dict(out, self.episodes[f"2_{_b2s}"])
                elif f"2_{_fns}" in self.episodes:
                    out = await self._merge_dict(out, self.episodes[f"2_{_fns}"])

                results.append(out)

        return results

    async def get_episode(self, id: int = None, arc=None, episode=None, crc32: str = None, blake2s: str = None, file_name: str = None, with_descriptions: bool = False, ids_only: bool = False):
        result = await self.get_episodes(id, arc, episode, crc32, blake2s, file_name, with_descriptions, ids_only)
        return result[0] if len(result) > 0 else None

    async def get_other_edits(self, id: int = None, crc32: str = None, blake2s: str = None, edit_name: str = None, ids_only: bool = False):
        where_op = []
        data = []
        lookup = "id" if ids_only else "*"

        if id is not None:
            where_op.append("id = ?")
            data.append(id)

        if crc32 is not None:
            where_op.append("hash_crc32 = ?")
            data.append(crc32)

        if blake2s is not None:
            where_op.append("hash_blake2s = ?")
            data.append(blake2s)

        if len(where_op) > 0:
            full_where_op = " OR ".join(where_op)
            if edit_name is not None:
                query = f"SELECT {lookup} FROM other_edits WHERE ({full_where_op}) AND edit_name = ?"
                data.append(edit_name)
            else:
                query = f"SELECT {lookup} FROM other_edits WHERE {full_where_op}"

        elif edit_name is not None:
            query = f"SELECT {lookup} FROM other_edits WHERE edit_name = ?"
            data.append(edit_name)

        else:
            query = f"SELECT {lookup} FROM other_edits"

        results = []

        self.logger.debug(f"get_other_edits query: '{query}' / Data: {data}")

        async with self.conn.execute(query, tuple(data)) as cursor:
            async for row in cursor:
                row = dict(row)
                _id = int(row["id"])
                if ids_only:
                    results.append(_id)
                    continue

                _released = str(row["released"]).strip()
                try:
                    if "T" in _released:
                        _released = datetime.fromisoformat(_released)
                    elif "+" in _released:
                        _released = datetime.fromisoformat(_released.replace(" ", "T"))
                    elif _released.isdecimal():
                        _released = datetime.fromtimestamp(float(_released))
                    elif "-" in _released and " " not in _released:
                        _released = date.fromisoformat(_released)
                    else:
                        _released = ""

                except Exception as e:
                    self.logger.warning(f"[{_id}] Unknown time format: {_released} ({e})")

                results.append({
                    "id": _id,
                    "edit_name": str(row["edit_name"]).strip(),
                    "arc": int(row["arc"]),
                    "episode": int(row["episode"]),
                    "title": str(row["title"]).strip(),
                    "originaltitle": str(row["originaltitle"]).strip() if "originaltitle" in row else "",
                    "description": str(row["description"]).strip(),
                    "manga_chapters": str(row["manga_chapters"]).strip(),
                    "anime_episodes": str(row["anime_episodes"]).strip(),
                    "released": _released,
                    "duration": int(row["duration"]),
                    "extended": True if int(row["extended"]) == 1 or row["extended"] == "True" else False,
                    "hash_crc32": str(row["hash_crc32"]).strip(),
                    "hash_blake2s": str(row["hash_blake2s"]).strip()
                })

        return results

    async def get_other_edit(self, id: int = None, crc32: str = None, blake2s: str = None, edit_name: str = None, ids_only: bool = False):
        result = await self.get_other_edits(id, crc32, blake2s, edit_name, ids_only)
        return result[0] if len(result) > 0 else None
