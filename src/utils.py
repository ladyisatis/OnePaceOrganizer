import asyncio
import functools
import hashlib
import httpx
import orjson
import os
import shutil
import sys
import tomllib
import traceback
import yaml
import zlib
from inspect import iscoroutinefunction, iscoroutine
from pathlib import Path, UnsupportedOperation
from packaging.version import Version
from loguru import logger

def check_none(val):
    if val is None:
        print("User clicked Cancel")
        sys.exit(1)

def get_toml_info(base_path="."):
    in_bundle = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
    toml_path = Path(sys._MEIPASS, 'pyproject.toml') if in_bundle else Path(base_path, 'pyproject.toml')

    try:
        if toml_path.is_file():
            with toml_path.open(mode="rb") as f:
                t = tomllib.load(f)
                if "project" in t:
                    return t["project"]

    except:
        pass

    return {"description": "", "version": "?"}

def is_up_to_date(version="", base_path="."):
    if version == "":
        toml = get_toml_info(base_path)
        version = toml["version"]

        if version == "?":
            version = "0.0.0"

    version = Version(version)
    release_json = {"tag_name": ""}

    try:
        resp = httpx.get("https://api.github.com/repos/ladyisatis/onepaceorganizer/releases/latest", follow_redirects=True)
        if resp.status_code >= 400:
            return (True, None)

        release_json = orjson.loads(resp.content)
    except:
        logger.warning(f"Version check failure\n{traceback.format_exc()}")

    if not release_json["tag_name"].startswith("v"):
        return (True, None)

    latest = Version(release_json["tag_name"][1:])
    return (version == latest or version > latest, latest)

async def read_file(file, binary=False):
    data = bytearray() if binary else ""
    loop = asyncio.get_running_loop()

    try:
        if binary:
            f = await run(file.open, mode='rb', loop=loop)
            try:
                while chunk := await run(f.read, 65536, loop=loop):
                    await run(data.extend, chunk, loop=loop)
            finally:
                await run(f.close, loop=loop)
        else:
            f = await run(file.open, mode='r', encoding='utf-8', loop=loop)
            try:
                while chunk := await run(f.read, 65536, loop=loop):
                    data += chunk
            finally:
                await run(f.close, loop=loop)
    except:
        await run(logger.exception, f"Unable to read file {file}")
        return False

    return bytes(data) if binary else data

async def write_file(file, data, binary=False):
    loop = asyncio.get_running_loop()

    try:
        if isinstance(data, bytes):
            await run(file.write_bytes, data, loop=loop)
        else:
            await run(file.write_text, str(data), loop=loop)
    except:
        await run(logger.exception, f"Unable to write file {file}")
        return False

    return True

async def load_json(file):
    return await run(orjson.loads, await read_file(file, True))

async def load_yaml(file):
    data = await read_file(file, False)
    return await run(yaml.safe_load, data)

async def run(func, *args, **kwargs):
    loop = kwargs.pop("loop") if "loop" in kwargs else asyncio.get_running_loop()
    executor = kwargs.pop("executor") if "executor" in kwargs else None
    return await loop.run_in_executor(executor, functools.partial(func, *args, **kwargs))

async def run_func(func, *args, **kwargs):
    if iscoroutinefunction(func):
        return await func(*args, **kwargs)

    res = func(*args, **kwargs)
    if iscoroutine(res):
        return await res

    return res

async def find(*args):
    f = Path("data", "posters", *args)
    if await run(f.is_file):
        return await run(f.resolve)

    f = Path("posters", *args)
    return await run(f.resolve)

def find_from_list(base_dir, items):
    exts = [".png", ".apng", ".avif", ".gif", ".jpg", ".jpeg", ".webp"]
    for item in items:
        _dir, _file = item
        if not isinstance(_dir, Path):
            _dir = Path(base_dir, _dir)

        if not _dir.is_dir():
            continue

        for res in _dir.glob(_file, case_sensitive=False, recurse_symlinks=True):
            if res.suffix.lower() in exts:
                return res.resolve()

    return None

async def resolve(*args):
    return await run(Path(*args).resolve)

async def exists(file):
    return await run(file.exists)

async def stat(file):
    return await run(file.stat)

async def is_file(file):
    return await run(file.is_file)

async def is_dir(file):
    return await run(file.is_dir)

async def glob(dir, file_pattern, rglob=False, loop=None):
    if loop is None:
        loop = asyncio.get_running_loop()

    for file in await run(dir.rglob if rglob else dir.glob, file_pattern, case_sensitive=False, recurse_symlinks=True, loop=loop):
        yield file

async def download(url, out, progress_bar_func, loop=None):
    if loop is None:
        loop = asyncio.get_running_loop()

    await run_func(progress_bar_func, 0)

    dir_exists = await run(out.parent.is_dir, loop=loop)
    if not dir_exists:
        await run(out.parent.mkdir, exist_ok=True, loop=loop)

    f = await run(out.open, mode='wb', loop=loop)
    try:
        resp = await run(client.stream, "GET", url, follow_redirects=True, loop=loop)
        try:
            if resp.status_code >= 400:
                await run(resp.close, loop=loop)
                return False

            await run(logger.debug, f"Stream response: {url} -> {out}")

            t = int(resp.headers["Content-Length"])
            c = 0

            for chunk in await run(resp.iter_bytes, loop=loop):
                if t > 0:
                    c = c + len(chunk)

                if c >= 0 and c <= 100:
                    await run_func(progress_bar_func, c)

                await run(f.write, chunk, loop=loop)

        finally:
            await run(resp.close, loop=loop)

    except:
        await run(logger.debug, f"Download response: {url} -> {out}")
        resp = await run(httpx.get, url, follow_redirects=True, loop=loop)

        if resp.status_code >= 400:
            return False

        await run(f.write, resp.content, loop=loop)

    finally:
        await run(f.close, loop=loop)

    await run_func(progress_bar_func, 100)
    return True

def compare_file(file1, file2):
    with file1.open(mode='rb') as f1, file2.open(mode='rb') as f2:
        while True:
            c1 = f1.read(65536)
            c2 = f2.read(65536)

            if not c1 and not c2:
                return True

            if c1 != c2:
                return False

def move_file(src, dst, file_action=0):
    if isinstance(src, str):
        src = Path(str(src))

    if isinstance(dst, str):
        dst = Path(str(dst))

    try:
        if dst.exists():
            if compare_file(src, dst):
                return ""
            else:
                dst.unlink(missing_ok=True)

        if file_action == 1: #Copy
            shutil.copy2(str(src), str(dst))
            #logger.info(f"copy2 [{src}] [{dst}]")
        elif file_action == 2: #Symlink
            dst.symlink_to(src)
            #logger.info(f"symlink [{src}] [{dst}]")
        elif file_action == 3: #Hardlink
            dst.hardlink_to(src)
            #logger.info(f"hardlink [{src}] [{dst}]")
        else: #Move, or other
            shutil.move(str(src), str(dst))
            #logger.info(f"move [{src}] [{dst}]")

    except UnsupportedOperation:
        return "Aborting: failed due to an 'UnsupportedOperation' error. If you're on Windows, and have chosen the symlink option, you may need administrator privileges."

    except OSError as e:
        return f"Aborting due to {e} (check that you have permission to write here)"

    except Exception as e:
        return f"Aborting due to unknown error: {traceback.format_exc()}"

    return ""

def move_file_worker(old_file, new_file, file_action=0, episode_info=None):
    return (old_file, new_file, move_file(old_file, new_file, file_action), episode_info)

def crc32(video_file):
    if isinstance(video_file, str):
        video_file = Path(video_file)

    crc_value = 0

    try:
        with Path(video_file).open(mode='rb') as f:
            while chunk := f.read(1024 * 1024):
                crc_value = zlib.crc32(chunk, crc_value)

    except Exception as e:
        return (video_file, str(e), "")

    res = f"{crc_value & 0xFFFFFFFF:08x}"
    return (video_file, "", res.upper())

def blake2s(video_file):
    if isinstance(video_file, str):
        video_file = Path(video_file)

    h = hashlib.blake2s()

    try:
        with Path(video_file).open(mode='rb') as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)

    except Exception as e:
        return (video_file, str(e), "")

    res = h.hexdigest().lower()
    return (video_file, "", res.lower())

def get_env(name, default=""):
    key = f"OPO_{name.upper()}"

    val = os.environ[key] if key in os.environ else default
    if val == "true":
        return True
    elif val == "false":
        return False

    return val
