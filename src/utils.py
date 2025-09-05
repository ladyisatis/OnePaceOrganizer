import asyncio
import functools
import hashlib
import httpx
import orjson
import os
import sys
import yaml
import tomllib
import traceback
import zlib
from aiopath import AsyncPath
from pathlib import Path
from loguru import logger

def check_none(val):
    if val is None:
        print("User clicked Cancel")
        sys.exit(1)

def get_toml_info():
    in_bundle = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
    toml_path = Path(sys._MEIPASS, 'pyproject.toml') if in_bundle else Path('.', 'pyproject.toml')

    try:
        if toml_path.is_file():
            with toml_path.open(mode="rb") as f:
                t = tomllib.load(f)
                if "project" in t:
                    return t["project"]

    except:
        pass

    return {"description": "", "version": "?"}

async def check_asyncpath(file):
    if isinstance(file, str):
        file = AsyncPath(file)
    elif not isinstance(file, AsyncPath):
        file = AsyncPath(str(file))

    return file

async def load_json(file):
    file = await check_asyncpath(file)
    data = await file.read_bytes()
    return await run(orjson.loads, data)

async def load_yaml(file):
    file = await check_asyncpath(file)
    data = await file.read_text()
    return await run(yaml.safe_load, data)

async def run(func, *args, **kwargs):
    loop = kwargs.pop("loop") if "loop" in kwargs else asyncio.get_event_loop()
    executor = kwargs.pop("executor") if "executor" in kwargs else None
    return await loop.run_in_executor(executor, functools.partial(func, *args, **kwargs))

async def run_func(func, *args, **kwargs):
    if asyncio.iscoroutine(func):
        return asyncio.create_task(func(*args, **kwargs))

    return asyncio.create_task(run(func, *args, **kwargs))

async def find(*args):
    f = AsyncPath("data", "posters", *args)
    if await f.is_file():
        return await f.resolve()

    f = AsyncPath("posters", *args)
    return await f.resolve()

async def resolve(*args):
    f = AsyncPath(*args)
    return await f.resolve()

async def download(url, out, progress_bar_func):
    out = await check_asyncpath(out)
    await run_func(progress_bar_func, 0)

    dir_exists = await out.parent.is_dir()
    if not dir_exists:
        out.parent.mkdir(exist_ok=True)

    async with out.open(mode='wb') as f:
        try:
            async with httpx.AsyncClient() as client:
                async with client.stream("GET", url, follow_redirects=True) as resp:
                    t = int(resp.headers["Content-Length"])
                    c = 0

                    async for chunk in resp.aiter_bytes():
                        if t > 0:
                            c = c + len(chunk)

                        if c >= 0 and c <= 100:
                            await run_func(progress_bar_func, c)

                        await f.write(chunk)
        except:
            resp = await run(httpx.get, url, follow_redirects=True)
            await f.write(resp.content)

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
    if isinstance(src, AsyncPath) or isinstance(src, str):
        src = Path(str(src))

    if isinstance(dst, AsyncPath) or isinstance(dst, str):
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
    if isinstance(video_file, AsyncPath) or isinstance(video_file, str):
        video_file = Path(str(video_file))

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
    if isinstance(video_file, AsyncPath) or isinstance(video_file, str):
        video_file = Path(str(video_file))

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
