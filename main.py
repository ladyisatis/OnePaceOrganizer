import asyncio
import concurrent.futures
import faulthandler
import sys
import yaml

from argparse import ArgumentParser
from loguru import logger
from multiprocessing import freeze_support
from pathlib import Path
from src.organizer import OnePaceOrganizer
from src import utils

def strbool(v):
    if isinstance(v, bool):
        return v
    if not isinstance(v, str):
        return None
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    if v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        return None

def main():
    opo = OnePaceOrganizer()
    mode = "console"
    log_level = "INFO"
    log_file = ""
    is_bundle = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')

    if is_bundle:
        try:
            _mode_file = Path(sys._MEIPASS, ".mode")
            if _mode_file.is_file():
                mode = _mode_file.read_text().strip()
        except:
            pass

    if hasattr(sys, 'argv'):
        toml = utils.get_toml_info()
        parser = ArgumentParser(description=toml["description"]) if "description" in toml else ArgumentParser()

        if is_bundle and mode == "console":
            parser.add_argument(
                "programmode",
                choices=["console", "headless"],
                nargs="?",
                default=mode,
                help="Program mode"
            )
        elif not is_bundle:
            parser.add_argument(
                "programmode",
                choices=["gui", "console", "headless"],
                nargs="?",
                default=mode,
                help="Program mode"
            )

        parser.add_argument("--mode", help="Mode (0=.nfo, 1=Plex Username/Password, 2=Plex External Login, 3=Plex Auth Token)", default=None, type=int)
        parser.add_argument("--input-path", help="where to read unsorted .mkv/.mp4 files from", default=None)
        parser.add_argument("--output-path", help="Where to put sorted .mkv/.mp4 files (and .nfo/posters if Jellyfin)", default=None)
        parser.add_argument("--cwd", help="Working directory", default=None)
        parser.add_argument("--config-file", help="Path to config.json or config.yml", default=None)
        parser.add_argument("--metadata-url", help="Metadata path", default=None)
        parser.add_argument("--dl-path", help="Download path (for posters, etc)", default=None)
        parser.add_argument("--log-level", help="Log level (TRACE, DEBUG, INFO, SUCCESS, WARNING, ERROR, CRITICAL)", default="info", type=str)
        parser.add_argument("--log-file", help="Log to file (empty to disable)", default="", type=str)
        parser.add_argument("--file-action", help="Action to take on unsorted file when processing. 0 for Move, 1 for Copy, 2 for Symlink, 3 for Hardlink, 4 for generate metadata only (not on Plex)", default=None)
        parser.add_argument("--folder-action", help="How to categorize episodes into season folders. 0 for with leading zeroes (Season 01-09), 1 for no leading zeroes (Season 1-9), 2 to disable", default=None)
        parser.add_argument("--threads", help="Use threads instead of processes", default=None, type=strbool)
        parser.add_argument("--workers", help="Concurrency workers", default=None, type=int)
        parser.add_argument("--fetch-posters", help="Fetch posters if not found", default=None, type=strbool)
        parser.add_argument("--filename-tmpl", help="Filename template (see wiki page)", default=None)
        parser.add_argument("--overwrite-nfo", help="Overwrite .nfo files", default=None, type=strbool)
        parser.add_argument("--lockdata", help="Set lockdata (Jellyfin)/locked (Plex)", default=None, type=strbool)
        parser.add_argument("--plex-url", help="Plex URL (e.g. http://127.0.0.1:32400)", default=None)
        parser.add_argument("--plex-server", help="Plex Server ID", default=None)
        parser.add_argument("--plex-library", help="Plex Library Key", default=None)
        parser.add_argument("--plex-show", help="Plex Show GUID", default=None)
        parser.add_argument("--plex-set-show-edits", help="Overwrite Plex show information", default=None, type=strbool)
        parser.add_argument("--plex-code", help="Plex 2-Factor Auth Code (headless mode only)", default=None)
        parser.add_argument("--plex-remember", help="Remember Plex Credentials", default=None, type=strbool)
        parser.add_argument("--plex-retry-times", help="How many times Organizer should retry to fetch a Plex season/episode", default=None)
        parser.add_argument("--plex-retry-secs", help="How many seconds Organizer should retry to fetch a Plex season/episode", default=None)
        parser.add_argument("--plex-wait-secs", help="Number of seconds to wait for file transfers (headless mode only)", default=300, type=int)

        args = parser.parse_args()

        if args.mode is not None:
            opo.mode = int(args.mode)

        if args.input_path is not None:
            opo.input_path = args.input_path

        if args.output_path is not None:
            opo.output_path = args.output_path

        if args.cwd is not None:
            opo.base_path = args.cwd

        if args.config_file is not None:
            opo.config_file = args.config_file

        if args.metadata_url is not None:
            opo.metadata_url = args.metadata_url

        if args.dl_path is not None:
            opo.download_path = args.dl_path

        if args.workers is not None:
            opo.workers = args.workers

        if args.threads is not None:
            opo.set_executor(args.threads == False)

        if args.file_action is not None:
            opo.file_action = int(args.file_action)

        if args.folder_action is not None:
            opo.folder_action = int(args.folder_action)

        if args.fetch_posters is not None:
            opo.fetch_posters = args.fetch_posters

        if args.overwrite_nfo is not None:
            opo.overwrite_nfo = args.overwrite_nfo

        if args.lockdata is not None:
            opo.lockdata = args.lockdata

        if args.filename_tmpl is not None:
            opo.filename_tmpl = args.filename_tmpl

        if args.plex_url is not None:
            opo.plex_config_url = args.plex_url

        if args.plex_server is not None:
            opo.plex_config_server_id = args.plex_server

        if args.plex_library is not None:
            opo.plex_config_library_key = args.plex_library

        if args.plex_show is not None:
            opo.plex_config_show_guid = args.plex_show

        if args.plex_set_show_edits is not None:
            opo.plex_set_show_edits = args.plex_set_show_edits

        if args.plex_retry_times is not None:
            opo.plex_retry_times = int(args.plex_retry_times)

        if args.plex_retry_secs is not None:
            opo.plex_retry_secs = int(args.plex_retry_secs)

        if args.plex_remember is not None:
            opo.plex_config_remember = args.plex_remember

        log_level = args.log_level.upper()
        log_file = args.log_file

        if hasattr(args, "programmode"):
            mode = args.programmode

    if log_level.lower() not in ["trace", "debug", "info", "success", "warning", "error", "critical"]:
        log_level = "INFO"

    if log_file != "":
        logger.add(Path(log_file), level=log_level, enqueue=True)

    if mode == "gui":
        try:
            from src import gui
        except:
            logger.critical("gui mode unavailable")
            return

        gui.main(opo, log_level)

    elif mode == "headless":
        try:
            from src import headless
        except:
            logger.critical("headless mode unavailable")
            return

        headless.main(opo, log_level, args.plex_wait_secs)

    else:
        try:
            from src import console
        except:
            logger.critical("console mode unavailable")
            return

        console.main(opo, log_level)

if __name__ == "__main__":
    logger.remove(None)

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        freeze_support()
    else:
        faulthandler.enable()

    main()