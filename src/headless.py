import asyncio
import sys
import traceback

from functools import partial as func_partial
from pathlib import Path
from loguru import logger
from src import utils, organizer

class Headless:
    def __init__(self, organizer=None, log_level="info", plex_wait_secs=300):
        self.log_level = log_level.upper()
        self.plex_wait_secs = plex_wait_secs

        logger.add(
            sys.stderr,
            level=self.log_level,
            format="{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {message}",
            enqueue=True
        )

        self.organizer = organizer.OnePaceOrganizer() if organizer is None else organizer
        self.organizer.progress_bar_func = logger.trace

    async def run(self):
        await self.organizer.load_config()

        logger.info(self.organizer.window_title)
        logger.info("-")

        is_latest, latest_vers = await utils.run(utils.is_up_to_date, self.organizer.toml["version"], self.organizer.base_path)
        if not is_latest:
            logger.info(f"Note: There is a new version of this application available, and can be downloaded from GitHub. (Installed: {self.organizer.toml['version']}, Latest: {latest_vers})")
            logger.info("-")

        _action = "Action after Sorting: Move"
        if self.organizer.file_action == 1:
            _action = "Action after Sorting: Copy"
        elif self.organizer.file_action == 2:
            _action = "Action after Sorting: Symlink"
        elif self.organizer.file_action == 3:
            _action = "Action after Sorting: Hardlink"
        elif self.organizer.file_action == 4:
            if self.organizer.plex_config_enabled:
                _action = "After Scan: Update Plex metadata only"
            else:
                _action = "After Scan: Generate metadata only"

        text = (
            f"Path to One Pace Files: {self.organizer.input_path}\n"
            f"Where to Place After Renaming: {self.organizer.output_path}\n"
            f"{_action}\n"
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

        for line in text.split("\n"):
            if line != "":
                logger.info(line)

        logger.info("-")

        if self.organizer.plex_config_enabled:
            tasks = [
                func_partial(self.organizer.plex_login),
                func_partial(self.organizer.plex_get_servers),
                func_partial(self.organizer.plex_select_server, self.organizer.plex_config_server_id),
                func_partial(self.organizer.plex_get_libraries),
                func_partial(self.organizer.plex_select_library, self.organizer.plex_config_library_key),
                func_partial(self.organizer.plex_get_shows),
                func_partial(self.organizer.plex_select_show, self.organizer.plex_config_show_guid)
            ]

            for task in tasks:
                if not await task():
                    return 1

        success, queue, completed, skipped = await self.organizer.start()
        if success:
            if self.organizer.plex_config_enabled and self.organizer.file_action != 4:
                logger.success(f"Completed: {completed} completed, {skipped} skipped")
                logger.info(f"Pausing {self.plex_wait_secs} seconds to allow file transfers")
                await asyncio.sleep(float(self.plex_wait_secs))

                success, queue, completed, skipped = await self.organizer.process_plex_episodes(queue)

            logger.success(f"Completed: {completed} processed, {skipped} skipped")

        await self.organizer.save_config()
        return 0 if success else 1

def main(organizer, log_level, plex_wait_secs):
    code = asyncio.run(Headless(organizer, log_level, plex_wait_secs).run())
    sys.exit(code)