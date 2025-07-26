import asyncio
import sys
import webbrowser
import httpx
import traceback
import orjson
import xml.etree.ElementTree as ET
import datetime
from shutil import copy as shcopy
from re import compile as Regexp, sub as rsub
from hashlib import blake2s
from zlib import crc32
from tomllib import load as TomlLoad
from pathlib import Path
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import message_dialog, input_dialog, yes_no_dialog, radiolist_dialog, progress_dialog, button_dialog
from plexapi.myplex import MyPlexAccount
from plexapi.server import PlexServer
from plexapi.exceptions import Unauthorized as PlexApiUnauthorizedException, TwoFactorRequired as PlexApiTwoFactorRequiredException
from loguru import logger

class OnePaceOrganizer:
    title = "One Pace Organizer"
    config_file = Path(".", "config.json")
    data_file = Path(".", "data.json")
    toml_file = Path(".", "pyproject.toml")
    video_files = {}
    plex_account: MyPlexAccount = None
    plex_server: PlexServer = None
    illegal_filename_chars = r'[<>:"/\\|?*\x00-\x1F]'
    yml = {"episodes": {}, "seasons": {}, "tvshow": {}}
    config = {
        "path_to_eps": str(Path(".", "in").resolve()),
        "episodes": str(Path(".", "out").resolve()),
        "plex": {
            "enabled": False,
            "url": "http://127.0.0.1:32400",
            "use_token": False,
            "name": "",
            "token": "",
            "library_key": "",
            "show_guid": "",
            "username": "",
            "password": "",
            "remember": True
        }
    }

    def __init__(cls):
        pass

    @classmethod
    def setup(cls):
        message_dialog(
            title=cls.title,
            text='Make sure to create a folder that has all of the One Pace video\nfiles! The next step will ask for the path to that directory.'
        ).run()

        cls.config["path_to_eps"] = input_dialog(
            title=cls.title,
            text='Directory of One Pace files:',
            default=cls.config["path_to_eps"]
        ).run()

        if cls.config["path_to_eps"] == None:
            sys.exit(0)

        cls.config["episodes"] = input_dialog(
            title=cls.title,
            text='Where should this program move the renamed video files to?\nThis will create folders in it such as Season 01, Season 02, etc.',
            default=cls.config["episodes"]
        ).run()

        if cls.config["episodes"] == None:
            sys.exit(0)

        cls.config["plex"]["enabled"] = yes_no_dialog(
            title=cls.title,
            text='Are you using Plex to watch One Pace?'
        ).run()

        if cls.config["plex"]["enabled"]:
            cls.plex_setup()

        cls.save()

    @classmethod
    def plex_username_password_login(cls, first_run=False):
        if first_run or (first_run == False and cls.config["plex"]["username"] == "" and cls.config["plex"]["password"] == ""):
            username = input_dialog(
                title=cls.title,
                text='Enter your Plex username:',
                default=cls.config["plex"]["username"]
            ).run()

            if cls.config["plex"]["username"] is None:
                return

            password = input_dialog(
                title=cls.title,
                text='Enter your Plex password:',
                default=cls.config["plex"]["password"],
                password=True
            ).run()

            if cls.config["plex"]["password"] is None:
                return

            remember = yes_no_dialog(
                title=cls.title,
                text='Do you want to remember your Plex username and password?'
            ).run()

            cls.config["plex"]["remember"] = remember

            if remember:
                cls.config["plex"]["username"] = username
                cls.config["plex"]["password"] = password
        else:
            username = cls.config["plex"]["username"]
            password = cls.config["plex"]["password"]

        try:
            cls.plex_account = MyPlexAccount(username=username, password=password, remember=cls.config["plex"]["remember"])
        except PlexApiTwoFactorRequiredException:
            unauthorized = True

            while unauthorized:
                code = int(input_dialog(
                    title=cls.title,
                    text='Enter your 2-Factor code for your Plex account:',
                    default='',
                    password=True
                ).run())

                if code is None:
                    return

                try:
                    cls.plex_account = MyPlexAccount(username=username, password=password, code=code, remember=False)
                    unauthorized = False
                except PlexApiUnauthorizedException:
                    message_dialog(
                        title=cls.title,
                        text='Invalid 2 Factor authorization code, please try again.'
                    ).run()
        except PlexApiUnauthorizedException:
            cls.plex_account = None

            message_dialog(
                title=cls.title,
                text='Invalid username or password, please try again.'
            ).run()

        cls.config["plex"]["token"] = cls.plex_account.authenticationToken if cls.config["plex"]["remember"] else ""

    @classmethod
    def plex_ask_token(cls):
        while cls.plex_account is None:
            token = input_dialog(
                title=cls.title,
                text='Enter your Plex authorization token: (leave blank if you don\'t know\nit - this will open up a browser window with instructions to get it.)',
                default=cls.config["plex"]["token"]
            ).run()

            if token == "":
                webbrowser.open_new_tab("https://support.plex.tv/articles/204059436-finding-an-authentication-token-x-plex-token/#toc-0")
                continue

            if token is None:
                return

            try:
                cls.plex_account = MyPlexAccount(token=token)
            except PlexApiUnauthorizedException:
                cls.plex_account = None
                message_dialog(
                    title=cls.title,
                    text='Invalid token, please try again.'
                ).run()

    @classmethod
    def plex_setup(cls):
        cls.config["plex"]["url"] = input_dialog(
            title=cls.title,
            text='What is the URL to your Plex?',
            default=cls.config["plex"]["url"]
        ).run()

        if cls.config["plex"]["url"] is None:
            return

        use_user_pass = yes_no_dialog(
            title=cls.title,
            text="Do you wish to login via username and password, or via authentication token?",
            yes_text="User/Pass",
            no_text="Auth Token"
        ).run()

        if use_user_pass:
            cls.plex_account = None
            cls.config["plex"]["use_token"] = False

            while cls.plex_account is None:
                cls.plex_username_password_login(first_run=True)

        else:
            cls.config["plex"]["use_token"] = True
            cls.plex_ask_token()

        options = []

        if cls.config["plex"]["name"] == "":
            resources = cls.plex_account.resources()
            if len(resources) == 0:
                cont = yes_no_dialog(
                    title=cls.title,
                    text='Error: There are no Plex servers to choose from. Do you want to continue without Plex access?'
                ).run()
                if cont:
                    return
                else:
                    sys.exit(1)
            elif len(resources) == 1:
                cls.plex_server = resources[0].connect()
                cls.config["plex"]["name"] = resources[0].clientIdentifier
            else:
                for i, resource in enumerate(resources):
                    options.append((i, resource.name))

                index = radiolist_dialog(
                    title=cls.title,
                    text='Select your Plex server:',
                    values=options
                ).run()

                if index is None:
                    return

                cls.plex_server = resources[i].connect()
                cls.config["plex"]["name"] = resources[index].clientIdentifier

        options = []
        sections = cls.plex_server.library.sections()
        if len(sections) == 0:
            cont = yes_no_dialog(
                title=cls.title,
                text='Error: There are no Plex sections to choose from. Do you want to continue without Plex access?'
            ).run()
            if cont:
                return
            else:
                sys.exit(1)

        for section in sections:
            if section.type == 'show':
                options.append((section.key, section.title))

        cls.config["plex"]["library_key"] = radiolist_dialog(
            title=cls.title,
            text='Which library is One Pace currently in?',
            values=options
        ).run()

        if cls.config["plex"]["library_key"] is None:
            return

        options = []
        all_shows = cls.plex_server.library.sectionByID(cls.config["plex"]["library_key"]).all()

        if len(all_shows) == 0:
            cont = yes_no_dialog(
                title=cls.title,
                text='Error: There are no shows to choose from. Do you want to continue without Plex access?'
            ).run()
            if cont:
                return
            else:
                sys.exit(1)

        for show in all_shows:
            options.append((show.guid, show.title))

        cls.config["plex"]["show_guid"] = radiolist_dialog(
            title=cls.title,
            text='Which show is One Pace?',
            values=options
        ).run()

    @classmethod
    def check_setup(cls):
        if cls.config_file.exists():
            while True:
                use_existing_config = button_dialog(
                    title=cls.title,
                    text='A prior configuration was found. Do you wish to use this?',
                    buttons=[
                        ("Yes", 1),
                        ("No", 2),
                        ("View", 3)
                    ]
                ).run()

                if use_existing_config == 1:
                    cls.load()
                    return
                elif use_existing_config == 2:
                    cls.setup()
                    return
                else:
                    try:
                        config = orjson.loads(cls.config_file.read_bytes())
                        output = (
                            f"Path to One Pace Video Files: {config["path_to_eps"]}\n"
                            f"Where to Place After Renaming: {config["episodes"]}\n"
                        )
                        if config["plex"]["enabled"]:
                            output = (
                                f"{output}"
                                "Using Plex: Yes\n"
                                f"Use a Plex Token: {'Yes' if config["plex"]["use_token"] else 'No'}\n"
                                f"Plex Token: {'*'*len(config["plex"]["token"])}\n"
                                f"Plex Server Name: {config["plex"]["name"]}\n"
                                f"Plex Username: {config["plex"]["username"]}\n"
                                f"Plex Password: {'*'*len(config["plex"]["password"])}\n"
                                f"Save Username/Password: {'Yes' if config["plex"]["remember"] else 'No'}\n"
                                f"Plex Library Key: {config["plex"]["library_key"]}\n"
                                f"Plex Show ID: {config["plex"]["show_guid"]}\n"
                            )
                        else:
                            output = (
                                f"{output}"
                                "Using Plex: No\n"
                            )

                        message_dialog(
                            title=cls.title,
                            text=output
                        ).run()
                    except Exception as e:
                        message_dialog(
                            title=cls.title,
                            text=f"Configuration file is invalid or is not accessible, continuing to setup.\n\nError: {e}"
                        ).run()

                        cls.setup()
                        return

        else:
            cls.setup()

    @classmethod
    def calc_blake2s_16(cls, video_file):
        h = blake2s()
        chunks = 1024*1024*8
        with Path(video_file).open(mode='rb') as f:
            while chunk := f.read(chunks):
                h.update(chunk)

        return h.hexdigest()[:16]

    @classmethod
    def calc_crc32(cls, filepath):
        crc_value = 0
        chunks = 1024*1024*8
        with filepath.open(mode='rb') as f:
            while chunk := f.read(chunks):
                crc_value = crc32(chunk, crc_value)

        res = f"{crc_value & 0xFFFFFFFF:08x}"
        return res.upper()

    @classmethod
    def do_cache_crc32(cls, set_percentage, log_text):
        crc_pattern = Regexp(r'\[([A-Fa-f0-9]{8})\](?=\.(mkv|mp4))')

        video_files_path = Path(cls.config["path_to_eps"])
        cls.video_files = {}

        log_text("searching for .mkv and .mp4 files...\n")

        filelist = []
        filelist.extend(list(video_files_path.glob("**/*.[mM][kK][vV]")))
        filelist.extend(list(video_files_path.glob("**/*.[mM][pP]4")))

        for i, f in enumerate(filelist):
            match = crc_pattern.search(f.name)
            fpath = f.resolve()

            if match:
                crc32 = match.group(1)
            else:
                log_text(f"calculating for {fpath.name}...\n")
                crc32 = cls.calc_crc32(fpath)

            if crc32 in cls.yml["episodes"]:
                cls.video_files[fpath] = crc32
            else:
                log_text(f"skipping {fpath.name}, episode metadata missing\n")

            set_percentage(int((i / len(filelist)) * 100))

        set_percentage(100)

    @classmethod
    def run_plex(cls, video_files, out_path):
        try:
            if cls.plex_account is None:
                try:
                    cls.plex_account = MyPlexAccount(token=cls.config["plex"]["token"])
                except:
                    if cls.config["plex"]["use_token"]:
                        cls.plex_ask_token()
                    else:
                        cls.plex_username_password_login()

            if cls.plex_server is None:
                for resource in enumerate(cls.plex_account.resources()):
                    if resource.clientIdentifier == cls.config["plex"]["name"]:
                        cls.plex_server = resource.connect()
                        break

                if cls.plex_server is None:
                    message_dialog(
                        title=cls.title,
                        text="Plex server not found - please rerun the setup if it's changed."
                    ).run()

            show = cls.plex_server.library.sectionByID(cls.config["plex"]["library_key"]).getGuid(cls.config["plex"]["show_guid"])

            mismatch_title = show.title != cls.yml["tvshow"]["title"]
            mismatch_originaltitle = show.originalTitle != cls.yml["tvshow"]["originaltitle"]
            mismatch_summary = show.summary != cls.yml["tvshow"]["plot"]
            mismatch_contentRating = show.contentRating != cls.yml["tvshow"]["rating"]

            if mismatch_title or mismatch_originaltitle or mismatch_summary or mismatch_contentRating:
                show.editTitle(cls.yml["tvshow"]["title"])
                show.editOriginalTitle(cls.yml["tvshow"]["originaltitle"])
                show.editSortTitle(cls.yml["tvshow"]["sorttitle"])
                show.editSummary(cls.yml["tvshow"]["plot"])
                show.editContentRating(cls.yml["tvshow"]["rating"])

                if isinstance(cls.yml["tvshow"]["premiered"], datetime.date):
                    show.editOriginallyAvailable(cls.yml["tvshow"]["premiered"].isoformat())
                else:
                    show.editOriginallyAvailable(cls.yml["tvshow"]["premiered"])

                show.uploadPoster(filepath=str(Path(".", "data", "posters", "tvshow.png")))
        except:
            traceback.print_exc()
            sys.exit(1)

        total = len(video_files)
        queue = []

        def worker(set_percentage, log_text):
            i = 0

            for filepath, crc32 in video_files.items():
                i = i + 1
                episode_info = cls.yml["episodes"][crc32]
                if isinstance(episode_info, list):
                    stop = True
                    for v in episode_info:
                        if not "hashes" in episode_info or not "blake2" in episode_info["hashes"] or episode_info["hashes"]["blake2"] == "":
                            logger.error(f"Error: need a blake2 16-char hash for the video file {filepath} [{crc32}], skipping")
                        elif calc_blake2s_16(filepath) == episode_info["hashes"]["blake2"]:
                            stop = False
                            episode_info = v
                            break

                    if stop:
                        continue

                season = episode_info["season"]
                episode = episode_info["episode"]

                season_path = Path(out_path, "Specials" if season == 0 else f"Season {season:02d}")
                season_path_exists = season_path.exists()

                if not season_path_exists:
                    season_path.mkdir(exist_ok=True)

                if not "title" in episode_info or episode_info["title"] == "":
                        logger.error(f"crc32 {crc32} has no title, please report this as a GitHub issue")
                        continue

                prefix = f"One Pace - S{season:02d}E{episode_info['episode']:02d} - "
                safe_title = rsub(cls.illegal_filename_chars, "", episode_info["title"])

                new_video_file_path = Path(season_path, f"{prefix}{safe_title}{filepath.suffix}")
                shmove(str(filepath), str(new_video_file_path))

                queue.append((new_video_file_path, episode_info))

                set_percentage(int((i / total) * 100))

            set_percentage(100)

        cls.progress_dialog(
            title=cls.title,
            text="Moving the video files...",
            run_callback=worker
        )

        message_dialog(
            title=cls.title,
            text=(
                f"All of the One Pace files have been created in:\n"
                f"{out_path}\n\n"
                f"Please move the \"{out_path.name}\" folder to the Plex library folder you've selected,\n"
                "and make sure that it appears in Plex. Seasons and episodes will temporarily have\n"
                "incorrect information, and the next step will correct them.\n\n"
                "Click OK once this has been done and you can see the One Pace video files in Plex."
            )
        ).run()

        def plex_worker(set_percentage, log_text):
            seasons_done = []

            for i, item in enumerate(queue):
                try:
                    new_video_file_path = item[0]
                    episode_info = item[1]
                    season = episode_info['season']

                    if not season in seasons_done:
                        seasons_done.append(season)

                        plex_season = show.season(season=season)

                        if season in cls.yml["seasons"]:
                            season_info = cls.yml["seasons"][season]
                        else:
                            season_info = cls.yml["seasons"][f"{season}"]

                        new_title = season_info['title'] if season == 0 else f"{season}. {season_info['title']}"

                        mismatch_title = plex_season.title != new_title
                        mismatch_desc = plex_season.summary != season_info["description"]

                        if mismatch_title or mismatch_desc:
                            log_text(f"Season: {new_title}\n")
                            plex_season.editTitle(new_title)
                            plex_season.editSummary(season_info["description"])
                            plex_season.uploadPoster(filepath=str(Path(".", "data", "posters", f"season{season}-poster.png")))

                    try:
                        plex_episode = show.episode(season=season, episode=episode_info['episode'])

                        if plex_episode.title != episode_info['title']:
                            log_text(f"Season: {season} Episode: {episode_info['episode']}\n")

                            plex_episode.editTitle(episode_info["title"])
                            plex_episode.editContentRating(episode_info["rating"] if "rating" in episode_info else cls.yml["tvshow"]["rating"])
                            plex_episode.editSortTitle(episode_info["sorttitle"] if "sorttitle" in episode_info else episode_info["title"].replace("The ", "", 1))

                            if "released" in episode_info:
                                if isinstance(episode_info["released"], datetime.date):
                                    plex_episode.editOriginallyAvailable(episode_info["released"].isoformat())
                                else:
                                    plex_episode.editOriginallyAvailable(str(episode_info["released"]))

                            manga_anime = f"Manga Chapter(s): {episode_info['manga_chapters']}\n\nAnime Episode(s): {episode_info['anime_episodes']}"

                            if not "description" in episode_info or episode_info["description"] == "":
                                description = manga_anime
                            else:
                                description = f"{episode_info['description']}\n\n{manga_anime}"
                            
                            plex_episode.editSummary(description)
                    except:
                        log_text(f"Skipping Season {season} Episode {episode_info['episode']} due to an error\n")

                except:
                    e = traceback.format_exc()
                    log_text(f"{e}\n")

                set_percentage(int((i / len(queue)) * 100))

            set_percentage(100)

        cls.progress_dialog(
            title=cls.title,
            text="Setting information for all seasons and episodes...",
            run_callback=plex_worker
        )

        cls.save()

    @classmethod
    def run_nfo(cls, video_files, out_path):
        tvshow_nfo = Path(cls.config["episodes"], "tvshow.nfo")
        if not tvshow_nfo.exists():
            root = ET.Element("tvshow")

            for k, v in cls.yml["tvshow"].items():
                if isinstance(v, datetime.date):
                    ET.SubElement(root, k).text = v.isoformat()
                elif k == "plot":
                    ET.SubElement(root, "plot").text = v
                    ET.SubElement(root, "outline").text = v
                else:
                    ET.SubElement(root, str(k)).text = str(v)

            for k, v in dict(sorted(cls.yml["seasons"].items())).items():
                if k == 0:
                    ET.SubElement(root, "namedseason", attrib={"number": "0"}).text = str(v['title'])
                else:
                    ET.SubElement(root, "namedseason", attrib={"number": str(k)}).text = f"{k}. {v['title']}"

            src = Path(".", "data", "posters", "tvshow.png")
            dst = Path(out_path, "poster.png")
            shcopy(src, dst)

            art = ET.SubElement(root, "art")
            ET.SubElement(art, "poster").text = str(dst)

            ET.indent(root)
            ET.ElementTree(root).write(
                str(tvshow_nfo),
                encoding='utf-8',
                xml_declaration=True
            )

        total = len(video_files)

        def worker(set_percentage, log_text):
            i = 0

            for filepath, crc32 in video_files.items():
                i = i + 1
                episode_info = cls.yml["episodes"][crc32]
                if isinstance(episode_info, list):
                    stop = True
                    for v in episode_info:
                        if not "hashes" in episode_info or not "blake2" in episode_info["hashes"] or episode_info["hashes"]["blake2"] == "":
                            logger.error(f"Error: need a blake2 16-char hash for the video file {filepath} [{crc32}], skipping")
                        elif calc_blake2s_16(filepath) == episode_info["hashes"]["blake2"]:
                            stop = False
                            episode_info = v
                            break

                    if stop:
                        continue

                season = episode_info["season"]

                season_path = Path(out_path, "Specials" if season == 0 else f"Season {season:02d}")
                season_path_exists = season_path.exists()

                if not season_path_exists:
                    season_path.mkdir(exist_ok=True)

                    root = ET.Element("season")

                    if season in cls.yml["seasons"]:
                        season_info = cls.yml["seasons"][season]
                    else:
                        season_info = cls.yml["seasons"][f"{season}"]

                    title_text = season_info['title'] if season == 0 else f"{season}. {season_info['title']}"

                    ET.SubElement(root, "title").text = title_text
                    ET.SubElement(root, "plot").text = season_info["description"]
                    ET.SubElement(root, "outline").text = season_info["description"]
                    ET.SubElement(root, "seasonnumber").text = f"{season}"

                    src = Path(".", "data", "posters", f"season{season}-poster.png")
                    dst = Path(season_path, "poster.png")
                    shcopy(src, dst)

                    art = ET.SubElement(root, "art")
                    ET.SubElement(art, "poster").text = str(dst)

                    ET.indent(root)
                    ET.ElementTree(root).write(
                        str(Path(season_path, "season.nfo")),
                        encoding="utf-8",
                        xml_declaration=True
                    )

                episodedetails = ET.Element("episodedetails")

                if not "title" in episode_info or episode_info["title"] == "":
                    logger.error(f"crc32 {crc32} has no title, please report this as a GitHub issue")
                    continue

                prefix = f"One Pace - S{season:02d}E{episode_info['episode']:02d} - "
                safe_title = rsub(cls.illegal_filename_chars, "", episode_info["title"])

                new_video_file_path = Path(season_path, f"{prefix}{safe_title}{filepath.suffix}")

                log_text(f"creating metadata and moving {filepath.name} to {new_video_file_path}\n")

                ET.SubElement(episodedetails, "title").text = episode_info["title"]
                ET.SubElement(episodedetails, "showtitle").text = cls.yml["tvshow"]["title"]
                ET.SubElement(episodedetails, "season").text = f"{season}"
                ET.SubElement(episodedetails, "episode").text = f"{episode_info['episode']}"
                ET.SubElement(episodedetails, "rating").text = episode_info["rating"] if "rating" in episode_info else cls.yml["tvshow"]["rating"]

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
                ET.ElementTree(episodedetails).write(
                    str(Path(season_path, f"{prefix}{safe_title}.nfo")), 
                    encoding='utf-8', 
                    xml_declaration=True
                )
                
                shmove(str(filepath), str(new_video_file_path))

                if total > 0:
                    set_percentage(int((i / total) * 100))

            set_percentage(100)

        if total > 0:
            cls.progress_dialog(
                title=cls.title,
                text="Creating episode metadata and moving the video files...",
                run_callback=worker
            )

        cls.save()

    @classmethod
    def progress_dialog(cls, *args, **kwargs):
        async def runner():
            return await progress_dialog(*args, **kwargs).run_async()

        return asyncio.run(runner())

    @classmethod
    def load(cls) -> bool:
        try:
            if cls.config_file.exists():
                cls.config = orjson.loads(cls.config_file.read_bytes())
                return True
        except:
            return False
        
        return False

    @classmethod
    def save(cls) -> bool:
        try:
            cls.config_file.write_bytes(orjson.dumps(cls.config))
            return True
        except:
            return False

        return False

    @classmethod
    def run(cls):
        in_bundle = getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')
        if in_bundle:
            cls.data_file = Path(sys._MEIPASS, "data.json")
            cls.toml_file = Path(sys._MEIPASS, "pyproject.toml")

        try:
            with cls.toml_file.open(mode='rb', encoding='utf-8') as f:
                toml = TomlLoad(f)
                cls.title = f"One Pace Organizer v{version}"
        except:
            pass

        with patch_stdout():
            try:
                r = httpx.get("https://raw.githubusercontent.com/ladyisatis/OnePaceOrganizer/refs/heads/main/data.json", follow_redirects=True)
                r.raise_for_status()

                cls.yml = orjson.loads(r.content)
            except:
                cls.yml = orjson.loads(cls.data_file.read_bytes())

            cls.check_setup()

            cls.progress_dialog(
                title=cls.title,
                text="Fetching all checksums for the video files...",
                run_callback=cls.do_cache_crc32
            )

            out_path = Path(cls.config["episodes"])
            if not out_path.exists():
                out_path.mkdir(exist_ok=True)

            if cls.config["plex"]["enabled"]:
                cls.run_plex(cls.video_files, out_path)
            else:
                cls.run_nfo(cls.video_files, out_path)

            message_dialog(
                title=cls.title,
                text=f"Completed! All files have been moved to:\n{out_path}"
            ).run() 

if __name__ == '__main__':
    try:
        sys.exit(OnePaceOrganizer.run())
    except KeyboardInterrupt:
        sys.exit(0)
