import traceback
import re
import sys
import orjson
import httpx
import javaproperties
import io
import os
import string
import time
from loguru import logger
from deepdiff import DeepDiff
from csv import DictReader as CSVReader
from datetime import date, datetime, timezone, timedelta
from yaml import dump as YamlDump, safe_load as YamlLoad
from pathlib import Path
from httpx_retries import RetryTransport, Retry
from rss_parser import RSSParser
from bs4 import BeautifulSoup

def escape_char(c):
    if c == "’":
        return "'"
    elif c == "…":
        return "..."
    elif c == "“" or c == "”":
        return '"'
    elif c in string.printable and ord(c) < 128:
        return c
    elif ord(c) <= 0xFFFF:
        return f'\\u{ord(c):04x}'
    else:
        return f'\\U{ord(c):08x}'

def unicode_fix(s):
    return ''.join(escape_char(c) for c in s)

def update():
    GCLOUD_API_KEY=os.environ['GCLOUD_API_KEY'] if 'GCLOUD_API_KEY' in os.environ else ''
    if GCLOUD_API_KEY == "":
        logger.critical("Skipping: GCLOUD_API_KEY is empty")
        return

    ONE_PACE_EPISODE_GUIDE_ID="1HQRMJgu_zArp-sLnvFMDzOyjdsht87eFLECxMK858lA"
    ONE_PACE_EPISODE_DESC_ID="1M0Aa2p5x7NioaH9-u8FyHq6rH3t5s6Sccs8GoC6pHAM"
    ONE_PACE_RSS_FEED=os.environ['ONE_PACE_RSS_FEED'] if 'ONE_PACE_RSS_FEED' in os.environ else ''

    PATTERN_END_NUMBER = r'(\d+)'
    PATTERN_CHAPTER_EPISODE = r'\b\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*\b'
    PATTERN_TITLE = r'\[One Pace\]\[\d+(?:[-,]\d+)*\]\s+(.+?)\s+(\d{2,})\s*(\w+)?\s*\[\d+p\]\[([A-Fa-f0-9]{8})\]\.mkv'

    out_seasons = {}
    out_episodes = {}
    season_eps = {}
    season_to_num = {}

    try:
        retry = Retry(total=999, backoff_factor=0.5)
        spreadsheet = {"sheets": []}

        with httpx.Client(transport=RetryTransport(retry=retry)) as client:
            title_props = None
            mkv_titles = {}

            logger.info("--------------------------")

            try:
                resp = httpx.get("https://raw.githubusercontent.com/one-pace/one-pace-public-subtitles/refs/heads/main/main/title.properties", follow_redirects=True)
                title_props = javaproperties.loads(resp.text)

            except:
                logger.warning(f"Skipping title.properties parsing\n{traceback.format_exc()}")

            if isinstance(title_props, dict):
                pattern = re.compile(r"^(?P<arc>[a-z]+)(?:_[0-9]+)?_(?P<num>\d+)\.eptitle$")
                arc_name_to_id = {}

                for k, v in title_props.items():
                    match = pattern.match(k)
                    if not match:
                        continue

                    arc_name = match.group("arc")
                    ep_num = f"{int(match.group("num"))}"

                    if arc_name not in arc_name_to_id:
                        if arc_name == "loguetown":
                            arc_name_to_id["adv_buggy"] = {}
                        elif arc_name == "littlegarden":
                            arc_name_to_id["trials_koby"] = {}
                        elif arc_name == "marineford":
                            arc_name_to_id["adv_strawhats"] = {}

                        arc_id = f"{len(arc_name_to_id)}"
                        arc_name_to_id[arc_name] = arc_id
                        mkv_titles[arc_id] = {}

                        logger.success(f"{arc_id}. {arc_name}")

                    arc_id = arc_name_to_id[arc_name]
                    mkv_titles[arc_id][ep_num] = v

                    logger.success(f"-- {ep_num}. {v}")

            logger.info("--------------------------")

            with client.stream("GET", f"https://docs.google.com/spreadsheets/d/{ONE_PACE_EPISODE_DESC_ID}/export?gid=2010244982&format=csv", follow_redirects=True) as resp:
                reader = CSVReader(resp.iter_lines())

                for row in reader:
                    if 'title_en' not in row or row['title_en'] == '' or row['part'] == '':
                        continue

                    part = int(row['part'])
                    title = row['title_en']

                    if part == 11:
                        part = 10
                    elif part == 10:
                        part = 11
                    elif part == 99:
                        part = 0
                    elif part > 90:
                        continue

                    out_seasons[part] = {
                        "saga": row['saga_title'],
                        "title": title,
                        "description": row['description_en']
                    }

                    logger.success(f"{part}. {title}")

                    season_to_num[title] = part

            logger.info("--------------------------")

            r = client.get(f"https://sheets.googleapis.com/v4/spreadsheets/{ONE_PACE_EPISODE_GUIDE_ID}?key={GCLOUD_API_KEY}")
            spreadsheet = orjson.loads(r.content)

            for season, sheet in enumerate(spreadsheet['sheets']):
                sheetId = sheet['properties']['sheetId']
                if sheetId == 0:
                    continue

                season_title = sheet['properties']['title']

                logger.success(f"{season}. {season_title} ({sheetId})")

                if season_title != out_seasons[season]['title']:
                    out_seasons[season]['originaltitle'] = out_seasons[season]['title']
                    out_seasons[season]['title'] = season_title
                    season_to_num[season_title] = season

                    logger.info(f"-- Renaming to: {out_seasons[season]['title']}")

                with client.stream("GET", f"https://docs.google.com/spreadsheets/d/{ONE_PACE_EPISODE_GUIDE_ID}/export?gid={sheetId}&format=csv", follow_redirects=True) as resp:
                    reader = CSVReader(resp.iter_lines())

                    for row in reader:
                        if 'MKV CRC32' not in row:
                            continue

                        id = row['One Pace Episode'] if 'One Pace Episode' in row else ''
                        if id == '' and ' One Pace Episode' in row:
                            id = row[' One Pace Episode']

                        chapters = row['Chapters'] if 'Chapters' in row else ''
                        anime_episodes = row['Episodes'] if 'Episodes' in row else ''
                        release_date = row['Release Date'] if 'Release Date' in row else ''
                        mkv_crc32 = row['MKV CRC32'] if 'MKV CRC32' in row else ''
                        mkv_crc32_ext = row['MKV CRC32 (Extended)'] if 'MKV CRC32 (Extended)' in row else ''

                        if mkv_crc32 == '':
                            continue

                        if id == '' or chapters == '' or anime_episodes == '' or release_date == '' or mkv_crc32 == '':
                            logger.warning(f"Skipping: {row} (no data)")
                            continue

                        logger.success(f"-- {id}")

                        match = re.search(PATTERN_END_NUMBER, id)
                        if match:
                            episode = int(match.group(1))
                        else:
                            episode = 1

                        match = re.search(PATTERN_CHAPTER_EPISODE, chapters)
                        if match:
                            chapters = match.group(0).replace(" ", "").replace(",", ", ")

                        match = re.search(PATTERN_CHAPTER_EPISODE, anime_episodes)
                        if match:
                            anime_episodes = match.group(0).replace(", ", ",").replace(",", ", ")

                        release_date_group = release_date.split(".")
                        if len(release_date_group) == 3:
                            release_date = date(int(release_date_group[0]), int(release_date_group[1]), int(release_date_group[2]))
                        else:
                            release_date_group = release_date.split("-")
                            if len(release_date_group) == 3:
                                release_date = date(int(release_date_group[0]), int(release_date_group[1]), int(release_date_group[2]))
                            else:
                                logger.warning(f"Skipping: {row} (invalid release date)")
                                continue

                        out_episodes[mkv_crc32] = {
                            "season": season,
                            "episode": episode,
                            "title": f"{out_seasons[season]['title']} {episode:02d}",
                            "description": "",
                            "manga_chapters": str(chapters),
                            "anime_episodes": str(anime_episodes),
                            "released": release_date.isoformat()
                        }

                        if len(mkv_crc32_ext) > 0:
                            logger.info(f"-- Aliasing {mkv_crc32_ext} -> {mkv_crc32}")
                            out_episodes[mkv_crc32_ext] = out_episodes[mkv_crc32]

                        key = f"{out_seasons[season]['originaltitle']} {episode}" if 'originaltitle' in out_seasons[season] else f"{out_seasons[season]['title']} {episode}"
                        if key in season_eps:
                            season_eps[key].append(mkv_crc32)

                            if mkv_crc32_ext != '':
                                season_eps[key].append(mkv_crc32_ext)
                        else:
                            season_eps[key] = [mkv_crc32] if mkv_crc32_ext == '' else [mkv_crc32, mkv_crc32_ext]

            if ONE_PACE_RSS_FEED != '':
                logger.info("--------------------------")

                try:
                    r = client.get(ONE_PACE_RSS_FEED)
                    title_pattern = re.compile(PATTERN_TITLE, re.IGNORECASE)
                    now = datetime.now().astimezone(timezone.utc)

                    for i, item in enumerate(RSSParser.parse(r.text).channel.items):
                        if i == 10:
                            break

                        if not item.title or not item.title.content or item.title.content == "":
                            logger.warning(f"Skipping: {item}")
                            continue

                        match = title_pattern.match(item.title.content)
                        if not match:
                            logger.warning(f"Skipping: {item.title.content} (title does not match)")
                            continue

                        arc_name, ep_num, extra, crc32 = match.groups()
                        if Path(".", "data", "episodes", f"{crc32}.yml").exists():
                            logger.warning(f"Skipping: {item.title.content} (crc32 file exists)")
                            continue

                        pub_date = datetime.strptime(item.pub_date.content, "%a, %d %b %Y %H:%M:%S %z")
                        if now - pub_date > timedelta(hours=24):
                            logger.warning(f"Skipping: {item.title.content} (more than 24 hours)")
                            continue

                        r = httpx.get(item.guid.content)
                        div = BeautifulSoup(r.text, 'html.parser').find('div', { 'class': 'panel-body', 'id': 'torrent-description' })
                        desc = div.get_text(strip=True).split("\n") if div else []

                        chs = ""
                        eps = ""

                        for d in desc:
                            if d.startswith("Chapters: "):
                                chs = d.replace("Chapters: ", "")
                            elif d.startswith("Episodes: "):
                                eps = d.replace("Episodes: ", "")

                        if arc_name in season_to_num:
                            ep_num = int(ep_num)
                            released = (pub_date.isoformat().split("T"))[0]
                            t = f"{arc_name} {ep_num:02d}"

                            if crc32 not in out_episodes:
                                out_episodes[crc32] = {
                                    "season": season_to_num[arc_name],
                                    "episode": ep_num,
                                    "title": t,
                                    "description": "",
                                    "manga_chapters": chs,
                                    "anime_episodes": eps,
                                    "released": released
                                }

                            key = f"{arc_name} {ep_num}"
                            if key in season_eps:
                                season_eps[key].append(crc32)
                            else:
                                season_eps[key] = [crc32]

                            logger.success(f"Added S{season_to_num[arc_name]}E{ep_num:02d} from RSS ({t}, {released})")

                        else:
                            logger.warning(f"Skipping: {item.title.content} (arc {arc_name} not found)")

                except:
                    logger.error(f"Skipping RSS parsing\n{traceback.format_exc()}")

            logger.info("--------------------------")

            with client.stream("GET", f"https://docs.google.com/spreadsheets/d/{ONE_PACE_EPISODE_DESC_ID}/export?gid=0&format=csv", follow_redirects=True) as resp:
                reader = CSVReader(resp.iter_lines())

                for row in reader:
                    if 'arc_title' not in row:
                        continue

                    season = row['arc_title']
                    episode = row['arc_part']
                    title = row['title_en']
                    description = row['description_en']

                    if season == '' or episode == '' or title == '':
                        continue

                    key = f"{season} {episode}"
                    if key not in season_eps:
                        logger.warning(f"Skipping: {key} (not found)")
                        continue

                    logger.info(f"{key}: Adding {len(season_eps[key])} episodes")

                    for crc32 in season_eps[key]:
                        out_episodes[crc32]["title"] = title
                        out_episodes[crc32]["description"] = description

                        try:
                            _s = f"{out_episodes[crc32]['season']}"
                            _e = f"{out_episodes[crc32]['episode']}"

                            if _s != "0" and _s in mkv_titles and _e in mkv_titles[_s]:
                                _origtitle = mkv_titles[_s][_e]

                                if title.lower() != _origtitle.lower():
                                    out_episodes[crc32]["originaltitle"] = _origtitle

                        except:
                            logger.error(f"Skipping: {key}\n{traceback.format_exc()}")

        logger.info("--------------------------")

        for crc32, data in out_episodes.items():
            file_path = Path(".", "data", "episodes", f"{crc32}.yml")

            season = data['season']
            episode = data['episode']
            released = data['released']

            if season == 99:
                season = 0
            elif season > 90:
                episode = season
                season = 0

            if isinstance(released, date) or isinstance(released, datetime):
                released = released.isoformat()

            if file_path.exists():
                old_data = {"title": "", "description": "", "manga_chapters": "", "anime_episodes": "", "released": ""}

                with file_path.open(mode='r', encoding='utf-8') as f:
                    old_data = YamlLoad(stream=f)

                if "reference" in old_data:
                    continue

                if isinstance(old_data["released"], date) or isinstance(old_data["released"], datetime):
                    old_data["released"] = old_data["released"].isoformat()

                if old_data["title"] != "" and old_data["description"] != "" and old_data["manga_chapters"] != "" and old_data["anime_episodes"] != "" and old_data["released"] == data["released"]:
                    continue

            out = (
                f"season: {season}\n"
                f"episode: {episode}\n"
                "\n"
                "{title}"
                "{originaltitle}"
                "{sorttitle}\n"
                "{description}"
                f"manga_chapters: {data['manga_chapters']}\n"
                f"anime_episodes: {data['anime_episodes']}\n"
                "\n"
                "# rating: TV-14\n"
                f"released: {released}\n"
                "\n"
                "hashes:\n"
                f"  crc32: {crc32}\n"
                "# blake2: \n"
            )

            # attempt to bypass some unicode nonsense

            if 'originaltitle' in data and data['originaltitle'] != "":
                out = out.replace("{originaltitle}", YamlDump({"originaltitle": data['originaltitle']}, allow_unicode=True), 1)
            else:
                out = out.replace("{originaltitle}", "# originaltitle: \n", 1)

            if data['title'].startswith('The '):
                out = out.replace("{sorttitle}", YamlDump({"sorttitle": data['title'].replace('The ', '', 1)}, allow_unicode=True), 1)
            else:
                out = out.replace("{sorttitle}", "# sorttitle: \n", 1)

            out = out.replace("{title}", YamlDump({"title": data['title']}, allow_unicode=True), 1)
            out = out.replace("{description}", YamlDump({"description": data['description']}, allow_unicode=True), 1)

            with file_path.open(mode='w') as f:
                f.write(out)

            logger.success(f"Wrote episode to {file_path}")

        season_path = Path(".", "data", "seasons.yml")
        with season_path.open(mode='w') as f:
            YamlDump(data=out_seasons, stream=f, allow_unicode=True, sort_keys=False)

        logger.success(f"Wrote seasons to {season_path}")

    except:
        logger.critical(f"Uncaught Exception\n{traceback.format_exc()}")
        sys.exit(1)

def sort_dict(d):
    return {key: d[key] for key in sorted(d.keys())}

def dict_changed(old, new):
    changed = DeepDiff(old, new)
    for i in ['dictionary_item_added', 'dictionary_item_removed', 'values_changed']:
        if i in changed:
            return True

    return False

def generate_json():
    tvshow_yml = Path(".", "data", "tvshow.yml")
    seasons_yml = Path(".", "data", "seasons.yml")
    episodes_dir = Path(".", "data", "episodes")
    json_file = Path(".", "data.json")

    out = {"last_update": datetime.now(timezone.utc).isoformat()}

    with tvshow_yml.open(mode='r', encoding='utf-8') as f:
        out["tvshow"] = YamlLoad(stream=f)

    with seasons_yml.open(mode='r', encoding='utf-8') as f:
        out["seasons"] = sort_dict(YamlLoad(stream=f))

    episodes = {}

    for episode_yml in episodes_dir.glob('*.yml'):
        key = episode_yml.name.replace('.yml', '')

        with episode_yml.open(mode='r', encoding='utf-8') as f:
            episodes[key] = YamlLoad(stream=f)

        if 'reference' in episodes[key]:
            with Path(episodes_dir, f"{episodes[key]['reference']}.yml").open(mode='r', encoding='utf-8') as f:
                episodes[key] = YamlLoad(stream=f)

        for inner_key, val in episodes[key].items():
            if inner_key == "season" or inner_key == "episode":
                continue
            elif isinstance(val, date) or isinstance(val, datetime):
                episodes[key][inner_key] = val.isoformat()
            elif isinstance(val, str):
                episodes[key][inner_key] = unicode_fix(val)
            elif isinstance(val, int) or isinstance(val, float):
                episodes[key][inner_key] = str(val)

    out["episodes"] = sort_dict(episodes)

    try:
        old_json = orjson.loads(json_file.read_bytes())
        episodes_changed = dict_changed(old_json["episodes"], out["episodes"])
        seasons_changed = dict_changed(old_json["seasons"], out["seasons"])
        tvshow_changed = dict_changed(old_json["tvshow"], out["tvshow"])
    except Exception as e:
        print(f"Warning: {e}")
        episodes_changed = True
        seasons_changed = True
        tvshow_changed = True

    if episodes_changed or seasons_changed or tvshow_changed:
        out = orjson.dumps(out, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_INDENT_2).replace(b"\\\\u", b"\\u")
        json_file.write_bytes(out)

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'update':
        update()
        return

    generate_json()

if __name__ == '__main__':
    main()
