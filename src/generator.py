import traceback
import re
import sys
import orjson
import httpx
import io
import os
import time
from deepdiff import DeepDiff
from csv import DictReader as CSVReader
from datetime import date, datetime, timezone
from yaml import dump as YamlDump, safe_load as YamlLoad
from pathlib import Path
from httpx_retries import RetryTransport, Retry

def update():
    GCLOUD_API_KEY=os.environ['GCLOUD_API_KEY'] if 'GCLOUD_API_KEY' in os.environ else ''
    if GCLOUD_API_KEY == "":
        print("Skipping: GCLOUD_API_KEY is empty")
        return

    ONE_PACE_EPISODE_GUIDE_ID="1HQRMJgu_zArp-sLnvFMDzOyjdsht87eFLECxMK858lA"
    ONE_PACE_EPISODE_DESC_ID="1M0Aa2p5x7NioaH9-u8FyHq6rH3t5s6Sccs8GoC6pHAM"

    PATTERN_END_NUMBER = r'(\d+)'
    PATTERN_CHAPTER_EPISODE = r'\b\d+(?:-\d+)?(?:,\s*\d+(?:-\d+)?)*\b'

    out_seasons = {}
    out_episodes = {}
    season_eps = {}

    try:
        retry = Retry(total=999, backoff_factor=0.5)
        spreadsheet = {"sheets": []}

        with httpx.Client(transport=RetryTransport(retry=retry)) as client:
            with client.stream("GET", f"https://docs.google.com/spreadsheets/d/{ONE_PACE_EPISODE_DESC_ID}/export?gid=2010244982&format=csv", follow_redirects=True) as resp:
                reader = CSVReader(resp.iter_lines())

                for row in reader:
                    if 'title_en' not in row or row['title_en'] == '' or row['part'] == '':
                        continue

                    part = int(row['part'])

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
                        "title": row['title_en'],
                        "description": row['description_en']
                    }

            r = client.get(f"https://sheets.googleapis.com/v4/spreadsheets/{ONE_PACE_EPISODE_GUIDE_ID}?key={GCLOUD_API_KEY}")
            spreadsheet = orjson.loads(r.content)

            for season, sheet in enumerate(spreadsheet['sheets']):
                sheetId = sheet['properties']['sheetId']
                if sheetId == 0:
                    continue

                season_title = sheet['properties']['title']

                if season_title != out_seasons[season]['title']:
                    out_seasons[season]['originaltitle'] = out_seasons[season]['title']
                    out_seasons[season]['title'] = season_title

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
                            print(f"Skipping: {row} (no data)")
                            continue

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
                                print(f"Skipping: {row} (invalid release date)")
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
                            out_episodes[mkv_crc32_ext] = out_episodes[mkv_crc32]

                        key = f"{out_seasons[season]['originaltitle']} {episode}" if 'originaltitle' in out_seasons[season] else f"{out_seasons[season]['title']} {episode}"
                        if key in season_eps:
                            season_eps[key].append(mkv_crc32)

                            if mkv_crc32_ext != '':
                                season_eps[key].append(mkv_crc32_ext)
                        else:
                            season_eps[key] = [mkv_crc32] if mkv_crc32_ext == '' else [mkv_crc32, mkv_crc32_ext]

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
                            continue

                        for crc32 in season_eps[key]:
                            out_episodes[crc32]["title"] = title
                            out_episodes[crc32]["description"] = description

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

            if isinstance(released, datetime.date):
                released = released.isoformat()

            if file_path.exists():
                old_data = {"title": "", "description": "", "manga_chapters": "", "anime_episodes": "", "released": ""}

                with file_path.open(mode='r', encoding='utf-8') as f:
                    old_data = YamlLoad(stream=f)

                if isinstance(old_data["released"], datetime.date):
                    old_data["released"] = old_data["released"].isoformat()

                if old_data["title"] != "" and old_data["description"] != "" and old_data["manga_chapters"] != "" and old_data["anime_episodes"] != "" and old_data["released"] == data["released"]:
                    continue

            out = (
                f"season: {season}\n"
                f"episode: {episode}\n"
                "\n"
                "{title}"
                "# originaltitle: \n"
                "# sorttitle: \n"
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
            out = out.replace("{title}", YamlDump({"title": data['title']}, allow_unicode=True), 1)
            out = out.replace("{description}", YamlDump({"description": data['description']}, allow_unicode=True), 1)

            with file_path.open(mode='w') as f:
                f.write(out)

        season_path = Path(".", "data", "seasons.yml")
        with season_path.open(mode='w') as f:
            YamlDump(data=out_seasons, stream=f, allow_unicode=True, sort_keys=False)

    except:
        print(traceback.format_exc())
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

        if not isinstance(episodes[key]["manga_chapters"], str):
            episodes[key]["manga_chapters"] = str(episodes[key]["manga_chapters"])

        if not isinstance(episodes[key]["anime_episodes"], str):
            episodes[key]["anime_episodes"] = str(episodes[key]["anime_episodes"])

        if isinstance(episodes[key]["released"], datetime.date):
            episodes[key]["released"] = episodes[key]["released"].isoformat()

    out["episodes"] = sort_dict(episodes)

    old_json = orjson.loads(json_file.read_bytes())
    episodes_changed = dict_changed(old_json["episodes"], out["episodes"])
    seasons_changed = dict_changed(old_json["seasons"], out["seasons"])
    tvshow_changed = dict_changed(old_json["tvshow"], out["tvshow"])

    if episodes_changed or seasons_changed or tvshow_changed:
        with json_file.open(mode='wb') as f:
            f.write(orjson.dumps(out, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_INDENT_2 ))

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'update':
        update()
        return

    generate_json()

if __name__ == '__main__':
    main()
