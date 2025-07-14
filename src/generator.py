import traceback
import re
import sys
import click
import orjson
from csv import DictReader as CSVReader
from yaml import dump as YamlDump, safe_load as YamlLoad
from pathlib import Path

@click.group()
def generate():
    pass

@click.command()
@click.option('--file', default='One Pace Episode Descriptions - Arcs.csv')
@click.option('--outfile', default='./data/seasons.yml')
def arcs(file, outfile):
    try:
        out = {}

        with Path(file).open(mode='r', newline='', encoding='utf-8') as in_f:
            reader = CSVReader(in_f)
            for row in reader:
                if row['part'] == '':
                    continue

                part = int(row['part'])
                out[part] = {
                    'saga': row['saga_title'],
                    'title': row['title_en'],
                    'description': row['description_en']
                }

                click.echo(f"adding s{part}: {out[part]}")

        with Path(outfile).open(mode='w', encoding='utf-8') as f:
            YamlDump(data=out, stream=f, sort_keys=False, allow_unicode=True)

        click.echo(f"\nwrote to file {str(Path(outfile).resolve())}")
    except Exception as e:
        click.echo(traceback.format_exc())
        sys.exit(1)

generate.add_command(arcs)

@click.command()
@click.option('--file', default='One Pace Episode Descriptions - Episodes.csv')
@click.option('--seasonsyml', default='./data/seasons.yml')
@click.option('--outdir', default='./data/episodes')
def episodes(file, seasonsyml, outdir):
    try:
        seasons = {}
        with Path(seasonsyml).open(mode='r', encoding='utf-8') as f:
            seasons = YamlLoad(stream=f)

        title_to_season = {
            season_data['title']: season_num
            for season_num, season_data in seasons.items()
        }

        with Path(file).open(mode='r', newline='', encoding='utf-8') as f:
            reader = CSVReader(f)
            for row in reader:
                arc_title = row['arc_title']
                if arc_title == '':
                    continue

                season_num = title_to_season.get(arc_title)
                if season_num is None:
                    season_num = 99

                out = {
                    "season": season_num,
                    "episode": int(row['arc_part']),
                    "title": row['title_en'],
                    "description": row['description_en'],
                    "manga_chapters": "",
                    "anime_episodes": "",
                    "released": "2000-01-01 00:00"
                }

                if 'filename' not in row or row['filename'] == "":
                    out_filename = f"{arc_title}_{out['episode']}.yml"
                else:
                    match = re.search(r'\[([A-F0-9]{8})\]\.(?:mkv|mp4)$', row['filename'], re.IGNORECASE)
                    if match:
                        out_filename = f"{match.group(1)}.yml"
                    else:
                        out_filename = f"{arc_title}_{out['episode']}.yml"

                total_file = Path(outdir, out_filename)
                if total_file.exists():
                    total_file = Path(outdir, out_filename.replace('.yml', '_2.yml'))
                
                with total_file.open(mode='w', encoding='utf-8') as o_f:
                    click.echo(f"writing to {total_file.name}: {out}")
                    YamlDump(data=out, stream=o_f, allow_unicode=True, sort_keys=False)

    except Exception as e:
        click.echo(traceback.format_exc())
        sys.exit(1)

generate.add_command(episodes)

@click.command()
@click.option('--datadir', default='./data')
@click.option('--json', default='./data.json')
def json(datadir, json):
    tvshow_yml = Path(datadir, "tvshow.yml")
    seasons_yml = Path(datadir, "seasons.yml")
    episodes_dir = Path(datadir, "episodes")

    out = {}

    with tvshow_yml.open(mode='r', encoding='utf-8') as f:
        out["tvshow"] = YamlLoad(stream=f)

    with seasons_yml.open(mode='r', encoding='utf-8') as f:
        out["seasons"] = YamlLoad(stream=f)

    episodes = {}

    for episode_yml in episodes_dir.glob('*.yml'):
        key = episode_yml.name.replace('.yml', '')
        with episode_yml.open(mode='r', encoding='utf-8') as f:
            episodes[key] = YamlLoad(stream=f)
    
    out["episodes"] = episodes

    with Path(json).open(mode='wb') as f:
        f.write(orjson.dumps(out, option=orjson.OPT_NON_STR_KEYS | orjson.OPT_SORT_KEYS))

generate.add_command(json)

generate()