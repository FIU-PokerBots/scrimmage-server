import binascii
import datetime
import json
import os
import random
import re
import subprocess
import tempfile
import time
import zipfile

import boto3
import jinja2
from sqlalchemy.orm import raiseload

from scrimmage import app, celery_app, db
from scrimmage.helpers import get_s3_object, put_s3_object
from scrimmage.models import (
    Bot,
    Game,
    GameStatus,
    Team,
    Tournament,
    TournamentBot,
    TournamentGame,
    TournamentStatus,
)
from scrimmage.settings import settings

ENGINE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), os.pardir, "deps", "test_engine", "test_engine.py")
)
MAX_ZIP_SIZE = 1024 * 1024 * 1024


def render_template(tpl_path, **context):
    tpl_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "templates", tpl_path)
    )
    path, filename = os.path.split(tpl_path)
    return (
        jinja2.Environment(loader=jinja2.FileSystemLoader(path or "./"))
        .get_template(filename)
        .render(context)
    )


def _verify_zip(zip_file_path):
    try:
        total_size = 0
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            for info in zip_ref.infolist():
                total_size += info.file_size
        if total_size > MAX_ZIP_SIZE:
            return False, "Bot zip would be too large unzipped"
        return True, None
    except zipfile.BadZipfile as xxx_todo_changeme:
        zipfile.LargeZipfile = xxx_todo_changeme
        return False, "Bot zip file is malformed"


def _safe_name(name):
    name = re.sub(r"[^a-z0-9_\-]", "-", name.lower())
    if name == "":
        return "player-" + binascii.hexlify(os.urandom(4)).decode()
    return name


def _download_and_verify(bot, tmp_dir):
    bot_dir = os.path.join(tmp_dir, binascii.hexlify(os.urandom(10)).decode())
    os.mkdir(bot_dir)
    bot_download_dir = os.path.join(bot_dir, "download")
    os.mkdir(bot_download_dir)
    bot_extract_dir = os.path.join(bot_dir, "source")
    os.mkdir(bot_extract_dir)

    bot_zip_path = os.path.join(bot_download_dir, "bot.zip")
    with open(bot_zip_path, "wb") as bot_zip_file:
        bot_zip_file.write(get_s3_object(bot.s3_key).read())

    valid_zip, msg = _verify_zip(bot_zip_path)
    if not valid_zip:
        return False, msg

    try:
        with zipfile.ZipFile(bot_zip_path, "r") as z:
            z.extractall(bot_extract_dir)

        bot_dir = None
        for root, dirs, files in os.walk(bot_extract_dir):
            if "commands.json" in files:
                bot_dir = root
                print(bot_dir)
                break

        if bot_dir is None:
            return False, "Bot dir has no commands.json"

        return True, bot_dir
    except OSError:
        return False, "Bot zip is missing files. (Maybe missing commands.json?)"


def _get_scores(game_log):
    matches = re.search(r"Final, [^ ]+ \(([\-0-9]+)\), [^ ]+ \(([\-0-9]+)\)", game_log)
    if matches is None:
        return 0, 0
    bot_a_score = int(matches.group(1))
    bot_b_score = int(matches.group(2))

    return bot_a_score, bot_b_score


def _get_bids(game_log, player_name):
    matches = re.findall(rf"{player_name} bids ([\-0-9]+)", game_log)
    if matches == []:
        return 0
    return sum(map(int, matches)) / len(matches)


def _get_bet_evs(game_log, player_name, street_name):
    matches = re.search(rf"{player_name} {street_name} bets EV: ([\-0-9]+)", game_log)
    if matches is None:
        return 0
    return int(matches.group(1))


def _get_winner(bot_a_score, bot_b_score):
    if bot_a_score == bot_b_score:
        return "ab"[ord(os.urandom(1)) % 2]

    if bot_a_score is None:
        return "b"
    elif bot_b_score is None:
        return "a"

    return "a" if bot_a_score > bot_b_score else "b"


K = 40


def _elo(team_a, team_b, winner):
    maximum = max(team_a, team_b)
    ar = 10 ** ((team_a - maximum) / 400.0)
    br = 10 ** ((team_b - maximum) / 400.0)

    expected_a = ar / (ar + br)
    actual_a = 0.5 if winner == "tie" else (1.0 if winner == "a" else 0.0)

    expected_b = br / (ar + br)
    actual_b = 0.5 if winner == "tie" else (1.0 if winner == "b" else 0.0)

    new_a_elo = team_a + (actual_a - expected_a) * K
    new_b_elo = team_b + (actual_b - expected_b) * K

    return new_a_elo, new_b_elo


def _get_environment():
    base = os.environ.copy()
    for key in list(app.config.keys()):
        if key in os.environ:
            del base[key]
    return base


def _read_logfile(filename, log_filesize):
    if not os.path.isfile(filename):
        return None

    with open(filename, "r") as f:
        return f.read(log_filesize)


def _run_bots(bot_a, bot_a_name, bot_b, bot_b_name):
    with tempfile.TemporaryDirectory() as tmp_dir:
        is_valid_a_bot, a_path = _download_and_verify(bot_a, tmp_dir)
        is_valid_b_bot, b_path = _download_and_verify(bot_b, tmp_dir)

        if not is_valid_a_bot and not is_valid_b_bot:
            # These are actually logs
            return (
                (None, None),
                "Both bots are invalid, so the game is tied",
                a_path,
                b_path,
            )
        elif not is_valid_a_bot:
            return (
                (None, 0),
                "Bot {} is invalid, so {} wins.".format(bot_a_name, bot_b_name),
                a_path,
                None,
            )
        elif not is_valid_b_bot:
            return (
                (0, None),
                "Bot {} is invalid, so {} wins.".format(bot_b_name, bot_a_name),
                None,
                b_path,
            )

        game_dir = os.path.join(tmp_dir, "game")
        os.mkdir(game_dir)
        
        # Extensive debugging information about the bot directories
        print(f"Bot A extracted to: {a_path}")
        print(f"Bot B extracted to: {b_path}")
        
        # Check if commands.json exists in the extracted bot directories
        print(f"commands.json exists in bot A: {os.path.exists(os.path.join(a_path, 'commands.json'))}")
        print(f"commands.json exists in bot B: {os.path.exists(os.path.join(b_path, 'commands.json'))}")
        
        # List files in the bot directories to see what's actually there
        print(f"Files in bot A directory:")
        for root, dirs, files in os.walk(a_path, topdown=True):
            for name in files:
                if name == "commands.json":
                    print(f"  Found commands.json at: {os.path.join(root, name)}")
        
        print(f"Files in bot B directory:")
        for root, dirs, files in os.walk(b_path, topdown=True):
            for name in files:
                if name == "commands.json":
                    print(f"  Found commands.json at: {os.path.join(root, name)}")
        
        # Create symbolic links with expected names
        player1_link = os.path.join(game_dir, "PlayerA")
        player2_link = os.path.join(game_dir, "PlayerB")
        
        # Clean up existing links
        for link_path in [player1_link, player2_link]:
            if os.path.exists(link_path):
                if os.path.islink(link_path):
                    os.unlink(link_path)
                else:
                    import shutil
                    shutil.rmtree(link_path)
        
        # Create symbolic links and verify they're created correctly
        os.symlink(a_path, player1_link)
        os.symlink(b_path, player2_link)
        
        print(f"Created symlink: {player1_link} -> {os.path.realpath(player1_link)}")
        print(f"Created symlink: {player2_link} -> {os.path.realpath(player2_link)}")
        
        # Verify commands.json can be accessed through the symbolic links
        print(f"commands.json via symlink A: {os.path.exists(os.path.join(player1_link, 'commands.json'))}")
        print(f"commands.json via symlink B: {os.path.exists(os.path.join(player2_link, 'commands.json'))}")
        
        # Create config as before...
        with open(os.path.join(game_dir, "config.py"), "w") as config_file:
            config_txt = render_template(
                "config.txt",
                bot_a={"name": bot_a_name, "path": "./player2_monte_carlo"},
                bot_b={"name": bot_b_name, "path": "./mccfr"},
                game_big_blind=int(settings["game_big_blind"]),
                game_small_blind=int(settings["game_small_blind"]),
                game_starting_stack=int(settings["game_starting_stack"]),
                game_num_hands=int(settings["game_num_hands"]),
                game_time_restriction=int(settings["game_time_restriction"]),
                player_log_size_limit=int(settings["player_log_size_limit"]),
            )
            config_file.write(config_txt)
        
        # Print the generated config file for verification
        print(f"Generated config file:")
        with open(os.path.join(game_dir, "config.py"), "r") as config_file:
            print(config_file.read())
        
        try:
            # Run engine and process results as before...
            subprocess.check_call(
                ["python", ENGINE_PATH], cwd=game_dir, env=_get_environment()
            )
            
            with open(os.path.join(game_dir, "gamelog.txt"), "r") as game_log_file:
                game_log = game_log_file.read()
            
            player_log_filesize = int(settings["maximum_player_log_file_size"])
            
            bot_a_log = _read_logfile(
                os.path.join(game_dir, "{}.txt".format(bot_a_name)), player_log_filesize
            )
            bot_b_log = _read_logfile(
                os.path.join(game_dir, "{}.txt".format(bot_b_name)), player_log_filesize
            )
            
            return _get_scores(game_log), game_log, bot_a_log, bot_b_log
        finally:
            # Clean up
            if os.path.exists(player1_link):
                os.unlink(player1_link)
            if os.path.exists(player2_link):
                os.unlink(player2_link)


def _run_bots_and_upload(bot_a, bot_a_name, bot_b, bot_b_name):
    scores, game_log, bot_a_log, bot_b_log = _run_bots(
        bot_a, bot_a_name, bot_b, bot_b_name
    )

    log_key_base = os.path.join(
        "logs",
        "{}_{}".format(int(time.time()), binascii.hexlify(os.urandom(32)).decode()),
    )

    gamelog_key = os.path.join(log_key_base, "gamelog.txt")
    put_s3_object(gamelog_key, game_log)

    if bot_a_log is not None:
        bot_a_log_key = os.path.join(log_key_base, "bot_a.txt")
        put_s3_object(bot_a_log_key, bot_a_log)
    else:
        bot_a_log_key = None

    if bot_b_log is not None:
        bot_b_log_key = os.path.join(log_key_base, "bot_b.txt")
        put_s3_object(bot_b_log_key, bot_b_log)
    else:
        bot_b_log_key = None

    return scores, gamelog_key, bot_a_log_key, bot_b_log_key


def _multiple_with_for_update(cls, pks):
    query = cls.query.options(raiseload("*")).filter(cls.id.in_(pks)).with_for_update()
    results = query.all()
    mapping = {result.id: result for result in results}
    return tuple([mapping[pk] for pk in pks])


@celery_app.task(ignore_result=True)
def play_game_task(game_id):
    game = Game.query.get(game_id)
    assert game.status == GameStatus.created or game.status == GameStatus.internal_error
    game.status = GameStatus.in_progress
    db.session.commit()

    challenger = game.challenger
    challenger_bot = game.challenger_bot
    challenger_bot_id = challenger_bot.id
    challenger_name = "A"

    opponent = game.opponent
    opponent_bot = game.opponent_bot
    opponent_bot_id = opponent_bot.id
    opponent_name = "B"

    if opponent_bot_id == challenger_bot_id:
        return

    try:
        scores, log_key, challenger_log_key, opponent_log_key = _run_bots_and_upload(
            challenger_bot, challenger_name, opponent_bot, opponent_name
        )
        db.session.expire_all()

        # Reload stuff from DB.
        game = Game.query.options(raiseload("*")).with_for_update().get(game_id)
        challenger, opponent = _multiple_with_for_update(
            Team, [game.challenger_id, game.opponent_id]
        )
        challenger_bot, opponent_bot = _multiple_with_for_update(
            Bot, [challenger_bot_id, opponent_bot_id]
        )

        winner = _get_winner(*scores)

        # Relevant database updates.
        game.winner_id = challenger.id if winner == "a" else opponent.id
        game.loser_id = opponent.id if winner == "a" else challenger.id
        challenger.wins += int(winner == "a")
        challenger.losses += int(winner == "b")
        challenger_bot.wins += int(winner == "a")
        challenger_bot.losses += int(winner == "b")

        game.challenger_score, game.opponent_score = scores
        opponent.wins += int(winner == "b")
        opponent.losses += int(winner == "a")
        opponent_bot.wins += int(winner == "b")
        opponent_bot.losses += int(winner == "a")

        game.challenger_elo = challenger.elo
        game.opponent_elo = opponent.elo
        if (
            settings["down_challenges_affect_elo"].lower() == "true"
            or challenger.elo <= opponent.elo
        ):
            challenger.elo, opponent.elo = _elo(challenger.elo, opponent.elo, winner)

        game.status = GameStatus.completed
        game.completed_time = datetime.datetime.now()
        game.log_s3_key = log_key
        game.challenger_log_s3_key = challenger_log_key
        game.opponent_log_s3_key = opponent_log_key

        db.session.commit()

    except:
        db.session.rollback()
        game = Game.query.get(game_id)
        game.status = GameStatus.internal_error
        db.session.commit()
        raise


def arbitrary_tournament_data_collection_function(gamelog):
    # This function collects data on games that are played in a tournament.
    # Gamelogs from tournaments are not saved since they can result in 200+GB of data, per tournament.
    # Parse the interesting data you want from the gamelog and return it here (but keep it small!)
    pnls_B = []
    pnls_A = []
    i = 0

    log_split_into_rounds = gamelog.split("Round #")
    # count number of times a team wins despite
    # the other player winning the auction
    A_win_auction_loss = 0
    B_win_auction_loss = 0
    for curr_round_string in log_split_into_rounds:
        B_wins_auction = "B won the auction" in curr_round_string
        A_wins_auction = "A won the auction" in curr_round_string
        if A_wins_auction and B_wins_auction:
            continue
        elif A_wins_auction and ("A awarded -" in curr_round_string):
            B_win_auction_loss += 1
        elif B_wins_auction and ("B awarded -" in curr_round_string):
            A_win_auction_loss += 1

    for n in range(100, 1100, 100):
        i = gamelog.find("Round #" + str(n), i)
        if i == -1:
            pnls_A.append("nan")
            pnls_B.append("nan")
            i = 0
        else:
            b_start = gamelog.find(
                "(", i
            )  # team B is listed first on even number rounds (i.e. multiples of 100)
            b_end = gamelog.find(")", i)
            a_start = gamelog.find("(", b_end + 1)
            a_end = gamelog.find(")", b_end + 1)

            if b_start != -1 and b_end != -1:
                pnls_B.append(gamelog[b_start + 1 : b_end])
            else:
                pnls_B.append("nan")

            if a_start != -1 and a_end != -1:
                pnls_A.append(gamelog[a_start + 1 : a_end])
            else:
                pnls_A.append("nan")

    return {
        "Aai": gamelog.count("A went all in"),
        "Bai": gamelog.count("B went all in"),
        "Ar": gamelog.count("A raises"),
        "Br": gamelog.count("B raises"),
        "Ab": gamelog.count("A bets"),
        "Bb": gamelog.count("B bets"),
        "Aca": gamelog.count("A calls"),
        "Bca": gamelog.count("B calls"),
        "Ach": gamelog.count("A checks"),
        "Bch": gamelog.count("B checks"),
        "Af": gamelog.count("A folds"),
        "Bf": gamelog.count("B folds"),
        "Ash": gamelog.count("A shows"),
        "Bsh": gamelog.count("B shows"),
        "pnls_A": pnls_A,
        "pnls_B": pnls_B,
        "bid_A": _get_bids(gamelog, "A"),
        "bid_B": _get_bids(gamelog, "B"),
        "A_bid_W": gamelog.count("A won the auction"),
        "B_bid_W": gamelog.count("B won the auction"),
        "A_W_bid_L": A_win_auction_loss,
        "B_W_bid_L": B_win_auction_loss,
        "ev_A_flop": _get_bet_evs(gamelog, "A", "flop"),
        "ev_B_flop": _get_bet_evs(gamelog, "B", "flop"),
        "ev_A_turn": _get_bet_evs(gamelog, "A", "turn"),
        "ev_B_turn": _get_bet_evs(gamelog, "B", "turn"),
    }


@celery_app.task(ignore_result=True)
def play_tournament_game_task(tournament_game_id):
    game = TournamentGame.query.get(tournament_game_id)
    assert game.status == GameStatus.created or game.status == GameStatus.internal_error
    game.status = GameStatus.in_progress
    db.session.commit()

    tournament_bot_a = game.bot_a
    bot_a = tournament_bot_a.bot

    tournament_bot_b = game.bot_b
    bot_b = tournament_bot_b.bot

    try:
        scores, gamelog, _, _ = _run_bots(bot_a, "A", bot_b, "B")
        db.session.expire_all()

        # Reload stuff from DB.
        game = (
            TournamentGame.query.options(raiseload("*"))
            .with_for_update()
            .get(tournament_game_id)
        )
        tournament_bot_a, tournament_bot_b = _multiple_with_for_update(
            TournamentBot, [game.bot_a_id, game.bot_b_id]
        )

        winner = _get_winner(*scores)

        # Relevant database updates.
        game.bot_a_score, game.bot_b_score = scores

        game.winner_id = tournament_bot_a.id if winner == "a" else tournament_bot_b.id
        game.loser_id = tournament_bot_b.id if winner == "a" else tournament_bot_a.id
        tournament_bot_a.wins += int(winner == "a")
        tournament_bot_a.losses += int(winner == "b")
        tournament_bot_b.wins += int(winner == "b")
        tournament_bot_b.losses += int(winner == "a")

        game.status = GameStatus.completed
        game.completed_time = datetime.datetime.now()

        try:
            if scores[0] is not None and scores[1] is not None:
                game.json_statistics = json.dumps(
                    arbitrary_tournament_data_collection_function(gamelog)
                )
        except:
            pass

        db.session.commit()

    except:
        db.session.rollback()
        game = TournamentGame.query.get(tournament_game_id)
        game.status = GameStatus.internal_error
        db.session.commit()
        raise


@celery_app.task(ignore_result=True)
def spawn_tournament_task(tournament_id):
    tournament = Tournament.query.get(tournament_id)
    assert tournament.status == TournamentStatus.created
    print("Updating tournament status.")
    tournament.status = TournamentStatus.spawning
    db.session.commit()

    participants = list(tournament.participants)

    mappings = []
    for i in range(len(participants)):
        for j in range(i + 1, len(participants)):
            for game_index in range(tournament.games_per_pair):
                participant_a = participants[i]
                participant_b = participants[j]
                if game_index % 2 == 1:
                    participant_a, participant_b = participant_b, participant_a
                mappings.append(
                    {
                        "tournament_id": tournament.id,
                        "bot_a_id": participant_a.id,
                        "bot_b_id": participant_b.id,
                        "status": GameStatus.created,
                    }
                )
    print("Mappings assembled.")

    random.shuffle(mappings)
    db.session.bulk_insert_mappings(TournamentGame, mappings)
    db.session.commit()

    print("Mappings committed.")

    games = tournament.games

    print("Spawning tasks.")

    for game in games:
        play_tournament_game_task.delay(game.id)

    tournament.status = TournamentStatus.spawned
    db.session.commit()


@celery_app.task(ignore_result=True)
def calculate_tournament_elo_task(tournament_id):
    tournament = Tournament.query.get(tournament_id)
    assert tournament.status != TournamentStatus.done
    assert (
        tournament.num_games_queued() + tournament.num_games_running() == 0
    ), "Some games are in progress"

    games = (
        TournamentGame.query.filter(TournamentGame.status == GameStatus.completed)
        .filter(TournamentGame.tournament == tournament)
        .all()
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        with open(os.path.join(tmp_dir, "tournament.pgn"), "w") as pgn_file:
            pgn = render_template("tournament.pgn", games=games, tournament=tournament)
            pgn_file.write(pgn)

        command = subprocess.Popen(
            ["bayeselo"], cwd=tmp_dir, env=_get_environment(), stdin=subprocess.PIPE
        )

        command.communicate(
            "\n".join(
                [
                    "readpgn tournament.pgn",
                    "elo",
                    "mm",
                    "exactdist",
                    "ratings >ratings.txt",
                    "",  # newline at the end
                ]
            ).encode("utf-8")
        )

        with open(os.path.join(tmp_dir, "ratings.txt"), "r") as ratings_file:
            ratings_string = ratings_file.read()

        lines = ratings_string.split("\n")[1:]
        for line in lines:
            numbers = line.split()
            if len(numbers) == 0:
                break
            bot_id = int(numbers[1])
            bot = TournamentBot.query.get(bot_id)
            bot.elo = float(numbers[2]) + 1500.0
            bot.elo_plus_margin = float(numbers[3])
            bot.elo_minus_margin = float(numbers[4])

    tournament.status = TournamentStatus.done
    db.session.commit()
