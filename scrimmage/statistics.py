from scrimmage.settings import settings
from scrimmage.models import Game, GameStatus

from collections import namedtuple
import datetime
from pytz import timezone

from sqlalchemy.orm import load_only, raiseload
from sqlalchemy import or_


EloDatapoint = namedtuple('EloDatapoint', ['datetime', 'elo'])
HistogramDatapoint = namedtuple('HistogramDatapoint', ['datetime', 'wins', 'losses', 'challenges'])


# this is so hacky, whoever reads this next god have mercy.
TIMEZONE = timezone('America/New_York')
EPOCH_DATE = datetime.datetime.fromtimestamp(0)
def _round_date(d, granularity):
  total_seconds = int((d.replace(tzinfo=timezone('UTC')) - EPOCH_DATE.replace(tzinfo=TIMEZONE)).total_seconds())
  rounded_seconds = total_seconds/granularity
  rounded = datetime.datetime.fromtimestamp(rounded_seconds*granularity)

  # I couldn't get time rounding + daylight savings to work... whatever.
  return (rounded - TIMEZONE.utcoffset(rounded) + datetime.timedelta(hours=1))


def generate_team_stats(team):
  fields_to_load = ['challenger_id', 'opponent_id', 'challenger_elo', 'opponent_elo', 'winner_id', 'loser_id', 'completed_time']
  query = (Game.query.filter(Game.status == GameStatus.completed)
                     .filter(or_(Game.opponent == team, Game.challenger == team))
                     .order_by(Game.completed_time.asc())
                     .options(load_only(*fields_to_load))
                     .options(raiseload('*'))
          )
  games = query.all()

  granularity = int(settings['chart_granularity'])

  elo_over_time = []
  histogram_data = []

  current_bucket = [0, 0, 0, 0] if len(games) == 0 else [_round_date(games[0].completed_time, granularity), 0, 0, 0]

  for game in games:
    did_challenge = game.challenger_id == team.id
    did_win = game.winner_id == team.id

    elo = game.challenger_elo if did_challenge else game.opponent_elo
    elo_over_time.append(EloDatapoint(game.completed_time, elo))

    rounded_date = _round_date(game.completed_time, granularity)

    if current_bucket[0] != rounded_date:
      histogram_data.append(HistogramDatapoint(*current_bucket))
      current_bucket = [rounded_date, 0, 0, 0]

    # wins
    current_bucket[1] += int(did_win)
    current_bucket[2] += int(not did_win)
    current_bucket[3] += int(did_challenge)

  histogram_data.append(HistogramDatapoint(*current_bucket))

  return elo_over_time, histogram_data
