import os
import binascii

from flask import g, redirect, render_template, request, url_for, send_file, Response

from scrimmage import app, db
from scrimmage.decorators import team_required
from scrimmage.models import Bot, Game, GameStatus, TeamJoinRequest, User
from scrimmage.helpers import get_s3_object, put_s3_object
from scrimmage.statistics import generate_team_stats

from coolname import generate_slug

from sqlalchemy import and_

@app.route('/team')
@team_required
def manage_team():
  return render_template('manage_team.html')


@app.route('/team/games')
@team_required
def show_games():
  pagination = (Game.query.filter((Game.challenger_id == g.team.id) | (Game.opponent_id == g.team.id))
                          .order_by(Game.create_time.desc())
                          .paginate())
  return render_template('show_games.html', pagination=pagination)


@app.route('/team/game/<int:game_id>/game_log')
@team_required
def game_log(game_id):
  game = Game.query.get(game_id)
  assert game.status == GameStatus.completed
  assert game.opponent == g.team or game.challenger == g.team
  return send_file(get_s3_object(game.log_s3_key), mimetype="text/plain")


@app.route('/team/game/<int:game_id>/player_log')
@team_required
def player_log(game_id):
  game = Game.query.get(game_id)
  assert game.opponent == g.team or game.challenger == g.team
  if game.challenger == g.team:
    key = game.challenger_log_s3_key
  else:
    key = game.opponent_log_s3_key

  if not key:
    return Response("No player log available.", mimetype='text/plain')

  return send_file(get_s3_object(key), mimetype="text/plain")


# NoCredntialsError --> issue with AWS credentials
@app.route('/team/create_bot', methods=['POST'])
@team_required
def create_bot():
  fil = request.files['file']
  name = request.form['name']

  if name == '' or name is None:
    name = generate_slug(2)

  key = os.path.join('bots', str(g.team.id), binascii.hexlify(os.urandom(10)).decode() + '.zip')
  put_s3_object(key, fil)

  new_bot = Bot(g.team, name, key)
  db.session.add(new_bot)
  db.session.commit()
  g.team.set_current_bot(new_bot)
  db.session.commit()
  return redirect(url_for('manage_team'))


@app.route('/team/delete_bot', methods=['POST'])
@team_required
def delete_bot():
  bot_id = int(request.form['bot_id'])
  bot = Bot.query.get(bot_id)
  assert bot.team == g.team, "Tried to delete bot from other team"
  assert g.team.current_bot != bot, "Tried to delete the current bot"

  bot.is_disabled = True
  db.session.commit()
  return redirect(url_for('manage_team'))


@app.route('/team/set_bot', methods=['POST'])
@team_required
def set_bot():
  bot_id = int(request.form['bot_id'])
  bot = Bot.query.get(bot_id)
  g.team.set_current_bot(bot)
  db.session.commit()
  return redirect(url_for('manage_team'))


@app.route('/team/download_bot/<int:bot_id>')
@team_required
def download_bot(bot_id):
  bot = Bot.query.get(bot_id)
  assert bot.team == g.team, "Tried to get bot from other team"
  return send_file(get_s3_object(bot.s3_key), mimetype="application/zip")


@app.route('/team/leave', methods=['POST'])
@team_required
def leave_team():
  if len(g.team.members) == 1:
    g.team.is_disabled = True

  me = User.query.filter(User.kerberos == g.kerberos).one_or_none()
  assert me is not None
  db.session.delete(me)
  db.session.commit()

  return redirect(url_for('index'))


@app.route('/team/answer_join', methods=['POST'])
@team_required
def answer_join():
  join_request = TeamJoinRequest.query.filter(and_(TeamJoinRequest.team == g.team, TeamJoinRequest.kerberos == request.form['kerberos'])).one_or_none()
  assert join_request is not None

  if request.form['action'] == 'accept':
    assert g.team.can_be_joined()
    user = User(join_request.kerberos, join_request.team)
    db.session.add(user)

  db.session.delete(join_request)
  db.session.commit()
  return redirect(url_for('manage_team'))



@app.route('/team/charts')
@team_required
def team_charts():
  elo_over_time, histogram_data = generate_team_stats(g.team)
  return render_template('charts.html', elo_over_time=elo_over_time, histogram_data=histogram_data)
