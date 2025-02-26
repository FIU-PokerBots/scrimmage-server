from flask import render_template, request, session, redirect, url_for

from scrimmage import app, db
from scrimmage.decorators import admin_required
from scrimmage.models import Team, Tournament, TournamentGame, TournamentBot, GameStatus

from scrimmage.tasks import spawn_tournament_task, play_tournament_game_task, calculate_tournament_elo_task

import random
import datetime

@app.route('/admin/tournaments', methods=['GET'])
@admin_required
def admin_tournaments():
  teams = Team.query.filter(Team.is_disabled == False).all()
  eligible_teams = [team for team in teams if team.can_be_challenged() and team.can_challenge()]
  tournaments = Tournament.query.order_by(Tournament.create_time.desc()).all()
  return render_template('admin/tournaments.html', num_teams=len(eligible_teams), tournaments=tournaments)


@app.route('/admin/tournaments/spawn', methods=['POST'])
@admin_required
def admin_tournaments_spawn():
  title = request.form['title']
  if title == '' or title is None:
    title = "Tournament #{}".format(Tournament.query.count() + 1)

  games_per_pair = int(request.form['games_per_pair'])
  assert games_per_pair >= 0

  is_private = bool(request.form.get('is_private', False))
  tournament = Tournament(title, games_per_pair, is_private)
  db.session.add(tournament)

  teams = Team.query.filter(Team.is_disabled == False).all()
  eligible_teams = [team for team in teams if team.can_be_challenged() and team.can_challenge()]
  participants = [TournamentBot(team.current_bot, tournament) for team in eligible_teams]
  db.session.add_all(participants)
  db.session.commit()

  spawn_tournament_task.delay(tournament.id)

  return redirect(url_for('admin_tournaments'))


@app.route('/admin/tournaments/<int:tournament_id>/handle', methods=['POST'])
@admin_required
def admin_handle_failed(tournament_id):
  tournament = Tournament.query.get(tournament_id)

  if request.form['action'] == 'generate_elo':
    calculate_tournament_elo_task.delay(tournament.id)
    return redirect(url_for('admin_tournaments'))

  query = (
    TournamentGame.query
                  .filter(TournamentGame.tournament == tournament)
                  .filter(TournamentGame.status == GameStatus.internal_error)
  )

  if request.form['action'] == 'delete':
    query.delete()
    db.session.commit()
    return redirect(url_for('admin_tournaments'))


  failed_games = query.all() 

  for game in failed_games:
    game.status = GameStatus.created
    game.create_time = datetime.datetime.now()

  db.session.commit()

  for game in failed_games:
    play_tournament_game_task.delay(game.id)

  return redirect(url_for('admin_tournaments'))



