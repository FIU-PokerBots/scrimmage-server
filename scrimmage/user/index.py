from flask import render_template, g, url_for, redirect, request, Response

from sqlalchemy import and_

from scrimmage import app, db
from scrimmage.models import User, Team, TeamJoinRequest, GameRequest, GameRequestStatus, Game, Announcement, Tournament
from scrimmage.decorators import login_required, team_required, set_flash, sponsor_or_team_required

@app.route('/')
def index():
  games_to_show = int(g.settings['recent_games_to_show'])
  recent_games = Game.query.order_by(Game.create_time.desc()).limit(games_to_show).all()
  if not g.is_logged_in:
    announcements = Announcement.query.filter(Announcement.is_public == True).order_by(Announcement.create_time.desc()).all()
    return render_template('auth/logged_out.html', recent_games=recent_games, announcements=announcements)

  announcements = Announcement.query.order_by(Announcement.create_time.desc()).limit(1).all()
  if not g.team:
    join_request = TeamJoinRequest.query.filter(TeamJoinRequest.kerberos == g.kerberos).one_or_none()
    joinable_teams = Team.query.filter(and_(Team.is_disabled == False, Team.must_autoaccept == False)).all()
    requestable_teams = [team for team in joinable_teams if team.can_be_requested()]
    return render_template('no_team.html', announcements=announcements, teams=requestable_teams, join_request=join_request)
  
  teams = Team.query.filter(Team.is_disabled == False).all()
  challengeable_teams = [team for team in teams if team.can_be_challenged()]
  if not g.team.can_be_challenged():
    challengeable_teams.append(g.team)
  return render_template('homepage.html',
                         challengeable_teams=challengeable_teams,
                         pending_requests=g.team.pending_requests(),
                         recent_games=recent_games,
                         announcements=announcements)



@app.route('/request_team', methods=['POST'])
@login_required
def request_team():
  team = Team.query.get(int(request.form['team_id']))
  assert team.can_be_requested()
  join_request = TeamJoinRequest(g.kerberos, team)
  db.session.add(join_request)
  db.session.commit()
  return redirect(url_for('index'))


@app.route('/request_team/cancel', methods=['POST'])
@login_required
def cancel_team_request():
  join_request = TeamJoinRequest.query.filter(TeamJoinRequest.kerberos == g.kerberos).one_or_none()
  assert join_request is not None
  db.session.delete(join_request)
  db.session.commit()
  return redirect(url_for('index'))


@app.route('/create_team', methods=['POST'])
@login_required
def create_team():
  team_name = request.form['team_name']

  if Team.query.filter(Team.name == team_name).count() != 0:
    return Response("A team with that name already exists. Try again.", content_type="text/plain", status=400)

  team = Team(team_name)
  db.session.add(team)
  user = User(g.kerberos, team)
  db.session.add(user)
  db.session.commit()
  return redirect(url_for('index'))


@app.route('/announcements')
@login_required
def announcements():
  announcements = Announcement.query.order_by(Announcement.create_time.desc()).all()
  return render_template('announcements.html', announcements=announcements)


@app.route('/challenge', methods=['POST'])
@team_required
def challenge():
  team_id = int(request.form['team_id'])
  team = Team.query.get(team_id)
  assert g.settings['challenges_enabled'].lower() == 'true'
  assert g.settings['challenges_only_reference'] == 'false' or team.must_autoaccept
  assert g.team.can_challenge()
  assert team.can_be_challenged()

  g_request = GameRequest(g.team, team)
  db.session.add(g_request)

  if g_request.should_autoaccept():
    if g.team.can_initiate():
      game = g_request.accept(was_automatic=True)
      db.session.add(game)
      set_flash("Challenged {}. The game is now in the queue".format(g_request.opponent.name), level='success')
      db.session.commit()
      game.spawn()
    else:
      set_flash("Game could not be spawned since you have too many games currently running. Please wait a little bit.", level='warning')
  else:
    set_flash("Challenged {}. Since they are lower ELO, they must accept the request.".format(g_request.opponent.name), level='success')
    db.session.commit()

  return redirect(url_for('index'))


@app.route('/answer_request/<int:request_id>', methods=['POST'])
@team_required
def answer_request(request_id):
  g_request = GameRequest.query.get(request_id)
  assert g_request.opponent == g.team
  action = request.form['action']

  if action == 'reject':
    g_request.reject()
    db.session.commit()
    set_flash("Rejected {}'s game request.".format(g_request.challenger.name), level='success')
  elif action == 'accept':
    if g.team.can_initiate():
      game = g_request.accept(was_automatic=False)
      db.session.add(game)
      db.session.commit()
      game.spawn()
      set_flash("Accepted {}'s game request. It is now in the game queue.".format(g_request.challenger.name), level='success')
    else:
      set_flash("Could not accept the game request, since you have too many games currently running. Please wait a little bit", level='warning')
  return redirect(url_for('index'))


@app.route('/tournaments')
@sponsor_or_team_required
def show_tournaments():
  query = Tournament.query.order_by(Tournament.create_time.desc())
  if not g.is_admin and not g.is_sponsor:
    query = query.filter(Tournament.is_private == False)
  tournaments = query.all()
  return render_template('tournaments.html', tournaments=tournaments)
