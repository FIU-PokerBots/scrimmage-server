from flask import g, render_template, request, session, redirect, url_for, send_file, jsonify
from collections import defaultdict

from scrimmage import app, db
from scrimmage.decorators import admin_required, set_flash
from scrimmage.helpers import get_s3_object
from scrimmage.models import Game, GameStatus, Announcement, Tournament, Team

@app.route('/admin/')
@admin_required
def admin_index():
  return render_template('admin/index.html')


@app.route('/admin/export_to_playground', methods=['GET'])
@admin_required
def admin_export_to_playground():
  team_id_to_team = {}
  team_id_to_bots = defaultdict(lambda: [])

  for tournament in Tournament.query.all():
    for participant in tournament.participants:
      team = participant.bot.team
      team_id_to_bots[team.id].append({
        'name': tournament.title,
        's3_key': participant.bot.s3_key
      })
      team_id_to_team[team.id] = team

  result = { 'teams': [] }
  for tid, team in team_id_to_team.items():
    result['teams'].append({
      'name': team_id_to_team[tid].name,
      'bots': team_id_to_bots[tid]
    })

  result['teams'].sort(key=lambda t: t['name'])
  return jsonify(result)

@app.route('/admin/export_to_playground_current', methods=['GET'])
@admin_required
def admin_export_to_playground_current():
  result = { 'teams': [] }
  for team in Team.query.all():
    active_bots = team.active_bots()
    current_bot = team.current_bot
    result['teams'].append({
      'name': team.name,
      'bots': [
          {'name': bot.name + (' (current)' if bot == current_bot else ''), 's3_key': bot.s3_key} 
          for bot in active_bots
      ]
    })

  result['teams'].sort(key=lambda t: t['name'])
  return jsonify(result)


@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def admin_announcements():
  if request.method == 'POST':
    if request.form['action'] == 'create':
      new_announcement = Announcement(
        author_kerberos=g.real_kerberos,
        title=request.form['title'],
        text=request.form['text'],
        is_public=bool(request.form.get('is_public', False))
      )
      db.session.add(new_announcement)
      set_flash('Announcement posted!', level='success')
    elif request.form['action'] == 'delete':
      db.session.delete(Announcement.query.get(request.form['announcement_id']))
      set_flash('Announcement deleted!', level='negative')
    db.session.commit()
  return render_template('admin/announcements.html', announcements=Announcement.query.order_by(Announcement.create_time.desc()).all())


@app.route('/admin/impersonate', methods=['GET', 'POST'])
@admin_required
def admin_impersonate():
  if request.method == 'POST':
    session['kerberos'] = request.form['kerberos']
    return redirect(url_for('index'))
  return render_template('admin/impersonate.html')


@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
  if request.method == 'POST':
    g.settings[request.form['key']] = request.form['value']
    db.session.commit()
    set_flash('Setting changed!', level='success')
  return render_template('admin/settings.html')


@app.route('/admin/games')
@admin_required
def admin_all_games():
  pagination = Game.query.order_by(Game.create_time.desc()).paginate()
  return render_template('admin/all_games.html', pagination=pagination)


@app.route('/admin/game/<int:game_id>/log')
@admin_required
def admin_game_log(game_id):
  game = Game.query.get(game_id)
  assert game.log_s3_key is not None
  return send_file(get_s3_object(game.log_s3_key), mimetype="text/plain")


@app.route('/admin/game/<int:game_id>/challenger_log')
@admin_required
def admin_challenger_log(game_id):
  game = Game.query.get(game_id)
  assert game.challenger_log_s3_key is not None
  return send_file(get_s3_object(game.challenger_log_s3_key), mimetype="text/plain")


@app.route('/admin/game/<int:game_id>/opponent_log')
@admin_required
def admin_opponent_log(game_id):
  game = Game.query.get(game_id)
  assert game.opponent_log_s3_key is not None
  return send_file(get_s3_object(game.opponent_log_s3_key), mimetype="text/plain")
