from flask import g, render_template, request, session, redirect, url_for, send_file

from scrimmage import app, db
from scrimmage.decorators import sponsor_or_admin_required
from scrimmage.models import Team
from scrimmage.statistics import generate_team_stats


@app.route('/sponsor/')
@sponsor_or_admin_required
def sponsor_index():
  teams = Team.query.filter(Team.is_disabled == False).all()
  return render_template('sponsor/index.html', teams=teams)


@app.route('/sponsor/team/<int:team_id>')
@sponsor_or_admin_required
def sponsor_team(team_id):
  team = Team.query.get_or_404(team_id)
  elo_over_time, histogram_data = generate_team_stats(team)
  return render_template('sponsor/team_info.html', team=team, elo_over_time=elo_over_time, histogram_data=histogram_data)

