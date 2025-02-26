from flask import render_template, request, session, redirect, url_for

from scrimmage import app, db
from scrimmage.decorators import admin_required
from scrimmage.models import User, Team

@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
  users = User.query.all()
  teams = Team.query.all()
  return render_template('admin/users.html', users=users, teams=teams)

@app.route('/admin/users/create', methods=['POST'])
@admin_required
def admin_users_create():
  team_id = int(request.form['team_id'])
  kerberos = request.form['kerberos']
  team = Team.query.get(team_id)
  user = User(kerberos, team)
  db.session.add(user)
  db.session.commit()
  return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_user_delete(user_id):
  user = User.query.get(user_id)
  db.session.delete(user)
  db.session.commit()
  return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/set_team', methods=['POST'])
@admin_required
def admin_user_set_team(user_id):
  team_id = int(request.form['team_id'])
  team = Team.query.get(team_id)
  user = User.query.get(user_id)
  user.team = team
  db.session.commit()
  return redirect(url_for('admin_users'))
