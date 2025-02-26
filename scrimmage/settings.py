from scrimmage import app, db

from scrimmage.models import AdminSetting

DEFAULTS = {
  'spawn_limit_per_team': '5',
  'maximum_team_size': '4',
  'chart_granularity': '86400',
  'recent_games_to_show': '20',
  'challenges_enabled': 'true',
  'challenges_only_reference': 'false',
  'sponsor_portal_password': 'abc123',
  'extra_admins': '',
  'maximum_player_log_file_size': '10485760', # 10*1024*1024
  'game_big_blind': '2',
  'game_small_blind': '1',
  'game_starting_stack': '400',
  'game_num_hands': '1000',
  'game_time_restriction': '60',
  'down_challenges_affect_elo': 'true',
  'down_challenges_require_accept': 'true',
  'player_log_size_limit': 524288
}

DESCRIPTIONS = {
  'spawn_limit_per_team': 'The maximum number of games a team can have running or queued at a time',
  'maximum_team_size': 'The maximum size of a team',
  'chart_granularity': 'The time, in seconds, between buckets of the charts',
  'recent_games_to_show': 'The number of games to show on the homepage',
  'challenges_enabled': 'If challenges are allowed or not',
  'challenges_only_reference': 'If challenges are enabled, can they only challenge reference teams?',
  'sponsor_portal_password': 'The password to the sponsor portal. The username is sponsor',
  'extra_admins': 'Comma separated kerberoses of other admins',
  'maximum_player_log_file_size': 'The size, in bytes, from the player log to upload.', # 10*1024*1024
  'game_big_blind': 'The size of the big blind for games, in coins.',
  'game_small_blind': 'The size of the small blind for games, in coins',
  'game_starting_stack': 'The size of the starting stack for games, in coins.',
  'game_num_hands': 'The number of hands to play in a single game.',
  'game_time_restriction': 'The number of seconds to allow each player.',
  'down_challenges_affect_elo': 'If a higher elo player challenges a lower elo player, does it affect elo?',
  'down_challenges_require_accept': 'If a higher elo player challenges a lower elo player, does it need to be accepted?',
  'player_log_size_limit': 'The player log size limit'
}

class SettingsClass(object):
  # Key, value pairs. The value represents the defaults if it is not stored in the DB.

  def items(self):
    return list(DEFAULTS.keys())

  def description(self, key):
    return DESCRIPTIONS.get(key, 'No description provided')

  def __getitem__(self, key):
    setting = AdminSetting.query.filter(AdminSetting.key == key).one_or_none()
    if setting is None:
      return DEFAULTS[key]
    else:
      return setting.value

  def __getattr__(self, key):
    return self[key]

  def __setitem__(self, key, value):
    assert key in DEFAULTS
    setting = AdminSetting.query.filter(AdminSetting.key == key).one_or_none()
    if setting is None:
      db.session.add(AdminSetting(key, str(value)))
    else:
      setting.value = str(value)

  def __setattr__(self, key, value):
    self[key] = value

settings = SettingsClass()
