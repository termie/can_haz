import json

def can_haz(match_list, target_dict, credentials_dict):
  """Check the authz of some rules against credentials.

  Match lists look like:

    ('rule:compute:get_volume',)

  or

    ('role:compute_admin',
     ('tenant_id:%(tenant_id)s', 'role:compute_sysadmin'))


  Target dicts contain as much information as we can about the object being
  operated on.

  Credentials dicts contain as much information as we can about the user
  performing the action.

  """
  b = Brain()
  if not b.check(match_list, target_dict, credentials_dict):
    raise Exception('Not Allowed')


class Brain(object):
  # class level on purpose, the brain is global
  rules = {}

  def __init__(self, rules=None):
    if rules is not None:
      self.__class__.rules = rules

  def add_rule(self, key, match):
    self.rules[key] = match

  def check(self, match_list, target_dict, cred_dict):
    for and_list in match_list:
      matched = False
      for match in and_list:
        # check each rule and if any fail return false
        if match.startswith('rule:'):
          new_match_list = self.rules.get(match[5:])
          rv = self.check(new_match_list, target_dict, cred_dict)
          if not rv:
            matched = False
            break
        else:
          rv = self._check(match, target_dict, cred_dict)
          if not rv:
            matched = False
            break
        matched = True

      # all AND matches passed
      if matched:
        return True

    # no OR rules matched
    return False

  def _check(self, match, target_dict, cred_dict):
    """Check an individual match.

    Matches look like:

      tenant:%(tenant_id)s
      role:compute:admin

    """

    # TODO(termie): do dict inspection via dot syntax
    match = match % target_dict
    key, value = match.split(':', 2)
    if key in cred_dict:
      return value == cred_dict[key]
    return False


def load_json(path):
  rules_dict = json.load(open(path))
  b = Brain(rules=rules_dict)
