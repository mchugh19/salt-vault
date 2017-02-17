# -*- coding: utf-8 -*-
'''
:maintainer:    Calle Pettersson <cpettsson@gmail.com>
:maturity:      new
:depends:       python-requests
:platform:      all

Interact with Hashicorp Vault
'''

import logging
import requests
import base64
import re

import salt.crypt
import salt.exceptions

log = logging.getLogger(__name__)

def generate_token(minion_id, signature, impersonated_by_master=False):
  log.debug('Token generation request for {0} (impersonated by master: {1})'.format(minion_id, impersonated_by_master))
  _validate_signature(minion_id, signature, impersonated_by_master)

  try:
    config = __opts__['vault']

    url = '{0}/v1/auth/token/create'.format(config['url'])
    headers = {'X-Vault-Token': config['auth']['token']}
    audit_data = {
      'saltstack-jid': globals().get('__jid__', '<no jid set>'),
      'saltstack-minion': minion_id,
      'saltstack-user': globals().get('__user__', '<no user set>')
    }
    payload = { 'policies': _get_policies(minion_id, config), 'num_uses': 1, 'metadata': audit_data }

    log.trace('Sending token creation request to Vault')
    response = requests.post(url, headers=headers, json=payload)

    if response.status_code != 200:
      return { 'error': response.reason }

    authData = response.json()['auth']
    return { 'token': authData['client_token'], 'url': config['url'] }
  except Exception as e:
    return { 'error': str(e) }

def show_policies(minion_id):
  config = __opts__['vault']
  return _get_policies(minion_id, config)

def _validate_signature(minion_id, signature, impersonated_by_master):
  pki_dir = __opts__['pki_dir']
  if impersonated_by_master:
    public_key = '{0}/master.pub'.format(pki_dir)
  else:
    public_key = '{0}/minions/{1}'.format(pki_dir, minion_id)

  log.trace('Validating signature for {0}'.format(minion_id))
  signature = base64.b64decode(signature)
  if not salt.crypt.verify_signature(public_key, minion_id, signature):
    raise salt.exceptions.AuthenticationError('Could not validate token request from {0}'.format(minion_id))
  log.trace('Signature ok')

def _get_policies(minion_id, config):
  _, grains, _ = salt.utils.minions.get_minion_data(minion_id, __opts__)
  policyPatterns = config.get('policies', ['saltstack/minion/{minion}', 'saltstack/minions'])

  # Allowing pillars in the policy template creates infinite recursion if there
  # are pillars with secrets as values. Removed until that can be solved.
  #minion_pillar = __salt__['pillar.show_pillar'](minion_id)
  #mappings = { 'minion': minion_id, 'grains': __grains__, 'pillar': minion_pillar }
  mappings = { 'minion': minion_id, 'grains': grains}

  policies = _expand_patterns(policyPatterns, mappings)

  log.debug('{0} policies: {1}'.format(minion_id, policies))
  return policies


def _expand_patterns(patterns, mappings=None):
  '''
  Expand each pattern - format mapping data
    For mappings that return a list expand the list
    creating multiple patterns. This has only been
    tested with a one dimensional list.

  patterns:
    list of patterns to expand
    example:
      [
        'path/{minion}/{grains[ec2_tags][Environment]}',
        'path/{minion}/{grains[ec2_tags][Environment]}/{grains[ec2_roles]}'
      ]

  mappings:
    any variable to be expanded should be present in the mappings

    example:
      mappings = {
        'minion': 'bacon',
        'grains': {
          'ec2_tags': {'Environment':'eggs'},
          'ec2_roles': ['love','me', 'some']
        }
      }

  '''
  expanded_patterns = []
  for pindex,pattern in enumerate(patterns):
    try:
      current_pattern = pattern.format(**mappings)
    except:
      log.debug('Unable to render {0}'.format(pattern))
      continue
    if "[" in current_pattern:
      exploded_pattern = current_pattern.split('/')
      for index,part in enumerate(exploded_pattern):
        if '[' in part:
          try:
            # Don't eval here
            # evaluated_expanded_parts = eval(part)
            evaluated_expanded_parts = re.sub('[\'\[\]]','',part).split(',')
            for eep in evaluated_expanded_parts:
              exploded_pattern[index] = eep.strip()
              expanded_patterns.append("/".join(exploded_pattern))
          except Exception, e:
            log.debug('Unable to render {0}'.format(evaluated_expanded_parts))
    else:
      expanded_patterns.append(current_pattern)
  return expanded_patterns
