import binascii
import hashlib
import hmac
import io
import json
import oursql
import os
import tornado.httpclient

conn = oursql.connect(db='pyhole', user='pyhole', passwd='pyhole', autoreconnect=True)
eve_conn = oursql.connect(db='eve', user='eve', passwd='eve', autoreconnect=True)

class ACTIONS(object):
    ADD_SYSTEM = 1
    DELETE_SYSTEM = 2
    TOGGLE_EOL = 3
	# CREATE_USER = 4
    # ADD_SIGNATURES = 5
    # UPDATE_SIGNATURES = 6
    # DELETE_SIGNATURE = 7

def query(cursor, sql, *args):
	cursor.execute(sql, args)
	while True:
		r = cursor.fetchone()
		if r is None:
			break
		attribs = DBRow(r, cursor.description)
		yield attribs

def query_one(cursor, sql, *args):
	results = query(cursor, sql, *args)
	try:
		r = next(results)
	except StopIteration:
		return
	try:
		next(results)
	except StopIteration:
		return r
	else:
		raise RuntimeError('multiple rows for query {}, {}'.format(sql, args))

def __gen_hash(password):
	salt = os.urandom(16)
	h = hmac.new(salt, password.encode('utf-8'), hashlib.sha256)
	hashed = h.hexdigest()
	salt_hex = binascii.hexlify(salt)
	return hashed, salt_hex

def create_user(auth_user, username, password):
	hashed, salt_hex = __gen_hash(password)
	with conn.cursor() as c:
		c.execute('INSERT INTO users (username, password, salt, admin) VALUES(?, ?, ?, 0)',
				[username, hashed, salt_hex])
	#log_action(c, auth_user, ACTIONS.CREATE_USER, {'username':username})

def check_login(username, password):
	with conn.cursor() as c:
		r = query_one(c, 'SELECT id, password, salt FROM users WHERE username = ?', username)
	if r is None:
		return
	salt = binascii.unhexlify(bytes(r.salt, 'ascii'))
	h = hmac.new(salt, password.encode('utf-8'), hashlib.sha256)
	if h.hexdigest() == r.password:
		return r.id

def change_password(user_id, password):
	hashed, salt_hex = __gen_hash(password)
	with conn.cursor() as c:
		c.execute('UPDATE users SET password = ?, salt = ? WHERE id = ?',
				[hashed, salt_hex, user_id])
		if c.rowcount != 1:
			raise RuntimeError('expected to update 1 row, affected {}'.format(c.rowcount))

class UpdateError(Exception):
	def __init__(self, message):
		self.message = message

def add_system(auth_user, system):
	def add_node(node):
		if node['name'] == system['src']:
			node.setdefault('connections', [])
			system['name'] = system['dest']
			del system['dest']
			node['connections'].append(system)
			return True
		if 'connections' in node:
			for c in node['connections']:
				if add_node(c):
					return True

	root_system = 'src' not in system
	wspace_system = False
	if system['dest'][0] == 'J':
		try:
			int(system['dest'][1:])
			wspace_system = True
		except ValueError:
			pass
	if not wspace_system and not root_system:
		with eve_conn.cursor() as c:
			r = query_one(c, '''
			SELECT solarSystemID, security FROM mapSolarSystems
			WHERE solarSystemName = ?
			''', system['dest'])
			if r is None:
				raise UpdateError('system does not exist')
			security = round(r.security, 1)
			if security >= 0.5:
				system['class'] = 'highsec'
			elif security > 0.0:
				system['class'] = 'lowsec'
			else:
				system['class'] = 'nullsec'
			client = tornado.httpclient.HTTPClient()
			ec_api = 'http://api.eve-central.com/api/route/from/{}/to/{}'
			jumps = {
				'Jita': 30000142,
				'Amarr': 30002187,
				'Dodixie': 30002659,
				'Rens': 30002510,
				'Hek': 30002053,
			}
			for trade_hub in jumps.keys():
				system_id = jumps[trade_hub]
				response = client.fetch(ec_api.format(r.solarSystemID, system_id))
				route = json.load(io.TextIOWrapper(response.buffer, 'utf-8'))
				route = map(lambda j: (j['to']['name'], j['to']['security']), route)
				jumps[trade_hub] = list(route)
			client.close()
			system['jumps'] = jumps
	with conn.cursor() as c:
		if wspace_system:
			r = query_one(c, '''
			SELECT class, effect, w1.name, w1.dest, w2.name, w2.dest
			FROM wh_systems
			JOIN wh_types AS w1 ON static1 = w1.id
			LEFT JOIN wh_types AS w2 ON static2 = w2.id
			WHERE wh_systems.name = ?;
			''', system['dest'])
			system['class'] = getattr(r, 'class')
			system['effect'] = r.effect
			system['static1'] = {'name': r.raw[2], 'dest': r.raw[3]}
			if r.raw[4] is not None:
				system['static2'] = {'name': r.raw[4], 'dest': r.raw[5]}

		r = query_one(c, 'SELECT json from maps')
		map_data = json.loads(r.json)
		if root_system:
			system = {'name': system['dest'], 'class': 'home'}
			map_data.append(system)
		elif not any(map(add_node, map_data)):
			raise UpdateError('src system not found')
		map_json = json.dumps(map_data)
		c.execute('UPDATE maps SET json = ?', (map_json,))
		log_action(c, auth_user, ACTIONS.ADD_SYSTEM, system)
	return map_json

def delete_system(auth_user, system_name):
	def delete_node(node):
		if 'connections' in node:
			for i, c in enumerate(node['connections']):
				if c['name'] == system_name:
					node['connections'].pop(i)
					return c
				deleted_node = delete_node(c)
				if deleted_node:
					return deleted_node

	with conn.cursor() as c:
		r = query_one(c, 'SELECT json from maps')
		map_data = json.loads(r.json)
		for i, root_node in enumerate(map_data):
			if root_node['name'] == system_name:
				deleted_node = map_data.pop(i)
				break
		else:
			for node in map_data:
				deleted_node = delete_node(node)
				if deleted_node is not None:
						break
		if deleted_node is None:
				raise UpdateError('system not found')
		map_json = json.dumps(map_data)
		c.execute('UPDATE maps SET json = ?', (map_json,))
		log_action(c, auth_user, ACTIONS.DELETE_SYSTEM, deleted_node)
	return map_json

def toggle_eol(auth_user, src, dest):
	def toggle_node(node):
		if 'connections' in node:
			for i, c in enumerate(node['connections']):
				if node['name'] == src and c['name'] == dest:
					c['eol'] = not c['eol']
					return c
				else:
					return toggle_node(c)

	with conn.cursor() as c:
		r = query_one(c, 'SELECT json from maps')
		map_data = json.loads(r.json)
		changed_node = None
		for node in map_data:
			changed_node = toggle_node(node)
			if changed_node is not None:
				break
		if changed_node is None:
			raise UpdateError('system not found')
		map_json = json.dumps(map_data)
		c.execute('UPDATE maps SET json = ?', (map_json,))
		log_action(c, auth_user, ACTIONS.TOGGLE_EOL, changed_node)
	return map_json

def add_signatures(auth_user, system_name, new_sigs):
	log_added = {'system_name':system_name, 'signatures': []}
	log_updated = {'system_name':system_name, 'signatures': []}
	def add_sigs_node(node):
		if node['name'] == system_name:
			sigs = node.get('signatures', [])
			for sig in sigs:
				sig_id = sig[0]
				if sig_id in new_sigs:
					new_sig = new_sigs[sig_id]
					if new_sig[4] >= sig[4]: # compare signal strength
						for i in range(1, len(new_sig)):
							sig[i] = new_sig[i]
						log_updated['signatures'].append(sig)
					del new_sigs[sig_id]
			for sig_id in new_sigs:
				log_added['signatures'].append(new_sigs[sig_id])
			sigs.extend(new_sigs.values())

			node['signatures'] = sigs
			return True
		if 'connections' in node:
			for c in node['connections']:
				if add_sigs_node(c):
					return True

	with conn.cursor() as c:
		r = query_one(c, 'SELECT json from maps')
		map_data = json.loads(r.json)
		if not any(map(add_sigs_node, map_data)):
			raise UpdateError('system not found')
		# For now, don't log
		# if log_added['signatures']: log_action(c, auth_user, ACTIONS.ADD_SIGNATURES, log_added)
		# if log_updated['signatures']: log_action(c, auth_user, ACTIONS.UPDATE_SIGNATURES, log_updated)
		map_json = json.dumps(map_data)
		c.execute('UPDATE maps SET json = ?', (map_json,))
	return map_json

def delete_signature(auth_user, system_name, sig_id):
	def del_sig_node(node):
		if node['name'] == system_name:
			index = None
			for i, sig in enumerate(node['signatures']):
				if sig[0] == sig_id:
					index = i
					break
			if index is None:
				raise UpdateError('sig id not found')
			return node['signatures'].pop(index)
		if 'connections' in node:
			for c in node['connections']:
				return del_sig_node(c)

	with conn.cursor() as c:
		r = query_one(c, 'SELECT json from maps')
		map_data = json.loads(r.json)
		sig_removed = None
		for node in map_data:
			sig_removed = del_sig_node(node)
			if sig_removed is not None:
				break
		if sig_removed is None:
			raise UpdateError('system not found')
		map_json = json.dumps(map_data)
		c.execute('UPDATE maps SET json = ?', (map_json,))
		#log_item = {'system_name':system_name, 'signature':sig_removed}
		#log_action(c, auth_user, ACTIONS.DELETE_SIGNATURE, log_item)
	return map_json

def log_action(conn_cursor, user_id, action, details):
	"""Adds a log entry to the database.

	Arguments:
	user_id -- integer that must match an existing user in the database
	action -- enum representing the action
	details -- dict with the details of the action
	"""

	log_message = ''

	if action == ACTIONS.ADD_SYSTEM:
		if 'src' not in details:
			log_message =  'Added new home system ' + details['name']
		else:
			log_message =  'Added system ' + details['name'] + ' connected to ' + details['src']

	elif action == ACTIONS.DELETE_SYSTEM:
		if details['class'] == 'home':
			log_message = 'Deleted home system ' + details['name']
		else:
			log_message = 'Deleted system ' + details['name']
		if 'connections' in details:
			for system in details['connections']:
				log_action(conn_cursor, user_id, ACTIONS.DELETE_SYSTEM, system)

	elif action == ACTIONS.TOGGLE_EOL:
		if details['eol']:
			log_message =  'System ' + details['name'] + ' set to EOL'
		else:
			log_message =  'System ' + details['name'] + ' reverted to not EOL'

	else:
		raise RuntimeError('unhandled log_action')

	''' For now, don't log these

	elif action == ACTIONS.CREATE_USER:
		log_message = 'Created user ' + details['username']

	elif action == ACTIONS.ADD_SIGNATURES:
		log_message = 'Added signatures to ' + details['system_name'] + ': '
		for i in range(len(details['signatures'])-1):
			log_message += details['signatures'][i][0] + ', '
		log_message += details['signatures'][-1][0]

	elif action == ACTIONS.UPDATE_SIGNATURES:
		log_message = 'Updated signatures at ' + details['system_name'] + ': '
		for i in range(len(details['signatures'])-1):
			log_message += details['signatures'][i][0] + ', '
		log_message += details['signatures'][-1][0]

	elif action == ACTIONS.DELETE_SIGNATURE:
		log_message = 'Deleted signature from ' + details['system_name'] + ': ' + details['signature'][0]
	'''

	#trim if it's too long so database doesn't complain
	if len(log_message) > 65:
		log_message = log_message[:65]
	conn_cursor.execute('INSERT INTO log (time, user_id, action_id, log_message) VALUES(UTC_TIMESTAMP(), ?, ?, ?)',
		[user_id, action, log_message])


class DBRow:
	def __init__(self, result, description):
		for i, f in enumerate(description):
			setattr(self, f[0], result[i])
		self.raw = result

	def __str__(self):
		return '<DBRow>: ' + str(self.__dict__)
