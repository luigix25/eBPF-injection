# import argparse
# import paramiko


# def executeCommand(command):
# 	nbytes = 4096
# 	hostname = "localhost"
# 	port = 2222
# 	username = "giacomo"
# 	password = "p"

# 	client = paramiko.Transport((hostname, port))
# 	client.connect(username=username, password=password)	
# 	session = client.open_channel(kind='session')

# 	stdout_data = []
# 	stderr_data = []
# 	session.exec_command(command)
# 	while True:
# 	    if session.recv_ready():
# 	        stdout_data.append(session.recv(nbytes))
# 	    if session.recv_stderr_ready():
# 	        stderr_data.append(session.recv_stderr(nbytes))
# 	    if session.exit_status_ready():
# 	        break

# 	print('exit status: ', session.recv_exit_status())
# 	print(b','.join(stdout_data))
# 	print(b','.join(stderr_data))
	
# 	session.close()
# 	client.close()

# if __name__ == "__main__":
# 	# Parse arguments
# 	# parser = argparse.ArgumentParser(description='Execute spscq tests.')
# 	# parser.add_argument('command', metavar='c', nargs=1,
# 	# 	                help='command to run on remote server')
# 	# args = parser.parse_args()

# 	affinity_test = "cd shared; cd simplified-spscq; python3 affinity_test.py 3 unpinned"
# 	pin_vcpu = "cd shared; cd affinity_test; ./affinity_test 0; ./affinity_test 1"
# 	# executeCommand(affinity_test)
# 	executeCommand(pin_vcpu)





###################################

		# FABRIC WAY

###################################





from invoke import Responder
import fabric
from fabric import Connection, Config

affinity_test = "python3 affinity_test.py 3 unpinned"
pin_vcpu = "./affinity_test 0; ./affinity_test 1"

sudo_pass = 'p'
config = Config(overrides={'sudo': {'password': sudo_pass}})
c = fabric.Connection(host='localhost', user='giacomo', port=2222, connect_kwargs={'password': 'p'}, config=config)

with c.cd('shared/simplified-spscq'):
	c.run(affinity_test)

# with c.cd('shared/affinity_test'):
# 	c.run(pin_vcpu)


# c.run('cd shared')
# c.run('ls')
# c.sudo('cd shared; ls', hide='stderr')
# c.run('sudo whoami', pty=True, watchers=[sudopass])

c.close()



# # with cd('/var/www'):
# #     run('ls') # cd /var/www && ls
# #     with cd('website1'):
# #         run('ls') # cd /var/www/website1 && ls