from core.FlowmonDDD import FlowmonDDD
from core.FlowmonREST import FlowmonREST
from cement.core.foundation import CementApp
from cement.core.controller import CementBaseController, expose
from cement.core import backend
from datetime import datetime
import json
import subprocess

# define CLI controller
class cliBase(CementBaseController):
	class Meta:
		label = 'base'
		description = "This application is to send notification by email in DDD"
		epilog = "It is curently in beta testing phase"

	@expose(hide=True, aliases=['run'] )
	def default(self):
		self.app.log.info( 'No action specified. Check -h if you need some assitance' )

	@expose( help="send the email for alert" )
	def send(self):
		if self.app.pargs.attack is not None:
			self.app.log.info( 'Sending the email now')
			client = FlowmonREST( self.app )
			device = client.get_basicinfo()
			rest = FlowmonDDD( self.app, client )
			attack = rest.get_attack( self.app.pargs.attack )
			segment_id = str( json.loads( attack )['segment']['id'] )
			segment = rest.get_segment( segment_id )
			alert = rest.get_segment_alert( segment_id )
			send = str( json.loads( alert )['sendEmail'] )
			mail = str( json.loads( alert )['email'] )
			template = str ( json.loads( alert )['template']['id'] )
			full_temp = rest.get_template( template )
			devname = str( json.loads( device )['deviceName'] )
			subject = str( json.loads( full_temp )['subject'] )
			body = str( json.loads( full_temp )['body'] )
			method = str( json.loads( attack )['attackDetection'] )
			# replace the strings from template in subject
			subject = subject.replace( "%DEVICE", devname )
			subject = subject.replace( "%SEGMENT", str( json.loads( attack )['segment']['name'] ) )
			subject = subject.replace( "%EVENT", str( json.loads( attack )['status']['id'] ) )
			subject = subject.replace( "%TIME", str( datetime.now() ) )
			subject = subject.replace( "%SUBNETS", str( json.loads( segment )['subnets'] ) )
			subject = subject.replace( "%METHODS", method )
			subject = subject.replace( "%ATTACK_SIGNATURE", str( json.loads( attack )['attackSignature'] ) ) 
			subject = subject.replace( "%ATTACK_ID", str( json.loads( attack )['id'] )  )
			# and also in body of email
			body = body.replace( "%DEVICE", devname )
			body = body.replace( "%SEGMENT", str( json.loads( attack )['segment']['name'] ) )
			body = body.replace( "%EVENT", str( json.loads( attack )['status']['id'] ) )
			body = body.replace( "%TIME", str( datetime.now() ) )
			body = body.replace( "%SUBNETS", str( json.loads( segment )['subnets'] ) )
			body = body.replace( "%METHODS", method )
			body = body.replace( "%ATTACK_SIGNATURE", str( json.loads( attack )['attackSignature'] ) ) 
			body = body.replace( "%ATTACK_ID", str( json.loads( attack )['id'] )  )
			if send == 'false':
				self.app.log.debug( 'Notification handled by DDD, nothing to do' )
			else:
				if mail != "":
					self.app.log.debug( 'Sending email to {} by {}'.format(mail, devname) )
					command = '/usr/bin/php /var/www/shtml/index.php Cli:SendEmail -body="{}" -to="{}" -subject="{}"'.format( body, mail, subject )
					try:
						subprocess.run( [command], shell=True )
					except OSError as err:
						self.app.log.error('Could not run file import', __name__)
						self.app.log.debug('OS error: {0}'.format(err), __name__)
						return False
					except SubprocessError as err:
						self.app.log.error('Could not run file import', __name__)
						self.app.log.debug('Subprocess error: {0}'.format(err), __name__)
						return False
					
				else:
					self.app.log.info( 'No email configured at {}!'.format(devname) )
		else:
			self.app.log.error( 'You need to specify attack ID.' )

class dddalertcli(CementApp):
	class Meta:
		label = 'dddalert'
		base_controller = cliBase
		config_files = ['./config.ini']