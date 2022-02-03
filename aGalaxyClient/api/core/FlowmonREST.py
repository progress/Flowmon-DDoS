# This class is here to initiate the connection to the Flowmon
# For now only support authentication and returns the token

import requests
import json
import logging
# To disable warning about unverified HTTPS
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
class FlowmonREST:
	# For the start it needs the following arguments
	# string host : Hostname where we want to connect
	# string user : username we are going to use for connection
	# string pass : User password for connection
	def __init__( self, app ):
		self.hostname = str( app.config.get('REST', 'host') )
		self.username = str( app.config.get('REST', 'user') )
		self.password = str( app.config.get('REST', 'pass') )
		self.token = ''
		if app.config.get('REST', 'verify') == "False":
			self.verify = False
		else:
			self.verify = True
		self.app = app
		self.connect()
	
	# helper to build a good URL	
	def _url( self, path ):
		return "https://" + self.hostname + path
		
	def get_verify( self ):
		return self.verify
	
	# connection method which will open a connection to API of Flowmon
	# bool verify : Tell if the certificate errors should be ignored
	def connect( self ):
		url = '/resources/oauth/token'
		payload = { 'grant_type' : 'password',
					'client_id' : 'invea-tech',
					'username' : self.username,
					'password' : self.password
		}
		
		r = requests.post( self._url(url), data=payload, verify=self.verify )
		
		if r.status_code != 200 :
			self.app.log.error( 'Cannot autheticate to Flowmon: {}'.format( r.status_code ) )
		else:
			self.app.log.info( 'API User successfuly authenticated' )
			
		self.token = r.json()['access_token']
		
	# returns authentication token for the header
	def get_header( self ):
		return { 'Authorization' : 'bearer ' + self.token }

	# returns basic information about the collector
	def get_basicinfo( self ):
		r = requests.get( self._url( '/rest/fcc/device/info' ), headers=self.get_header(), verify=self.get_verify() )
		if r.status_code == 200:
			return r.content
		else:
			self.app.log.error( 'Cannot get information about the device {}: {}'.format(r.status_code, r.content) )
	#end def get_basicinfo( self ):