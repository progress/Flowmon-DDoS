from core.FlowmonREST import FlowmonREST
import requests
import logging
import json

class FlowmonDDD:
	def __init__( self, app, rest ):
		self.rest = rest
		self.app = app

	# Return information about Segment
	# int id ID of segment we want to get
	def get_segment( self, id ):
		r = requests.get( self.rest._url( '/rest/iad/segments/{}'.format(id) ), headers=self.rest.get_header(), verify=self.rest.get_verify() )
		if r.status_code == 200:
			return r.content
		else:
			self.app.log.error( 'Cannot get information about segment {}: {} - {}'.format(id, r.status_code, r.content) )

	# Return information about alert configuration of specific segment
	# int id ID of segment
	def get_segment_alert( self, id ):
		r = requests.get( self.rest._url( '/rest/iad/segments/{}'.format(id) ), headers=self.rest.get_header(), verify=self.rest.get_verify() )
		if r.status_code == 200:
			alert = json.loads( r.content )['measures']['alert']
			alert = str(alert)
			if 'None' == alert:
				self.app.log.info( 'No alerting configured for the segment' )
			else:
				alertId = str( json.loads(r.content)['measures']['alert']['id'] )

				return self.get_alert( alertId )
		else:
			self.app.log.error( 'Cannot get information about segment {}: {} - {}'.format(id, r.status_code, r.content) )

	# Return alert configuration
	def get_alert( self, id ):
		r = requests.get( self.rest._url( '/rest/iad/alerts/{}'.format(id) ), headers=self.rest.get_header(), verify=self.rest.get_verify() )
		if r.status_code == 200:
			return r.content
		else:
			self.app.log.error( 'Cannot get information about alert {}: {} - {}'.format(id, r.status_code, r.content) )
	#end def get_alert( self, id ):

	# Get specific email template
	def get_template( self, id ):
		r = requests.get( self.rest._url( '/rest/iad/email-templates/{}'.format(id) ), headers=self.rest.get_header(), verify=self.rest.get_verify() )

		if r.status_code == 200:
			return r.content
		else:
			self.app.log.error( 'Cannot get email template {}: {} - {}'.format(id, r.status_code, r.content) )
	#end get_template( self, id ):

	# This method returns Segment ID fo specific Attack ID
	#
	def get_attack_segment( self, id ):
		r = requests.get( self.rest._url( '/rest/iad/attacks/{}'.format(id) ), headers=self.rest.get_header(), verify=self.rest.get_verify() )
		if r.status_code == 200:
			segment = json.loads( r.content )['segment']['id']
			return str( segment )
		else:
			self.app.log.error( 'Cannot get information about attack {}: {} - {}'.format(id, r.status_code, r.content) )
	#end def get_attack_segment( self, id ):

	# This method returns Segment ID fo specific Attack ID
	#
	def get_attack( self, id ):
		r = requests.get( self.rest._url( '/rest/iad/attacks/{}'.format(id) ), headers=self.rest.get_header(), verify=self.rest.get_verify() )
		if r.status_code == 200:
			return r.content
		else:
			self.app.log.error( 'Cannot get information about attack {}: {} - {}'.format(id, r.status_code, r.content) )
	#end def get_attack_segment( self, id ):


