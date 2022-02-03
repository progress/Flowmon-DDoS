#!/usr/bin/python3.6
# -*- coding: utf-8 -*-
"""
The purpose of this application is to trigger a notification to specified email when needed
=========================================================================================
"""
__author__ = "Jiri Knapek"
__copyright__ = "Copyright 2019, Flowmon Networks"
__credits__ = ["Jiri Knapek"]
__license__ = "GPL"
__version__ = "1.0.0"
__maintainer__ = "Jiri Knapek"
__email__ = "jiri.knapek@flowmon.com"
__status__ = "beta"

from cli.dddalertcli import dddalertcli

# Main method to run the application
def main():
	# start cement app with configuration
	with dddalertcli() as app:
		app.args.add_argument( '-a', '--attack', action='store', dest='attack' )
		app.args.add_argument( '-b', '--body', action='store', dest='body' )
		app.args.add_argument( '-s', '--subject', action='store', dest='subject' )
		app.run()
		app.log.info('Completed')

if __name__ == '__main__':
	# execute only if runs as a script
	main()