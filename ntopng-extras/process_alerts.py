#!/usr/bin/python3

#  ntopng alert notifications shell script to mark Blacklisted Flow alerts as acknowledged

#  Copyright (C) 2024  David King <dave@daveking.com>
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License,
#  version 2, as published by the Free Software Foundation.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License,
#  version 2, along with this program; if not, see 
#  <https://www.gnu.org/licenses/old-licenses/gpl-2.0.html>.

#  ntopng database schema: https://github.com/ntop/ntopng/blob/dev/httpdocs/misc/alert_store_schema.sql
#  REST API doc: http://firewall.localdomain:3000/lua/swagger.lua
#  List of ALERT_IDs: http://firewall.localdomain:3000/lua/defs_overview.lua

import logging
import sys
import json
import requests
import time
import os

#  ntopng API authentication header.  Generate this token in your user 
#  profile on the ntopng instance.
headers = {
    'Authorization': 'Token 3e8211ddfd4c519f8d2dcbcf4198dd7c'
}

#  Change level to DEBUG to get lots of output from the script
log_file = '/tmp/process_alerts.log'
logging.basicConfig(
    filename=log_file, 
    format='%(asctime)s: %(levelname)s: %(message)s', 
    datefmt='%d-%b-%y %H:%M:%S', 
    level=logging.INFO
)

#  We keep a list of the alerts we've missed because they weren't yet  
#  in the alerts DB when we were called.  We retry them on subsequent runs.
missed_alerts_filename = '/tmp/missed_alerts_list.txt'

#  Query the alerts DB, looking for a flow alert that matches the data we
#  are passed.
#
#  There's a timing issue here as the insert of the alert into the DB is 
#  also done by a notification so the alert may not be in the DB yet when
#  we get called and go looking for it.  In that case we'll add it to the
#  list of missed_alerts and reprocess it during a later run.
def getROWID(alert):
    logging.debug('getROWID called')

    params = { 
        "ifid": alert['ifid'], 
        "alert_family": 'flow', 
        "epoch_begin": 0, 
        "epoch_end": int(time.time()),
        "where_clause": 'CLI_IP = \'{}\' AND CLI_PORT = {} AND SRV_IP = \'{}\' AND SRV_PORT = {}'.format(alert['cli_ip'], alert['cli_port'], alert['srv_ip'], alert['srv_port']),
        "maxhits_clause": 100, 
        "order_by_clause": 'ROWID' 
    }
    rsp = requests.get('http://localhost:3000/lua/rest/v2/get/alert/list/alerts.lua', 
        headers=headers, 
        params=params)
    rsp = rsp.json()
    logging.debug(rsp)
    if len(rsp['rsp']) > 0:
        return rsp['rsp'][0]
    return False

#  Mark an alert as "acknowledged"
def acknowledgeAlert(alert):
    logging.debug('acknowledgeAlert called:\n{}'.format(alert))
    #with open('/tmp/{}_before'.format(alert['rowid']), 'w') as f:
    #    f.write(json.dumps(alert, indent=4, sort_keys=True))
    params = {
        'ifid': alert['interface_id'],
        'row_id': alert['rowid']
    }
    rsp = requests.get('http://localhost:3000/lua/rest/v2/acknowledge/flow/alerts.lua', 
        headers=headers, 
        params=params)
    if rsp.status_code == 200:
        logging.debug('Alert acknowledged')
        
        ### Test
        #params = { 
        #    "ifid": alert['interface_id'],          
        #    "alert_family": 'flow', 
        #    "epoch_begin": 0, 
        #    "epoch_end": int(time.time()),
        #    "where_clause": 'ROWID = {}'.format(alert['rowid']),
        #}
        #rsp = requests.get('http://localhost:3000/lua/rest/v2/get/alert/list/alerts.lua', 
        #    headers=headers, 
        #    params=params)
        #rsp = rsp.json()
        #with open('/tmp/{}_after'.format(alert['rowid']), 'w') as f:
        #    f.write(json.dumps(alert, indent=4, sort_keys=True))
        ### End test
        
    else:
        logging.debug('Unable to mark alert as acknowledged:\n{} - {}\n{}'.format(rsp.status_code, rsp.reason, rsp.text))

#  Process the alert string into JSON format and then query the database to get
#  the alert.  If we find the alert, mark the alert as "acknowledged".  If not,
#  then add it to the missed alerts list for later reprocessing when, hopefully,
#  it will have made it into the alerts DB..
def processAlert(alert, missed_alerts_filename):
    try:
        alert_json = json.loads(alert)
    except json.decoder.JSONDecodeError:
        logging.debug('Unable to convert this string into a JSON object:\n{}'.format(alert))
        return
    logging.debug('Alert information in JSON format:\n{}'.format(json.dumps(alert_json, indent=4)))
    logging.debug('Attempting to retrieve this alert from the alerts DB')
    rsp = getROWID(alert_json)
    if rsp:
        acknowledgeAlert(rsp)
    else:
        #  Add this alert to the list of missed alerts
        logging.debug('Unable to retrieve this alert from the DB, adding it to the missed alerts list')
        with open(missed_alerts_filename, 'a') as f:
            f.write('{}\n'.format(alert))

#  We keep a list of the alerts we've missed because they weren't yet  
#  in the alerts DB when we were called.  We retry them on subsequent runs.
def processMissedAlerts(missed_alerts_filename):
    #  Read the file containing the list of previously missed alerts, 
    #  erase the file, and then process each alert in the list
    missed_alerts = []
    try:
        with open(missed_alerts_filename, 'r') as f:
            for alert in f.readlines():
                missed_alerts.append(alert)
        os.unlink(missed_alerts_filename)
    except FileNotFoundError:
        pass
    if len(missed_alerts) > 0:
        logging.debug('Processing {} missed alerts'.format(len(missed_alerts)))
        for alert in missed_alerts:
            logging.debug('Processing missed alert')
            processAlert(alert.rstrip('\n'), missed_alerts_filename)

if __name__ == "__main__":

    try:
        logging.info('script started')

        #  ntopng pipes us a list of alerts via stdin
        if not sys.stdin.isatty():
            alert_data = sys.stdin.readlines()

            #  Process the previously missed alerts saved in missed_alerts_filename
            processMissedAlerts(missed_alerts_filename)

            #  Process the new alert(s) from stdin
            logging.debug('Processing alert piped into script:\n{}'.format(alert_data))
            for alert in alert_data:
                processAlert(alert, missed_alerts_filename)

        logging.debug('script ended')
    except SystemExit:
        pass
    except:
        logging.exception('Unexpected exception', exc_info=True)
    
