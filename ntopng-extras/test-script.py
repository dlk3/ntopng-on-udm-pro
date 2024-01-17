#!/usr/bin/python

import logging
import os
import sys
import json

logging.basicConfig(
    format='%(levelname)s: %(message)s', 
    level=logging.INFO
)

try:
    fn = os.path.basename(__file__)
    logging.info('{} was called to process an alert'.format(fn))

    #  ntopng pipes us a list of alerts via stdin
    if sys.stdin.isatty():
        logging.error('No data was piped in via STDIN')
    else:
        alert_data = sys.stdin.readlines()
        for alert in alert_data:
            try:
                alert_json = json.loads(alert)
            except json.decoder.JSONDecodeError:
                logging.error('Unable to convert alert text string into a JSON object:\n{}'.format(alert))
                exit()
            logging.debug('Alert details in JSON format:\n{}'.format(json.dumps(alert_json, indent=4)))
except SystemExit:
    pass
except:
    logging.exception('Unexpected exception', exc_info=True)
    
