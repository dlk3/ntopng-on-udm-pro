#!/bin/bash

ALERT=$(cat)
echo "$ALERT" | jq . >/tmp/sample_script.log

    
