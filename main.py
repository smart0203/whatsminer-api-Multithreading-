import threading
import re

from whatsminer import WhatsminerAccessToken, WhatsminerAPI

asics = [
    ("1.2.4.0xf0", "adminPassword"),                  # tuple with IP and adminPassword i.e. ("1.2.3.4" ,"admin")
    ("1.2.3.4", "adminPassword"),
    ("1.2.3.4", "adminPassword")
]

commands = {
    "command": "poweroff",
    "additional_params": {},
    "conditional": { 
        "type": "summary",
        "item": "Temperature",
        "operator": ">",
        "value": "78.0"
    }
},

def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            )
          ){0,3}
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None

def execCommand(asic: tuple, command: dict):
    
    if is_valid_ipv4(asic[0]):
        try:
            token = WhatsminerAccessToken(
                ip_address = asic[0],
                admin_password = asic[1]
            )
            
            conditional = False
            if bool(command["conditional"]):
                json_summary = WhatsminerAPI.get_read_only_info(
                    access_token = token,
                    cmd = command["conditional"]["type"]
                )
                
                conditionExp = "json_summary[{type}][0][{item}]{operator}{value}".format(
                    type = command["conditional"]["type"],
                    item = command["conditional"]["item"],
                    operator = command["conditional"]["operator"],
                    value = command["conditional"]["value"]
                )

                if eval(conditionExp):
                    conditional = True
            else:
                conditional = True
                
            if conditional:
                WhatsminerAPI.exec_command(
                    access_token = token,
                    cmd = command["command"],
                    additional_params = command["additional_params"]
                )
        except Exception as e:
            print("The exception has been Handled in the Main, Details of the Exception are:\n", e)
    else:
        print("IP Address is invalid.")

for asic in asics:
    threading.Thread(execCommand(asic, commands)).start()