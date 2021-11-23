# FortiGate-Security-Feature-Identifier-Tool
A tool to assist administrators with identifying the security features enabled across a FortiGate estate.

The tool relies on manual input of FortiGate details or a config file 'config.ini' containing an entry for each FortiGate to analyse.

The config file format is defined as:
```
[FortiGateName]
address=<FortiGate address>
api_key=<FortiGate API key>
port=<FortiGate HTTPS port>
```

Each FortiGate entry must have a unique name, i.e. Hostname.

It will use a series of API calls to each FortiGate to gather the necessary image, which can be a very large amount on larger installations.

Once completed it will output the results of the analysis to the screen, and save the results to a CSV file: security_features.csv
