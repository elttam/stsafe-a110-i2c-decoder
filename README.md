
# Logic2 plugin for decoding STSAFE-A110 API messages on the I2C bus

## Installation

There are two options for installation:
1. Install the pluging directly from the Logic app - just search for `STSAFE-A110 API` in Extensions 
2. Clone this repo and load this extension by going to `Extensions` -> `Load existing extension` and selecting the `extension.json` from the `stsafea110` directory within this repo

## Usage

Once the extension is loaded in Logic, in the Analyzers section add it by clicking on the `+` button and selecting `STSAFE-A110 API`. 
No additional setup is needed, the plugin will stream the decoded messages to the `Terminal` view of the Data section in Analyzers.

## Limitations

- Currently the plugin can only decode the following commands and their responses:
	- `STSAFEA_CMD_QUERY`
	- `STSAFEA_CMD_GENERATE_KEY`
- Additionally, if the message header contains a CMAC, the plugin won't be able to identify the command code.
