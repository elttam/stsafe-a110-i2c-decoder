from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

cmdCodes = {
    0: "STSAFEA_CMD_ECHO",
    1: "STSAFEA_CMD_RESET",
    2: "STSAFEA_CMD_GENERATE_RANDOM",
    3: "STSAFEA_CMD_START_SESSION",
    4: "STSAFEA_CMD_DECREMENT",
    5: "STSAFEA_CMD_READ",
    6: "STSAFEA_CMD_UPDATE",
    12: "STSAFEA_CMD_DELETE_KEY",
    13: "STSAFEA_CMD_HIBERNATE",
    14: "STSAFEA_CMD_WRAP_LOCAL_ENVELOPE",
    15: "STSAFEA_CMD_UNWRAP_LOCAL_ENVELOPE",
    16: "STSAFEA_CMD_PUT_ATTRIBUTE",
    17: "STSAFEA_CMD_GENERATE_KEY",
    20: "STSAFEA_CMD_QUERY",
    22: "STSAFEA_CMD_GENERATE_SIGNATURE",
    23: "STSAFEA_CMD_VERIFY_SIGNATURE",
    24: "STSAFEA_CMD_ESTABLISH_KEY",
    26: "STSAFEA_CMD_VERIFY_PASSWORD"
}

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    lastCommand = 0
    
    decodedPacket = {
        "address": {
            "address": "0x00",
            "read": False
        },
        "data": []
    }
    prevFrame = ""

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'mytype': {
            'format': 'Output type: {{type}}, Input type: {{data.input_type}}'
        }
    }

    def __init__(self):
        
        self.prevFrame = ""
        
    def clearFrame(self):

        self.decodedPacket = {
            "address": {
                "address": "0x00",
                "read": False

            },  
            "data": []
        }
        
    def endFrame(self, frametype):

        if frametype == 'stop':
            return True
        else:
            return False

    def decode(self, frame: AnalyzerFrame):
          
        if frame.type == 'address':
            self.decodedPacket['address']['address'] = frame.data['address'].hex()
            self.decodedPacket['address']['read'] = frame.data['read']
           # print('{} operation started at address 0x{}'.format(("Read" if frame.data['read'] == True else "Write"), self.decodedPacket['address']['address']))
        
        if frame.type == 'data':
            if not self.decodedPacket['address']['read']:
                if self.prevFrame == 'address':
                    try: 
                        self.lastCommand = int(frame.data['data'].hex(), 16)
                        print('{} command sent'.format(cmdCodes[self.lastCommand]))
                    except:
                        # not really unkown, might just include a C-MAC
                        print("Unknown or CMAC'd command code")
            self.decodedPacket['data'].append(frame.data['data'].hex())
        
        self.prevFrame = frame.type
        if self.endFrame(frame.type):
            if not self.decodedPacket['address']['read']:
                if self.decodedPacket['data'][0] == '14':
                    print('STSAFE_TAG_HOST_KEY_SLOT: 0x{}'.format(self.decodedPacket['data'][1]))
                    print('Command MAC: {}'.format(self.decodedPacket['data'][2:]))
                elif self.decodedPacket['data'][0] == '11':
                    print('STSAFEA_TAG_PRIVATE_KEY_SLOT: {}'.format(self.decodedPacket['data'][1]))
                    print('InKeySlotNum: {}'.format(self.decodedPacket['data'][2]))
                    print('STSAFE_KEY_SLOT: {}'.format(self.decodedPacket['data'][3:5]))
                    print('Mode of operation masks: {}'.format(self.decodedPacket['data'][5:7]))
                    print('STSAFEA_GET_ECC_CURVE_OID_LEN (Curve length): {}'.format(self.decodedPacket['data'][7:9]))
                    print('STSAFEA_GET_ECC_CURVE_OID (Curve ID): {}'.format(self.decodedPacket['data'][9:18]))
                    print('Command MAC: {}'.format(self.decodedPacket['data'][19:25]))
            elif self.decodedPacket['address']['read']:
                # print(self.lastCommand)
                if self.lastCommand == 20:
                    if self.decodedPacket['data'][0] == '00':
                        print("Return code is: STSAFEA_OK")
                        print("Response length: {}".format(self.decodedPacket['data'][2]))
                        print("HostKeyPresenceFlag: {}".format(self.decodedPacket['data'][3]))
                        print("Response MAC: {}".format(self.decodedPacket['data'][4:6]))
                elif self.lastCommand == 17:
                    if self.decodedPacket['data'][0] == '00':
                        print("Return code is: STSAFEA_OK")
                        print("Response length: {}".format(self.decodedPacket['data'][2]))
                        print("pOutPointRepresentationId: {}".format(self.decodedPacket['data'][3]))
                        print("Public key X length: {}".format(self.decodedPacket['data'][4:6]))
                        print("Public key X: {}".format(self.decodedPacket['data'][4:53]))
                        print("Public key Y length: {}".format(self.decodedPacket['data'][53:55]))
                        print("Public key Y: {}".format(self.decodedPacket['data'][55:104]))
                        print("Response MAC: {}".format(self.decodedPacket['data'][104:107]))

            print(self.decodedPacket['data'])
            print("\n") 
            self.clearFrame()
        
        # Return the data frame itself
        return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
            'input_type': frame.type
        })
