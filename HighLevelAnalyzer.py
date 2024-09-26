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
    my_string_setting = StringSetting()
    my_number_setting = NumberSetting(min_value=0, max_value=100)
    my_choices_setting = ChoicesSetting(choices=('A', 'B'))
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
        
        if frame.type == 'data':
            if not self.decodedPacket['address']['read']:
                if self.prevFrame == 'address':
                    try: 
                        self.lastCommand = int(frame.data['data'].hex(), 16)
                        print('[CMD] {} command sent'.format(cmdCodes[self.lastCommand]))
                    except:
                        print("[CMD] Unknown or CMAC'd command code")
            self.decodedPacket['data'].append(frame.data['data'].hex())
        
        self.prevFrame = frame.type

        # parse commands sent to STSAFE
        if self.endFrame(frame.type):
            if not self.decodedPacket['address']['read']:
                command_length = len(self.decodedPacket['data'])

                # STSAFEA_CMD_QUERY command
                if self.decodedPacket['data'][0] == '14':
                    print('[CMD] STSAFE_TAG_HOST_KEY_SLOT: 0x{}'.format(self.decodedPacket['data'][1]))
                    print('[CMD] Command MAC: {}'.format(self.decodedPacket['data'][2:]))
                    print("\n") 
                
                # 
                elif self.decodedPacket['data'][0] == '11':
                    print('[CMD] STSAFEA_TAG_PRIVATE_KEY_SLOT: {}'.format(self.decodedPacket['data'][1]))
                    print('[CMD] InKeySlotNum: {}'.format(self.decodedPacket['data'][2]))
                    print('[CMD] STSAFE_KEY_SLOT: {}'.format(self.decodedPacket['data'][3:5]))
                    print('[CMD] Mode of operation masks: {}'.format(self.decodedPacket['data'][5:7]))
                    print('[CMD] STSAFEA_GET_ECC_CURVE_OID_LEN (Curve length): {}'.format(self.decodedPacket['data'][7:9]))
                    print('[CMD] STSAFEA_GET_ECC_CURVE_OID (Curve ID): {}'.format(self.decodedPacket['data'][9:18]))
                    print('[CMD] Command MAC: {}'.format(self.decodedPacket['data'][19:25]))
                    print("\n") 
                
                # STSAFEA_CMD_READ command
                if self.decodedPacket['data'][0] == '05':
                    if self.decodedPacket['data'][1] == 1:
                        print('[CMD] Change access condition indicator: true')
                        # TODO: calculate the new AC
                    else:
                        print('[CMD] Change access condition indicator: false')
                    print('[CMD] Zone index to read from: {}'.format(self.decodedPacket['data'][2]))
                    print('[CMD] Zone offset: {}'.format(self.decodedPacket['data'][3:4]))
                    # the actual response lenght will be +2 bytes due to a counter I think
                    print('[CMD] Expected response length: {} bytes'.format(int(self.decodedPacket['data'][6], 16)))
                    print('[CMD] Command MAC: {}'.format(self.decodedPacket['data'][7:]))
                    print("\n") 
                
                # STSAFEA_CMD_GENERATE_RANDOM command
                elif self.decodedPacket['data'][0] == '02':
                    print('[CMD] Random bytes type (only with STSAFE-A100): {}'.format(self.decodedPacket['data'][1]))
                    print('[CMD] Expected response length: {} bytes'.format(int(self.decodedPacket['data'][2], 16)))
                    print('[CMD] Command MAC: {}'.format(self.decodedPacket['data'][3:]))
                    print("\n") 
                
                # STSAFEA_CMD_GENERATE_SIGNATURE command
                if self.decodedPacket['data'][0] == '16':
                    print('[CMD] Private Key Table Slot Number: {}'.format(self.decodedPacket['data'][1]))
                    if self.decodedPacket['data'][1] == '00':
                        print('[CMD] Digest type: SHA-256')
                    elif self.decodedPacket['data'][1] == '01':
                        print('[CMD] Digest type: SHA-384')
                    else:
                        print('[CMD] Unknown digest type')
                    print('[CMD] Expected signature size: {} bytes'.format(int(self.decodedPacket['data'][3], 16)))
                    print('[CMD] Digest: {}'.format(self.decodedPacket['data'][4:command_length-2]))
                    print('[CMD] Command MAC: {}'.format(self.decodedPacket['data'][command_length-2:]))
                    print("\n")

                # default case, print the full command if we don't yet support it  
                #else:
                #    print(self.decodedPacket['data'])
                #    print("\n")
            
            # parse responses from STSAFE
            elif self.decodedPacket['address']['read']:
                resp_length = len(self.decodedPacket['data'])
                
                # STSAFEA_CMD_QUERY response
                if self.lastCommand == 20:
                    if self.decodedPacket['data'][0] == '00':
                        print("[RESP] Return code is: STSAFEA_OK")
                        print("[RESP] Response length: {} bytes".format(int(self.decodedPacket['data'][2], 16)-2))
                        print("[RESP] HostKeyPresenceFlag: {}".format(self.decodedPacket['data'][3]))
                        print("[RESP] Response MAC: {}".format(self.decodedPacket['data'][4:6]))
                        print("\n") 
                    else:
                        print("[RESP] Error returned from STSAFE with error code: {}".format(self.decodedPacket['data'][0]))
                        print("\n") 
                
                # STSAFEA_CMD_GENERATE_KEY response
                elif self.lastCommand == 17:
                    if self.decodedPacket['data'][0] == '00':
                        print("[RESP] Return code is: STSAFEA_OK")
                        print("[RESP] Response length: {} bytes".format(int(self.decodedPacket['data'][2], 16)-2))
                        print("[RESP] pOutPointRepresentationId: {}".format(self.decodedPacket['data'][3]))
                        print("[RESP] Public key X length: {}".format(self.decodedPacket['data'][4:6]))
                        print("[RESP] Public key X: {}".format(self.decodedPacket['data'][4:53]))
                        print("[RESP] Public key Y length: {}".format(self.decodedPacket['data'][53:55]))
                        print("[RESP] Public key Y: {}".format(self.decodedPacket['data'][55:104]))
                        print("[RESP] Response MAC: {}".format(self.decodedPacket['data'][104:107]))
                        print("\n")
                    else:
                        print("[RESP] Error returned from STSAFE with error code: {}".format(self.decodedPacket['data'][0]))
                        print("\n") 
                
                # STSAFEA_CMD_READ response
                if self.lastCommand == 5:
                    if self.decodedPacket['data'][0] == '00':
                        print("[RESP] Return code is: STSAFEA_OK")
                        print("[RESP] Response length: {} bytes".format(int(self.decodedPacket['data'][2], 16)-2))
                        print("[RESP] Read data from STSAFE: {}".format(self.decodedPacket['data'][3:resp_length-2]))
                        print("[RESP] Response MAC: {}".format(self.decodedPacket['data'][resp_length-2:]))
                        print("\n") 
                    else:
                        print("[RESP] Error returned from STSAFE with error code: {}".format(self.decodedPacket['data'][0]))
                        print("\n") 
                        
                
                # STSAFEA_CMD_GENERATE_RANDOM response
                elif self.lastCommand == 2:
                    if self.decodedPacket['data'][0] == '00':
                        print("[RESP] Return code is: STSAFEA_OK")
                        print("[RESP] Response length: {} bytes".format(int(self.decodedPacket['data'][2], 16)-2))
                        print("[RESP] Generated random data: {}".format(self.decodedPacket['data'][3:resp_length-2]))
                        print("[RESP] Response MAC: {}".format(self.decodedPacket['data'][resp_length-2:]))
                        print("\n") 
                    else:
                        print("[RESP] Error returned from STSAFE with error code: {}".format(self.decodedPacket['data'][0]))
                        print("\n") 
                
                 # STSAFEA_CMD_GENERATE_SIGNATURE response
                if self.lastCommand == 22:
                    if self.decodedPacket['data'][0] == '00':
                        print("[RESP] Return code is: STSAFEA_OK")
                        print("[RESP] Response length: {} bytes".format(int(self.decodedPacket['data'][2], 16)-2))
                        print("[RESP] R MPI Signature length: {}".format(int(self.decodedPacket['data'][4], 16)))
                        print("[RESP] R MPI Signature: {}".format(self.decodedPacket['data'][5:37]))
                        print("[RESP] S MPI Signature length: {}".format(int(self.decodedPacket['data'][38], 16)))
                        print("[RESP] S MPI Signature: {}".format(self.decodedPacket['data'][39:71]))
                        print("[RESP] Response MAC: {}".format(self.decodedPacket['data'][resp_length-2:]))
                        print("\n") 
                    else:
                        print("[RESP] Error returned from STSAFE with error code: {}".format(self.decodedPacket['data'][0]))
                        print("\n") 
                
                # print the full response if we don't yet support it  
                #else:
                #    print(self.decodedPacket['data'])
                #    print("\n") 


            self.clearFrame()
        
        # Return the data frame itself
        return AnalyzerFrame('mytype', frame.start_time, frame.end_time, {
            'input_type': frame.type
        })
