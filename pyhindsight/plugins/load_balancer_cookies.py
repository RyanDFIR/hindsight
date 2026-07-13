###################################################################################################
#
# load_balancer_cookies.py
#   Decodes persistence cookies set by load balancers - currently NetScaler and BIG-IP.
#   These cookies can reveal internal IPs and other configuration information.
#
# References:
#   "Netscaler-Cookie-Decryptor" by Adam Maxwell (https://github.com/catalyst256/Netscaler-Cookie-Decryptor)
#   "Netscalers: Making sense of the cookie" by Adam Maxwell (https://web.archive.org/web/20200509063851/https://itgeekchronicles.co.uk/category/netscaler/)
#   "bigip_cookie_decoder.py" by z0mbiehunt3r (https://github.com/trietptm/loadbalancer-finder/blob/master/
#      loadbalancer-finder/src/methods/bigip_cookie_decoder.py)
#
# Plugin Author: Ryan Benson (ryan@hindsig.ht), based on work by:
#   Adam Maxwell (catalyst256@gmail.com)
#   Alejandro Nolla Blanco (alejandro.nolla@gmail.com)
#   Daniel Grootveld (danielg75@gmail.com)
#
###################################################################################################

# Config
friendlyName = "Load Balancer Cookie Decoder"
description = "Decodes persistence cookies set by load balancers"
artifactTypes = ('cookie',)  # Artifacts that this plugin processes
remoteLookups = 0  # if this plugin will query online sources/databases
browser = []  # browsers that the plugin applies to; empty list if no restrictions
browserVersion = []  # browser versions that the plugin applies to; empty list if no restrictions
version = "20200213"  # version of the plugin (use the date)
parsedItems = 0  # count of items that the plugin parsed; initialized to 0


def plugin(analysis_session=None):
    import re
    import struct
    if analysis_session is None:
        return

    def nsc_decode_service_name(service_name):
        """Decrypts the Caesar Substitution Cipher Encryption used on the NetScaler Cookie Name"""
        # This decrypts the Caesar Substitution Cipher Encryption used on the NetScaler Cookie Name
        service_name_s = str(service_name)
        trans = str.maketrans('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ',
                              'zabcdefghijklmnopqrstuvwxyZABCDEFGHIJKLMNOPQRSTUVWXY')
        real_name = service_name_s.translate(trans)
        return real_name

    def nsc_decode_server_ip(server_ip):
        """Decrypts the XOR encryption used for the NetScaler Server IP"""
        ip_key = 0x03081e11
        decoded_ip = hex(server_ip ^ ip_key)
        t = decoded_ip[2:10].zfill(8)
        real_ip = '.'.join(str(int(i, 16)) for i in ([t[i:i + 2] for i in range(0, len(t), 2)]))
        return real_ip

    def nsc_decode_server_port(server_port):
        """Decrypts the XOR encryption used on the NetScaler Server Port"""
        port_key = 0x3630
        decoded_port = server_port ^ port_key  # No need to convert to hex since an integer will do for port
        real_port = str(decoded_port)
        return real_port

    def big_ip_decode_cookie(encoded_string):
        (host, port, end) = encoded_string.split('.')

        # Hexadecimal details:
        (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]
        (v) = [ord(j) for j in struct.pack("<H", int(port))]
        p = "0x%02X%02X" % (v[0], v[1])
        return "{}.{}.{}.{}".format(a, b, c, d), int(p, 16)

    # NetScaler regexes
    nsc_cookie_name_re = re.compile(r'^NSC_([a-zA-Z0-9\-_\.\*\+]*)')
    nsc_cookie_value_re = re.compile(r'[0-9a-f]{8}([0-9a-f]{8}).{24}([0-9a-f]{4})$')

    # BIG-IP regex
    big_ip_cookie_value_re = re.compile(r'^\d{8,10}\.\d{1,5}\.\d{4}$')

    # Setting up our return variable
    global parsedItems
    parsedItems = 0

    # For each item that Hindsight has parsed,
    for item in analysis_session.parsed_artifacts:
        # if the row if of a supported type for this plugin, and
        if item.row_type.startswith(artifactTypes):
            # if there isn't already an interpretation,
            if item.interpretation is None:
                # check if the cookie's name matches the NetScaler format, and
                nsc_cookie_name_m = re.search(nsc_cookie_name_re, item.name)

                # check if the cookie's value matches the BIG-IP format.
                bigip_cookie_value_m = re.match(big_ip_cookie_value_re, item.value)

                # If it matches the NetScaler regex,
                if nsc_cookie_name_m:
                    # set the item's interpretation to be the decoded name of the service.
                    item.interpretation = "Service Name: {} "\
                        .format(nsc_decode_service_name(nsc_cookie_name_m.group(1)))

                    # Now if the value matches our regex,
                    cookie_value_m = re.search(nsc_cookie_value_re, item.value)
                    if cookie_value_m:
                        # decode the server IP and port and add it to the item's interpretation.
                        item.interpretation += "| Server IP: {} | Server Port: {} "\
                            .format(nsc_decode_server_ip(int(cookie_value_m.group(1), 16)),
                                    nsc_decode_server_port(int(cookie_value_m.group(2), 16)))

                    # Add the plugin name to the end of the new interpretation.
                    item.interpretation += "[NetScaler Cookie]"

                    # Increment the count of parsed items
                    parsedItems += 1

                # If it matches the BIG-IP regex,
                elif bigip_cookie_value_m:
                    try:
                        # set the item's interpretation to be the decoded values.
                        item.interpretation = "Server IP: {} | Server Port: {} [BIG-IP Cookie]"\
                            .format(*big_ip_decode_cookie(bigip_cookie_value_m.group(0)))
                    except:
                        pass

                    # Increment the count of parsed items
                    parsedItems += 1

    # Lastly, a count of parsed items with a description of what the plugin did
    return "%s cookies parsed" % parsedItems
