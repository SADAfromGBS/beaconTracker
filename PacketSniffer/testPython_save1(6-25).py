#This App was coded by SiO2 R&E All Rights Reserved.
'''
	App requirements: 
		1. Wireshark PCAP Files
		2. pip3 dpkt install
		3. apt install arping
		4. pip install requests
'''
import os, struct, dpkt, datetime, socket, json, time, calendar, requests
from dpkt.compat import compat_ord

#Collect System MAC and IP address
mac_system_call = ''.join(os.popen('iwconfig | grep "Access Point"').readlines()) #.readlines() returns a list, so we should join them to a string
router_mac_addr = mac_system_call[mac_system_call.find("Access Point")+14:].replace(":", "") #remove semicolons
	
ip_system_call = ''.join(os.popen('curl -4 ifconfig.me').readlines()) #get ip of current env.

print("[SYSTEM] Router Mac Address: ", router_mac_addr)
print("[SYSTEM] Router IP Address: ", ip_system_call)

#path to find files in
path = '.'

def mac_addr(address):
	'''
		Convert a MAC address to a readable/printable string
		Args: address (str) in HEX
		Returns: (string)
	'''
	out_str = ''
	for mac_byte in address:
		out_str += '{:02x}'.format(int(mac_byte))
	return out_str

def inet_to_str(inet):
	'''
		Convert inet object to a string
		Args: inet (inet struct): inet network address
		Returns: (string)
	'''
	#We will try ipV4 and then ipV6
	try:
		return socket.inet_ntop(socket.AF_INET, inet)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, inet)

def send_REST_data(deviceName, deviceMac, routerMac, beaconID=1):
	URL = "https://sada.gbshs.kr/beacontracker/packetListUpload.php"
	PARAMS = {
		'deviceName':deviceName,
		'deviceMac' :deviceMac,
		'routerMac' :routerMac,
		'beaconID'  :beaconID
	}
	r = requests.get(url = URL, params = PARAMS)
	print("[SADA WEB] Uploaded Data to server, got ", r)


#Get all the files in local directory
files = []

def find_all_files():
	for r,d,f in os.walk(path):
		for file in f:
			if '.pcap' in file:
				files.append(os.path.join(r,file))

	'''
		f = open(path,'rb').read()
		for i in f[:10]:
			print('{:02x}'.format(int(i)),end=' ')
		print()
	'''	

def analyze_packets():
	#Iterate over the pcap files found in the directory this program runs in
	file_no = 0
	packet_no = 0
	for path in files:
		time_delta = calendar.timegm(time.gmtime()) - os.path.getmtime(path)
		if(time_delta < 10): #files under 10s from creation may not be finished and thus should be ignored
			continue
		file_no += 1
		packet_no = 0
		print("######\nAnalyzing Packet @: \n" + path + "\n#######\n") 
		#Iterate over the packets captured in the selected pcap file
		try:
			pcap_file = open(path, 'rb')
		except: 
			print("==[ERROR!: FS SYNC FALSE]==")
			continue
			
		for timestamp, buf in dpkt.pcap.Reader(open(path, 'rb')):
			packet_no += 1

			#Print out the timestamp in UTC (of the packet)
			#print('Packet # ', packet_no, ' @ file #', file_no)
			#print('Timestamp: ', str(datetime.datetime.utcfromtimestamp(timestamp)))
			
			#Unpack the Ethernet frame
			eth = dpkt.ethernet.Ethernet(buf)
			#print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

			#Make sure the Ethernet frame contains an IP packet

			if not isinstance(eth.data, dpkt.ip.IP):
				#print('--------------[ARP/MDNS (NonIP)]--------------')
				#for i in buf:
					#print('{:02x}'.format(int(i)),end=' ')
				#print('\n')
				continue
			ip = eth.data
			
			#Pull out fragment information (flags and offset all packed into off field)
			#Utilized Bitmasking to pull the information
			do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
			more_fragments = bool(ip.off & dpkt.ip.IP_MF)
			fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
			
			no_dhcp_cnt = 0
					
			if ip.get_proto(ip.p).__name__ == 'UDP':

				try:
					dhcp_pack = dpkt.dhcp.DHCP(buf)
					if dhcp_pack.pack_opts()[2:4]==b'Sc':
						opts = dhcp_pack.pack_opts()
						#print("--------[Found DHCP packet!]---------")
						#print(opts)
						opts_len = len(opts)
						cur_pos = 4
						is_discovery_packet = False

						while cur_pos <= opts_len:
							
							data_type = opts[cur_pos]
							cur_pos += 1
							data_len = opts[cur_pos]
							cur_pos += 1
							data_payload = opts[cur_pos:cur_pos+data_len]
							client_name = ""
							
							if data_type == 53: #DHCP Message Type
								print("--------[Found DHCP REQUST packet!]---------")
								print("This is a DHCP Message Type!")
								if data_payload[0] == 3: #REQUEST data
									is_discovery_packet = True
									print("This is a valid Discovery Packet")
										
							if data_type == 12 and is_discovery_packet == True: #Host Name
								print("Found User Device Name...")
								for i in data_payload:
									print(chr(int(i)), end='')
									client_name+=(chr(int(i)))	
								print('IP: %s -> %s  (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
								print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
								print('[SADA WEB] Sending Data to server...')
								send_REST_data(client_name, mac_addr(eth.src), router_mac_addr)
								
							
							#print(data_type)
							#for i in data_payload:
							#	print('{:02x}'.format(int(i)), end = ' ')
							#print()
							cur_pos += data_len
				except:
					no_dhcp_cnt += 1

			#Print out the info
			#print('IP: %s -> %s  (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))


		#Analyzed all packets in file, now delete it
	
		try:
			os.remove(path)
		except:
			print("==[FS SYNC DEL ERROR]==")
		print("Deleted", path)


print("======[SCANNING DIR]======")		
find_all_files()
print("======[ANALYZING FILES]======")
analyze_packets()
print('The Program Has Terminated Successfully')

