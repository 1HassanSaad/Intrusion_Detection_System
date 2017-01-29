import socket,struct,binascii,time,datetime

sock_created = False
sniffer_socket = 0
num = 0
retn_data = {'num':'',
			'time':'',
			'ether_type':'',
			'proto':'',
			'src_mac':'',
			'dst_mac':'',
			'src_ip':'',
			'src_port':'',
			'dst_ip':'',
			'dst_port':'',
			'pure_data':'',
			'total_data':''
			}

#get-local-ip#
def get_local_ip():
	try:
		tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		tmp.connect(('google.com', 0))
		LOCAL_IP = tmp.getsockname()[0]
		tmp.close()
	except:
		print "Internet Connection Fails : Using Destination IP as 127.0.0.1"
		LOCAL_IP = "127.0.0.1"
	return LOCAL_IP

def clear():
		global retn_data
		retn_data['time'] = ''
		retn_data['ether_type'] = ''
		retn_data['proto'] = ''
		retn_data['src_mac'] = ''
		retn_data['dst_mac'] = ''
		retn_data['src_ip'] = ''
		retn_data['src_port'] = ''
		retn_data['dst_ip'] = ''
		retn_data['dst_port'] = ''
		retn_data['pure_data'] = ''
		retn_data['total_data'] = ''
		return

def analyze_ARP_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data","a")
		arp_hdr = struct.unpack("!1H1H1s1s2s6s4s6s4s",recv_data[:28])
		hard_type=arp_hdr[0]
		proto_type = arp_hdr[1]
		hard_addr = binascii.hexlify(arp_hdr[2]) 
		proto_addr = binascii.hexlify(arp_hdr[3]) 
		operation_code = binascii.hexlify(arp_hdr[4])
		src_mac = binascii.hexlify(arp_hdr[5])
		src_IP = socket.inet_ntoa(arp_hdr[6])
		dst_mac = binascii.hexlify(arp_hdr[7])
		dst_IP =  socket.inet_ntoa(arp_hdr[8])

		file_data.write("|==========ARP HEADER==========|<br>")
		file_data.write("hard type = %s <br>" %hard_type)
		file_data.write("protocol type = %s <br>"%hex(proto_type))
		file_data.write("hardware address = %s <br>" %int(hard_addr))
		file_data.write("protocol address = %s <br>" %int(proto_addr))
		file_data.write("operation code = %s <br>" %int(operation_code))
		file_data.write("source mac = %s:%s:%s:%s:%s:%s <br>" %(src_mac[0:2],src_mac[2:4],src_mac[4:6],src_mac[6:8],src_mac[8:10],src_mac[10:12]))
		file_data.write("source ip = %s <br>" %src_IP)
		file_data.write("destination mac =  %s:%s:%s:%s:%s:%s <br>" %(dst_mac[0:2],dst_mac[2:4],dst_mac[4:6],dst_mac[6:8],dst_mac[8:10],dst_mac[10:12]))
		file_data.write("destination ip = %s <br>" %dst_IP)
		file_data.close()
		
		data = recv_data[28:]
		retn_data['proto'] = "ARP"
		return data

def analyze_RDP_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data",a)
		rdp_hdr = struct.unpack("!2B2BH3I",recv_data[:18])
		flages=rdp_hdr[0]
		headerlen=rdp_hdr[1]
		src_port=rdp_hdr[2]
		dst_port=rdp_hdr[3]
		sec_nu=rdp_hdr[4]
		ack_nu=rdp_hdr[5]
		check=rdp_hdr[6]       

		file_data.write("|==========RDP HEADER==========|<br>")
		file_data.write("flages = %hu <br>" %flages)
		file_data.write("header length = %hu <br>"%headerlen)
		file_data.write("source port = %hu <br>" %src_port)
		file_data.write("destination port = %hu <br>" %dst_port)
		file_data.write("sequence number = %hu <br>" %sec_nu)
		file_data.write("acknowledge number = %hu <br>" %ack_nu)
		file_data.write("checksum = %hu <br>" %check) 
		file_data.close()
		
		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		data = recv_data[18:]
		return data

def analyze_DCCP_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data","a")
		dccp_hdr = struct.unpack("!4HI",recv_data[:12])
		src_port = dccp_hdr[0]
		dst_port = dccp_hdr[1]
		dataofset = dccp_hdr[2] >> 8
		CCVal = dccp_hdr[2] & 0xf0
		CsCov = dccp_hdr[2] & 0x0f
		check = dccp_hdr[3]
		res = dccp_hdr[4] >> 29
		typee = dccp_hdr[4] & 0x1E000000
		x = dccp_hdr[4] & 00001000000 
		receve = dccp_hdr[4] & 0xff0000
		if x == 1:
		     	sequ_nu = dccp_hdr[4] & 0x00ffff

		file_data.write("|==========DCCP HEADER==========|<br>")
		file_data.write("source port = %hu <br>" %src_port)
		file_data.write("destination port = %hu <br>"%des_port)
		file_data.write("data offset = %hu <br>" %dataofset)
		file_data.write("ccval = %hu <br>" %CCVal)
		file_data.write("cscov = %hu <br>" %CsCov)
		file_data.write("check = %hu <br>" %check)
		file_data.write("result = %hu <br>" %res)
		file_data.write("type = %hu <br>" %typee)
		file_data.write("x = %hu <br>" %x)
		file_data.write("receve: "+str(receve)+"<br>")
		file_data.close()

		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		data = recv_data[12:]
		return data

def analyze_igmp_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data","a")
		icgp_hdr=struct.unpack("!2H4s",recv_data[:8])
		ver= icgp_hdr[0] >> 12
		typee= icgp_hdr[0] & 0x0f00
		unused= icgp_hdr[0] & 0xff
		cucksum = icgp_hdr[1] 
		group_addr = socket.inet_ntoa(icgp_hdr[2])
		
		file_data.write("|==========IGMP HEADER==========|<br>")
		file_data.write("version = %hu <br>" %ver) 
		file_data.write("type = %hu <br>"%typee)
		file_data.write("unused = %hu <br>" %unused)
		file_data.write("cucksum = %hu <br>" %cucksum)
		file_data.write("group address = %s <br>" %group_addr)
		file_data.close() 
		data = recv_data[8:]
		return data

def analyze_icmp_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data","a")
		icmp_hdr  = struct.unpack("!1s1s",recv_data[:2])
		typee = binascii.hexlify(icmp_hdr[0])
		code = binascii.hexlify(icmp_hdr[1])
		data = recv_data[2:]

		file_data.write("|==========ICMP HEADER==========|<br>")
		file_data.write("type = "+str(typee)+"<br>code = "+str(code)+"<br>")
		file_data.close()
		return data

def analyze_udp_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data","a")
		udp_hdr  = struct.unpack("!4H",recv_data[:8])
		src_port = udp_hdr[0]
		dst_port = udp_hdr[1]
		length   = udp_hdr[2]
		chk_sum  = udp_hdr[3]
		data     = recv_data[8:]

		file_data.write("|==========UDP HEADER==========|<br>")
		file_data.write("source port = %u <br>" % src_port)
		file_data.write("destination port = %u <br>" % dst_port)
		file_data.write("length = %u <br>" % length)
		file_data.write("checksum = %u <br>" % chk_sum)
		file_data.close()
		
		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		return data

def analyze_tcp_header(recv_data):
		global retn_data
		file_data=open("User Interface/file_data","a")
		tcp_hdr  = struct.unpack("!2H2I4H",recv_data[:20])
		src_port = tcp_hdr[0]
		dst_port = tcp_hdr[1]
		seq_num  = tcp_hdr[2]
		ack_num  = tcp_hdr[3]
		data_off = tcp_hdr[4] & 0xf000
		reserved = tcp_hdr[4] & 0xF00
		flags    = tcp_hdr[4] & 0xFF
		win_size = tcp_hdr[5]
		chk_sum  = tcp_hdr[6]
		urg_ptr  = tcp_hdr[7]
		data     = recv_data[20:]

		urg = bool(flags & 0x20)
		ack = bool(flags & 0x10)
		psh = bool(flags & 0x8)
		rst = bool(flags & 0x4)
		syn = bool(flags & 0x2)
		fin = bool(flags & 0x1)

		file_data.write("|==========TCP HEADER==========|<br>")
		file_data.write("source port = %u <br>" % src_port)
		file_data.write("destination port = %u <br>" % dst_port)
		file_data.write("sequence number = %u <br>" % seq_num)
		file_data.write("acknowledge number = %u<br>" % ack_num)
		file_data.write("flags --> <br>")
		file_data.write("URG = %u <br>" % urg)
		file_data.write("ACK = %u <br>" % ack)
		file_data.write("PSH = %u <br>" % psh)
		file_data.write("RST = %u <br>" % rst)
		file_data.write("SYN = %u <br>" % syn)
		file_data.write("FIN = %u <br>" % fin)
		file_data.write("window = %u <br>" % win_size)
		file_data.write("checksum = %u <br>" % chk_sum)
		file_data.write("data offset = "+str(data_off)+"<br>")
		file_data.write("reserved = "+str(reserved)+"<br>")
		file_data.write("urgent pointer = "+str(urg_ptr)+"<br>")
		file_data.close()
		
		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		return data

def analyze_ip_header(recv_data):
		global retn_data
		file_data = open("User Interface/file_data","a")
		ip_hdr      = struct.unpack("!6H4s4s",recv_data[:20])
		ver = ip_hdr[0] >> 12
		hdr_len     = (ip_hdr[0] >> 8) & 0x0f
		ip_tos      = ip_hdr[0] & 0x00ff
		tot_len     = ip_hdr[1]
		ip_id       = ip_hdr[2]
		flag= ip_hdr[3] & 0xe000
		offset      = ip_hdr[3] & 0x1fff
		ttl = ip_hdr[4] >> 8
		ip_proto    = ip_hdr[4] & 0x00ff
		ip_cksum    = ip_hdr[5]
		src_ip      = socket.inet_ntoa(ip_hdr[6])
		dst_ip      = socket.inet_ntoa(ip_hdr[7])
		data= recv_data[20:]

		file_data.write("|==========IP HEADER==========|<br>")
		file_data.write("version = "+str(ver)+"<br>")
		file_data.write("header length = "+str(hdr_len)+"<br>")
		file_data.write("ip_tos = "+str(ip_tos)+"<br>")
		file_data.write("total length = "+str(tot_len)+"<br>")
		file_data.write("ip id = "+str(ip_id)+"<br>")
		file_data.write("flag = "+str(flag)+"<br>")
		file_data.write("offset = "+str(offset)+"<br>")
		file_data.write("time to live ="+str(ttl)+"<br>")
		file_data.write("ip protocol = "+str(ip_proto)+"<br>")
		file_data.write("source ip = "+str(src_ip)+"<br>")
		file_data.write("destination ip = "+str(dst_ip)+"<br>")
		file_data.close()
		retn_data['src_ip'] = src_ip
		retn_data['dst_ip'] = dst_ip

		if ip_proto == 6:
				proto = "TCP"
				retn_data['proto'] = "TCP"
		elif ip_proto == 17:
				proto = "UDP"
				retn_data['proto'] = "UDP"
		elif ip_proto == 1:
				proto = "ICMP"
				retn_data['proto'] = "ICMP"
		elif ip_proto == 2:
				proto = "IGMP"
				retn_data['proto'] = "IGMP"
		elif proto == 27:
				proto = "RDP"
				retn_data['proto'] = "RDP"
		elif ip_proto == 33:
				proto = "DCCP"
				retn_data['proto'] = "DCCP"
		else:
				proto = "OTHER"
				retn_data['proto'] = "OTHER"

		return data

def analyze_ether_header(recv_data):
		global retn_data,num
		file_data = open("User Interface/file_data","a")
		eth_hdr    = struct.unpack("!6s6sH",recv_data[:14])
		dst_mac    = binascii.hexlify(eth_hdr[0])
		src_mac    = binascii.hexlify(eth_hdr[1])
		ether_type = eth_hdr[2]
		data       = recv_data[14:]
		
		x=datetime.datetime.now()
		retn_data['time'] = str(x.hour)+":"+str(x.minute)+":"+str(x.second)
		retn_data['num'] = num
		file_data.write("num:"+str(num)+"<br>")
		file_data.write("time = "+str(retn_data['time'])+"<br>")
		num += 1
		file_data.write("|==========ETHERNET HEADER==========|<br>")
		
		retn_data['src_mac'] = str(src_mac[:2])+":"+str(src_mac[2:4])+":"+str(src_mac[4:6])+":"+str(src_mac[6:8])+":"+str(src_mac[8:10])+":"+str(src_mac[10:12])
		retn_data['dst_mac'] = str(dst_mac[:2])+":"+str(dst_mac[2:4])+":"+str(dst_mac[4:6])+":"+str(dst_mac[6:8])+":"+str(dst_mac[8:10])+":"+str(dst_mac[10:12])
		file_data.write("source mac = "+retn_data['src_mac']+"<br>")
		file_data.write("destination mac = "+retn_data['dst_mac']+"<br>")
		file_data.write("ether type = "+str(ether_type)+"<br>")
		file_data.close()
		if ether_type == 0x0800: #IPV4
				retn_data['ether_type'] = "IPV4"
				return data
		if ether_type == 0x0806: #ARP
				retn_data['ether_type'] = "ARP"
				return data
		retn_data['ether_type'] = "OTHER"
		return data       #OTHER

def sniffer():
		clear()
		global sock_created,sniffer_socket,retn_data
		file_data = open("User Interface/file_data","a")
		if sock_created == False:
				sniffer_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
				sock_created = True
		recv_data = sniffer_socket.recv(2048)
		retn_data['total_data'] = recv_data
		recv_data = analyze_ether_header(recv_data)
		
		if(retn_data['ether_type'] == "IPV4"): #IPV4
				recv_data = analyze_ip_header(recv_data)
		elif(retn_data['ether_type'] == "ARP"): #ARP
				recv_data = analyze_ARP_header(recv_data)
				retn_data['pure_data'] = ''.join([i if (ord(i) < 128 and ord(i) > 31) else '' for i in recv_data])		
				file_data.write("|===========DATA===========|<br>"+str(retn_data['pure_data'])+"<br>")
				file_data.close()
				return retn_data
		else:     #OTHER
				retn_data['pure_data'] = ''.join([i if (ord(i) < 128 and ord(i) > 31) else '' for i in recv_data])
				file_data.write("|===========DATA===========|<br>"+str(retn_data['pure_data'])+"<br>")
				file_data.close()
				return retn_data
		
		if(retn_data['proto'] == "TCP"):
				recv_data = analyze_tcp_header(recv_data)
		if(retn_data['proto'] == "UDP"):
				recv_data = analyze_udp_header(recv_data)
		if(retn_data['proto'] == "ICMP"):
				recv_data = analyze_icmp_header(recv_data)
		if(retn_data['proto'] == "IGMP"):
				recv_data = analyze_igmp_header(recv_data)
		if(retn_data['proto'] == "DCCP"):
				recv_data = analyze_dccp_header(recv_data)
		if(retn_data['proto'] == "RDP"):
				recv_data = analyze_rdp_header(recv_data)

		retn_data['pure_data'] = ''.join([i if (ord(i) < 128 and ord(i) > 29) else '' for i in recv_data])
		file_data.write("|===========DATA===========|<br>"+str(retn_data['pure_data'])+"<br>")
		file_data.close()
		return retn_data

