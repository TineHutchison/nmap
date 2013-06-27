import xml.etree.ElementTree as ET, argparse

parser = argparse.ArgumentParser(description='This is a script to find SSL certificates in an XML file produced by nmap.')
parser.add_argument('-i','--input', help='Input file name',required=True)
parser.add_argument('-s','--search', default='Subject', help='Search for a string in the SSL information', required=False)
args = parser.parse_args()

xmldoc = args.input
search = args.search

tree = ET.parse(xmldoc)
root = tree.getroot()

for host in root.findall('host'):
	for status in host.iter('status'):
		reason = status.attrib['reason']
	if (reason == 'syn-ack'):
		#print 'found syn-ack'
		for address in host.iter('address'):
			addr = address.attrib['addr']
			#print addr
		for port in host.iter('port'):
			#print port.tag, port.attrib
			for script in port.iter('script'):
				output = script.attrib['output']
				if ((output != 'ERROR') and (output != 'TIMEOUT') and (search in output)):
					start = output.find('Not valid after')
					expire_date = output[(start + 18): (start + 28)]
					print addr + ' ' + port.attrib['portid'] + ' ' + expire_date
