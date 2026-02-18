# Packet manipulation libraries
import os
from dotenv import load_dotenv
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from elasticsearch.helpers import streaming_bulk
import time
from prometheus_client import start_http_server, Counter, Gauge , CollectorRegistry
import prometheus_client
load_dotenv()

# Gets rid of the noise in the prometheus
my_registry = CollectorRegistry()
prometheus_client.Counter._generate_created_series = False

# Define the Metrics with Labels
pcap_packets_total = Gauge('pcap_packets_total', 'Total number of packets captured', ['protocol'] , registry=my_registry)
pcap_bytes_total = Gauge('pcap_bytes_total', 'Total bytes captured', ['protocol'] , registry=my_registry)
pcap_elastic_write_total = Gauge('pcap_elastic_write_total',  'Total Elasticsearch write operations', ['status'] , registry=my_registry)


# Packet info variables
class packet_info:
	def __init__(self):
		self.src_ip = None
		self.dst_ip = None
		self.src_port = None
		self.dst_port = None
		self.l4_protocol = None
		# Counts the amount of packets that failed to enter elastic
		self.error_num = 0
		# Defining the protocols that are in the elastic
		self.protocols = []


# Extracts metrics from elastic to prometheus format
def process_network_data(protocols,es,error_num):
	total_bytes = 0
	res = 0
	rel_docs = 0
	# Counts the number of documents of each protocol
	for proto in protocols:
		res = es.count(index=os.getenv("ELASTIC_INDEX"),
			query= {"match": {"l4_protocol": proto}}
		)
		count = res['count']
		pcap_packets_total.labels(protocol=proto).set(count)

		# Extracts the documents from protocol so we can extract the length of them without the "byets" part
		rel_docs = helpers.scan(client=es, index=os.getenv("ELASTIC_INDEX"), query={
			"query": {"match": {"l4_protocol": proto}},
			"_source": ["packet_length(bytes)"]
		}
						)
		size_data = 0
		for doc in rel_docs:
			size_data += (doc.get('_source', {})).get('packet_length(bytes)', 0)
		pcap_bytes_total.labels(protocol=proto).set(size_data)
		total_bytes += size_data
	total_docs = es.count(index=os.getenv("ELASTIC_INDEX"))['count']
	pcap_packets_total.labels("all protocols").set(total_docs)
	pcap_bytes_total.labels("all protocols").set(total_bytes)
	pcap_elastic_write_total.labels(status='success').set(total_docs)
	pcap_elastic_write_total.labels(status='fail').set(error_num)

# Extracts packet info
def extract_packet_info (info,packet,ip_type):
	info.src_ip = packet[ip_type].src
	info.dst_ip = packet[ip_type].dst

	# Checks if transport layer exists
	transport_layer = packet[ip_type].payload
	if hasattr(transport_layer, 'sport'):
		info.src_port = transport_layer.sport
		info.dst_port = transport_layer.dport

	# Get the protocol name
	info.l4_protocol = packet[ip_type].payload.name

# Extracts all pcap file's names from pcap folder
def all_pcap_files(dir_to_pcaps):
	file_path_list = []
	for file in os.listdir(dir_to_pcaps):
		if file.endswith(".pcap"):
			file_path_list.append(os.path.abspath(os.path.join("pcap_files", file)))
	return file_path_list


def main():
	# Prepare packets for bulk insert
	packets = []
	# Prepare failed packets to try again
	failed_packets = []

	# Iterates through the packets
	for packet in pcap:
		# Create instance
		timestemp = datetime.fromtimestamp(float(packet.time))
		if IP in packet:
			extract_packet_info (info,packet,IP)
		elif IPv6 in packet:
			extract_packet_info (info,packet,IPv6)
		else:
			info.l4_protocol = "No l4 protocol"
		packet_length = len(packet)

		# For later organisation in the prometheus format
		if not info.l4_protocol in info.protocols:
			info.protocols.append(info.l4_protocol)

		# Prepare packets for bulk insert
		packets.append({
			"_index": f"pcap-packets-{timestemp.strftime('%Y-%m-%d')}",
			"_source": {
				"timestamp": timestemp.strftime("%Y-%m-%d %H:%M:%S"),
				"src_ip": info.src_ip,
				"dst_ip": info.dst_ip,
				"src_port": info.src_port,
				"dst_port": info.dst_port,
				"l4_protocol": info.l4_protocol,
				"packet_length(bytes)": packet_length
			}
		})


	# Inserts data into elastic
	for inx , (ok, result) in enumerate(streaming_bulk(es, packets, raise_on_error=False)):
		if not ok:
			failed_packets.append(packets[inx])

	# Retry + returns status and fail reason
	for inx , (ok, result) in enumerate(streaming_bulk(es, failed_packets, raise_on_error=False)):
		if not ok:
			print(f"{failed_packets[inx]['_index']} - status: {ok} , result: {result} \n")
			# Counts the amount of packets that failed to enter elastic
			info.error_num +=1


if __name__ == '__main__':
	# Packet info variables
	info = packet_info()

	# Connection to Elasticsearch
	es = Elasticsearch(os.getenv("ELASTIC_URL"))

	file_path_list = os.getenv("FILE_PATH_LIST")
	# Iterates through all pcap's from the dictionary's
	if file_path_list != []:
		for file_path in all_pcap_files(file_path_list):
			pcap = PcapReader(rf"{file_path}")
			main()

			# Start the server on port 9100
			start_http_server(int(os.getenv("METRICS_PORT")), registry=my_registry)

			# Added time to write after upload logs
			time.sleep(20)
			print("Elasticsearch available at http://localhost:9200")
			print("Kibana available at http://localhost:5601")
			print("Prometheus metrics available at http://localhost:9100/metrics")
			print("The prometheus server with close in 5 minutes")
			# Exports metrics and keeps the prometheus server running
			process_network_data(info.protocols, es, info.error_num)
			time.sleep(300)



