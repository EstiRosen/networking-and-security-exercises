from scapy.all import *
FILE_PATH = "dnsenum.txt"


# Function to find the authoritative DNS server for a given domain
def find_dns_server(domain):
    # Create a DNS query packet of type SOA (Start of Authority)
    dns_query = IP(dst="8.8.8.8") / UDP(sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="SOA"))

    # Send the packet and receive the response
    response = sr1(dns_query, verbose=0)

    # Check if a response was received
    if response and response[DNS].ancount > 0:
        # Extract the DNS server name from the response
        dns_server = response[DNS].an.mname.decode()
        return dns_server


# Function to resolve sub domains using a specific DNS server
def resolve_subdomains(dns_server, domain, wordlist_path):
    try:
        # Read the sub domain list from the specified wordlist file
        with open(wordlist_path, 'r') as file:
            subdomains = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        # Handle case where wordlist file is not found
        print(f"Error: File '{wordlist_path}' not found.")
        sys.exit(1)

    # Iterate through each sub-domain and send DNS queries
    for sub_domain in subdomains:
        full_domain = f"{sub_domain}.{domain}"  # Full domain name
        # Create a DNS query for the current sub-domain
        dns_query = IP(dst=dns_server) / UDP(sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=full_domain, qtype="A"))
        response = sr1(dns_query, verbose=0)

        # Check if a response contains valid answers
        if response and response[DNS].ancount > 0:
            print(f"\nSub domain: {full_domain}")
            for i in range(response[DNS].ancount):
                answer = response[DNS].an[i]
                if answer.type == 1:  # Type 1 represents an 'A' (IPv4 address) record
                    ip_address = answer.rdata
                    print(f"  - IPv4: {ip_address}")


# Main function to handle command-line arguments and execute the script
def main():
    # Ensure the script is called with exactly one argument (the domain)
    if len(sys.argv) != 2:
        print("Usage: python dnsenum.py <domain>")
        sys.exit(1)

    # Get the domain from the command-line argument
    domain = sys.argv[1]

    # Find the authoritative DNS server for the given domain
    dns_server = find_dns_server(domain)
    if dns_server:
        # Resolve sub domains using the found DNS server
        resolve_subdomains(dns_server, domain, FILE_PATH)
    else:
        print("No authoritative DNS server found for given domain")


# Entry point of the script
if __name__ == '__main__':
    main()
