import argparse
import sys
import json
import base64
import ipaddress
from time import time
from dnslib import DNSRecord


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)


parser = MyParser(
    description="Convert AdGuard log file to human readable format")
parser.add_argument("log_file", help="AdGuard log file")
parser.add_argument("output_log_file", help="Output log file")
parser.add_argument("--exclude-cname", dest="exclude_cname",
                    help="Exclude CNAME responses from output", action="store_true")
args = parser.parse_args()
start = time()
try:
    with open(args.log_file, "r") as f1:
        request_dict = {}
        for line in f1:
            try:
                data = json.loads(line)
            except json.decoder.JSONDecodeError as err:
                print("Error: can't parse JSON \n" + str(err))
                sys.exit(1)
            # skip if Result field isn't empty (in other words request was blocked)
            if data.get('Result', None):
                continue
            record = DNSRecord.parse(base64.decodebytes(data['Answer'].encode(
                'utf-8'))).short().split("\n")  # parse the dns answer
            result = []
            # remove cname responses from the answer
            for addr in record:
                try:
                    if args.exclude_cname:
                        ip = ipaddress.ip_address(addr)
                    result.append(addr)
                except ValueError:
                    pass
            NL = "\n    "
            request_dict[", ".join(result)] = (
                f"{data['IP']} requested {data['QH']} {data['QT']} "
                f"on {data['T']} and received response: \n    {NL.join(result)}"
            )
        l = time() - start
        print("Done Parsing in " + str(l))
        try:
            with open(args.output_log_file, "w") as output_file:
                for record in request_dict:
                    print(request_dict[record], file=output_file)
        except OSError:
            print("Error writing to file")

except FileNotFoundError:
    print(f"Error: File '{args.log_file}' not found")
