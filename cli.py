from netscanner.Netscanner import Scanner
import optparse


def get_options():
    parser = optparse.OptionParser()
    parser.add_option("-a", "--address", dest="address", help="Field for IPv4 Address including # octets (0.0.0.0/0 format)")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False)
    parser.add_option("-s", "--save", dest="save", action="store_true", default=False)
    required = ['address']

    options, arguments = parser.parse_args()
    options = vars(options)
    for command in required:
        if not options[command]:
            raise Exception(f"Required argument {command} not supplied")
    
    return options


if __name__ == "__main__":
    options = get_options()
    scanner = Scanner(options)
    scanner.main()