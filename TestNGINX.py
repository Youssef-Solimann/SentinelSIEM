from parsers.nginx_parser import NginxLogParser

parser = NginxLogParser()
events = parser.parse_file("sample_logs/nginx_access.log")
print(len(events))
print(events[0])