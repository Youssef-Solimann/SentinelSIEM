from parsers.auth_parser import AuthLogParser

parser = AuthLogParser(default_year=2026)
events = parser.parse_file("sample_logs/auth.log")
print(len(events))
for e in events:
    print(e)