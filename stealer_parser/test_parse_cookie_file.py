from stealer_parser.parsing.parsing_cookies import parse_cookie_file


# Path to a sample cookie file for testing
test_file_path = "/Users/nicolascolucci/Desktop/cookieExamples/Chrome_Default.txt"

# Call the function and print the result
cookies = parse_cookie_file(test_file_path)
print("Parsed Cookies:")
for cookie in cookies:
    print(cookie)
