from stealer_parser.models.cookie import Cookie
import logging

logger = logging.getLogger("StealerParser")

def parse_cookie_file(file_path):
    """Parses a cookie file and returns a list of Cookie objects.

    Parameters
    ----------
    file_path : str
        Path to the cookie file to parse.

    Returns
    -------
    list of Cookie
        A list of Cookie objects parsed from the file.
    """
    # Add a logger message to confirm when this function is called
    logger.info(f"Parsing cookie file: {file_path}")
    cookies = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Skip empty lines
                if not line.strip():
                    continue

                # Split line into fields
                fields = line.strip().split('\t')
                if len(fields) == 7:  # Ensure there are exactly 7 fields
                    domain, flag, path, secure, expiration, name, value = fields

                    # Convert expiration timestamp to an integer
                    expiration_timestamp = int(expiration)

                    # Create a Cookie object and add it to the list
                    cookie = Cookie(
                        domain=domain,
                        flag=flag,
                        path=path,
                        secure=secure,
                        expiration_timestamp=expiration_timestamp,
                        name=name,
                        value=value
                    )
                    cookies.append(cookie)
                    # Debug log to check each parsed cookie
                    print(f"Parsed cookie: {cookie}")
                else:
                    print(f"Unexpected format in line: {line}")
    except Exception as e:
        print(f"Failed to parse cookie file {file_path}: {e}")

    return cookies
