from stealer_parser.models.cookie import Cookie
import logging

logger = logging.getLogger("StealerParser")

def parse_cookie_file(filename: str, text: str = None) -> list[Cookie]:
    """Parse cookie content and return a list of Cookie objects."""
    logger.info(f"Parsing cookie file: {filename}")
    cookies = []
    
    # If text is not provided, read from file
    if text is None:
        with open(filename, 'r', encoding='utf-8') as f:
            text = f.read()
    
    try:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('\00'):  # Skip empty lines and Mac OS metadata
                continue
                
            # Split by any number of whitespace characters
            fields = [f for f in line.split() if f]
            
            if len(fields) >= 7:
                try:
                    cookie = Cookie(
                        domain=fields[0],
                        flag=fields[1],
                        path=fields[2],
                        secure=fields[3],
                        expiration_timestamp=int(fields[4]),
                        name=fields[5],
                        value=' '.join(fields[6:])  # Join remaining fields for value
                    )
                    cookies.append(cookie)
                except (ValueError, IndexError) as e:
                    # Just log warning and continue instead of raising error
                    logger.warning(f"Invalid cookie format in {filename}. Line: {line}")
                    continue
            
    except Exception as e:
        logger.error(f"Failed to parse cookie file {filename}: {e}")
        
    return cookies
