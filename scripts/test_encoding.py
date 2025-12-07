import re
from urllib.parse import quote, unquote

# Test the logic
test_url = "assets/Pasted%2520image%252020251207102032.png"
print(f"Original URL: {test_url}")

# Fully decode
decoded_url = test_url
while True:
    new_decoded = unquote(decoded_url)
    print(f"  Decode iteration: {new_decoded}")
    if new_decoded == decoded_url:
        break
    decoded_url = new_decoded

print(f"Fully decoded: {decoded_url}")

# Encode
encoded = quote(decoded_url, safe="/")
print(f"After quote: {encoded}")

print(f"\nAre they different? {test_url != encoded}")
