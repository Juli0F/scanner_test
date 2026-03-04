# modules/xss/stored_manager.py

import time


class StoredXSSManager:

    def __init__(self):
        self.pending_tokens = {}

    def register_token(self, token, payload, origin_url, parameter):
        self.pending_tokens[token] = {
            "payload": payload,
            "origin_url": origin_url,
            "parameter": parameter,
            "timestamp": time.time(),
            "confirmed": False
        }

    def mark_confirmed(self, token):
        if token in self.pending_tokens:
            self.pending_tokens[token]["confirmed"] = True

    def get_pending(self):
        return {
            t: data
            for t, data in self.pending_tokens.items()
            if not data["confirmed"]
        }

    def get_token_data(self, token):
        return self.pending_tokens.get(token)