class XSSDetector:

    @staticmethod
    def detect_reflection(html, token):
        if not html:
            return False
        if token in html:
            return True
        return False