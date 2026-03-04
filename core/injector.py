from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urldefrag

class Injector:

    @staticmethod
    def inject_in_url(url, payload):
        url, _ = urldefrag(url)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        results = []

        for key in params:
            modified = {k: v[0] for k, v in params.items()}
            modified[key] = payload

            new_query = urlencode(modified)
            new_url = urlunparse(parsed._replace(query=new_query))

            results.append((new_url, key))

        return results

    @staticmethod
    def inject_in_form(form, payload):
        injected_forms = []

        for key in form["inputs"]:
            modified_inputs = form["inputs"].copy()
            modified_inputs[key] = payload

            injected_forms.append({
                "action": form["action"],
                "method": form["method"],
                "inputs": modified_inputs,
                "injected_param": key
            })

        return injected_forms