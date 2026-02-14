from mitmproxy import http
import json

from detector import detect_payload, is_request_in_scope
from ui import show_request, show_detection


class SQLiAddon:

    def request(self, flow: http.HTTPFlow):

        # ===============================
        # Scope Gate (HARD FILTER)
        # ===============================

        has_body = bool(
            flow.request.query
            or flow.request.urlencoded_form
            or flow.request.multipart_form
            or (
                "application/json"
                in flow.request.headers.get("Content-Type", "")
            )
        )

        if not is_request_in_scope(
            port=flow.request.port,
            path=flow.request.path,
            method=flow.request.method,
            has_body=has_body
        ):
            return  # 🔕 completely ignore out-of-scope traffic

        # ===============================
        # In-scope request
        # ===============================

        show_request(flow)

        # -------------------------------
        # GET parameters
        # -------------------------------
        for k, v in flow.request.query.items():
            risk, reason = detect_payload(v)
            if risk:
                show_detection(flow, "GET", k, v, reason, risk)

        # -------------------------------
        # POST form data
        # -------------------------------
        if flow.request.urlencoded_form:
            for k, v in flow.request.urlencoded_form.items():
                risk, reason = detect_payload(v)
                if risk:
                    show_detection(flow, "POST", k, v, reason, risk)

        # -------------------------------
        # JSON body
        # -------------------------------
        if "application/json" in flow.request.headers.get("Content-Type", ""):
            try:
                data = json.loads(flow.request.text)
                self.inspect_json(data, flow, "json")
            except Exception:
                pass

    def inspect_json(self, data, flow, location):
        if isinstance(data, dict):
            for k, v in data.items():
                self.inspect_json(v, flow, f"{location}.{k}")
        elif isinstance(data, list):
            for i, v in enumerate(data):
                self.inspect_json(v, flow, f"{location}[{i}]")
        elif isinstance(data, str):
            risk, reason = detect_payload(data)
            if risk:
                show_detection(flow, "JSON", location, data, reason, risk)


addons = [SQLiAddon()]
