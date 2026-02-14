import re

# ===============================
# Scope Configuration
# ===============================

TARGET_PORTS = {5000}  # your app port

TARGET_PATH_PREFIXES = (
    "/login",
    "/search",
    "/register",
    "/api",
)

ALLOWED_METHODS = {"GET", "POST"}

# ===============================
# Core SQL Indicators
# ===============================

SQL_KEYWORDS = [
    "union", "select", "insert", "update", "delete", "drop",
    "where", "from", "into", "values", "having", "order", "group"
]

SQL_LOGIC_OPERATORS = ["and", "or"]

SQL_SPECIAL_CHARS = ["'", "\"", "--", ";", "#", "/*", "*/"]

# ===============================
# Strong SQLi Patterns
# ===============================

STRONG_SQLI_PATTERNS = [
    r"'\s*(or|and)\s+\d+=\d+",
    r"'\s*(or|and)\s+'?\w+'?='?\w+'?",
    r"(or|and)\s+\d+=\d+\s*--",
    r"union\s+select",
    r"sleep\s*\(\s*\d+\s*\)",
    r"benchmark\s*\(",
    r"waitfor\s+delay",
]

# ===============================
# Telemetry / Noise Suppression
# ===============================

NOISE_PATTERNS = [
    r"^[a-z0-9_\-]+$",  # rollout / flags
    r"mozilla",
    r"firefox",
    r"telemetry",
    r"rollout",
    r"experiment",
    r"nimbus",
    r"metrics",
    r"^/favicon\.ico$",
    r"\.(css|js|png|jpg|jpeg|gif|svg|woff2?|ttf|ico)$"
]

MIN_PAYLOAD_LENGTH = 6

# ===============================
# Scope Gate (NEW)
# ===============================

def is_request_in_scope(
    *,
    port: int,
    path: str,
    method: str,
    has_body: bool
) -> bool:
    """
    Hard gate to eliminate non-target traffic
    """

    if port not in TARGET_PORTS:
        return False

    if not path.lower().startswith(TARGET_PATH_PREFIXES):
        return False

    if method.upper() not in ALLOWED_METHODS:
        return False

    if not has_body:
        return False

    return True


# ===============================
# Helpers
# ===============================

def is_noise_value(v: str) -> bool:
    if len(v) < MIN_PAYLOAD_LENGTH:
        return True

    for p in NOISE_PATTERNS:
        if re.search(p, v):
            return True

    return False


def calculate_score(v: str) -> int:
    score = 0

    # Quotes
    score += v.count("'") * 2
    score += v.count('"') * 2

    # SQL keywords
    for k in SQL_KEYWORDS:
        if re.search(rf"\b{k}\b", v):
            score += 2

    # Logical operators only with structure
    for op in SQL_LOGIC_OPERATORS:
        if re.search(rf"('\s*{op}\s+|\b{op}\s+\d+=\d+)", v):
            score += 2

    # SQL comments
    if "--" in v or "/*" in v:
        score += 3

    return score


# ===============================
# Payload Detection
# ===============================

def detect_payload(value: str):
    if not value:
        return None, None

    v = value.lower().strip()

    if is_noise_value(v):
        return None, None

    for p in STRONG_SQLI_PATTERNS:
        if re.search(p, v):
            return "HIGH", "Strong SQL injection pattern detected"

    score = calculate_score(v)

    if score >= 7:
        return "HIGH", "High-confidence SQL injection"
    elif score >= 4:
        return "MEDIUM", "Suspicious SQL-like structure"
    elif score >= 2:
        return "LOW", "Weak SQL indicators"

    return None, None
