import json

def save_database(path: str, data: dict) -> bool:
    pass

def load_database(path: str) -> dict:
    pass

def serialize_data(data: list) -> bytes:
    json_string = json.dumps(data)
    return json_string.encode('utf-8')

def deserialize_data(data: bytes) -> list:
    try:
        json_string=data.decode("utf-8")
        return json.loads(json_string)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("Odszyfrowane dane sa uszkodzone lub nie stanowia poprawnego formatu JSON.") from e