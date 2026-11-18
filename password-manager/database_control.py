import json
from pathlib import Path

def save_database(path: str, data: dict) -> bool:
    serialized_data = json.dumps(data, ensure_ascii=False, indent=4)
    Path(path).write_text(serialized_data, encoding="utf-8")
    return True

def load_database(path: str) -> dict:
    with Path(path).open("r", encoding="utf-8") as database_file:
        data = json.load(database_file)

    if not isinstance(data, dict):
        raise ValueError("Plik bazy danych musi zawierać obiekt JSON.")

    return data

def serialize_data(data: list) -> bytes:
    json_string = json.dumps(data)
    return json_string.encode('utf-8')

def deserialize_data(data: bytes) -> list:
    try:
        json_string=data.decode("utf-8")
        return json.loads(json_string)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("Odszyfrowane dane sa uszkodzone lub nie stanowia poprawnego formatu JSON.") from e