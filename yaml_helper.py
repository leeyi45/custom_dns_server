from typing import *

T = TypeVar('T')

class YamlHelper:
    def __init__(self, yaml_obj):
        self._yaml = yaml_obj

    def get(self, path: str, default=None) -> Any:
        entries = list(map(str.strip, path.split('/')))
        obj = self._yaml.get(entries[0])

        for i in range(1, len(entries)):
            if obj is None:
                return default
            obj = obj.get(entries[i])
        
        return obj

    def get_list(self, path: str, default=None) -> List[Any]:
        obj = self.get(path)
        if isinstance(obj, list):
            return obj
        elif obj is not None:
            return [obj]
        else:
            return default

    def get_bool(self, path: str, default: bool = False) -> bool:
        return bool(self.get(path, default))

    def get_as(self, path: str, converter: Callable[[str], T], default: T = None) -> T:
        result = self.get(path, default)
        return converter(result) if result is not None else result
