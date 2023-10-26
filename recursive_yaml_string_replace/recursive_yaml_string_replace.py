import json
import os
from pprint import pprint
import yaml

class YamlRepoStrReplace:
    def __init__(self):
        self.repo_path = input("Input repo directory path: ") or "rules"
        self.replace_dict = input("Input replace dictionary containing key, value pairs where k = field and v = {dictionary of {original: replacement} string mapping data: ") or "replace_dict.json"
        self.write_to_file = input("Write output to file for all changes? (y/n)") or "n"
        self.filenames = []
        for root, dirs, files in os.walk(self.repo_path):
            for filename in files:
                self.filenames.append((os.path.join(root, filename)))
            for dirname in dirs:
                self.filenames.append((os.path.join(root, dirname)))
    
    def return_new(self):
        filenames = self.filenames
        self.updates = {}
        with open(self.replace_dict) as replace_dict:
            replace_dict_json = json.loads(replace_dict.read())
            for i in filenames:
                if str(i).endswith(".yml"):
                    try:
                        with open(""+i, "r") as ry: 
                                yaml_load = yaml.safe_load(ry)
                                for key, replace in replace_dict_json.items():
                                    if isinstance(replace, dict):
                                        for old, new in replace.items():
                                            if yaml_load[key]:
                                                y_replace = yaml_load[key]
                                                if i in self.updates.keys():
                                                    x = self.updates[i]
                                                    if str(old) in str(x):
                                                        self.updates.update({i: {key: str(x).replace(str(old), str(new))}})
                                                        pass
                                                else:
                                                    if str(old) in str(y_replace):
                                                        self.updates.update({i: {key: str(y_replace).replace(str(old), str(new))}})
                                                        pass
                                    else:
                                        print(f'unhandled: {i}')
                        
                    except Exception as e:
                        print(f'Exception for {i}: {e}')
                
        pprint(self.updates, indent=2) 
        return self.updates
    
    def writetf(self):
        if str(self.write_to_file) == "y" or "yes":
            with open('updates_dict.json', 'w') as fp:
                json.dump(self.updates, fp, indent=4)

repo_str_replace = YamlRepoStrReplace()

meta = repo_str_replace.return_new()

if __name__=="__main__":
    pprint('Done!')
