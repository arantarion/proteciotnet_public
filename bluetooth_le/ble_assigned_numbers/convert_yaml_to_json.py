import yaml
import json
import sys
import os


class LoaderNoHexAutoConvert(yaml.SafeLoader):
    """
    A custom loader class that prevents automatic conversion of hexadecimal numbers to integers.
    """

    def construct_yaml_int(self, node):
        if node.value.lower().startswith('0x'):
            return self.construct_scalar(node)
        else:
            return super().construct_yaml_int(node)


LoaderNoHexAutoConvert.add_constructor(u'tag:yaml.org,2002:int', LoaderNoHexAutoConvert.construct_yaml_int)


def parse_yaml_to_dict(file_path, output_path):
    """
    Parse the specified section of a YAML file and convert it into a dictionary.

    :param file_path: str, Path to the YAML file.
    :param output_path: str, Path to the output JSON file.
    """
    try:
        with open(file_path, 'r') as stream:
            try:
                # Use the custom loader instead of the default one
                yaml_content = yaml.load(stream, Loader=LoaderNoHexAutoConvert)
            except yaml.YAMLError as exc:
                return

        company_identifiers_list = yaml_content.get('uuids', [])

        company_identifiers_dict = {
            item['uuid']: item['name'] for item in company_identifiers_list
        }

        with open(output_path, 'w') as j_file:
            json.dump(company_identifiers_dict, j_file, indent=4)

    except IOError as e:
        print(f"Error reading the YAML file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <filename>")
        sys.exit(1)
    
    full_filename = sys.argv[1]
    filename_without_extension = os.path.splitext(os.path.basename(full_filename))[0]

    path_to_yaml = full_filename
    path_to_json = f"{filename_without_extension}.json"

    parse_yaml_to_dict(path_to_yaml, path_to_json)
