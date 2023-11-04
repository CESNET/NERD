import yaml
import ast
from datetime import datetime


class ClassifiableEvent:
    def __getattr__(self, name):
        """
        Override __getattr__ so that no error is raised when a module asks for a non-existing attribute
        :param name: Name of the attribute
        :return: Value of the attribute (or None if it does not exist)
        """
        return self.__dict__[name] if name in self.__dict__ else None

    def __str__(self):
        """
        Override __str__ for easier logging of assigned categories
        :param name: Name of the attribute
        :return: String representation of the object's attribute dictionary
        """
        return str(self.__dict__)

    def __init__(self, module_name=None, *args):
        """
        Initialize the event (fill metadata from source module)
        :param module_name: Name of the attribute
        :param *args: Module specific attributes (such as a list of protocols from Warden)
        :return:
        """
        init_fn = getattr(self, f"init_{module_name}")
        init_fn(*args)

    def init_warden_receiver(self, event, source):
        """
        Fill in metadata from a warden event
        :param event: Source event
        :return:
        """
        self.categories = event.get('Category', [])
        self.source_types = source.get('Type', [])
        self.description = event.get("Description", "")
        target_ports = []
        protocols = source.get('Proto', [])
        for target in event.get('Target', []):
            target_ports += target.get('Port', [])
            protocols += target.get('Proto', [])
        self.target_ports = list(set(target_ports))
        self.protocols = list(set(protocols))

    def init_otx_receiver(self, pulse):
        """
        Fill in metadata from an OTX pulse
        :param pulse: Source pulse
        :return:
        """
        self.indicator_role = pulse.get('indicator_role', "")
        self.indicator_title = pulse.get('indicator_title', "")
        self.pulse_name = pulse.get('pulse_name', "")

    def init_misp_receiver(self, event, attrib, ip_role):
        """
        Fill in metadata from a MISP event
        :param event: Source event
        :param attrib: Attribute with the source IP
        :param ip_role: Role of the IP address (src/dst/both)
        :return:
        """
        self.tags = [tag["name"] for tag in event.get('tag_list', [])]
        self.info = event.get('info', "")
        self.attrib_comment = attrib.get('comment', "")
        self.ip_role = ip_role
        try:
            if attrib['type'] == "ip-dst|port":
                split_attrib = attrib['value'].split('|')
                if len(split_attrib) == 1:
                    split_attrib = attrib['value'].split(':')
                if len(split_attrib) > 1:
                    self.target_ports = [int(split_attrib[1])]
        except ValueError:
            pass


def eval_trigger(trigger, event):
    """
    Evaluate a category trigger, i.e. a statement that resolves to either True or False
    :param trigger: Trigger to be evaluated
    :param event: Source event (instance of ClassifiableEvent) from which the trigger reads data
    :return: Result of the evaluation (True/False), dictionary with subcategory assignments
    """
    result = False
    subcategories = {}
    a = trigger.split("->")
    if eval(a[0]) is True:
        result = True
    if len(a) > 1:
        subcategories = ast.literal_eval(a[1].lstrip())
    return result, subcategories


def match_str(str_a, str_b):
    """
    Approximate (sub)string matching

    Ignores character casing, whitespace and some special characters
    """
    simplified_a = str_a.strip().replace("_", "").replace(".", "").lower()
    simplified_b = str_b.strip().replace("_", "").replace(".", "").lower()
    return simplified_a in simplified_b


def log_category(id, module, category, event):
    """
    Log assigned category
    :param id: ID of the record (e.g. IP address or blacklist name)
    :param module: Name of the source module
    :param category: Assigned category
    :param event: Source event (instance of ClassifiableEvent)
    :return:
    """
    with open(f"/var/log/nerd/threat_categorization_{module}.log", "a+") as logfile:
        logfile.write(f"{datetime.now()}\n")
        logfile.write(f"ID: {id}\n")
        logfile.write(f"Category: {category}\n")
        logfile.write(f"Event: {event}\n")
        logfile.write("===============================================\n")


def load_malware_families():
    """
    Load the list of malware families downloaded from Malpedia
    :return:
    """
    try:
        with open("/data/malpedia/malware_families.yml", "r") as f:
            return yaml.safe_load(f)
    except Exception:
        return {}


def load_categorization_config(module_name=None):
    """
    Load categorization configuration for a specific module
    :param module_name: Name of the source module
    :return: Dictionary containing categorization config
    """
    categories = {}
    categorization_config = yaml.safe_load(open("/etc/nerd/threat_categorization.yml"))
    for category_id, category_config in categorization_config.items():
        categories[category_id] = {
            "label": category_config.get("label", ""),
            "role": category_config.get("role", "src"),
            "subcategories": category_config.get("subcategories", []),
            "triggers": category_config.get("triggers", {}).get(module_name, "False").split("\n")
        }
    return categories
