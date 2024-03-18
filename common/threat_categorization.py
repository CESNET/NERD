import yaml
import ast
from datetime import datetime

from .utils import parse_rfc_time


class ClassifiableEvent:
    def __getattr__(self, name):
        """
        Override __getattr__ so that no error is raised when a trigger tries to use non-existing attribute
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
        :param *args: Module specific attributes
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
        detect_time = parse_rfc_time(event["DetectTime"])
        self.date = detect_time.strftime("%Y-%m-%d")
        self.categories = event.get('Category', [])
        self.ip_info = ";".join(source.get('Type', []))
        self.description = event.get("Description", "")
        target_ports = []
        protocols = source.get('Proto', [])
        for target in event.get('Target', []):
            target_ports += target.get('Port', [])
            protocols += target.get('Proto', [])
        self.target_ports = [str(port) for port in set(target_ports)]
        self.protocols = list(set(protocols))

    def init_otx_receiver(self, pulse):
        """
        Fill in metadata from an OTX pulse
        :param pulse: Source pulse
        :return:
        """
        self.date = datetime.strftime(pulse.get('pulse_modified', datetime.now()), "%Y-%m-%d")
        self.indicator_role = str(pulse.get('indicator_role', None))
        self.ip_info = str(pulse.get('indicator_title', None))
        self.description = str(pulse.get('pulse_name', None))
        self.protocols = []
        self.target_ports = []

    def init_misp_receiver(self, event, attrib, ip_role):
        """
        Fill in metadata from a MISP event
        :param event: Source event
        :param attrib: Attribute with the source IP
        :param ip_role: Role of the IP address (src/dst/both)
        :return:
        """
        self.date = datetime.strftime(attrib.get('date', datetime.now()), "%Y-%m-%d")
        self.tags = [tag["name"] for tag in event.get('tag_list', [])]
        self.description = event.get('info', "")
        self.ip_info = attrib.get('comment', "")
        self.ip_role = ip_role
        self.protocols = []
        self.target_ports = []
        try:
            if attrib['type'] == "ip-dst|port":
                split_attrib = attrib['value'].split('|')
                if len(split_attrib) == 1:
                    split_attrib = attrib['value'].split(':')
                if len(split_attrib) > 1:
                    self.target_ports = [int(split_attrib[1])]
        except ValueError:
            pass

    def init_blacklists(self, blacklist_id, ip_info, download_time):
        """
        Fill in metadata from a blacklist record
        :param blacklist_id: ID of the blacklist
        :param ip_info: Additional info about the IP
        :param download_time: Time when the blacklist was downloaded
        :return:
        """
        self.date = download_time.strftime("%Y-%m-%d")
        self.description = blacklist_id
        self.ip_info = str(ip_info)
        self.description = ""
        self.protocols = []
        self.target_ports = []


def classify_ip(ip_addr, module_name, logger, config, *args):
    """
    Assign a threat category based on the information provided in the incoming event

    :return: List of assigned categories
    """
    try:
        output = []
        event = ClassifiableEvent(module_name, *args)
        for category_id, category_params in config["categories"].items():
            category_triggers = category_params.get("triggers", {}).get("general", "False").split("\n") + \
                                category_params.get("triggers", {}).get(module_name, "False").split("\n")
            for trigger in category_triggers:
                result, subcategories = eval_trigger(trigger, event, category_params, config, logger)
                if result is True:
                    output.append({
                        "date": event.date,
                        "id": category_id,
                        "role": category_params["role"],
                        "subcategories": subcategories
                    })
                    break
    except Exception as e:
        logger.error(f"Error in threat category classification for IP {ip_addr}: {e}")
    if not output:
        output.append({"date": event.date, "id": "unknown", "role": "src", "subcategories": {}})
    #   with open(f"/var/log/nerd/threat_categorization_unknown.log", "a+") as logfile:
    #      logfile.write(f"[{datetime.now()}] MODULE: {module_name} IP: {ip_addr} EVENT-INFO: {event}\n")
    logger.debug(f"Threat category classification for {ip_addr}: {output}; Event info: {event}")
    return output


def eval_trigger(trigger, event, category_params, config, logger):
    """
    Evaluate a category trigger
    :param trigger: Trigger to be evaluated
    :param event: Source event (instance of ClassifiableEvent) from which the trigger reads data
    :param category_params: Category parameters (e.g. list of subcategories)
    :param logger: Source module logger
    :return: Result of the evaluation (True/False), dictionary with subcategory assignments
    """
    result = False
    required_subcategories = category_params.get("subcategories", [])
    subcategories = {s: [] for s in required_subcategories}

    try:
        split_trigger = trigger.split("->")
        if eval(split_trigger[0]) is True:
            result = True
        if len(split_trigger) > 1:
            subcategories.update(ast.literal_eval(split_trigger[1].lstrip()))
    except Exception as e:
        logger.error(f"Error when evaluating category trigger ({trigger}): {e}")
        logger.error(f"Event info: {event}")

    if result is True:
        if "port" in required_subcategories:
            subcategories["port"] += event.target_ports
            subcategories["port"] = list(set(subcategories["port"]))
        if "protocol" in required_subcategories:
            subcategories["protocol"] += event.protocols
            subcategories["protocol"] = list(set(subcategories["protocol"]))
        if "malware_family" in required_subcategories:
            text = f"{event.description};{event.ip_info}"
            for family_id, family_data in config["malware_families"].items():
                if match_str(family_data["common_name"], text):
                    subcategories["malware_family"].append(family_id.lower())
            subcategories["malware_family"] = list(set(subcategories["malware_family"]))
    return result, subcategories


def match_str(str_a, str_b):
    """
    Approximate (sub)string matching

    Ignores character casing, whitespace and some special characters
    """
    simplified_a = str_a.strip().replace("_", "").replace(".", "").replace("-", "").lower()
    simplified_b = str_b.strip().replace("_", "").replace(".", "").replace("-", "").lower()
    return simplified_a in simplified_b
