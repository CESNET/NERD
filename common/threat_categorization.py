import yaml


class ClassifiableEvent:
    def __getattr__(self, name):
        return self.__dict__[name] if name in self.__dict__ else None

    def __init__(self, module_name=None, *args):
        init_fn = getattr(self, f"init_{module_name}")
        init_fn(*args)

    def init_warden_receiver(self, event, source):
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
        self.indicator_role = pulse.get('indicator_role', "")
        self.indicator_title = pulse.get('indicator_title', "")
        self.n_reports = 1  # TODO

    def init_misp_receiver(self, event, ip_role):
        self.tags = [tag["name"] for tag in event.get('tag_list', [])]
        self.ip_role = ip_role


def load_categorization_config(module_name=None):
    categories = {}
    categorization_config = yaml.safe_load(open("/etc/nerd/threat_categorization.yml"))
    for category_id, category_config in categorization_config.items():
        categories[category_id] = {
            "label": category_config.get("label", ""),
            "role": category_config.get("role", "src"),
            "subcategories": category_config.get("subcategories", []),
            "triggers": category_config.get("triggers", {}).get(module_name, "False").split("\n"),
            "blacklists": category_config.get("blacklists", [])
        }
    return categories
