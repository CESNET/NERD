"""
NERD module summarizing all information about an entity into its reputation score.

Should be triggered at least once a day for every address.
"""

from core.basemodule import NERDModule
import common.config
import g

import datetime
import math
import os


def nonlin(val, scale, coef=0.5, max=20):
    """Nonlinear transformation of [0,inf) to [0,1)"""
    if (val_s := float(val) / scale) > max:
        return 1.0
    else:
        return 1 - coef**val_s


class Reputation(NERDModule):
    """
    Module estimating reputation score of IPs.

    TODO better description
    """

    def __init__(self):
        # Load config
        common_config_file = os.path.join(g.config_base_path, g.config.get("common_config"))
        reputation_config_file = os.path.join(g.config_base_path, g.config.get("reputation_config"))
        self.config = common.config.read_config(common_config_file)
        self.config.update(common.config.read_config(reputation_config_file))
        self.max_event_history = int(self.config.get("max_event_history", 30))

        # Load reputation parameters for each module
        self.enabled_modules = self.config.get("rep_enabled_modules")
        self.module_params = {mod: {} for mod in self.enabled_modules}
        for mod in self.enabled_modules:
            self.module_params[mod]["coef_events"] = float(self.config[f"rep_params"][mod].get("coef_events", 0.5))
            self.module_params[mod]["coef_detectors"] = float(self.config[f"rep_params"][mod].get("coef_detectors", 0.5))
            self.module_params[mod]["scale_events"] = float(self.config[f"rep_params"][mod].get("scale_events", 1))
            self.module_params[mod]["scale_detectors"] = float(self.config[f"rep_params"][mod].get("scale_detectors", 1))
            self.module_params[mod]["date_range"] = int(self.config[f"rep_params"][mod]["history"].get("date_range", self.max_event_history))
            if (time_decay := self.config[f"rep_params"][mod]["history"].get("time_decay", "none")).startswith("half_life"):
                time_decay, half_life = time_decay.split(":")
                self.module_params[mod]["half_life"] = float(half_life)
            self.module_params[mod]["time_decay"] = time_decay

        # Register handler functions
        g.um.register_handler(
            self.rep_total,
            "ip",
            [f"_rep_{mod}" for mod in self.enabled_modules],
            ("rep",)
        )
        for mod in self.enabled_modules:
            g.um.register_handler(
                self.make_handler(mod),
                "ip",
                ("!every1d",) + tuple(self.config["rep_params"][mod]["triggers"]),
                (f"_rep_{mod}",)
            )

    def make_handler(self, module):
        """Generate handler function for the given module"""
        def handler(ekey, rec, updates):
            etype, key = ekey
            if etype != "ip":
                return None
            return [("set", f"_rep_{module}", self.partial_reputation(rec, module, **self.module_params[module]))]
        handler.__name__ = f"rep_{module}"
        return handler

    def rep_total(self, ekey, rec, updates):
        """Handler function to compute total reputation"""
        etype, key = ekey
        if etype != "ip":
            return None
        rep_total = 1 - math.prod([(1 - rec.get(f"_rep_{mod}", 0)) for mod in self.enabled_modules])
        return [("set", "rep", rep_total)]

    def partial_reputation(self, rec, module, coef_events, coef_detectors, scale_events, scale_detectors, date_range, time_decay, half_life=1):
        """
        Compute partial reputation from the given module
        """
        if not (data := self.get_module_data(rec, module, date_range)):
            return 0.0
        num_events, num_detectors = data

        # Compute daily reputation and apply time decay
        sum_weight = 0.0
        rep = 0.0
        for d in range(0, date_range):
            daily_rep = nonlin(num_events[d], scale_events, coef_events)
            if num_detectors:
                daily_rep *= nonlin(num_detectors[d], scale_detectors, coef_detectors)
            if time_decay == "linear":
                weight = float(date_range - d) / date_range # Weight decreases linearly with age
            elif time_decay == "half_life":
                weight = 0.5 ** (float(d) / half_life) # Weights are computed as 2^-(age/half_life)
            else:
                weight = 1 # No time decay
            sum_weight += weight
            rep += daily_rep * weight

        # Final score is the weighted average of daily reputation
        return rep / sum_weight if sum_weight else 0.0

    def get_module_data(self, rec, module, date_range):
        """
        Call the correct function to load module-specific data and return the result
        """
        fn = getattr(self, f"get_{module}_data")
        return fn(rec, date_range, datetime.datetime.now(datetime.timezone.utc))

    def get_warden_data(self, rec, date_range, today):
        """
        Get total number of Warden events / nodes for each day of the date range
        """
        if not (records := rec.get("events")) or not date_range:
            return None
        num_events = [0 for _ in range(date_range)]
        set_nodes = [set() for _ in range(date_range)]
        for evtrec in records:
            event_date = evtrec["date"]
            event_date = datetime.date(int(event_date[0:4]), int(event_date[5:7]), int(event_date[8:10]))
            if (age := (today.date() - event_date).days) >= date_range:
                continue
            num_events[age] += evtrec["n"]
            set_nodes[age].add(evtrec["node"])
        return num_events, [len(s) for s in set_nodes]

    def get_dshield_data(self, rec, date_range, today):
        """
        Get number of DShield reports / targets for each day of the date range
        """
        if not (records := rec.get("dshield")) or not date_range:
            return None
        num_reports = [0 for _ in range(date_range)]
        num_targets = [0 for _ in range(date_range)]
        for r in records:
            rec_date, reports, targets = r.values()
            rec_date = datetime.date(int(rec_date[0:4]), int(rec_date[5:7]), int(rec_date[8:10]))
            if (age := (today.date() - rec_date).days) >= date_range:
                continue
            num_reports[age] += reports
            num_targets[age] += targets
        return num_reports, num_targets

    def get_blacklists_data(self, rec, date_range, today):
        """
        Get number of blacklists for each day of the date range
        """
        if not (records := rec.get("bl")):
            return None
        blacklists = [set() for _ in range(date_range)]
        for blrec in records:
            for rec_date in blrec["h"]:
                rec_date = rec_date.replace(tzinfo=datetime.timezone.utc) # timestamps in DB are offset-naive
                if (age := (today - rec_date).days) >= date_range:
                    continue
                blacklists[age].add(blrec["n"])
        num_blacklists = [len(bl) for bl in blacklists]
        return num_blacklists, None

    def get_otx_data(self, rec, date_range, today):
        """
        Get number of OTX pulses for each day of the date range
        """
        if not (records := rec.get("otx_pulses")):
            return None
        num_events = [0 for _ in range(date_range)]
        for pulse in records:
            rec_date = pulse["pulse_created"].replace(tzinfo=datetime.timezone.utc) # timestamps in DB are offset-naive
            if (age := (today - rec_date).days) >= date_range:
                continue
            num_events[age] += 1
        return num_events, None

    def get_misp_data(self, rec, date_range, today):
        """
        Get total number of MISP events (all events are treated as if they were published today)
        """
        if not (records := rec.get("misp_events")) or not (num_events_total := len(records)):
            return None
        num_events = [0 for _ in range(date_range)]
        num_events[0] = num_events_total
        return num_events, None
