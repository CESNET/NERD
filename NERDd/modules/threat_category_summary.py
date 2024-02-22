"""
NERD module summarizing threat category records.

Should be triggered at least once a day for every address.
"""

from core.basemodule import NERDModule
import common.config
import g

from copy import deepcopy
import datetime
import os


def nonlin(val, coef=0.5, max=20):
    """Nonlinear transformation of [0,inf) to [0,1)"""
    if val > max:
        return 1.0
    else:
        return (1 - coef**val)


class ThreatCategorySummary(NERDModule):
    """
    Module summarizing threat category records.
    """

    def __init__(self):
        categorization_config_file = os.path.join(g.config_base_path, g.config.get("threat_categorization_config"))
        self.config = common.config.read_config(categorization_config_file).get("threat_categorization", {})

        g.um.register_handler(
            self.create_summary,  # function (or bound method) to call
            'ip',  # entity type
            ('_threat_category', '!every1d'),  # tuple/list/set of attributes to watch (their update triggers call of the registered method)
            ('_threat_category_summary',)  # tuple/list/set of attributes the method may change
        )

    def create_summary(self, ekey, rec, updates):
        """
        Summarize threat caregory records - group records by category
                                          - get total number of reports for each source module
                                          - compute confidence

        Category confidence (based on reputation score method):
        - take list of records from last 14 days
        - compute a "daily confidence" for each day as:
          - nonlin(num_of_reports) * nonlin(number_of_sources)
          - where nonlin is a nonlinear transformation: 1 - 1/2^x
        - get total confidence as weighted average of all "daily" ones with
          linearly decreasing weight (weight = (14-n)/14 for n=0..13)
        """
        etype, key = ekey
        if etype != 'ip':
            return None

        if '_threat_category' not in rec:
            return None # No threat category records, nothing to do

        subcategory_max_length = 10
        grouped_by_category = {}
        for record in rec['_threat_category']:
            cat = record['c']
            if cat not in grouped_by_category:
                grouped_by_category[cat] = []
            grouped_by_category[cat].append(record)

            # limit the number of subcategory values in each record
            for key, values in record.items():
                if type(record[key]) is list:
                    record[key] = record[key][:subcategory_max_length]

        today = datetime.datetime.utcnow().date()
        DATE_RANGE = 14
        summary = []

        for cat, records in grouped_by_category.items():
            role = self.config[cat]['role']
            cat_summary = {
                'r': role,
                'c': cat,
                'src': {},
                's': {}
            }
            sources = {}
            subcategories = {}
            sum_weight = 0
            confidence = 0
            for record in deepcopy(records):
                date = record['d']
                date = datetime.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
                record_age_days = (today - date).days
                if record_age_days >= DATE_RANGE:
                    continue
                daily_reports = 0
                for source in record['src']:
                    if source not in sources:
                        sources[source] = 0
                    sources[source] += record['src'][source]
                    daily_reports += record['src'][source]
                daily_confidence = nonlin(daily_reports) * nonlin(len(record['src']))
                weight = float(DATE_RANGE - record_age_days) / DATE_RANGE
                sum_weight += weight
                confidence += daily_confidence * weight
                del record['d']
                del record['c']
                del record['src']
                for key, values in record.items():
                    if key not in subcategories:
                        subcategories[key] = set()
                    subcategories[key].update(values)
            if confidence > 0:
                cat_summary['conf'] = round(confidence / sum_weight, 2)
                cat_summary['src'] = sources
                cat_summary['s'] = {k: list(v)[:subcategory_max_length] for k, v in subcategories.items()}
                summary.append(cat_summary)
        summary = sorted(summary, key=lambda rec: rec['conf'], reverse=True)
        return [('set', '_threat_category_summary', summary)]
