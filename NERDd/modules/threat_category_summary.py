"""
NERD module summarizing threat category records.

Should be triggered at least once a day for every address.
"""

from core.basemodule import NERDModule
import g

from copy import deepcopy
import datetime


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

        grouped_by_category = {}
        for record in rec['_threat_category']:
            cat = record['id']
            if cat not in grouped_by_category:
                grouped_by_category[cat] = []
            grouped_by_category[cat].append(record)

        today = datetime.datetime.utcnow().date()
        DATE_RANGE = 14
        summary = []

        for cat, records in grouped_by_category.items():
            cat_summary = {
                'role': records[0]['role'],
                'id': records[0]['id'],
                'sources': {},
                'subcategories': {}
            }
            sources = {}
            subcategories = {}
            sum_weight = 0
            confidence = 0
            for record in deepcopy(records):
                date = record['date']
                date = datetime.date(int(date[0:4]), int(date[5:7]), int(date[8:10]))
                record_age_days = (today - date).days
                if record_age_days >= DATE_RANGE:
                    continue
                daily_reports = 0
                for source in record['n_reports']:
                    if source not in sources:
                        sources[source] = 0
                    sources[source] += record['n_reports'][source]
                    daily_reports += record['n_reports'][source]
                daily_confidence = nonlin(daily_reports) * nonlin(len(record['n_reports']))
                weight = float(DATE_RANGE - record_age_days) / DATE_RANGE
                sum_weight += weight
                confidence += daily_confidence * weight
                del record['date']
                del record['role']
                del record['id']
                del record['n_reports']
                for key, values in record.items():
                    if key not in subcategories:
                        subcategories[key] = set()
                    subcategories[key].update(values)
            if confidence > 0:
                cat_summary['confidence'] = round(confidence / sum_weight, 2)
                cat_summary['sources'] = sources
                cat_summary['subcategories'] = {k: list(v) for k, v in subcategories.items()}
                summary.append(cat_summary)
        summary = sorted(summary, key=lambda rec: rec['confidence'], reverse=True)
        return [('set', '_threat_category_summary', summary)]
