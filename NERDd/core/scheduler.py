"""
NERD scheduler - allows modules to register functions (callables) to be run at
specified times or intervals (like cron does).

Based on APScheduler package
"""

import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

class Scheduler():
    """
    NERD scheduler - allows modules to register functions (callables) to be run
    at specified times or intervals (like cron does).
    """
    def __init__(self):
        self.log = logging.getLogger("Scheduler")
        #self.log.setLevel("DEBUG")
        logging.getLogger("apscheduler.scheduler").setLevel("WARNING")
        logging.getLogger("apscheduler.executors.default").setLevel("WARNING")
        self.sched = BackgroundScheduler(timezone="UTC")

    def start(self):
        self.log.debug("Scheduler start")
        self.sched.start()
    
    def stop(self):
        self.log.debug("Scheduler stop")
        self.sched.shutdown()
    
    def register(self, func, year=None, month=None, day=None, week=None, 
            day_of_week=None, hour=None, minute=None, second=None, timezone="UTC",
            args=None, kwargs=None):
        """
        Register a function to be run at specified times.
        
        func - function or method to be called
        year,month,day,week,day_of_week,hour,minute,second -
           cron-like specification of when the function should be called,
           see docs of apscheduler.triggers.cron for details
           https://apscheduler.readthedocs.io/en/latest/modules/triggers/cron.html
        timezone - Timezone for time specification (default is UTC).
        args, kwargs - arguments passed to func
        """
        trigger = CronTrigger(year, month, day, week, day_of_week, hour, minute,
            second, timezone=timezone)
        self.sched.add_job(func, trigger, args, kwargs, coalesce=True, max_instances=1)
        self.log.debug("Registered function {0} to be called at {1}".format(func.__qualname__, trigger))
        

