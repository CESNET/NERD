from nerd_main import app as application
application.debug = True # Enable logging of exceptions into Apache log file
from nerd_main import config
config.testing = True

