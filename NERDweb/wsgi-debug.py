from nerd_main import app

# Enable logging of exceptions into Apache log file
app.debug = True

# Enable interactive debuggin in web browser.
# ! Don't use this on production server, it allows to run arbitarary code !
from werkzeug.debug import DebuggedApplication
application = DebuggedApplication(app, True)

# Enable testing mode of NERDweb, in particular this disables authentication
# (everyone is automacitally logged in as 'test' account with full privileges)
from nerd_main import config
config.testing = True
