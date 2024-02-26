from flask import Flask, render_template
from Poc.info.infoLoader import *
from Poc.app.appLoader import *
app = Flask(__name__)


app.register_blueprint(infoLoader, url_prefix='/info')
app.register_blueprint(appLoader, url_prefix='/app')

@app.route('/')
def hello_world():  # put application's code here
    return render_template('index.html')


if __name__ == '__main__':
    app.run()
