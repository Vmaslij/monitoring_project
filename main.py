import json

from analizatorcpp import Analizator
from flask import Flask, render_template, request, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, send, emit
from multiprocessing import Process, Pipe
import netifaces
import simple_websocket

app = Flask(__name__)

app.config['SECRET_KEY'] = 'diplom'

app.config['object_analizator'] = Analizator()

socketio = SocketIO(app)

items = ['Номер', 'Время', 'Протокол', 'Mac-адресс отправителя', 'Mac-адресс получателя', 'Длина данных',
         'Порт отправителя',
         'IP-адресс отправителя', 'Порт получателя', 'IP-адресс получателя']


@socketio.on('stop')
def stop_monitoring():
    intfc = app.config['intfc']
    app.config[intfc].terminate()
    app.config[intfc + 'File'].close()
    app.config[intfc + 'File'] = None
    app.config['file_for_download'].close()
    return 0


@app.route('/monitoring')
def monitoring():
    app.config['file_for_download'] = open("static/DownloadFile.json", "w")
    packages = parse_data()
    return render_template('monitoring.html', intfc=app.config['intfc'], items=items, packages=packages)


@app.route('/charts')
def charts():
    return render_template("charts.html")


def parse_data():
    intfc = app.config['intfc']
    string = 'b'
    if not app.config[intfc + 'File']:
        app.config[intfc + 'File'] = open('logfile.txt')
        ip = app.config[intfc + 'File'].readline().split(' ')[-1]
        mask = app.config[intfc + 'File'].readline().split(' ')[-1]
        mtu = app.config[intfc + 'File'].readline().split(' ')[-1]
        indx = app.config[intfc + 'File'].readline().split(' ')[-1]
        string = app.config[intfc + 'File'].readline()
    else:
        string = app.config[intfc + 'File'].readline()

    data = []
    package_info = [0] * 10
    while string:
        package_info[0] = int(app.config[intfc + 'File'].readline())
        package_info[1] = int(app.config[intfc + 'File'].readline())
        string = app.config[intfc + 'File'].readline().split(' ')
        package_info[3] = string[0]
        package_info[4] = string[-1].replace('\n', '', 1)
        string = app.config[intfc + 'File'].readline().split(' ')
        package_info[5] = string[-1].replace('\n', '', 1)
        string = app.config[intfc + 'File'].readline().split(' ')
        package_info[6] = string[0]
        # print(string)
        # print(package_info)
        package_info[7] = string[1]
        # print(string)
        # print(package_info)
        package_info[8] = string[-2]
        package_info[9] = string[-1].replace('\n', '', 1)
        package_info[2] = app.config[intfc + 'File'].readline().replace('\n', '', 1)
        string = app.config[intfc + 'File'].readline()
        data.append({'Number': package_info[0], 'Time': package_info[1], 'Protocol': package_info[2],
                     'Mac_sender': package_info[3],
                     'Mac_receiver': package_info[4], 'Length': package_info[5], 'Port_sender': package_info[6],
                     'IP_sender': package_info[7], 'Port_receiver': package_info[8], 'IP_receiver': package_info[9]})
        app.config['file_for_download'].write(json.dumps(data, check_circular=True))
    return data


@socketio.on('download file')
def download():
    app.config['file_for_download'].close()
    app.config['file_for_download'] = open("static/DownloadFile.json", "r")
    emit('save file', app.config['file_for_download'].read())
    app.config['file_for_download'].close()
    app.config['file_for_download'] = open("static/DownloadFile.json", "w")


@socketio.on('update data')
def update():
    emit('send data', json.dumps(parse_data(), check_circular=True))


@app.route('/', methods=['GET', 'POST'])
def index():
    # proc.start()
    intfcs = netifaces.interfaces()
    if request.method == 'GET':
        return render_template('main_menu.html', intfcs=intfcs)
    else:
        if request.method == 'POST':
            for i in intfcs:
                if request.form.get(i, None) == i:
                    app.config['intfc'] = i
                    app.config[i] = Process(target=app.config['object_analizator'].main_cycle,
                                            args=(bytes(i, encoding="ASCII"),))
                    app.config[i + 'File'] = None
                    app.config[i].start()
                    return redirect(url_for('monitoring'))


if __name__ == '__main__':
    socketio.run(app, host='127.0.0.1', port=8014, allow_unsafe_werkzeug=True)
