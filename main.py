from flask import Flask, request, redirect, render_template
from sign_pdf import PDFSign
from flask import send_from_directory
import os
from os import path, walk

app = Flask(__name__)
pdfSign = PDFSign()

@app.route('/')
def index():
    return render_template("main.html", result = "")

@app.route('/download/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    uploads = os.path.join(app.root_path, app.config['fixtures'])
    return send_from_directory(directory=uploads, filename=filename)

@app.route('/signpdf', methods = ['GET', 'POST'])
def signpdf():
    if request.method == "GET":
        return render_template("main.html", result = "")
    if not request.files:
        return render_template("main.html", result = "No input!")

    try:
        pdf = request.files["pdf"]
        pdf_path = os.path.join(app.config["fixtures"], pdf.filename)
        pdf.save(pdf_path)
        print("pdf saved", pdf_path)

        p12 = request.files["p12"]
        p12_path = os.path.join(app.config["fixtures"], p12.filename)
        p12.save(p12_path)
        print("P12 saved", p12_path)


        keyname= p12.filename
        keypwd = request.values.get('pwd', 'pwd')
        print('keypwd', keypwd)
        reason = request.values.get('reason', 'I am the author')
        verifyname = 'darwin_ca'

        pos_x = request.values.get("pos_x", 0)
        pos_y = request.values.get("pos_y" ,0)
        print ('position [', pos_x, pos_y, ']')
        pdfSign.start_sign(pdf_path, keyname, keypwd, verifyname, reason, int(pos_x), int(pos_y))
        downpath = pdf.filename.replace('.pdf', '-signed.pdf')
        return render_template("main.html", result = "Success", downpath=downpath)
    except Exception as e:
        print(e)
        return render_template("main.html", result = "ERROR", downpath='')

if __name__ == '__main__':
    # signpdf()

    # app.run()
    app.config["fixtures"] = "fixtures"
    app.run(host='127.0.0.1', threaded=True)
