# coding: utf-8
import os
import cv2
import numpy as np
from OpenSSL.crypto import load_pkcs12
from endesive import pdf
import datetime
import sys
from OpenSSL import crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from enum import Enum
from subprocess import call

r_x = 100
r_y = 500
r_w = 500
r_h = 200
rr_w = 250
rr_h = 100

tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, 'fixtures')

def fixture(pdfname):
    return os.path.join(fixtures_dir, pdfname)

def signature_string(organization='', date='', country='', reason=''):
    return 'Signature VALID' + '\n\n' +\
        '\t' + str(organization) + '\n' + \
        '\tDATE: ' + str(date) + '\n' +\
        '\tReason: ' + str(reason) + '\n' +\
        '\tLocation: ' + str(country)

class MakeSignature():
    def __init__(self):
        self.check_png = os.path.join(tests_root, 'sign_200.png')
        self.output_png = os.path.join(tests_root, 'output.png')

    def overlay(self, l_img, s_img, x_offset, y_offset) :
        y1, y2 = y_offset, y_offset + s_img.shape[0]
        x1, x2 = x_offset, x_offset + s_img.shape[1]

        for y in range(y1, y2):
            for x in range(x1, x2):
                alpha_s = s_img[y-y1, x-x1, 3] / 255
                alpha_l = 1.0 - alpha_s
                # l_img[y, x, 3] = s_img[y-y1, x-x1, 3]
                l_img[y, x, 3] = 255
                for c in range(0, 3):
                    l_img[y, x, c] = (alpha_s * s_img[y-y1, x-x1, c] + alpha_l * l_img[y, x, c])
        return l_img
    def drawtext(self, img, text = 'Hello', x_off=0, y_off=0, fontScale=1.0, thickness=1):
        font                   = cv2.FONT_HERSHEY_SIMPLEX
        bottomLeftCornerOfText = (x_off, y_off)
        fontColor              = (0,0,0,255)
        lineType               = cv2.LINE_AA

        cv2.putText(img, text, 
            bottomLeftCornerOfText, 
            font, 
            fontScale,
            fontColor,
            thickness,
            lineType)

    def create_signature_img(self, organization, date, country, reason):
        signimage = cv2.imread(self.check_png, -1)
        signimage = cv2.resize(signimage, (r_h, r_h))
        background = np.zeros((r_h,r_w,4), np.uint8)
        background[:,:] = (255,255,255,0)
        # added_image = cv2.addWeighted(background,0.5,signimage,0.5,0)
        
        added_image = self.overlay(background, signimage,int((r_w)/2), 0)
        # added_image = added_image[:, :, 3]
        text_height = 25
        left_padding = 20
        self.drawtext(added_image, 'Signature VALID', left_padding, text_height * 1 + 10, fontScale=1, thickness = 2)
        self.drawtext(added_image, str(organization), left_padding, text_height * 3, fontScale=0.7, thickness = 1)
        self.drawtext(added_image, 'Date : ' + date, left_padding, text_height * 4, fontScale=0.7, thickness = 1)
        self.drawtext(added_image, 'Country : ' + str(country), left_padding, text_height * 5, fontScale=0.7, thickness = 1)
        self.drawtext(added_image, 'Reason : ' + reason, left_padding, text_height * 6, fontScale=0.7, thickness = 1)

        # added_image = cv2.resize(added_image, (int(r_w/2), int(r_h/2)))
        # cv2.imshow('window', added_image)
        # cv2.waitKey(1)
        cv2.imwrite(self.output_png, added_image)
        return self.output_png

class KeyUsage(Enum):
    digitalSignature = 0
    nonRepudiation = 1
    keyEncipherment = 2
    dataEncipherment = 3
    keyAgreement = 4
    keyCertSign = 5
    cRLSign = 6
    encipherOnly = 7
    decipherOnly = 8

class PDFSign():
    def __init__(self):
        self.makeSignature = MakeSignature()

    def output_cert(self, cert, fname):
        pemdata = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        with open(fname+'~.crt.pem', "wb") as f:
            f.write(pemdata)

    def checkUsage(self, cert):
        for index in range(0,cert.get_extension_count()): #Get no. of extensions
            if cert.get_extension(index).get_short_name() == b'keyUsage': #Check extension name
                # print ("Key Usage found")
                # print (cert.get_extension(index))
                if 'Digital Signature' in str(cert.get_extension(index)):
                    return True
                # KeyData = cert.get_extension(index).get_data() #ASN1 encoded string
                # DeData = decoder.decode(KeyData) #Returns tuple containing instance
                # for i in enumerate(tag):
                #     if i[1] == 1:
                #         print (KeyUsage(i[0]).name)
                # return True
        # print ("Key Usage not found")
        return False

    def get_self_p12(self, keyname, keypwd) :
        with open(fixture(keyname+'.p12'), 'rb') as fh:
            ori_p12 = load_pkcs12(fh.read(), keypwd)
        
        print (ori_p12.get_friendlyname())
        return ori_p12

    def start_sign(self, pdfname='', keyname='', keypwd='', verifyname='', reason='', off_x = r_x, off_y=r_y):
        self.pdfname = pdfname
        self.keyname = keyname
        self.keypwd = keypwd
        self.verifyname = verifyname
        self.reason = reason
        self.off_x = off_x
        self.off_y = off_y

        # with open(fixture(keyname), 'rb') as fh:
        #     ori_p12 = load_pkcs12(fh.read(), keypwd)
        opensslpath = 'C:\\Program Files\\Git\\usr\\bin\\openssl.exe'
        new_cert = 'cert.pem'
        new_key = 'key.pem'
        print(fixture(keyname))
        print(keypwd)

        # Get cert.pem
        result = call([opensslpath, 'pkcs12', '-in', fixture(keyname),
                         '-nokeys', '-out', fixture(new_cert), '-passin', 'pass:'+keypwd])
        print(result)
        # Get cert.pem
        result = call([opensslpath, 'pkcs12', '-in', fixture(keyname),
                         '-nodes', '-nocerts', '-out', fixture(new_key), '-passin', 'pass:'+keypwd])
        print(result)

        keysplitter = '-----END PRIVATE KEY-----'
        book = open(fixture(new_key)).read()
        x = book.split(keysplitter)

        i = 0
        for key_text in x:
            if key_text == '\n':
                continue
            # Save new KeyFile
            new_key_i = fixture('key' + str(i) + '.pem')
            with open(new_key_i, 'wb') as f:
                f.write(key_text.encode('utf-8'))
                f.write(keysplitter.encode('utf-8'))
            # Create New P12
            new_p12_i_name = keyname.replace('.p12', '_') + str(i) + '.p12'
            new_p12_i = fixture(new_p12_i_name)
            result = call([opensslpath, 'pkcs12', '-export', '-inkey', new_key_i, '-in', fixture(new_cert), '-name', 'spider', 
                             '-out', new_p12_i, '-passout', 'pass:'+keypwd])
            # print(result)
            # Load New P12
            with open(new_p12_i, 'rb') as fh:
                p12_i = load_pkcs12(fh.read(), keypwd)
            if self.checkUsage(p12_i.get_certificate()) == True:
                print('Found P12 For signing')
                self.sign_pdf(p12_i)
                return
            i = i + 1
        print('No P12 for Digital Signing')

    def sign_pdf(self, p12):

        date = datetime.datetime.utcnow() - datetime.timedelta(hours=12)
        strdate1 = date.strftime('%Y.%m.%d')
        subject = p12.get_certificate().get_subject()

        location = str(subject.C)
        signature = signature_string(subject.CN, strdate1, subject.C, self.reason)
        signature_img = self.makeSignature.create_signature_img(subject.CN, strdate1, location, self.reason)
        strdate2 = date.strftime('%Y%m%d%H%M%S+00\'00\'')

        # print(subject)

        dct = {
            b'sigbutton':b'mysignbutton',
            b'signature' : signature.encode(),
            b'signaturebox':(self.off_x, self.off_y, self.off_x+rr_w, self.off_y+rr_h),
            b'sigpage': 0,
            b'sigflags': 3,
            b'contact': b'darwinquintana@sidesoft.ec',
            b'location': location.encode(),
            # b'signingdate': b'20200301082642+02\'00\'',
            b'signingdate': strdate2.encode(),
            b'reason': self.reason.encode(),
            b'fontsize': 8,
            b'signature_img': signature_img.encode(),
        }
        with open(self.pdfname, 'rb') as fh:
            datau = fh.read()

        datas = pdf.cms.sign(datau, dct,
            p12.get_privatekey().to_cryptography_key(),
            p12.get_certificate().to_cryptography(),
            [],
            'sha256'
        )

        signedpdfname = self.pdfname.replace('.pdf', '-signed.pdf')
        with open(signedpdfname, 'wb') as fp:
            fp.write(datau)
            fp.write(datas)
        
        # with open(fixture(verifyname+'.crt.pem'), 'rt') as fh:
        #     trusted_cert_pems = (fh.read(),)
        # trusted_cert_pems = [crypto.dump_certificate(crypto.FILETYPE_PEM, p12.get_ca_certificates()[2])]
        # with open(pdfname, 'rb') as fh:
        #     data = fh.read()
        
        # (hashok, signatureok, certok) = pdf.verify(data, trusted_cert_pems)
        # assert signatureok and hashok and certok
