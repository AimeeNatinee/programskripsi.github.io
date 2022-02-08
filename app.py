import mysql.connector as conn
from flask import Flask, render_template, request, redirect,jsonify,send_file
from flask_socketio import SocketIO,emit
import flask_excel as excel
import xlsxwriter
import datetime
import pycountry
from geoip import geolite2
import urllib.request,urllib.error
from googletrans import Translator
import http.client
from bs4 import BeautifulSoup
import re
import ssl
from flashtext import KeywordProcessor
import speedtest
import schedule
import netifaces
import socket
import json
import pyshark as ps
import os
import time
import threading

app = Flask(__name__)
socketio = SocketIO(app)

db = conn.connect(host="localhost",user="root",passwd="",database="skripsi")
cursor = db.cursor()

URL ='https://127.0.0.1:5000/'
# cek koneksi yang digunakan
NIC = netifaces.gateways()['default'][netifaces.AF_INET][1]
localAreaNetwork = '\\Device\\NPF_{DFB6C5D6-4EFB-4BB5-8A7E-0D58756569BD}'
Main_Interface = localAreaNetwork
# Main_Interface = '\\Device\\NPF_'+NIC
Bpf_filter = 'udp port 53 or tcp port 80'
print(NIC)

packets ={}
captureTime ={
    'startTime':"",
    'endTime':"",
}

berita = ['berita','informasi','kejadian','kecelakaan','kriminal','hukum','politik','ekonomi','olahraga','otomotif']
jualBeli = ['jual','beli','menjual','membeli','toko','perdagangan','belanja','produk','merek']
edukasi = ['edukasi','belajar','tutorial','artikel','ensiklopedia','penelitian','jurnal','pelajaran','pelajari','mempelajari','kursus','pendidikan','ilmu','perpustakaan','buku','ebook']
hiburan = ['hiburan','game','permainan','film','video','drama','musik','lagu','nonton','menonton','streaming','foto']
analisis = ['analisis','iklan','pemasaran','periklanan','analytics']
keywords = berita+jualBeli+edukasi+hiburan+analisis


@app.route("/")
def index():
    createTable()
    return redirect("/login")

@app.route("/login", methods=["POST","GET"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        cursor.execute("select * from pengguna")
        record = cursor.fetchall()

        for r in record:
            # [0]:id [1]:username [2]:password
            getUsername = r[1]
            getPassword = r[2]
            if username == getUsername and password == getPassword:
                return redirect("/capturer")
            elif username == getUsername and password != getPassword:
                return render_template("login.html", warning="Password salah")

        return render_template("login.html", warning="Username atau password salah")
    else:
        return render_template("login.html")

@app.route("/capturer")
def capturer():
    return render_template("capturer.html")

@app.route("/analyzer")
def analyzerPacket():
    # harus mengambil paket analisis dari id_waktu terakhir untuk ditampilkan ke pengguna
    cursor.execute('SELECT * FROM waktu ORDER BY id_waktu DESC LIMIT 1')
    waktu = cursor.fetchall()
    print(waktu)
    print(waktu[0][0])
    idWaktu = waktu[0][0]

    # data seluruh paket yang berhasil di analisis
    cursor.execute("SELECT paket.id_paket,ip_src,ip_dst,arrival_time,protocol,domain,tipe_situs,negara_tujuan FROM paket JOIN rangkuman ON paket.id_paket = rangkuman.id_paket JOIN waktu ON waktu.id_waktu = paket.id_waktu WHERE paket.id_waktu = %s",(idWaktu,))
    data = cursor.fetchall()

    # data bandwidth download dan upload
    cursor.execute("SELECT waktu_cek,download,upload FROM kecepatan WHERE id_waktu=%s",(idWaktu,))
    dataBandwidth = cursor.fetchall()

    # rata2 kecepatan download upload
    cursor.execute("SELECT ROUND(AVG(download),3),ROUND(AVG(upload),3) FROM kecepatan WHERE id_waktu = %s",(idWaktu,))
    dataRata2Bandwidth = cursor.fetchall()

    # 10 domain yang terdeteksi paling banyak
    cursor.execute("SELECT COUNT(domain),domain,tipe_situs FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE id_waktu = %s AND paket.protocol NOT LIKE 'HTTP'GROUP BY domain ORDER BY COUNT(domain) DESC LIMIT 10",(idWaktu,))
    dataWebDikunjungi = cursor.fetchall()

    # 10 domain dengan traffic terbanyak
    cursor.execute("SELECT domain,tipe_situs,SUM(length1+length2) FROM(SELECT ip_dst,domain,tipe_situs,sum(length) as length1 FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE id_waktu = %s GROUP BY ip_dst) as tb1 JOIN(SELECT ip_src,length as length2 FROM paket WHERE id_waktu = %s) as tb2 ON tb1.ip_dst = tb2.ip_src GROUP BY domain ORDER BY SUM(length1+length2) DESC LIMIT 10",(idWaktu,idWaktu,))
    dataWebMenghabiskanBandwidth = cursor.fetchall()

    dataWeb = []
    for i in dataWebMenghabiskanBandwidth:
        dataWeb.append((i[0],i[1],getFileSize(i[2])))

    # 10 ip yang menghabiskan bandwidth
    cursor.execute("SELECT ip_src,SUM(length1+tb2.length2) AS total FROM( SELECT ip_src,SUM(length) AS length1 FROM paket WHERE id_waktu = %s AND ip_src LIKE '192.168%' GROUP BY ip_src ) AS tb1 JOIN( SELECT ip_dst,SUM(length) AS length2 FROM paket WHERE id_waktu = %s AND ip_dst LIKE '192.168%' GROUP BY ip_dst ) AS tb2 ON tb1.ip_src = tb2.ip_dst GROUP BY ip_src ORDER BY total DESC LIMIT 10",(idWaktu,idWaktu))
    dataIPMenghabiskanBandwidth = cursor.fetchall()

    dataIP = []
    for i in dataIPMenghabiskanBandwidth:
        dataIP.append((i[0],getFileSize(i[1])))

    # jumlah pengguna
    cursor.execute("SELECT COUNT(DISTINCT ip_src) as jumlah FROM paket WHERE ip_src LIKE '192.168%' AND id_waktu = %s",(idWaktu,))
    dataJumlahPengguna = cursor.fetchall()

    return render_template("analyzerPacket.html",data=data,waktu=waktu,dataBandwidth=dataBandwidth,dataRata2Bandwidth=dataRata2Bandwidth,dataWebDikunjungi=dataWebDikunjungi,dataWebMenghabiskanBandwidth=dataWeb,dataIPMenghabiskanBandwidth=dataIP,dataJumlahPengguna=dataJumlahPengguna,idWaktu=idWaktu)

@app.route("/ajaxFile",methods=["POST","GET"])
def ajaxFile():
    if request.method == 'POST':
        idPaket = request.form['idPaket']
        print("ini id Paket:",idPaket)
        cursor.execute("SELECT * FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE paket.id_paket = %s", (idPaket,))
        detailPaket = cursor.fetchall()
        for i in detailPaket:
            print(i)
    return jsonify({'htmlresponse': render_template("detailPaket.html",detailPaket = detailPaket)})

@app.route("/history")
def history():
    cursor.execute('SELECT * FROM waktu')
    data = cursor.fetchall()
    return render_template("history.html", data=data)

@app.route("/history/<idWaktu>")
def historyDetail(idWaktu):
    print(idWaktu)
    # tabel waktu
    cursor.execute('SELECT * FROM waktu')
    data = cursor.fetchall()

    # data seluruh paket yang berhasil di analisis
    cursor.execute("SELECT paket.id_paket,ip_src,ip_dst,arrival_time,protocol,domain,tipe_situs,negara_tujuan FROM paket JOIN rangkuman ON paket.id_paket = rangkuman.id_paket JOIN waktu ON waktu.id_waktu = paket.id_waktu WHERE paket.id_waktu = %s",(idWaktu,))
    detailHistory = cursor.fetchall()

    # data bandwidth download dan upload
    cursor.execute("SELECT waktu_cek,download,upload FROM kecepatan WHERE id_waktu=%s", (idWaktu,))
    historyDataBandwidth = cursor.fetchall()

    # rata2 kecepatan download upload
    cursor.execute("SELECT ROUND(AVG(download),3),ROUND(AVG(upload),3) FROM kecepatan WHERE id_waktu = %s", (idWaktu,))
    historyDataRata2Bandwidth = cursor.fetchall()

    # 10 domain yang terdeteksi paling banyak
    cursor.execute("SELECT COUNT(domain),domain,tipe_situs FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE id_waktu = %s AND paket.protocol NOT LIKE 'HTTP' GROUP BY domain ORDER BY COUNT(domain) DESC LIMIT 10",(idWaktu,))
    historyDataWebDikunjungi = cursor.fetchall()

    # 10 domain dengan traffic terbanyak
    cursor.execute("SELECT domain,tipe_situs,SUM(length1+length2) FROM(SELECT ip_dst,domain,tipe_situs,sum(length) as length1 FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE id_waktu = %s GROUP BY ip_dst) as tb1 JOIN(SELECT ip_src,length as length2 FROM paket WHERE id_waktu = %s) as tb2 ON tb1.ip_dst = tb2.ip_src GROUP BY domain ORDER BY SUM(length1+length2) DESC LIMIT 10",(idWaktu,idWaktu,))
    dataWebMenghabiskanBandwidth = cursor.fetchall()

    historyDataWeb = []
    for i in dataWebMenghabiskanBandwidth:
        historyDataWeb.append((i[0], i[1], getFileSize(i[2])))

    # 10 ip yang menghabiskan bandwidth
    cursor.execute("SELECT ip_src,SUM(length1+tb2.length2) AS total FROM( SELECT ip_src,SUM(length) AS length1 FROM paket WHERE id_waktu = %s AND ip_src LIKE '192.168%' GROUP BY ip_src ) AS tb1 JOIN( SELECT ip_dst,SUM(length) AS length2 FROM paket WHERE id_waktu = %s AND ip_dst LIKE '192.168%' GROUP BY ip_dst ) AS tb2 ON tb1.ip_src = tb2.ip_dst GROUP BY ip_src ORDER BY total DESC LIMIT 10",(idWaktu,idWaktu))
    dataIPMenghabiskanBandwidth = cursor.fetchall()

    historyDataIP = []
    for i in dataIPMenghabiskanBandwidth:
        historyDataIP.append((i[0], getFileSize(i[1])))

    # jumlah pengguna
    cursor.execute("SELECT COUNT(DISTINCT ip_src) as jumlah FROM paket WHERE ip_src LIKE '192.168%' AND id_waktu = %s",(idWaktu,))
    historyDataJumlahPengguna = cursor.fetchall()

    return render_template("detailHistory.html",data=data,detailHistory=detailHistory,historyDataBandwidth=historyDataBandwidth,historyDataRata2Bandwidth=historyDataRata2Bandwidth,historyDataWebDikunjungi=historyDataWebDikunjungi,historyDataWeb=historyDataWeb,historyDataIP=historyDataIP,historyDataJumlahPengguna=historyDataJumlahPengguna,idWaktu=idWaktu)

@app.route("/ajaxDetailPaketHistory",methods=["POST","GET"])
def ajaxDetailPaketHistory():
    if request.method == 'POST':
        idPaket = request.form['idPaket']
        print("ini id Paket dari detail paket history:",idPaket)
        cursor.execute("SELECT * FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE paket.id_paket = %s", (idPaket,))
        detailPaket = cursor.fetchall()
        for i in detailPaket:
            print(i)
    return jsonify({'htmlresponse': render_template("detailPaketHistory.html",detailPaket = detailPaket)})

@app.route("/laporan/<idWaktu>",methods=["GET"])
def laporan(idWaktu):
    print("INI ID WAKTU DI LAPORANL:",idWaktu)

    cursor.execute("SELECT waktu_mulai,waktu_selesai FROM waktu WHERE id_waktu = %s",(idWaktu,))
    dataWaktu = cursor.fetchall()

    # Membuat file excel baru
    workbook = xlsxwriter.Workbook("Laporan Capture"+".xlsx")
    worksheet = workbook.add_worksheet('Detail Paket')

    # Membuat style untuk cells
    header_cell_format = workbook.add_format({'bold': True, 'border': True,'text_wrap':True})
    body_cell_format = workbook.add_format({'border': True})
    formatDate = workbook.add_format({'num_format': 'dd/mm/yy hh:mm:ss', 'border': True})
    formatDateTitle = workbook.add_format({'num_format': 'dd/mm/yy hh:mm:ss', 'size': 14,'bold': True, 'font_color': 'red'})
    formatTitle = workbook.add_format({'size': 14,'font_color': 'red'})

    # Membuat ukuran kolom di sheet 1
    worksheet.set_column(0, 0, 5)
    worksheet.set_column(1,1,16)
    worksheet.set_column(2, 2, 15)
    worksheet.set_column(3, 3, 16)
    worksheet.set_column(4, 4, 15)
    worksheet.set_column(5, 5, 10)
    worksheet.set_column(6, 6, 18)
    worksheet.set_column(7, 7, 30)
    worksheet.set_column(8, 8, 30)
    worksheet.set_column(9, 9, 24)
    worksheet.set_column(10, 10, 18)
    worksheet.set_column(11, 11, 20)
    worksheet.set_column(12, 12, 11)

    # Mengambil seluruh data hasil analisis
    cursor.execute("SELECT ip_src,port_src,ip_dst,port_dst,protocol,arrival_time,domain,path,tipe_situs,negara_tujuan,tipe_file,ukuran_file FROM waktu JOIN paket ON paket.id_waktu = waktu.id_waktu JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE waktu.id_waktu = %s AND tipe_situs != %s",(idWaktu,'Website error',))
    header =["No","IP Source","Port Source","IP Destination","Port Destination","Protocol","Arrival Time","Domain","Path","Tipe Situs","Negara Tujuan","Tipe File","Ukuran File"]
    rows = cursor.fetchall()

    title = "Laporan Capture "+str(dataWaktu[0][0])+" ~ "+str(dataWaktu[0][1])
    worksheet.merge_range("A1:E1", title,formatDateTitle)
    row_index = 2
    column_index = 0
    for column_name in header:
        worksheet.write(row_index,column_index,column_name,header_cell_format)
        column_index +=1

    row_index+=1
    for idx,row in enumerate(rows):
        column_index = 1
        worksheet.write(row_index, 0, idx + 1, body_cell_format)
        for idx,column in enumerate(row):
            if idx == 5:
                worksheet.write(row_index,column_index,column,formatDate)
            else:
                worksheet.write(row_index,column_index,column,body_cell_format)
            column_index+=1
        row_index+=1

    print(str(row_index) + ' rows written successfully to ' + worksheet.name)

    # Untuk sheet 2
    worksheet2 = workbook.add_worksheet('Hasil')

    worksheet2.set_column(0, 0, 5)
    worksheet2.set_column(1, 1, 30)
    worksheet2.set_column(2, 2, 30)
    worksheet2.set_column(3, 3, 30)

    # Untuk bandwidth download upload
    worksheet2.merge_range("A1:D1","Bandwidth Download dan Upload",formatTitle)
    header2 = ["No","Tanggal dan Waktu","Download (Mbps)","Upload (Mbps)"]
    cursor.execute("SELECT waktu_cek,download,upload FROM kecepatan WHERE id_waktu=%s",(idWaktu,))
    rows2 = cursor.fetchall()

    row_index = 1
    column_index = 0
    for column_name in header2:
        worksheet2.write(row_index, column_index, column_name, header_cell_format)
        column_index += 1

    row_index += 1
    for idx,row in enumerate(rows2):
        column_index = 1
        worksheet2.write(row_index, 0, idx+1, body_cell_format)
        for idx2,column in enumerate(row):
            if idx2 == 0:
                worksheet2.write(row_index, column_index, column, formatDate)
            else:
                worksheet2.write(row_index, column_index, column, body_cell_format)
            column_index += 1
        row_index += 1

    # Untuk rata2 kecepatan download upload
    cursor.execute("SELECT ROUND(AVG(download),3),ROUND(AVG(upload),3) FROM kecepatan WHERE id_waktu = %s", (idWaktu,))
    rows2 = cursor.fetchall()

    row_index = row_index
    for row in rows2:
        column_index = 2
        worksheet2.merge_range("A"+str(row_index+1)+":B"+str(row_index+1),"Kecepatan rata-rata",body_cell_format)
        for column in row:
            worksheet2.write(row_index, column_index, column, body_cell_format)
            column_index +=1
        row_index +=1

    # Untuk 10 domain yang terdeteksi paling banyak
    row_index +=2
    worksheet2.merge_range("A"+str(row_index)+":D"+str(row_index), "10 Domain yang Terdeteksi Paling Banyak", formatTitle)
    header2 = ["No", "Jumlah Dikunjungi", "Domain", "Tipe Situs"]
    cursor.execute("SELECT COUNT(domain),domain,tipe_situs FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE id_waktu = %s AND paket.protocol NOT LIKE 'HTTP'GROUP BY domain ORDER BY COUNT(domain) DESC LIMIT 10",(idWaktu,))
    rows2 = cursor.fetchall()

    column_index = 0
    for column_name in header2:
        worksheet2.write(row_index,column_index,column_name,header_cell_format)
        column_index +=1

    row_index += 1
    for idx, row in enumerate(rows2):
        column_index = 1
        worksheet2.write(row_index, 0, idx + 1, body_cell_format)
        for column in row:
            worksheet2.write(row_index, column_index, column, body_cell_format)
            column_index += 1
        row_index += 1

    # Untuk 10 domain dengan trafik terbanyak
    row_index +=2
    worksheet2.merge_range("A" + str(row_index) + ":D" + str(row_index), "10 Domain dengan Traffic Terbanyak",formatTitle)
    header2 = ["No", "Domain", "Tipe Situs", "Bandwidth"]
    cursor.execute("SELECT domain,tipe_situs,SUM(length1+length2) FROM(SELECT ip_dst,domain,tipe_situs,sum(length) as length1 FROM paket JOIN rangkuman ON rangkuman.id_paket = paket.id_paket WHERE id_waktu = %s GROUP BY ip_dst) as tb1 JOIN(SELECT ip_src,length as length2 FROM paket WHERE id_waktu = %s) as tb2 ON tb1.ip_dst = tb2.ip_src GROUP BY domain ORDER BY SUM(length1+length2) DESC LIMIT 10",(idWaktu,idWaktu,))
    dataWebMenghabiskanBandwidth = cursor.fetchall()

    rows2 = []
    for i in dataWebMenghabiskanBandwidth:
        rows2.append((i[0],i[1],getFileSize(i[2])))

    column_index = 0
    for column_name in header2:
        worksheet2.write(row_index, column_index, column_name, header_cell_format)
        column_index += 1

    row_index += 1
    for idx, row in enumerate(rows2):
        column_index = 1
        worksheet2.write(row_index, 0, idx + 1, body_cell_format)
        for column in row:
            worksheet2.write(row_index, column_index, column, body_cell_format)
            column_index += 1
        row_index += 1

    # Untuk 10 pengguna menghabiskan bandwidth
    row_index += 2
    worksheet2.merge_range("A" + str(row_index) + ":D" + str(row_index), "10 Pengguna yang Menghabiskan Bandwidth",formatTitle)
    cursor.execute("SELECT COUNT(DISTINCT ip_src) as jumlah FROM paket WHERE ip_src LIKE '192.168%' AND id_waktu = %s",(idWaktu,))
    rows2 = cursor.fetchone()

    row_index +=1
    worksheet2.merge_range("A" + str(row_index) + ":C" + str(row_index), "Jumlah Pengguna Aktif yang Terdeteksi: "+str(rows2[0]))

    row_index += 1
    waktu = str(dataWaktu[0][0]) + " ~ " + str(dataWaktu[0][1])
    worksheet2.merge_range("A" + str(row_index) + ":C" + str(row_index), "Terdeteksi pada : "+waktu)

    header2 = ["No", "IP Address", "Bandwidth"]
    cursor.execute("SELECT ip_src,SUM(length1+tb2.length2) AS total FROM( SELECT ip_src,SUM(length) AS length1 FROM paket WHERE id_waktu = %s AND ip_src LIKE '192.168%' GROUP BY ip_src ) AS tb1 JOIN( SELECT ip_dst,SUM(length) AS length2 FROM paket WHERE id_waktu = %s AND ip_dst LIKE '192.168%' GROUP BY ip_dst ) AS tb2 ON tb1.ip_src = tb2.ip_dst GROUP BY ip_src ORDER BY total DESC LIMIT 10",(idWaktu,idWaktu))
    dataIPMenghabiskanBandwidth = cursor.fetchall()
    rows2 = []
    for i in dataIPMenghabiskanBandwidth:
        rows2.append((i[0], getFileSize(i[1])))

    column_index = 0
    for column_name in header2:
        worksheet2.write(row_index, column_index, column_name, header_cell_format)
        column_index += 1

    row_index += 1
    for idx, row in enumerate(rows2):
        column_index = 1
        worksheet2.write(row_index, 0, idx + 1, body_cell_format)
        for column in row:
            worksheet2.write(row_index, column_index, column, body_cell_format)
            column_index += 1
        row_index += 1

    print(str(row_index) + ' rows written successfully to ' + worksheet2.name)
    # Closing workbook
    workbook.close()
    return send_file(path_or_file=workbook.filename,as_attachment=True)

@socketio.on('message')
def capture(msg):
    # program capturer
    try:
        cap = ps.LiveCapture(Main_Interface,bpf_filter=Bpf_filter)
        global packets
        global captureTime
        global id_waktu
        # read json
        msg = json.loads(msg)
        # get json type
        action = msg['action']
        if action == 'start':
            startCaptureTime = datetime.datetime.now()
            captureTime['startTime'] = startCaptureTime.strftime("%Y-%m-%d %X")
            print(captureTime['startTime'])
            insertWaktuMulai = ('INSERT INTO waktu (waktu_mulai,waktu_selesai) VALUES (%s,%s)')
            waktuValue = (captureTime['startTime'],"NULL")
            cursor.execute(insertWaktuMulai, waktuValue)
            db.commit()

            # Get idWaktu untuk idWaktu di table paket
            id_waktu = cursor.lastrowid
            print("id_waktu =",id_waktu)
            status = {
                'status': 'start',
                'time': startCaptureTime.strftime("%A,%d %B %Y - %X")
            }
            emit('capture', json.dumps(status))

            packets = {}
            threading.Thread(target=runCheckBandwidth,args=(id_waktu,)).start()
            for pkt in cap:
                try:
                    frame = pkt.frame_info
                    ip = pkt.ip

                    if pkt.highest_layer == 'DNS':
                        # ini paket DNS
                        udp = pkt.udp
                        dns = pkt.dns
                        frameNumber = frame.number
                        dnsName = dns.qry_name
                        print("THIS DNS DOMAIN:",dnsName)
                        if udp.dstport == '53':
                            # dns query
                            try:
                                ipSrc = ip.src
                                portSrc = udp.srcport
                                ipDst = socket.gethostbyname(dnsName)
                                print("THIS IP DST SOCKET GETHOSTBYNAME:",ipDst)
                                portDst = udp.dstport
                                protocol = pkt.highest_layer
                                arrivalTime = str(pkt.sniff_time)
                                length = pkt.length

                                packets[frameNumber] = {}
                                packets[frameNumber]['ipSrc'] = ipSrc
                                packets[frameNumber]['portSrc'] = portSrc
                                packets[frameNumber]['ipDst'] = ipDst
                                packets[frameNumber]['portDst'] = portDst
                                packets[frameNumber]['protocol'] = protocol
                                packets[frameNumber]['arrivalTime'] = arrivalTime
                                packets[frameNumber]['length'] = length
                                packets[frameNumber]['domain'] = dnsName
                                # print('Paket DNS query',packets[frameNumber])
                                # insert to table
                                insertToTablePacket(packets[frameNumber],id_waktu)
                            except socket.gaierror as e:
                                # tidak mendapatkan ipDst dari socket
                                print("ERROR GET IP DST FROM SOCKET")
                                pass
                        elif udp.srcport == '53':
                            # dns response
                            try:
                                ipSrc = socket.gethostbyname(dnsName)
                                portSrc = udp.srcport
                                ipDst = ip.dst
                                portDst = udp.dstport
                                protocol = pkt.highest_layer
                                arrivalTime = str(pkt.sniff_time)
                                length = pkt.length

                                packets[frameNumber] = {}
                                packets[frameNumber]['ipSrc'] = ipSrc
                                packets[frameNumber]['portSrc'] = portSrc
                                packets[frameNumber]['ipDst'] = ipDst
                                packets[frameNumber]['portDst'] = portDst
                                packets[frameNumber]['protocol'] = protocol
                                packets[frameNumber]['arrivalTime'] = arrivalTime
                                packets[frameNumber]['length'] = length

                                insertToTablePacket(packets[frameNumber], id_waktu)
                            except socket.gaierror as e:
                                # tidak mendapatkan ipSrc dari socket
                                pass
                            # print('packet DNS response',packets[frameNumber])
                    elif pkt.highest_layer == 'HTTP':
                        # ini paket HTTP
                        tcp = pkt.tcp
                        http = pkt.http
                        frameNumber = frame.number
                        # HTTP query
                        if tcp.dstport == '80':
                            # host : nama domain
                            domain = http.host
                            # file : nama file yang kemungkinan diakses
                            path = http.request_uri
                            ipSrc = ip.src
                            portSrc = tcp.srcport
                            ipDst = ip.dst
                            portDst = tcp.dstport
                            protocol = pkt.highest_layer
                            arrivalTime = str(pkt.sniff_time)
                            length = pkt.length

                            packets[frameNumber] = {}
                            packets[frameNumber]['ipSrc'] = ipSrc
                            packets[frameNumber]['portSrc'] = portSrc
                            packets[frameNumber]['ipDst'] = ipDst
                            packets[frameNumber]['portDst'] = portDst
                            packets[frameNumber]['protocol'] = protocol
                            packets[frameNumber]['arrivalTime'] = arrivalTime
                            packets[frameNumber]['length'] = length
                            packets[frameNumber]['domain'] = domain
                            packets[frameNumber]['path'] = path

                            insertToTablePacket(packets[frameNumber], id_waktu)
                        # HTTP response
                        elif tcp.srcport == '80':
                            ipSrc = ip.src
                            portSrc = tcp.srcport
                            ipDst = ip.dst
                            portDst = tcp.dstport
                            protocol = pkt.highest_layer
                            arrivalTime = str(pkt.sniff_time)
                            length = pkt.length

                            packets[frameNumber] = {}
                            packets[frameNumber]['ipSrc'] = ipSrc
                            packets[frameNumber]['portSrc'] = portSrc
                            packets[frameNumber]['ipDst'] = ipDst
                            packets[frameNumber]['portDst'] = portDst
                            packets[frameNumber]['protocol'] = protocol
                            packets[frameNumber]['arrivalTime'] = arrivalTime
                            packets[frameNumber]['length'] = length

                            insertToTablePacket(packets[frameNumber], id_waktu)
                    else:
                        pass
                except AttributeError as e:
                    print("INI PAKET DENGAN IP IPV6:", e)
        elif action == 'stop':
            print('capture has stoped')
            try:
                # Memberhentikan process tshark dan dumpcap
                os.system('taskkill /IM tshark.exe /F')
                os.system('taskkill /IM dumpcap.exe /F')

                # Menghentikan schedule
                schedule.CancelJob
                schedule.clear()

                # Menunda 2 detik untuk waktu update tabel waktu
                time.sleep(2)

                stopCaptureTime = datetime.datetime.now()
                captureTime['endTime'] = stopCaptureTime.strftime("%Y-%m-%d %X")
                # Update waktu_selsai
                updateTabelWaktu = ('UPDATE waktu SET waktu_selesai = %s WHERE id_waktu = %s')
                valueUpdate = (captureTime['endTime'], id_waktu)
                cursor.execute(updateTabelWaktu, valueUpdate)
                db.commit()

                status = {
                    'status': 'stop',
                    'time': stopCaptureTime.strftime("%A,%d %B %Y - %X")
                }
                emit('capture', json.dumps(status))

                cursor.execute("SELECT COUNT(id_paket) FROM paket WHERE id_waktu = %s",(id_waktu,))
                data = cursor.fetchall();

                # Kirim paket yang tercapture
                status = {
                    'capturePacket': 'false',
                    'jumlahPaket': data[0],
                    'info': 'Melakukan proses analisis harap tunggu sampai selesai'
                }
                emit('capture', json.dumps(status))
                insertToTableKecepatan(id_waktu)
                print('berhasil insert kecepatan')
                analayzer()
            except:
                print('Gagal menganalisis')
            print('jumlah paket:', len(packets))
    except ps.capture.capture.TSharkCrashException as e:
        print("pyshak crash:",e)
    except ps.capture.capture.asyncTimeoutError as e:
        print("asyncTimeout error:",e)

# negara tujuan
def getLocation(ip):
    address = geolite2.lookup(ip)
    if address is not None:
        try:
            code_country = address.country
            country_name = pycountry.countries.get(alpha_2=code_country)
            return country_name.name
        except:
            return None

# tipe situs
# menghitung persen kesamaan dengan keywords
def calculatePercent(x,y):
    try:
        result = float(y)/float(x)
        result = result*100
        return result
    except:
        return 0

def findSiteType(text):
    try:
        allText = text
        # Ubah allText ke bahasa indonesia
        if allText != "":
            translator = Translator()
            translation = translator.translate(allText.lower(), dest='id')
            allText = translation.text

        if allText == 'internet positif - positifkan diri kamu':
            return "Internet positif"

        allKeywordSite = KeywordProcessor(case_sensitive=False)
        for word in keywords:
            allKeywordSite.add_keyword(word)

        beritaKeyword = KeywordProcessor(case_sensitive=False)
        for word in berita:
            beritaKeyword.add_keyword(word)

        jualBeliKeyword = KeywordProcessor(case_sensitive=False)
        for word in jualBeli:
            jualBeliKeyword.add_keyword(word)

        edukasiKeyword = KeywordProcessor(case_sensitive=False)
        for word in edukasi:
            edukasiKeyword.add_keyword(word)

        hiburanKeyword = KeywordProcessor(case_sensitive=False)
        for word in hiburan:
            hiburanKeyword.add_keyword(word)

        analisisKeyword = KeywordProcessor(case_sensitive=False)
        for word in analisis:
            analisisKeyword.add_keyword(word)

        wordCountAllKW = len(allKeywordSite.extract_keywords(allText))
        wordCountBeritaKW = len(beritaKeyword.extract_keywords(allText))
        wordCountJualBeliKW = len(jualBeliKeyword.extract_keywords(allText))
        wordCountEdukasiKW = len(edukasiKeyword.extract_keywords(allText))
        wordCountHiburanKW = len(hiburanKeyword.extract_keywords(allText))
        wordCountAnalisisKW = len(analisisKeyword.extract_keywords(allText))

        percentageBerita = float(calculatePercent(wordCountAllKW, wordCountBeritaKW))
        percentageJualBeli = float(calculatePercent(wordCountAllKW, wordCountJualBeliKW))
        percentageEdukasi = float(calculatePercent(wordCountAllKW, wordCountEdukasiKW))
        percentageHiburan = float(calculatePercent(wordCountAllKW, wordCountHiburanKW))
        percentageAnalisis = float(calculatePercent(wordCountAllKW,wordCountAnalisisKW))

        if wordCountAllKW == 0:
            return "Kategori tidak ditemukan"
        else:
            if percentageEdukasi >= percentageBerita and percentageEdukasi >= percentageJualBeli and percentageEdukasi >= percentageHiburan and percentageEdukasi >= percentageAnalisis:
                return "Situs Edukasi"
            elif percentageJualBeli >= percentageBerita and percentageJualBeli >= percentageEdukasi and percentageJualBeli >= percentageHiburan and percentageJualBeli >= percentageAnalisis:
                return "Situs Jual Beli"
            elif percentageBerita >= percentageJualBeli and percentageBerita >= percentageEdukasi and percentageBerita >= percentageHiburan and percentageBerita >= percentageAnalisis:
                return "Situs Berita"
            elif percentageHiburan >= percentageBerita and percentageHiburan >= percentageJualBeli and percentageHiburan >= percentageEdukasi and percentageHiburan >= percentageAnalisis:
                return "Situs Hiburan"
            elif percentageAnalisis >= percentageEdukasi and percentageAnalisis >= percentageBerita and percentageAnalisis >= percentageJualBeli and percentageAnalisis >= percentageHiburan:
                return "Situs Analisis dan Iklan"
    except:
        return "Kategori tidak ditemukan"

def getSiteType(url):
    getUrl = 'https://'+str(url)
    titleWebsite = ""
    titlePropWebsite = ""
    descPropWebsite = ""
    descWebsite1 = ""
    descWebsite2 = ""
    allText = ""
    contex = ssl.create_default_context()
    contex.check_hostname = False
    contex.verify_mode = ssl.CERT_NONE
    # header untuk meminimalisir error
    header = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36',"Content-Type": "application/x-www-form-urlencoded"}
    try:
        # Menggunakan urllib
        # getproxies() untuk mencegah error connectionResetrror
        urllib.request.getproxies()
        source = urllib.request.Request(getUrl,headers=header)
        # Contex untuk SSL error
        htmlSource = urllib.request.urlopen(source,context=contex,timeout=120)
        readSource = htmlSource.read()
        soup = BeautifulSoup(readSource,'html.parser')

        titleWebsite = soup.title
        titleWebsite = titleWebsite.string if titleWebsite is not None else None
        titlePropWebsite = soup.find('meta',attrs={'property': 'og:title'})
        titlePropWebsite = titlePropWebsite['content'] if titlePropWebsite is not None else None
        descPropWebsite = soup.find('meta', attrs={'property': 'og:description'})
        descPropWebsite = descPropWebsite['content'] if descPropWebsite is not None else None
        descWebsite1 = soup.find('meta', attrs={'name': 'description'})
        descWebsite1 = descWebsite1['content'] if descWebsite1 is not None else None
        descWebsite2 = soup.find('meta', attrs={'name': 'Description'})
        descWebsite2 = descWebsite2['content'] if descWebsite2 is not None else None

        # Cek kesamaan title dan prop:title
        if titleWebsite is not None and titlePropWebsite is not None:
            if titleWebsite == titlePropWebsite:
                allText += titleWebsite+" "
            else:
                allText += titleWebsite+" "+titlePropWebsite+" "
        elif titleWebsite is not None and titlePropWebsite is None:
            allText+= titleWebsite+" "
        elif titlePropWebsite is not None and titleWebsite is None:
            allText += titlePropWebsite+" "

        # Cek kesamaan prop:description dan name:description (jika ke 2nya ada biasanya sama)
        if descPropWebsite is not None and descWebsite1 is not None:
            if descPropWebsite == descWebsite1:
                allText += descPropWebsite+" "
            else:
                allText += descPropWebsite+" "+descWebsite1
        elif descPropWebsite is not None and descWebsite1 is None:
            allText += descPropWebsite+" "
        elif descWebsite1 is not None and descPropWebsite is None:
            allText += descWebsite1+" "

        # Jika Description2 ada
        if descWebsite2 is not None:
            allText += descWebsite2+" "

        result = findSiteType(allText)
        return result
        http.client.HTTPConnection.close()
    except socket.timeout:
        print("Socket Timeout getSiteType")
        return "Kategori tidak ditemukan"
    except urllib.error.URLError as e:
        print("urllib error getSiteType",e)
        return "Website error"
    except ConnectionResetError as e:
        print("urllib error getSiteType:",e)
        return "Website error"
    except http.client.BadStatusLine as e:
        print("urllib error getSiteType:", e)
        return "Website error"

# tipe file download
def getFileType(url):
    result = []
    try:
        getFile = urllib.request.urlopen(url)
        contentFile = getFile.info()['Content-Disposition']
        print(getFile.info()['Content-Type'])

        if contentFile != None:
            namaFile = getFile.info().get_filename()
            result.append(namaFile)
            ukuranFile = getFile.info()['Content-Length']
            result.append(ukuranFile)
        else:
            contentType = getFile.info()['Content-Type']
            if contentType != None and re.split(";",contentType)[0] != "text/html":
                splitUrl = re.split("/", url)
                namaFile = splitUrl[len(splitUrl)-1]
                result.append(namaFile)
                ukuranFile = getFile.info()['Content-Length']
                result.append(ukuranFile)
            elif contentType == None:
                splitUrl = re.split("/", url)
                namaFile = splitUrl[len(splitUrl) - 1]
                result.append(namaFile)
                ukuranFile = getFile.info()['Content-Length']
                result.append(ukuranFile)
            else:
                result.append(None)
                result.append(None)
        return result
        http.client.HTTPConnection.close()
    except urllib.error.HTTPError as e:
        print("ERROR GET NAMA FILE :", e.errno)
    except urllib.error.URLError as e:
        print("ERROR GET NAMA FILE :", e.errno)
    except socket.timeout as e:
        print("ERROR GET NAMA FILE",e.errno)
    except http.client.RemoteDisconnected as e:
        print("ERROR GET NAMA FILE", e.errno)
    except ConnectionResetError as e:
        print("ERROR GET NAMA FILE", e.errno)

    result.append(None)
    result.append(None)
    return result

def getFileSize(size):
    if size == None:
        return None
    else:
        size = int(size)
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return "%3.1f %s" % (size, x)
            size /= 1024.0

# table
def checkTable(tableName):
    db.cursor()
    checkTable = "SHOW TABLES LIKE '"+tableName+"'"
    cursor.execute(checkTable)
    result = cursor.fetchone()
    if result:
        return True;
    else:
        return False

def createTable():
    # Create tabel
    tableName = ["waktu","paket","rangkuman","kecepatan","pengguna"]
    for i in tableName:
        if i == 'waktu':
            checkWaktuTable = checkTable(i)
            if checkWaktuTable == False:
                db.cursor()
                tabelWaktu = ('CREATE TABLE waktu (id_waktu int PRIMARY KEY AUTO_INCREMENT,waktu_mulai datetime,waktu_selesai datetime)')
                cursor.execute(tabelWaktu)
        elif i == 'paket':
            checkPaketTable = checkTable(i)
            if checkPaketTable == False:
                db.cursor()
                tabelPaket = ('CREATE TABLE paket (id_paket int PRIMARY KEY AUTO_INCREMENT,ip_src VARCHAR(19),port_src VARCHAR(5),ip_dst VARCHAR(19),port_dst VARCHAR(5),protocol VARCHAR(15),arrival_time datetime,length int,id_waktu int, FOREIGN KEY (id_waktu) REFERENCES waktu(id_waktu))')
                cursor.execute(tabelPaket)
        elif i == 'rangkuman':
            checkRangkumanTable = checkTable(i)
            if checkRangkumanTable == False:
                db.cursor()
                tabelRangkuman = ('CREATE TABLE rangkuman (id_rangkuman int PRIMARY KEY AUTO_INCREMENT,domain VARCHAR(30),tipe_situs VARCHAR(25),negara_tujuan VARCHAR(20),tipe_file VARCHAR(20),ukuran_file VARCHAR(20),id_paket int, FOREIGN KEY (id_paket) REFERENCES paket(id_paket))')
                cursor.execute(tabelRangkuman)
        elif i == 'kecepatan':
            checkKecepatanTable = checkTable(i)
            if checkKecepatanTable == False:
                db.cursor()
                tabelKecepatan = ('CREATE TABLE kecepatan (id_kecepatan int PRIMARY KEY AUTO_INCREMENT,waktu_cek datetime,download float,upload float,id_waktu int, FOREIGN KEY (id_waktu) REFERENCES waktu(id_waktu))')
                cursor.execute(tabelKecepatan)
        elif i == 'pengguna':
            checkPenggunaTable = checkTable(i)
            if checkPenggunaTable == False:
                db.cursor()
                tabelPengguna = ('CREATE TABLE pengguna (id_pengguna int PRIMARY KEY AUTO_INCREMENT, username VARCHAR(10),password VARCHAR(10))')
                cursor.execute(tabelPengguna)

                insertDefaultPengguna = ('INSERT INTO pengguna (username,password) VALUES (%s,%s)')
                penggunaValue = ("admin", "admin")
                cursor.execute(insertDefaultPengguna, penggunaValue)
                db.commit()

# insert
def insertToTablePacket(packets,idWaktu):
    if packets['protocol'] == 'DNS':
        if packets['portDst'] == '53':
            insertPacket = ('INSERT INTO paket (ip_src,port_src,ip_dst,port_dst,protocol,arrival_time,domain,length,id_waktu) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)')
            packetValue = (str(packets['ipSrc']), str(packets['portSrc']), str(packets['ipDst']), str(packets['portDst']),str(packets['protocol']),str(packets['arrivalTime']), str(packets['domain']),str(packets['length']), idWaktu)
            cursor.execute(insertPacket, packetValue)
            db.commit()
        else:
            insertPacket = ('INSERT INTO paket (ip_src,port_src,ip_dst,port_dst,protocol,arrival_time,length,id_waktu) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)')
            packetValue = (str(packets['ipSrc']), str(packets['portSrc']), str(packets['ipDst']), str(packets['portDst']),str(packets['protocol']), str(packets['arrivalTime']), str(packets['length']),
            idWaktu)
            cursor.execute(insertPacket, packetValue)
            db.commit()
    elif packets['protocol'] == 'HTTP':
        if packets['portDst'] == '80':
            insertPacket = ('INSERT INTO paket (ip_src,port_src,ip_dst,port_dst,protocol,arrival_time,domain,path,length,id_waktu) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)')
            packetValue = (str(packets['ipSrc']), str(packets['portSrc']), str(packets['ipDst']), str(packets['portDst']),str(packets['protocol']), str(packets['arrivalTime']),str(packets['domain']),str(packets['path']),str(packets['length']), idWaktu)
            cursor.execute(insertPacket, packetValue)
            db.commit()
        else:
            insertPacket = ('INSERT INTO paket (ip_src,port_src,ip_dst,port_dst,protocol,arrival_time,length,id_waktu) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)')
            packetValue = (str(packets['ipSrc']), str(packets['portSrc']), str(packets['ipDst']), str(packets['portDst']),str(packets['protocol']), str(packets['arrivalTime']),str(packets['length']), idWaktu)
            cursor.execute(insertPacket, packetValue)
            db.commit()

def insertToTableKecepatan(idWaktu):
    # Check kecepatan download dan upload

    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        waktuCheck = datetime.datetime.now().strftime("%Y-%m-%d %X")
        download = round(st.download() / 1024 / 1024, 3)
        upload = round(st.upload() / 1024 / 1024, 3)
        insertKecepatan = ('INSERT INTO kecepatan(waktu_cek,download,upload,id_waktu) VALUES (%s,%s,%s,%s)')
        kecepatanValue = (str(waktuCheck),download,upload,idWaktu)
        cursor.execute(insertKecepatan,kecepatanValue)
        db.commit()
    except speedtest.ConfigRetrievalError as e:
        print('error speed test:',e)

def runCheckBandwidth(idWaktu):
    insertToTableKecepatan(idWaktu)
    schedule.every(5).minutes.do(insertToTableKecepatan, idWaktu)
    while True:
        schedule.run_pending()
        time.sleep(1)

# program analyzer
def analayzer():
    print('masuk analyzer')
    paketAnalisis = 0
    # Mengambil waktu terakhir capture
    cursor.execute('SELECT id_waktu FROM waktu ORDER BY id_waktu DESC LIMIT 1')
    getIdWaktu = cursor.fetchone()
    idWaktu = getIdWaktu[0]
    cursor.execute('SELECT id_paket,ip_src,port_src,ip_dst,port_dst,protocol,arrival_time,domain,path FROM paket JOIN waktu ON waktu.id_waktu = paket.id_waktu WHERE paket.id_waktu = %s',(idWaktu,))
    data = cursor.fetchall()

    for idx,packets in enumerate(data):
        if packets[4] == '53' and packets[5] == 'DNS':
            # Analisis DNS
            paketAnalisis += 1
            idPaket = packets[0]
            location = getLocation(packets[3])
            typeSite = getSiteType(packets[7])
            if typeSite != 'Website error':
                insertRangkumanDNS = ('INSERT INTO rangkuman (tipe_situs,negara_tujuan,id_paket) VALUES (%s,%s,%s)')
                valueDNS = (str(typeSite),str(location),str(idPaket))
                cursor.execute(insertRangkumanDNS,valueDNS)
                db.commit()
        elif packets[4] == '80' and packets[5] == 'HTTP':
            # Analisis HTTP
            paketAnalisis += 1
            fullDomain = "http://"+packets[7]+packets[8]

            idPaket = packets[0]
            location = getLocation(packets[3])
            typeSite = getSiteType(packets[7])
            file = getFileType(fullDomain)
            fileName = file[0]
            sizeFile = getFileSize(file[1])

            if typeSite != 'Website error':
                insertRangkumanHTTP = ('INSERT INTO rangkuman (tipe_situs,negara_tujuan,tipe_file,ukuran_file,id_paket) VALUES (%s,%s,%s,%s,%s)')
                valueHttp = (str(typeSite),str(location),str(fileName),str(sizeFile),str(idPaket))
                cursor.execute(insertRangkumanHTTP, valueHttp)
                db.commit()

        status = {
            'status': 'proses',
            'jumlahPaket': len(data),
            'info': idx+1,
        }
        emit('capture', json.dumps(status))

if __name__ == "__main__":
    excel.init_excel(app)
    socketio.run(app,debug=True)