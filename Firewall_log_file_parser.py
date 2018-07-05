import mysql.connector
from mysql.connector import errorcode

#connecting to mysql database
def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user='root', password='P@ssw0rd',
                                      host='10.0.0.2', database='SIEM')
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None



cnx, cursor = ConnectToDB()

#creating a dictionary from an existing log file
def DicFromLogLine(path):
    #creates dic from log
    open_file = open(path, 'r')
    read_line = open_file.readlines()
    #all_logs_dics = []
    log_dic = {}
    for line in read_line:
        val = line.split()
        log_dic['DATE'] = val[0] + ' ' + val[1]
        log_dic['SRC_IP'] = val[2]
        log_dic['DST_IP'] = val[3]
        log_dic['PORT'] = val[4]
        log_dic['ACTION'] = val[5]
        log_dic['PROTOCOL'] = PortNumToProtocol(val[4])

        InsertToDB(log_dic,cnx,cursor)
    #all_logs_dics.append(log_dic)
    return log_dic


#defining known and unknown port protocols
def PortNumToProtocol(num):
    PORTS = {'21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '67': 'DHCP', '53': 'DNS', '80': 'HTTP', '445'
    : 'SMB', '443': 'HTTPS'}
    for key,value in PORTS.iteritems():
        if key == num:
            return value
    else:
        return 'UNKNOWN'



#inserting the log information into the database
def InsertToDB(log, cnx, cursor):
    add_log = ("""INSERT INTO fwlogs (ID, DATE, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION) VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    cursor.execute(add_log, log)
    cnx.commit()


def main():

    log = 'Ping_Sweep.txt'
    DicFromLogLine(log)
    ConnectToDB()


if __name__ == '__main__':
    main()