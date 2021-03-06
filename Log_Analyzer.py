import mysql.connector
from mysql.connector import errorcode
import datetime

#opening connection to mysql database
def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user='root', password='P@ssw0rd',
                                      host='192.168.252.223', database='SIEM')
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None

#checking for logs containing specific ports
def SpecificPortQuery():
    query = ("""SELECT * FROM fwlogs WHERE PORT = 444 OR PORT = 4445""")

    cnx,cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    for r in result:
        print r

#checking for a PortScan attack
def PortScanQuery():
    query = ("""SELECT SRC_IP,COUNT(SRC_IP) FROM (SELECT DISTINCT SRC_IP,DST_IP,PORT FROM fwlogs AS A) AS B GROUP BY SRC_IP""")


    cnx, cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    for r in result:
        print r[0],"ATTEMPTED TO CONNECT TO A DST_IP ON",r[1],"DIFFERENT PORTS"

#checking for a PingSweep attack
def PingSweep():
    query = ("""SELECT SRC_IP,COUNT(SRC_IP) FROM fwlogs WHERE PORT = 0 AND SRC_IP IN (SELECT DISTINCT SRC_IP FROM fwlogs)GROUP BY SRC_IP""")

    cnx, cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    for r in result:
        if r[1] >= 10:
            print r,"PING SWEEP ATTACK!"
        else:
            print r


def main():
    SpecificPortQuery()
    PortScanQuery()
    PingSweep()


if __name__ == '__main__':
    main()