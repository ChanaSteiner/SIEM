import mysql.connector
from mysql.connector import errorcode
import datetime


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


def SpecificPortQuery():
    query = ("""SELECT * FROM fwlogs WHERE PORT = 444 OR PORT = 4445""")

    cnx,cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    for r in result:
        print r


def PortScanQuery():
    query = ("""SELECT SRC_IP,COUNT(SRC_IP) FROM (SELECT DISTINCT SRC_IP,DST_IP,PORT FROM fwlogs AS A) AS B GROUP BY SRC_IP""")


    cnx, cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    for r in result:
        print r[0],"ATTEMPTED TO CONNECT TO A DST_IP ON",r[1],"DIFFERENT PORTS"

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


def GetTimeDifferences(start, end):
    c = end - start
    return divmod(c.days * 86400 + c.seconds, 60)



def PingSweepTime():
    query = ( """SELECT DATE,SRC_IP,COUNT(SRC_IP) FROM fwlogs WHERE PORT = 0 AND SRC_IP IN (SELECT DISTINCT SRC_IP FROM fwlogs)GROUP BY SRC_IP,DATE""")

    cnx, cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()

    for r in result:
        start = result[]
        end = result []
        print GetTimeDifferences(start,end)






def main():
    SpecificPortQuery()
    PortScanQuery()
    PingSweep()
    PingSweepTime()


if __name__ == '__main__':
    main()