import mysql.connector
from mysql.connector import errorcode


def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user='root', password='P@ssw0rd',
                                      host='192.168.84.133', database='SIEM')
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
    query = ("""SELECT DISTINCT SRC_IP,DST_IP FROM fwlogs WHERE PORT = * """)

    PortScanDic['']
    cnx, cursor = ConnectToDB()
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    for r in result:
        print r

def PingSweep():
    pass

def PingSweepTime():
    pass



def main():
    SpecificPortQuery()
    PortScanQuery()


if __name__ == '__main__':
    main()