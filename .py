import MySQLdb

try:
    conn = MySQLdb.connect(
        host="localhost",
        user="flaskuser",
        passwd="flaskpassword",
        db="steganografi_db"
    )
    print("Connection successful")
    conn.close()
except MySQLdb.OperationalError as e:
    print(f"Error: {e}")
