import mysql.connector


class SqlDatabase:

    def __init__(self, username, password, host="localhost"):

        self.username = None
        self.password = None
        self.host = None
        self.current_database = None
        self.connection = self.make_connection(username, password, host)

    def make_connection(self, username, password, host):

        connection = mysql.connector.connect(
            host=host,
            passwd=password,
            user=username
        )

        self.username = username
        self.password = password
        self.host = host

        return connection

    def create_database(self, database):

        try:
            mycursor = self.connection.cursor()
            command = "CREATE DATABASE {0}".format(database)
            mycursor.execute(command)

        except mysql.connector.Error as err:
            print("Failed creating database: {}".format(err))
            exit(1)

    def create_table(self, table_name, colums_dict):
        pass

    @property
    def my_database(self):

        if self.current_database is None:
            raise Exception("Database Not Yet Set")

        return self.current_database

    @my_database.setter
    def my_database(self, db_name):
        cursor = self.connection.cursor()
        cursor.execute("SHOW DATABASES")
        dbs = list(cursor)

        for i in dbs:
            if i[0] == db_name:
                self.current_database = db_name
                self.connection.database = db_name
                return

        raise Exception("No Database Named {0}".format(db_name))

    
