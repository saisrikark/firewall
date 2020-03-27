import mysql.connector


class SqlDatabase:

    def __init__(self, username, password, host="localhost"):

        self.username = None
        self.password = None
        self.host = None
        self.current_database = None
        self.connection = self._make_connection(username, password, host)

    def _make_connection(self, username, password, host):

        connection = mysql.connector.connect(
            host=host,
            passwd=password,
            user=username
        )

        self.username = username
        self.password = password
        self.host = host

        return connection

    def _execute_sql_command(self, command, args=None):

        cursor = self.connection.cursor()
        cursor.execute(command, args)
        return cursor

    def create_database(self, database):

        try:
            command = "CREATE DATABASE {0}".format(database)
            self._execute_sql_command(command)

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

        cursor = self._execute_sql_command("SHOW DATABASES")
        dbs = list(cursor)

        for i in dbs:
            if i[0] == db_name:
                self.current_database = db_name
                self.connection.database = db_name
                return

        raise Exception("No Database Named {0}".format(db_name))

    def insert_packets(self, table_name, values_tuple):

        sql_command = "INSERT INTO " + table_name + " VALUES(%s,%s,%s,%s,%s,%s,%s)"
        self._execute_sql_command(sql_command, args=values_tuple)
        self.connection.commit()

    def get_packets(self, table_name):

        sql_command = "SELECT * FROM " + table_name
        cursor = self._execute_sql_command(sql_command)
        return list(cursor)

    def check_if_malicious_ip(ip):

        sql_command = "SELECT TOP 1 src_ip FROM malicious_ip WHERE src_ip = " + ip;
        cursor = self._execute_sql_command(sql_command)
        return list(cursor)

    def update_table_with_packet(self, table_name, packet):
        pass

    def fetch_row_from_table(self, table_name, packet):
        return () 

