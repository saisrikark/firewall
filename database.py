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
            user=username,
            database="honeypot"
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

    def insert_into_packets(self, values_tuple):

        sql_command = 'INSERT INTO `packets`(`timestamp`, `src_ip`, `dest_ip`, `src_port`, `dest_port`, `src_mac`, `dest_mac`) VALUES ("1","1","1","1","1","1","1")'
        r = self._execute_sql_command(sql_command)
        print(r)



