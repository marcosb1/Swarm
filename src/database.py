import psycopg2.extras


class Database:
    def __init__(self, db_type, username, password, host, port=None, db_name=None):
        """
        A database wrapper for Swarm 
        :param username: Username needed for database
        :param password: Password needed for database
        :param host: IP of the given database
        :param port: Port if needed to connect to database
        :param db_name: The database name needed to connect too
        """

        self.db_type = db_type.lower()
        self.username = username
        self.password = password
        self.host = host
        self.port = port
        self.db_name = db_name
        self.connection_object = None

    def create_db_connection(self):
        db = None

        if self.db_type == "postgres":
            db = psycopg2.connect("dbname=" + self.db_name + " user=" + self.username
                                  + " host=" + self.host + " password=" + self.password)

        self.connection_object = db

    def query_fetch(self, statement, args=None, fetch=None):
        if self.connection_object is None:
            return None
        elif self.db_type == "postgres":
            cursor = self.connection_object.cursor(cursor_factory=psycopg2.extras.DictCursor)

            cursor.execute(
                statement,
                (args,)
            )

            if fetch == "all" or fetch is None:
                return cursor.fetchall()
            elif fetch == "one":
                return cursor.fetchone()

    def query_commit(self, statment, args=None):
        if self.connection_object is None:
            return None
