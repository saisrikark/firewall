from database import SqlDatabase

sql_object = SqlDatabase("shashank", "shash27")

#sql_object.create_database("trial_db2")

sql_object.my_database = "honeypot"

values = ("1584770033.410457902", "192.168.0.109", "111.221.29.254", \
          "57646", "443", "a8:6b:ad:73:0c:e3", "a0:ab:1b:d8:39:eb")


sql_object.insert_packets("packets", values)

# sql_object._execute_sql_command("CREATE TABLE malicious_packets (timestamp VARCHAR(255),\
#                                 src_ip VARCHAR(255),\
#                                 dest_ip VARCHAR(255),\
#                                 src_port VARCHAR(255),\
#                                 dest_port VARCHAR(255),\
#                                 src_mac VARCHAR(255), \
#                                 dest_mac VARCHAR(255))")

sql_object.insert_packets("malicious_packets", values)

print(sql_object.get_packets("packets"))

