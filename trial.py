from database import SqlDatabase

sql_object = SqlDatabase("shashank", "shash27")

#sql_object.create_database("trial_db2")

sql_object.my_database = "honeypot"
print(sql_object.my_database)

values = ("1584770033.410457902", "a8:6b:ad:73:0c:e3", "a0:ab:1b:d8:39:eb",
          "57646", "443", "192.168.0.109", "111.221.29.254")
sql_object.insert_into_packets(values)