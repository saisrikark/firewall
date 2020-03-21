from database import SqlDatabase

sql_object = SqlDatabase("shashank", "shash27")

#sql_object.create_database("trial_db1")

sql_object.my_database = "honeypot"
print(sql_object.my_database)

