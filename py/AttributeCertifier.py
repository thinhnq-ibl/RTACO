# create a schema order
# encode type

# title "Identity Certificate"
import datetime

schema = {}
encoding = {}
schemaOrder = []

encoding_type_map = {"1": type("string"), "2": type(1), "3": type(datetime.datetime.now())}

key = "msk"
schemaOrder.append(key)
schema.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding.setdefault(key, 2)

schemaOrder.append("name")
schema.setdefault(key, {"type" : encoding_type_map["1"], "visibility": "public"})
encoding.setdefault(key, int("1"))

schemaOrder.append("dob")
schema.setdefault(key, {"type" : encoding_type_map["3"], "visibility": "public"})
encoding.setdefault(key, int("3"))

schemaOrder.append("r")
schema.setdefault(key, {"type" : encoding_type_map["2"], "visibility": "private"})
encoding.setdefault(key, 2)

