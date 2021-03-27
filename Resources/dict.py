
# users = [{"username":"Ali"},{"username":"Hassan"}]
user = {}
# print(user['username'])
# 
# print(user.get("username")) 

# if user['username']:
#     print("create password")
# print(user.get("username"))
# if not user.get('username'):
#     print("create password")



user_detail = {"username":"geele","email":"gele@gmail.com"}
user_address = {"address":"Hodan Distric"}

# Combine  - Update
user_detail.update(user_address)
# print(combined)
# for user in user_detail.items():
#     print(user)

# combine **

# print(**user_detail,**user_address)
combined = {**user_detail,**user_address}
# print(combined)

# combined with | python 3.9

all_detail =  user_address | user_detail
for _, value in all_detail.items():
    pass
    # print(value)

# print(dir(all_detail))

name = "name"
# print(dir(name))
