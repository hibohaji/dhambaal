# 

# function with parameters 
def add(x:int,y:int)->int:
    return x,y

def display():
    print("hello world")

print(add(10,20))


def connect_to_server(*,ssl=False,server_name,ip):
    # server_name = "MY_SERVER"
    # ip = '127.0.0.1'
    if ssl:
        return f"connecting to server{server_name} with ip {ip}"
    return f"Cann't connect to the server"

# Keyword arguments
connected = connect_to_server(server_name='SomaliREN',ip='1.1.1.1')
print(connected)
   
# *34837483784

# values = (3,46,7,8,9,0)

# 

def do_something(*kwrgs):
    # print(type(kwrgs))
    # # print(type(args))
    # if isinstance(args,int):
        # return 'int'
    return kwrgs

# print(do_something(1,2,3,5,6,name="Ali"))

# Statically typed languages
# Java, C,C++,Rust,Go

# Dynamically typed languages
# Python, Ruby,


# 


mydict = {"name":"Hassan","id":1}

