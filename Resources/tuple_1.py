geo_location = (0.564,0.94574) 



# Type

# isinstance
# if isinstance(geo_location,tuple):
#     print("True")
# else:
#     print("Flase")

# 
if (type(geo_location),tuple):
    print("Tuple")
else:
    print("Not Tuple")


#
from sys import getsizeof
# When to use Tuple over Lists
huge_range_list = [x for x in range(100_000)]
print(f"List:{getsizeof(huge_range_list)} bytes")

huge_range_tuple = (x for x in range(100_000))
print(f"Tuple: {getsizeof(huge_range_tuple)} bytes")

# huge1_range = []
# for x in range(10_0000):
#     huge1_range.append(x)



print(geo_location.count(0.564))

cities = ("Mogadishu","Hargeisa","marka",'Jabuti','Hodan')
print(cities)

cities5 = cities*5

print(cities5)

print(len(cities))

location = ()
# location = None
# empty_list = []
# print(location)
# print(empty_list)

#  
#     print("No Location")

try:
    if not location:
        print("No Location")
    print("Varibale with location")
except:
    print("Error")


