# Set: Unique unordered set of collections
s = {12,4,56,67,7}

# sorted
sss = sorted(s)
print(type(sss))
print(sss)
print(s)

# Type 
print(type(s))

# Update 
s.update([34,56,12,7])
print(s)

# Empty set
my_set = set()
print(type(my_set))

# Add value to set
my_set.add(12)
my_set.add(134)
print(my_set)

# How check if a variable is in set
if 122 in my_set:
    print(True)
else:
    print(False)


# Remove 
my_set.remove(12)
print(my_set)
# Discard : Remove if found otherwise do nothing
my_set.discard(13455)
print(my_set)

# 
blue_eyes = {"Ali","Ahmed"}
black_hair = {"Hassan","Ali"}

# Intersection
# blue_eyes_with_black_hair = blue_eyes.intersection(black_hair)
# print(blue_eyes_with_black_hair)

blue_eyes_with_black_hair = blue_eyes.difference(black_hair)
print(blue_eyes_with_black_hair)
blue_eyes_with_black_hair = black_hair.difference(blue_eyes)
print(blue_eyes_with_black_hair)



# Issubset
blue_eyes_with_black_hair = black_hair.issubset(blue_eyes)
print(blue_eyes_with_black_hair)
# union 
# union 
# all = blue_eyes.union(black_hair)
# print(all)


# issuperset
# isdisjoint








