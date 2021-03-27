
colors = ['red','blue','green']
colors[0] = 'gaduud' 
print(colors)

# get red
# print(colors[0])

# !Don't do this
# for i in range(len(colors)):
#     # print(colors[i])

#? DO this # Loop
# for color in colors:
#     print(color)

# ? DO this # Reversed
# for color in reversed(colors):
#     print(color)

# for color in sorted(colors):
#     print(color)

#? Do this
# for index,color in enumerate(colors):
#     print(index,color)

names = ['Geedi','Ahmed','Ali']
titles = ['Finance Officer','Freenlance Journalist','Computer Engineer']
companies = ['SomaliREN','Asalsol','RE']
#! Don't do this 
for index,name in enumerate(names):
    title = titles[index]
    # print(f" {name} waa {title} ")


#? Do this
# for name,title,company in zip(names,titles,companies):
#     print(f"{name} waa {title} waxa uu  u shaqeeyaa {company}")

# unpacking 
*_,r= companies
# print(r)

# ! Don't do this
# if names != None:
#     print(names[0]) 

# ? Do this
# if  names:
#     print(names[0]) 



numbers = [2,4,6,7]
# square
# sqr_numbers = []
# for number in numbers:
#     sqr_numbers.append(number*2)
# print(sqr_numbers)

# ! Do this - List comprehensions
srq_numbers = [number*2 for number in numbers ]
print(srq_numbers)








